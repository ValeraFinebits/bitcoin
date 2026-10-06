// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_TEST_PAYJOIN_SENDER_FIXTURE_H
#define BITCOIN_WALLET_TEST_PAYJOIN_SENDER_FIXTURE_H

#include <consensus/amount.h>
#include <key.h>
#include <payjoin/transport.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <scheduler.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <wallet/db.h>
#include <wallet/payjoin/sender.h>
#include <wallet/sqlite.h>
#include <wallet/test/payjoin_test_transport.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace wallet::payjoin::test {
inline constexpr auto PAYMENT_RECORD = "payjoin/payment";
inline constexpr auto OWNER_RECORD = "payjoin/owner";
inline constexpr auto JOURNAL_RECORD = "payjoin/journal";

struct StoredPayment {
    std::string uri;
    std::vector<unsigned char> original, selected;
    bool exposed{false}, released{false};

    SERIALIZE_METHODS(StoredPayment, obj) { READWRITE(obj.uri, obj.original, obj.selected, obj.exposed, obj.released); }
};

class FaultDatabase final : public MockableSQLiteDatabase
{
public:
    enum class WriteTarget {
        Payment,
        PaymentUnexposed,
        Owner,
        LockedCoin,
        Journal,
        JournalEvent,
        JournalClose,
    };

    enum class WriteFailure {
        BeforeWrite,
        AfterWrite,
    };

    enum class Transaction {
        Begin,
        Commit,
        Abort,
    };

    enum class CursorFault {
        None,
        Open,
        Read,
        Decode,
    };

private:
    std::optional<WriteTarget> m_write_target;
    std::optional<std::string> m_read_key;
    size_t m_read_skip{0};
    size_t m_read_failures{0};
    WriteFailure m_write_failure{WriteFailure::BeforeWrite};
    size_t m_write_failures{0};
    bool m_failed_write_recorded{false};
    size_t m_write_count{0};

    struct TransactionFailure {
        bool enabled{false};
        size_t hits{0};
    };

    std::map<Transaction, TransactionFailure> m_transaction_failures;
    bool m_failed_abort_completed{false};
    bool m_lose_commit_acknowledgement{false};
    size_t m_lost_commit_acknowledgements{0};
    std::string m_fail_erase;
    size_t m_erase_failures{0};
    CursorFault m_cursor_fault{CursorFault::None};
    size_t m_cursor_failures{0};
    bool m_owner_collision{false};
    bool m_registering{false};
    size_t m_owner_collisions{0};

    bool FailTransaction(Transaction operation);

    bool MatchesWrite(const std::string& type, const DataStream& value) const;

public:
    template <typename Key>
    void FailNextRead(const Key& key, size_t skip = 0)
    {
        BOOST_REQUIRE(!m_read_key);

        m_read_key = (DataStream{} << key).str();
        m_read_skip = skip;
        m_read_failures = 0;
    }

    void CheckReadFailed() const;

    void FailNextWrite(WriteTarget target, WriteFailure failure = WriteFailure::BeforeWrite);

    void CheckWriteFailed() const;

    size_t WriteCount() const { return m_write_count; }

    void SetTransactionFailure(Transaction operation, bool enabled = true);

    void CheckTransactionFailed(Transaction operation) const;

    void LoseNextCommitAcknowledgement();

    void CheckCommitAcknowledgementLost() const;

    void SetEraseFailure(std::string type);

    void ClearEraseFailure() { m_fail_erase.clear(); }

    void CheckEraseFailed() const { BOOST_CHECK_GT(m_erase_failures, 0); }

    void SetOwnerCursorFault(CursorFault fault);

    void CheckOwnerCursorFailed() const { BOOST_CHECK_GT(m_cursor_failures, 0); }

    void SetOwnerCollision(bool enabled = true);

    void CheckOwnerCollision() const { BOOST_CHECK_GT(m_owner_collisions, 0); }

    std::function<void(const std::string&)> m_on_read;
    std::function<void(const std::string&)> m_on_write;
    std::function<void(Transaction, bool)> m_on_transaction;

    class Batch final : public SQLiteBatch
    {
        FaultDatabase& m_db;

        bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite) override;

    public:
        explicit Batch(FaultDatabase& db) : SQLiteBatch{db}, m_db{db} {}

        bool HasKey(DataStream&& key) override;

        bool ReadKey(DataStream&& key, DataStream& value) override;

        bool TxnAbort() override;

        bool EraseKey(DataStream&& key) override;

        bool TxnBegin() override;

        bool TxnCommit() override;

        std::unique_ptr<DatabaseCursor> GetNewPrefixCursor(std::span<const std::byte> prefix) override;
    };

    std::unique_ptr<DatabaseBatch> MakeBatch() override { return std::make_unique<Batch>(*this); }
};

struct SenderFixture : TestChain100Setup {
    enum class Execution {
        Controlled,
        Asynchronous,
    };

    const Execution m_execution;
    CKey m_sender_key, m_sender_extra_key, m_receiver_key;
    CTransactionRef m_receiver_coin;
    CTransactionRef m_receiver_input_override;
    std::unique_ptr<CWallet> m_sender, m_receiver;
    FaultDatabase* m_database{nullptr};
    CScheduler m_scheduler;
    std::unique_ptr<SerialTaskRunner> m_queue{std::make_unique<SerialTaskRunner>(m_scheduler)};
    ControlledTransport* m_transport{nullptr};
    SenderService::Clock::time_point m_now{};
    std::multimap<SenderService::Clock::time_point, std::function<void()>> m_timers;
    std::unique_ptr<SenderService> m_service;
    std::string m_uri;
    std::string m_relay{"https://relay.example"};

    std::unique_ptr<SenderService> MakeService(std::unique_ptr<SenderTransport> owned_transport);

    SenderFixture() : SenderFixture{Execution::Controlled, std::make_unique<ControlledTransport>()} {}

    explicit SenderFixture(Execution execution, std::unique_ptr<SenderTransport> owned_transport);

    ~SenderFixture() { Shutdown(); }

    void Shutdown();

    void Flush();

    PaymentIntent Intent() { return {m_uri, m_relay, COIN, CFeeRate{1000}, COIN / 100}; }

    StoredPayment ReadStoredPayment(const uint256& id);

    bool HasStoredPayment(const uint256& id);

    uint256 ReadOwner(const COutPoint& input);

    bool HasOwner(const COutPoint& input);

    void WriteOwner(const COutPoint& input, const uint256& owner);

    bool LockedMarker(const COutPoint& input);

    void CheckOwnedInputs(const uint256& id, const CTransaction& original) EXCLUSIVE_LOCKS_REQUIRED(m_sender->cs_wallet);

    void CheckReleased(const uint256& id);

    CBlock Confirm(const CTransactionRef& tx);

    void Disconnect(const CBlock& block);

    std::pair<std::vector<std::string>, bool> Journal(const uint256& id);

    void Tick();
};
} // namespace wallet::payjoin::test
#endif // BITCOIN_WALLET_TEST_PAYJOIN_SENDER_FIXTURE_H
