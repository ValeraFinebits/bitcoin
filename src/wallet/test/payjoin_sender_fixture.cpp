// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/test/payjoin_sender_fixture.h>

#include <addresstype.h>
#include <chain.h>
#include <consensus/validation.h>
#include <kernel/chain.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <scheduler.h>
#include <script/solver.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <validation.h>
#include <wallet/db.h>
#include <wallet/payjoin/sender.h>
#include <wallet/scan.h>
#include <wallet/sqlite.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace wallet::payjoin::test {

bool FaultDatabase::FailTransaction(Transaction operation)
{
    const auto failure = m_transaction_failures.find(operation);
    if (failure == m_transaction_failures.end() || !failure->second.enabled) return false;

    ++failure->second.hits;
    return true;
}

bool FaultDatabase::MatchesWrite(const std::string& type, const DataStream& value) const
{
    if (!m_write_target) return false;

    switch (*m_write_target) {
    case WriteTarget::Payment: return type == PAYMENT_RECORD;
    case WriteTarget::PaymentUnexposed: {
        if (type != PAYMENT_RECORD) return false;

        DataStream copy{value};
        StoredPayment payment;
        copy >> payment;
        return !payment.exposed;
    }
    case WriteTarget::Owner: return type == OWNER_RECORD;
    case WriteTarget::LockedCoin: return type == DBKeys::LOCKED_UTXO;
    case WriteTarget::Journal: return type == JOURNAL_RECORD;
    case WriteTarget::JournalEvent:
    case WriteTarget::JournalClose: {
        if (type != JOURNAL_RECORD) return false;

        DataStream copy{value};
        std::pair<std::vector<std::string>, bool> journal;
        copy >> journal;
        return *m_write_target == WriteTarget::JournalClose ? journal.second : !journal.first.empty();
    }
    }
    return false;
}

void FaultDatabase::CheckReadFailed() const
{
    BOOST_REQUIRE(!m_read_key);
    BOOST_REQUIRE_EQUAL(m_read_failures, 1);
}

void FaultDatabase::FailNextWrite(WriteTarget target, WriteFailure failure)
{
    BOOST_REQUIRE(!m_write_target);

    m_write_target = target;
    m_write_failure = failure;
    m_write_failures = 0;
    m_failed_write_recorded = false;
}

void FaultDatabase::CheckWriteFailed() const
{
    BOOST_CHECK(!m_write_target);
    BOOST_CHECK_EQUAL(m_write_failures, 1);
    BOOST_CHECK_EQUAL(m_failed_write_recorded, m_write_failure == WriteFailure::AfterWrite);
}

void FaultDatabase::SetTransactionFailure(Transaction operation, bool enabled)
{
    auto& failure = m_transaction_failures[operation];
    failure.enabled = enabled;
    if (enabled) failure.hits = 0;
}

void FaultDatabase::CheckTransactionFailed(Transaction operation) const
{
    const auto failure = m_transaction_failures.find(operation);
    BOOST_REQUIRE(failure != m_transaction_failures.end());
    BOOST_CHECK_GT(failure->second.hits, 0);
    if (operation == Transaction::Abort) BOOST_CHECK(m_failed_abort_completed);
}

void FaultDatabase::LoseNextCommitAcknowledgement()
{
    BOOST_REQUIRE(!m_lose_commit_acknowledgement);

    m_lose_commit_acknowledgement = true;
    m_lost_commit_acknowledgements = 0;
}

void FaultDatabase::CheckCommitAcknowledgementLost() const
{
    BOOST_CHECK(!m_lose_commit_acknowledgement);
    BOOST_CHECK_EQUAL(m_lost_commit_acknowledgements, 1);
}

void FaultDatabase::SetEraseFailure(std::string type)
{
    m_fail_erase = std::move(type);
    m_erase_failures = 0;
}

void FaultDatabase::SetOwnerCursorFault(CursorFault fault)
{
    m_cursor_fault = fault;
    m_cursor_failures = 0;
}

void FaultDatabase::SetOwnerCollision(bool enabled)
{
    m_owner_collision = enabled;
    if (enabled) m_owner_collisions = 0;
}

bool FaultDatabase::Batch::WriteKey(DataStream&& key, DataStream&& value, bool overwrite)
{
    DataStream copy{key};
    std::string type;
    copy >> type;

    if (m_db.m_on_write) m_db.m_on_write(type);
    if (type == PAYMENT_RECORD) m_db.m_registering = true;
    ++m_db.m_write_count;

    const bool fail = m_db.MatchesWrite(type, value);
    if (fail) {
        m_db.m_write_target.reset();
        ++m_db.m_write_failures;
        if (m_db.m_write_failure == WriteFailure::BeforeWrite) return false;
    }

    const bool result = SQLiteBatch::WriteKey(std::move(key), std::move(value), overwrite);
    if (fail) m_db.m_failed_write_recorded = result;
    return result && !fail;
}

bool FaultDatabase::Batch::HasKey(DataStream&& key)
{
    DataStream copy{key};
    std::string type;
    copy >> type;
    if (m_db.m_owner_collision && m_db.m_registering && type == OWNER_RECORD) {
        ++m_db.m_owner_collisions;
        return true;
    }

    return SQLiteBatch::HasKey(std::move(key));
}

bool FaultDatabase::Batch::ReadKey(DataStream&& key, DataStream& value)
{
    DataStream copy{key};
    std::string type;
    copy >> type;
    if (m_db.m_on_read) m_db.m_on_read(type);
    if (m_db.m_read_key && key.str() == *m_db.m_read_key) {
        if (m_db.m_read_skip > 0) {
            --m_db.m_read_skip;
        } else {
            m_db.m_read_key.reset();
            ++m_db.m_read_failures;
            return false;
        }
    }

    return SQLiteBatch::ReadKey(std::move(key), value);
}

bool FaultDatabase::Batch::TxnAbort()
{
    const bool result = SQLiteBatch::TxnAbort();
    const bool fail = m_db.FailTransaction(Transaction::Abort);
    if (fail) m_db.m_failed_abort_completed = result;
    const bool reported = result && !fail;
    if (m_db.m_on_transaction) m_db.m_on_transaction(Transaction::Abort, reported);
    return reported;
}

bool FaultDatabase::Batch::EraseKey(DataStream&& key)
{
    DataStream copy{key};
    std::string type;
    copy >> type;
    if (type == m_db.m_fail_erase) {
        ++m_db.m_erase_failures;
        return false;
    }

    return SQLiteBatch::EraseKey(std::move(key));
}

bool FaultDatabase::Batch::TxnBegin()
{
    const bool result = !m_db.FailTransaction(Transaction::Begin) && SQLiteBatch::TxnBegin();
    if (m_db.m_on_transaction) m_db.m_on_transaction(Transaction::Begin, result);
    return result;
}

bool FaultDatabase::Batch::TxnCommit()
{
    const bool result = !m_db.FailTransaction(Transaction::Commit) && SQLiteBatch::TxnCommit();
    bool reported = result;
    if (result && m_db.m_lose_commit_acknowledgement) {
        m_db.m_lose_commit_acknowledgement = false;
        ++m_db.m_lost_commit_acknowledgements;
        reported = false;
    }

    if (m_db.m_on_transaction) m_db.m_on_transaction(Transaction::Commit, reported);
    return reported;
}

std::unique_ptr<DatabaseCursor> FaultDatabase::Batch::GetNewPrefixCursor(std::span<const std::byte> prefix)
{
    DataStream copy{prefix};
    std::string type;
    copy >> type;
    if (type == OWNER_RECORD) {
        if (m_db.m_cursor_fault == CursorFault::Open) {
            ++m_db.m_cursor_failures;
            return nullptr;
        }
        if (m_db.m_cursor_fault != CursorFault::None) {
            class FailedCursor final : public DatabaseCursor
            {
                CursorFault m_fault;
                FaultDatabase& m_db;

            public:
                explicit FailedCursor(CursorFault fault, FaultDatabase& db) : m_fault{fault}, m_db{db} {}

                Status Next(DataStream& key, DataStream& value) override
                {
                    ++m_db.m_cursor_failures;
                    if (m_fault == CursorFault::Read) return Status::FAIL;
                    key << std::string{OWNER_RECORD};
                    return Status::MORE;
                }
            };

            return std::make_unique<FailedCursor>(m_db.m_cursor_fault, m_db);
        }
    }

    return SQLiteBatch::GetNewPrefixCursor(prefix);
}

std::unique_ptr<SenderService> SenderFixture::MakeService(std::unique_ptr<SenderTransport> owned_transport)
{
    if (m_execution == Execution::Asynchronous) {
        return std::make_unique<SenderService>(
            *m_sender, *m_queue, std::move(owned_transport), SenderService::Clock::now,
            [this](std::chrono::milliseconds delay, std::function<void()> fn) {
                m_scheduler.scheduleFromNow(std::move(fn), delay);
            });
    }

    return std::make_unique<SenderService>(
        *m_sender, *m_queue, std::move(owned_transport), [this] { return m_now; },
        [this](std::chrono::milliseconds delay, std::function<void()> fn) {
            m_timers.emplace(m_now + delay, std::move(fn));
        });
}

SenderFixture::SenderFixture(Execution execution, std::unique_ptr<SenderTransport> owned_transport)
    : m_execution{execution}
{
    m_sender_key.MakeNewKey(true);
    m_sender_extra_key.MakeNewKey(true);
    m_receiver_key.MakeNewKey(true);
    const auto sender_script = GetScriptForDestination(WitnessV0KeyHash{m_sender_key.GetPubKey()});
    CreateAndProcessBlock({}, sender_script);
    CreateAndProcessBlock({}, GetScriptForDestination(WitnessV0KeyHash{m_sender_extra_key.GetPubKey()}));
    const auto receiver_script = GetScriptForDestination(WitnessV0KeyHash{m_receiver_key.GetPubKey()});
    m_receiver_coin = CreateAndProcessBlock({}, receiver_script).vtx[0];
    mineBlocks(100);

    auto db = std::make_unique<FaultDatabase>();
    m_database = db.get();
    m_sender = std::make_unique<CWallet>(m_node.chain.get(), "", std::move(db));
    {
        LOCK(m_sender->cs_wallet);
        LOCK(cs_main);
        const auto& chain = m_node.chainman->ActiveChain();
        m_sender->SetLastBlockProcessed(chain.Height(), chain.Tip()->GetBlockHash());
        m_sender->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        m_sender->SetupDescriptorScriptPubKeyMans();
        CreateDescriptor(*m_sender, "combo(" + EncodeSecret(m_sender_key) + ")", true);
        CreateDescriptor(*m_sender, "combo(" + EncodeSecret(m_sender_extra_key) + ")", true);
    }

    WalletRescanReserver reserver{*m_sender};
    BOOST_REQUIRE(reserver.reserve());
    BOOST_REQUIRE(m_sender->Scanner().Scan(m_node.chainman->ActiveChain().Genesis()->GetBlockHash(), 0,
                                           std::nullopt, reserver, false)
                      .status == ScanResult::SUCCESS);
    m_receiver = CreateSyncedWallet(*m_node.chain, m_node.chainman->ActiveChain(), m_receiver_key);
    m_sender->SetBroadcastTransactions(true);

    m_uri = "bitcoin:" + EncodeDestination(WitnessV0KeyHash{m_receiver_key.GetPubKey()}) +
            "?amount=1&pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1QPTCDAQ-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-"
            "RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    if (m_execution == Execution::Controlled) m_transport = static_cast<ControlledTransport*>(owned_transport.get());
    m_service = MakeService(std::move(owned_transport));
    if (m_execution == Execution::Asynchronous) {
        m_scheduler.m_service_thread = std::thread{[this] { m_scheduler.serviceQueue(); }};
    }
}

void SenderFixture::Shutdown()
{
    m_service->Stop();
    m_scheduler.stop();
    m_queue->flush();
}

void SenderFixture::Flush()
{
    BOOST_REQUIRE(m_execution == Execution::Controlled);
    m_queue->flush();
    m_node.chain->waitForNotifications();
    m_queue->flush();
}

StoredPayment SenderFixture::ReadStoredPayment(const uint256& id)
{
    StoredPayment stored;
    BOOST_REQUIRE(m_database->MakeBatch()->Read(std::pair{std::string{PAYMENT_RECORD}, id}, stored));
    return stored;
}

bool SenderFixture::HasStoredPayment(const uint256& id)
{
    return m_database->MakeBatch()->Exists(std::pair{std::string{PAYMENT_RECORD}, id});
}

uint256 SenderFixture::ReadOwner(const COutPoint& input)
{
    uint256 owner;
    BOOST_REQUIRE(m_database->MakeBatch()->Read(std::pair{std::string{OWNER_RECORD}, input}, owner));
    return owner;
}

bool SenderFixture::HasOwner(const COutPoint& input)
{
    return m_database->MakeBatch()->Exists(std::pair{std::string{OWNER_RECORD}, input});
}

void SenderFixture::WriteOwner(const COutPoint& input, const uint256& owner)
{
    BOOST_REQUIRE(m_database->MakeBatch()->Write(std::pair{std::string{OWNER_RECORD}, input}, owner));
}

bool SenderFixture::LockedMarker(const COutPoint& input)
{
    uint8_t marker{0};
    const bool present = m_database->MakeBatch()->Read(
        std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(input.hash, input.n)), marker);
    if (present) BOOST_CHECK_EQUAL(marker, uint8_t{'1'});
    return present;
}

void SenderFixture::CheckOwnedInputs(const uint256& id, const CTransaction& original)
{
    AssertLockHeld(m_sender->cs_wallet);

    for (const auto& input : original.vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
        BOOST_CHECK(m_sender->IsLockedCoin(input.prevout));
        BOOST_CHECK(LockedMarker(input.prevout));
    }
}

void SenderFixture::CheckReleased(const uint256& id)
{
    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE(view.original);
    BOOST_REQUIRE(view.settlement);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(!view.storage_uncertain);
    BOOST_CHECK(!view.issue);

    const auto stored = ReadStoredPayment(id);
    BOOST_CHECK(stored.released);

    LOCK(m_sender->cs_wallet);
    for (const auto& input : view.original->vin) {
        BOOST_CHECK(!m_sender->IsLockedCoin(input.prevout));
        BOOST_CHECK(!LockedMarker(input.prevout));
        BOOST_CHECK(!HasOwner(input.prevout));
    }
}

CBlock SenderFixture::Confirm(const CTransactionRef& tx)
{
    CKey miner;
    miner.MakeNewKey(true);
    const auto block = CreateAndProcessBlock({CMutableTransaction{*tx}}, GetScriptForRawPubKey(miner.GetPubKey()));
    int height;
    {
        LOCK(m_sender->cs_wallet);
        LOCK(cs_main);
        height = m_node.chainman->ActiveChain().Height();
        m_sender->SetLastBlockProcessed(height, block.GetHash());
    }

    WalletRescanReserver reserver{*m_sender};
    BOOST_REQUIRE(reserver.reserve());
    BOOST_REQUIRE(m_sender->Scanner().Scan(block.GetHash(), height, std::nullopt, reserver, false).status == ScanResult::SUCCESS);
    return block;
}

void SenderFixture::Disconnect(const CBlock& block)
{
    auto* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip->GetBlockHash() == block.GetHash());
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
    m_sender->blockDisconnected(kernel::MakeBlockInfo(tip, &block));
}

std::pair<std::vector<std::string>, bool> SenderFixture::Journal(const uint256& id)
{
    std::pair<std::vector<std::string>, bool> journal;
    BOOST_REQUIRE(m_sender->GetDatabase().MakeBatch()->Read(std::pair{std::string{JOURNAL_RECORD}, id}, journal));
    return journal;
}

void SenderFixture::Tick()
{
    BOOST_REQUIRE(m_execution == Execution::Controlled);
    BOOST_REQUIRE(!m_timers.empty());

    auto it = m_timers.begin();
    m_now = it->first;
    auto fn = std::move(it->second);
    m_timers.erase(it);
    fn();
    m_queue->flush();
}

} // namespace wallet::payjoin::test
