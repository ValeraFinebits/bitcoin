// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PAYJOIN_SENDER_H
#define BITCOIN_WALLET_PAYJOIN_SENDER_H

#include <consensus/amount.h>
#include <payjoin/client.h>
#include <payjoin/transport.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <uint256.h>
#include <util/expected.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class SerialTaskRunner;

namespace wallet {
class CWallet;
namespace payjoin {
enum class PaymentPhase {
    Queued,
    Ready,
    Negotiating,
    Cancelled,
    Attention,
    Published,
    Rejected,
    Confirmed,
    Conflicted,
    Stopped,
};

enum class PaymentIssue {
    InvalidIntent,
    Preparation,
    Storage,
    Reservation,
    Protocol,
    Delivery,
    Deadline,
    Signing,
    Publication,
    BroadcastDisabled,
    ObservedSpend,
};

enum class CommandRefusal {
    InvalidState,
    StorageUncertain,
    Selected,
    Settled,
    InputsChanged,
};

enum class TransactionPresence {
    Missing,
    Inactive,
    Mempool,
    Abandoned,
    MempoolConflicted,
    BlockConflicted,
    Confirmed,
};

enum class SpendKind {
    Original,
    Selected,
    Other,
};

struct SpendObservation {
    CTransactionRef transaction;
    SpendKind kind;
    TransactionPresence presence;

    explicit SpendObservation(CTransactionRef tx, SpendKind spend_kind, TransactionPresence tx_presence)
        : transaction{std::move(tx)}, kind{spend_kind}, presence{tx_presence} {}
};

struct PaymentSnapshot {
    uint256 id;
    PaymentPhase phase{PaymentPhase::Queued};
    CTransactionRef original;
    CTransactionRef selected;

    bool original_saved{false};
    bool owns_inputs{false};

    bool locks_verified{false};
    bool possibly_exposed{false};
    bool transport_accepted{false};
    bool wallet_recorded{false};

    bool node_accepted{false};
    bool storage_uncertain{false};

    bool fallback_available{false};
    bool selection_saved{false};
    bool disclosure_saved{false};

    TransactionPresence original_presence{TransactionPresence::Missing};
    TransactionPresence selected_presence{TransactionPresence::Missing};
    std::optional<SpendObservation> observed_spend;

    std::optional<SpendObservation> settlement;

    std::optional<PaymentIssue> issue;
    std::string diagnostic;

    std::chrono::steady_clock::time_point deadline;

    bool cancel_available{false};
    bool signing_available{false};
    bool publication_retry_available{false};
};

struct PaymentIntent {
    std::string uri;
    std::string relay;
    CAmount amount{0};
    CFeeRate fee_rate;
    CAmount max_fee{0};
    std::chrono::milliseconds timeout{std::chrono::minutes{2}};
    std::chrono::milliseconds poll_interval{std::chrono::seconds{1}};
};

struct PaymentRequest {
    std::string uri;
    std::string relay;
    std::optional<CAmount> amount;
    std::optional<CFeeRate> fee_rate;
    std::optional<CAmount> max_total_fee;
    std::optional<int64_t> timeout_seconds;
    std::optional<std::string> request_id;

    bool operator==(const PaymentRequest&) const = default;
};

struct PaymentView {
    PaymentSnapshot payment;
    PaymentRequest requested;
    PaymentIntent effective;
};

enum class RequestError {
    InvalidParameter,
    Locked,
    UnsupportedWallet,
    FeePolicy,
    NetworkPolicy,
    IdempotencyConflict,
    Internal,
};

util::Expected<PayjoinUriInfo, std::string> ValidatePaymentIntent(const PaymentIntent& intent);

enum class SenderCommand {
    Cancel,
    Fallback,
    RetrySigning,
    RetryPublication,
    Refresh,
};

enum class CommandStatus {
    Completed,
    Refused,
    Failed,
    Stopped,
    NotFound,
};

struct ManagerResult {
    CommandStatus status{CommandStatus::Completed};
    std::vector<PaymentView> payments{};
    bool duplicate{false};
    std::optional<RequestError> error{};
    std::string diagnostic{};
    std::optional<CommandRefusal> refusal{};
};

class SenderService
{
public:
    using Clock = std::chrono::steady_clock;
    using Now = std::function<Clock::time_point()>;
    using Schedule = std::function<void(std::chrono::milliseconds, std::function<void()>)>;
    using TransportFactory = std::function<std::unique_ptr<SenderTransport>()>;
    using NetworkCheck = std::function<std::optional<std::string>()>;

    explicit SenderService(CWallet& wallet, SerialTaskRunner& executor,
                           std::unique_ptr<SenderTransport> transport, Now now, Schedule schedule);

    explicit SenderService(CWallet& wallet, SerialTaskRunner& executor,
                           TransportFactory transport, Now now, Schedule schedule, NetworkCheck network_check);
    ~SenderService();

    SenderService(const SenderService&) = delete;

    SenderService& operator=(const SenderService&) = delete;

    [[nodiscard]] uint256 Start(PaymentIntent intent);

    std::future<ManagerResult> Send(PaymentRequest request);

    std::future<ManagerResult> Read(std::optional<uint256> id = std::nullopt);

    [[nodiscard]] std::optional<PaymentSnapshot> Snapshot(const uint256& id) const;

    void Cancel(const uint256& id);

    void PublishFallback(const uint256& id);

    void RetryPublication(const uint256& id);

    void RetrySigning(const uint256& id);

    void Refresh(const uint256& id);

    std::future<ManagerResult> Execute(const uint256& id, SenderCommand command);

    void Close();

    void Stop();

    std::shared_ptr<const std::vector<PaymentView>> Archive() const;

private:
    struct State;
    std::shared_ptr<State> m_state;
};
} // namespace payjoin
} // namespace wallet
#endif // BITCOIN_WALLET_PAYJOIN_SENDER_H
