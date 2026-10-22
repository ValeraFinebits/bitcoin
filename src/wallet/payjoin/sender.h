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
/** Wallet workflow state, independent of protocol outcome, reservations, and current transaction presence. */
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

/** Published wallet state. Action flags are hints; execution rechecks current conditions, including network policy. */
struct PaymentSnapshot {
    uint256 id;
    PaymentPhase phase{PaymentPhase::Queued};
    /** Signed original, which the receiver may broadcast after disclosure. */
    CTransactionRef original;
    /** Transaction selected for publication; explicit fallback selects the original. */
    CTransactionRef selected;

    bool original_saved{false};
    bool owns_inputs{false};

    /** Verification of current in-memory wallet locks, not their database persistence. */
    bool locks_verified{false};
    bool possibly_exposed{false};
    /** A transport accepted a request; this does not establish receiver observation. */
    bool transport_accepted{false};
    bool wallet_recorded{false};

    /** Last recorded publication result; consult selected_presence for current observation. */
    bool node_accepted{false};
    bool storage_uncertain{false};

    bool fallback_available{false};
    bool selection_saved{false};
    bool disclosure_saved{false};

    TransactionPresence original_presence{TransactionPresence::Missing};
    TransactionPresence selected_presence{TransactionPresence::Missing};
    /** Wallet-known mempool or confirmed spend of original inputs, including a competing transaction. */
    std::optional<SpendObservation> observed_spend;

    /** Confirmed spend used for reconciliation. Original takes precedence over Selected when both transactions match. */
    std::optional<SpendObservation> settlement;

    std::optional<PaymentIssue> issue;
    std::string diagnostic;

    /** Negotiation deadline; saved-proposal signing and publication retries have separate eligibility checks. */
    std::chrono::steady_clock::time_point deadline;

    bool cancel_available{false};
    bool signing_available{false};
    bool publication_retry_available{false};
};

/** Effective parameters fixed at registration, including resolved wallet defaults. */
struct PaymentIntent {
    std::string uri;
    std::string relay;
    CAmount amount{0};
    CFeeRate fee_rate;
    CAmount max_fee{0};
    std::chrono::milliseconds timeout{std::chrono::minutes{2}};
    std::chrono::milliseconds poll_interval{std::chrono::seconds{1}};
};

/** Parsed input, separate from effective wallet defaults for idempotency. */
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

/** Validate active-chain address, amount, fee and time limits. The pinned URI parser still admits v1. */
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

/** Result of one operation; refusal is separate from the payment problem. */
struct ManagerResult {
    CommandStatus status{CommandStatus::Completed};
    std::vector<PaymentView> payments{};
    bool duplicate{false};
    std::optional<RequestError> error{};
    std::string diagnostic{};
    std::optional<CommandRefusal> refusal{};
};

/** Wallet, serial runner, and injected callback dependencies must outlive Stop().
 * Cancel(), PublishFallback(), RetryPublication(), RetrySigning(), and Refresh()
 * queue work without waiting for completion; use Execute() instead when a result is needed.
 */
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

    /** Register a fixed intent, waiting for current execution but not preparation. */
    [[nodiscard]] uint256 Start(PaymentIntent intent);

    /** Accept without waiting for preparation or its notification barrier.
     * Dropping the future does not cancel accepted work.
     */
    std::future<ManagerResult> Send(PaymentRequest request);

    /** Refresh views in one runner task after a notification barrier.
     * Later notifications may appear on the next read.
     * Stop completes the read even if its barrier has not run.
     */
    std::future<ManagerResult> Read(std::optional<uint256> id = std::nullopt);

    /** Last published snapshot; does not refresh observations or wait for a notification barrier. */
    [[nodiscard]] std::optional<PaymentSnapshot> Snapshot(const uint256& id) const;

    void Cancel(const uint256& id);

    void PublishFallback(const uint256& id);

    void RetryPublication(const uint256& id);

    /** Retry saved-proposal signing and, on success, attempt publication. */
    void RetrySigning(const uint256& id);

    /** Queue observation refresh without a notification barrier. Use Read() for a barrier. */
    void Refresh(const uint256& id);

    /** Return this invocation's result and post-command view asynchronously.
     * Failed commands may have partial effects. Dropping the future does not
     * cancel the command; Stop completes pending operations with final views.
     */
    std::future<ManagerResult> Execute(const uint256& id, SenderCommand command);

    /** Close admission without waiting for current wallet work. */
    void Close();

    /** Reconcile delivery and publish all registered results before returning.
     * No wallet locks may be held. Do not call from the service's runner.
     * Future payment timers are not drained; exposed inputs may remain reserved.
     */
    void Stop();

    /** Immutable final views after Stop(), retaining no wallet resources; null before Stop() completes. */
    std::shared_ptr<const std::vector<PaymentView>> Archive() const;

private:
    struct State;
    std::shared_ptr<State> m_state;
};
} // namespace payjoin
} // namespace wallet
#endif // BITCOIN_WALLET_PAYJOIN_SENDER_H
