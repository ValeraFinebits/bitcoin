// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/payjoin/sender.h>

#include <addresstype.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <key_io.h>
#include <logging.h>
#include <node/types.h>
#include <payjoin/client.h>
#include <payjoin/transport.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <random.h>
#include <scheduler.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <util/expected.h>
#include <util/result.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <wallet/coincontrol.h>
#include <wallet/db.h>
#include <wallet/fees.h>
#include <wallet/spend.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace wallet::payjoin {
namespace {
struct FallbackPolicyFacts {
    SenderPhase phase{SenderPhase::Initial};
    std::optional<SenderOutcomeKind> outcome;
    bool session_present{false};
    bool storage_uncertain{false};
    bool selected{false};
    bool settled{false};
    bool released{false};
};

[[nodiscard]] std::optional<CommandRefusal> EvaluateFallbackPolicy(const FallbackPolicyFacts& facts)
{
    if (facts.storage_uncertain) return CommandRefusal::StorageUncertain;
    if (facts.selected) return CommandRefusal::Selected;
    if (facts.settled) return CommandRefusal::Settled;
    if (!facts.session_present || facts.released) return CommandRefusal::InvalidState;

    if (facts.phase == SenderPhase::Initial || facts.phase == SenderPhase::Polling ||
        facts.phase == SenderPhase::PendingFallback) {
        return std::nullopt;
    }
    if (facts.phase == SenderPhase::Closed &&
        (facts.outcome == SenderOutcomeKind::Aborted || facts.outcome == SenderOutcomeKind::Proposal ||
         facts.outcome == SenderOutcomeKind::SuccessWithoutProposal)) {
        return std::nullopt;
    }
    return CommandRefusal::InvalidState;
}

[[nodiscard]] std::optional<CAmount> CheckedOutputValue(const CMutableTransaction& tx)
{
    CAmount total{0};
    for (const auto& output : tx.vout) {
        if (!MoneyRange(output.nValue) || output.nValue > MAX_MONEY - total) return std::nullopt;
        total += output.nValue;
    }
    return total;
}

constexpr auto PAYJOIN_LOG_CATEGORY{BCLog::WALLETDB};

auto RecordKey(const uint256& id) { return std::pair{std::string{"payjoin/payment"}, id}; }

auto JournalKey(const uint256& id) { return std::pair{std::string{"payjoin/journal"}, id}; }

auto OwnerKey(const COutPoint& out) { return std::pair{std::string{"payjoin/owner"}, out}; }

std::vector<unsigned char> TxBytes(const CTransactionRef& tx)
{
    if (!tx) return {};

    std::vector<unsigned char> bytes;
    VectorWriter{bytes, 0, TX_WITH_WITNESS(tx)};
    return bytes;
}

struct Record {
    std::string uri;
    std::vector<unsigned char> original;
    std::vector<unsigned char> selected;
    bool exposed{false};
    bool released{false};
    SERIALIZE_METHODS(Record, obj) { READWRITE(obj.uri, obj.original, obj.selected, obj.exposed, obj.released); }
};

struct JournalRecord {
    std::vector<std::string> events;
    bool closed{false};
    SERIALIZE_METHODS(JournalRecord, obj) { READWRITE(obj.events, obj.closed); }
};

class WalletJournal final : public SenderEventLog
{
    CWallet& m_wallet;
    uint256 m_id;

public:
    explicit WalletJournal(CWallet& wallet, const uint256& id) : m_wallet{wallet}, m_id{id} {}

    util::Expected<void, std::string> Save(std::string event) override
    {
        LOCK(m_wallet.cs_wallet);
        auto batch = m_wallet.GetDatabase().MakeBatch();
        JournalRecord record;
        if (!batch->Read(JournalKey(m_id), record) || record.closed) return util::Unexpected<std::string>{"journal unavailable"};

        record.events.push_back(std::move(event));
        if (!batch->Write(JournalKey(m_id), record)) return util::Unexpected<std::string>{"journal save failed"};
        return {};
    }

    util::Expected<std::vector<std::string>, std::string> Load() override
    {
        LOCK(m_wallet.cs_wallet);
        JournalRecord record;
        if (!m_wallet.GetDatabase().MakeBatch()->Read(JournalKey(m_id), record)) return util::Unexpected<std::string>{"journal load failed"};
        return record.events;
    }

    util::Expected<void, std::string> Close() override
    {
        LOCK(m_wallet.cs_wallet);
        auto batch = m_wallet.GetDatabase().MakeBatch();
        JournalRecord record;
        if (!batch->Read(JournalKey(m_id), record)) return util::Unexpected<std::string>{"journal load failed"};
        if (record.closed) return {};

        record.closed = true;
        if (!batch->Write(JournalKey(m_id), record)) return util::Unexpected<std::string>{"journal close failed"};
        return {};
    }
};
} // namespace

util::Expected<PayjoinUriInfo, std::string> ValidatePaymentIntent(const PaymentIntent& intent)
{
    if (!MoneyRange(intent.amount) || intent.amount == 0 || !MoneyRange(intent.max_fee) ||
        intent.fee_rate.GetFeePerK() <= 0 || intent.timeout <= std::chrono::milliseconds::zero() ||
        intent.timeout > std::chrono::hours{24} || intent.poll_interval <= std::chrono::milliseconds::zero() ||
        intent.poll_interval > intent.timeout) {
        return util::Unexpected<std::string>{"invalid amount, fee policy or timeout"};
    }

    // TODO: Reject v1 before admission and reservation once the FFI exposes
    // a typed v2 check: https://github.com/payjoin/rust-payjoin/issues/1849.
    const auto uri = ParsePayjoinUri(intent.uri);
    if (!uri) return util::Unexpected<std::string>{uri.error().message};

    const auto destination = DecodeDestination(uri->address);
    if (!IsValidDestination(destination) || (uri->amount_sats && *uri->amount_sats != static_cast<uint64_t>(intent.amount))) {
        return util::Unexpected<std::string>{"destination network or amount mismatch"};
    }
    return *uri;
}

struct SenderService::State : std::enable_shared_from_this<State> {
    struct Payment {
        PaymentIntent intent;
        PaymentRequest requested;
        uint256 id;
        PaymentPhase phase{PaymentPhase::Queued};
        CTransactionRef original;
        CTransactionRef selected;

        struct Storage {
            bool registered{false};
            bool selection_saved{false};
            bool disclosure_saved{false};
            bool released{false};
            bool uncertain{false};
        } storage;

        bool exposed{false};
        bool transport_accepted{false};
        bool wallet_recorded{false};

        bool node_accepted{false};
        bool locks_verified{false};
        std::optional<PaymentIssue> issue;
        std::string diagnostic;

        TransactionPresence original_presence{TransactionPresence::Missing};
        TransactionPresence selected_presence{TransactionPresence::Missing};
        std::optional<SpendObservation> observed_spend;
        std::optional<SpendObservation> settlement;

        std::optional<SenderSession> session;
        Clock::time_point deadline;

        struct RequestEvidence {
            uint64_t id;
            bool was_exposed;
            std::atomic<bool> not_sent{false};

            explicit RequestEvidence(uint64_t request_id, bool exposed_before_request) : id{request_id}, was_exposed{exposed_before_request} {}
        };

        std::shared_ptr<RequestEvidence> request;
        std::shared_ptr<RequestEvidence> retired_request;
        uint64_t generation{0};
    };

    CWallet& m_wallet;
    SerialTaskRunner& m_executor;
    interfaces::Chain& m_chain;
    std::unique_ptr<SenderTransport> m_transport;
    TransportFactory m_transport_factory;
    Now m_now;
    Schedule m_schedule;
    NetworkCheck m_network_check;
    std::unique_ptr<interfaces::Handler> m_notifications;
    Mutex m_stop_mutex;
    Mutex m_gate;
    std::map<uint256, Payment> m_payments GUARDED_BY(m_gate);
    std::map<std::string, uint256> m_request_ids GUARDED_BY(m_gate);
    uint64_t m_next_request GUARDED_BY(m_gate){0};

    enum class Lifecycle {
        Running,
        Closing,
        Stopped,
    };

    struct Operation {
        std::optional<uint256> id;
        std::promise<ManagerResult> promise;

        explicit Operation(std::optional<uint256> payment_id) : id{payment_id} {}
    };

    mutable Mutex m_operations_mutex;
    Lifecycle m_lifecycle GUARDED_BY(m_operations_mutex){Lifecycle::Running};
    std::set<std::shared_ptr<Operation>> m_operations GUARDED_BY(m_operations_mutex);
    bool m_observation_pending GUARDED_BY(m_operations_mutex){false};
    std::shared_ptr<const std::vector<PaymentView>> m_archive GUARDED_BY(m_operations_mutex);

    mutable Mutex m_views_mutex;
    std::map<uint256, PaymentSnapshot> m_views GUARDED_BY(m_views_mutex);

    explicit State(CWallet& wallet, SerialTaskRunner& executor,
                   std::unique_ptr<SenderTransport> transport, Now now, Schedule schedule)
        : m_wallet{wallet}, m_executor{executor}, m_chain{wallet.chain()}, m_transport{std::move(transport)}, m_now{std::move(now)}, m_schedule{std::move(schedule)} {}

    explicit State(CWallet& wallet, SerialTaskRunner& executor,
                   TransportFactory transport, Now now, Schedule schedule, NetworkCheck network_check)
        : m_wallet{wallet}, m_executor{executor}, m_chain{wallet.chain()}, m_transport_factory{std::move(transport)}, m_now{std::move(now)}, m_schedule{std::move(schedule)}, m_network_check{std::move(network_check)} {}

    static Record StoredRecord(const Payment& payment)
    {
        return {payment.intent.uri, TxBytes(payment.original), TxBytes(payment.selected), payment.exposed, payment.storage.released};
    }

    static std::optional<CommandRefusal> FallbackRefusal(const Payment& payment)
    {
        return EvaluateFallbackPolicy({
            .phase = payment.session ? payment.session->Phase() : SenderPhase::Initial,
            .outcome = payment.session ? payment.session->OutcomeKind() : std::nullopt,
            .session_present = payment.session.has_value(),
            .storage_uncertain = payment.storage.uncertain,
            .selected = bool(payment.selected),
            .settled = payment.settlement.has_value(),
            .released = payment.storage.released,
        });
    }

    static PaymentSnapshot BuildSnapshot(const Payment& payment)
    {
        PaymentSnapshot view;
        view.id = payment.id;
        view.phase = payment.phase;
        view.original = payment.original;
        view.selected = payment.selected;
        view.original_saved = payment.storage.registered;
        view.selection_saved = payment.storage.selection_saved;
        view.disclosure_saved = payment.storage.disclosure_saved;
        view.owns_inputs = payment.storage.registered && !payment.storage.released;
        view.storage_uncertain = payment.storage.uncertain;
        view.locks_verified = payment.locks_verified;
        view.possibly_exposed = payment.exposed;
        view.transport_accepted = payment.transport_accepted;
        view.wallet_recorded = payment.wallet_recorded;
        view.node_accepted = payment.node_accepted;
        view.fallback_available = !FallbackRefusal(payment);
        view.issue = payment.issue;
        view.diagnostic = payment.diagnostic;
        view.original_presence = payment.original_presence;
        view.selected_presence = payment.selected_presence;
        view.observed_spend = payment.observed_spend;
        view.settlement = payment.settlement;
        view.deadline = payment.deadline;
        view.cancel_available = !payment.storage.uncertain && !payment.selected && !payment.settlement &&
                                payment.phase != PaymentPhase::Stopped && payment.phase != PaymentPhase::Cancelled;
        view.signing_available = payment.session && payment.session->OutcomeKind() == SenderOutcomeKind::Proposal &&
                                 !payment.storage.uncertain && !payment.storage.released && !payment.selected && !payment.settlement &&
                                 payment.phase != PaymentPhase::Cancelled && payment.phase != PaymentPhase::Stopped;
        view.publication_retry_available = payment.selected && payment.storage.selection_saved && payment.wallet_recorded &&
                                           !payment.storage.uncertain && !payment.storage.released && !payment.settlement;
        return view;
    }

    void Update(const Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LOCK(m_views_mutex);
        m_views[payment.id] = BuildSnapshot(payment);
    }

    struct CommandOutcome {
        CommandStatus status;
        std::optional<CommandRefusal> refusal{};
    };

    static CommandOutcome Refuse(CommandRefusal reason) { return {CommandStatus::Refused, reason}; }

    void Fail(Payment& payment, PaymentIssue issue, std::string diagnostic) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LogDebug(PAYJOIN_LOG_CATEGORY, "Payjoin payment requires attention (issue %d)\n", static_cast<int>(issue));
        if (!payment.settlement) payment.phase = PaymentPhase::Attention;
        payment.issue = issue;
        payment.diagnostic = std::move(diagnostic);
        Update(payment);
    }

    void StorageFailure(Payment& payment, std::string diagnostic) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        payment.storage.uncertain = true;
        Fail(payment, PaymentIssue::Storage, std::move(diagnostic));
    }

    bool Running() const EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        LOCK(m_operations_mutex);
        return m_lifecycle == Lifecycle::Running;
    }

    void Post(std::function<void(State&)> work) EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        LOCK(m_operations_mutex);
        if (m_lifecycle != Lifecycle::Running) return;

        m_executor.insert([weak = weak_from_this(), work = std::move(work)] {
            if (auto state = weak.lock()) {
                LOCK(state->m_gate);
                if (!state->Running()) return;

                work(*state);
            }
        });
    }

    void Queue(const uint256& id, std::function<void(State&, Payment&)> fn) EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        Post([id, fn = std::move(fn)](State& state) EXCLUSIVE_LOCKS_REQUIRED(state.m_gate) {
            const auto found = state.m_payments.find(id);
            if (found == state.m_payments.end()) return;

            try {
                fn(state, found->second);
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                state.StorageFailure(found->second, "wallet operation failed; effects require reconciliation");
            }
        });
    }

    static PaymentView View(const Payment& payment)
    {
        return {BuildSnapshot(payment), payment.requested, payment.intent};
    }

    static ManagerResult StoppedResult(const std::vector<PaymentView>& archive, std::optional<uint256> id)
    {
        ManagerResult result{CommandStatus::Stopped};
        for (const auto& view : archive) {
            if (!id || view.payment.id == *id) result.payments.push_back(view);
        }
        return result;
    }

    std::pair<std::shared_ptr<Operation>, std::future<ManagerResult>> Register(std::optional<uint256> id)
        EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        auto operation = std::make_shared<Operation>(id);
        auto future = operation->promise.get_future();

        LOCK(m_operations_mutex);
        if (m_lifecycle == Lifecycle::Stopped) {
            operation->promise.set_value(StoppedResult(*m_archive, id));
            return {nullptr, std::move(future)};
        }

        m_operations.insert(operation);
        return {std::move(operation), std::move(future)};
    }

    void Finish(const std::shared_ptr<Operation>& operation, ManagerResult result, bool running_only = false) EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        LOCK(m_operations_mutex);
        if (running_only && m_lifecycle != Lifecycle::Running) return;
        if (!m_operations.contains(operation)) return;

        operation->promise.set_value(std::move(result));
        m_operations.erase(operation);
    }

    void RunOperation(const std::shared_ptr<Operation>& operation, std::function<ManagerResult(State&)> work) EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        Post([operation, work = std::move(work)](State& state) EXCLUSIVE_LOCKS_REQUIRED(state.m_gate) {
            ManagerResult result;
            try {
                result = work(state);
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                result = {CommandStatus::Failed, {}, false, RequestError::Internal, "Payjoin command failed"};
                const auto found = operation->id ? state.m_payments.find(*operation->id) : state.m_payments.end();
                if (found != state.m_payments.end()) result.payments.push_back(View(found->second));
            }

            state.Finish(operation, std::move(result));
        });
    }

    uint256 RegisterPayment(PaymentIntent intent, PaymentRequest requested) EXCLUSIVE_LOCKS_REQUIRED(m_gate, !m_views_mutex, !m_operations_mutex)
    {
        AssertLockHeld(m_gate);
        const auto id = GetRandHash();

        Payment payment;
        payment.intent = std::move(intent);
        payment.requested = std::move(requested);
        payment.id = id;
        payment.deadline = m_now() + std::clamp(payment.intent.timeout, std::chrono::milliseconds::zero(), std::chrono::milliseconds{std::chrono::hours{24}});

        auto [it, inserted] = m_payments.emplace(id, std::move(payment));
        if (it->second.requested.request_id) m_request_ids.emplace(*it->second.requested.request_id, id);
        Update(it->second);

        try {
            m_chain.requestNotificationBarrier([weak = weak_from_this(), id] {
                if (auto state = weak.lock()) {
                    state->Queue(id, [](State& queued_state, Payment& queued_payment) { queued_state.Prepare(queued_payment); });
                }
            });
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            Fail(it->second, PaymentIssue::Preparation, "Payjoin preparation barrier failed");
        }
        return id;
    }

    static ManagerResult Rejected(RequestError error, std::string diagnostic)
    {
        return {CommandStatus::Refused, {}, false, error, std::move(diagnostic)};
    }

    ManagerResult Accept(PaymentRequest request) EXCLUSIVE_LOCKS_REQUIRED(m_gate, !m_views_mutex, !m_operations_mutex)
    {
        AssertLockHeld(m_gate);
        if (request.request_id) {
            const auto found = m_request_ids.find(*request.request_id);
            if (found != m_request_ids.end()) {
                const auto& payment = m_payments.at(found->second);
                if (!(payment.requested == request)) return Rejected(RequestError::IdempotencyConflict, "request_id was accepted with different parameters");
                return {CommandStatus::Completed, {View(payment)}, true};
            }
            if (request.request_id->empty() || request.request_id->size() > 128 || request.request_id->find('\0') != std::string::npos) {
                return Rejected(RequestError::InvalidParameter, "request_id must contain 1 to 128 bytes without NUL");
            }
        }
        if (request.timeout_seconds && (*request.timeout_seconds < 1 || *request.timeout_seconds > 86400)) {
            return Rejected(RequestError::InvalidParameter, "timeout must be an integer from 1 to 86400 seconds");
        }

        const auto uri = ParsePayjoinUri(request.uri);
        if (!uri) return Rejected(RequestError::InvalidParameter, uri.error().message);
        if (!request.amount && !uri->amount_sats) return Rejected(RequestError::InvalidParameter, "amount is required when absent from the URI");
        if (uri->amount_sats && *uri->amount_sats > MAX_MONEY) return Rejected(RequestError::InvalidParameter, "URI amount out of range");

        PaymentIntent intent;
        intent.uri = request.uri;
        intent.relay = request.relay;
        intent.amount = request.amount.value_or(uri->amount_sats ? static_cast<CAmount>(*uri->amount_sats) : 0);
        intent.timeout = std::chrono::seconds{request.timeout_seconds.value_or(120)};

        if (m_network_check) {
            if (auto error = m_network_check()) return Rejected(RequestError::NetworkPolicy, std::move(*error));
        }

        {
            LOCK(m_wallet.cs_wallet);
            if (m_wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) || m_wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
                return Rejected(RequestError::UnsupportedWallet, "Payjoin requires local private keys");
            }
            if (m_wallet.IsLocked()) return Rejected(RequestError::Locked, "Wallet must be unlocked to accept a Payjoin payment");

            intent.max_fee = request.max_total_fee.value_or(m_wallet.m_max_tx_fee);
            if (intent.max_fee <= 0 || intent.max_fee > m_wallet.m_max_tx_fee) {
                return Rejected(RequestError::FeePolicy, "max_total_fee must be positive and must not exceed the wallet maximum");
            }

            CCoinControl control;
            control.m_feerate = request.fee_rate;
            intent.fee_rate = GetMinimumFeeRate(m_wallet, control).fee_rate;
            if (intent.fee_rate.GetFeePerK() <= 0 || (request.fee_rate && intent.fee_rate != *request.fee_rate)) {
                return Rejected(RequestError::FeePolicy, "Wallet policy could not provide the requested fee rate");
            }
            if (intent.fee_rate > m_wallet.m_max_tx_fee_rate) return Rejected(RequestError::FeePolicy, "fee_rate exceeds the wallet maximum");
        }

        if (const auto valid = ValidatePaymentIntent(intent); !valid) return Rejected(RequestError::InvalidParameter, valid.error());

        if (!m_transport) m_transport = m_transport_factory();
        if (!m_transport) throw std::runtime_error{"Payjoin transport creation failed"};

        Subscribe();
        const auto id = RegisterPayment(std::move(intent), std::move(request));
        return {CommandStatus::Completed, {View(m_payments.at(id))}};
    }

    void RefreshPayments(std::optional<uint256> id) EXCLUSIVE_LOCKS_REQUIRED(m_gate, !m_views_mutex)
    {
        AssertLockHeld(m_gate);
        LOCK(m_wallet.cs_wallet);
        for (auto& [payment_id, payment] : m_payments) {
            if (id && payment_id != *id) continue;

            try {
                Observe(payment);
                ApplySettlement(payment);
                Update(payment);
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                StorageFailure(payment, "wallet operation failed; effects require reconciliation");
            }
        }
    }

    ManagerResult ReadPayments(std::optional<uint256> id) EXCLUSIVE_LOCKS_REQUIRED(m_gate, !m_views_mutex)
    {
        AssertLockHeld(m_gate);
        if (id && !m_payments.contains(*id)) return {CommandStatus::NotFound};

        RefreshPayments(id);
        ManagerResult result;
        for (const auto& [payment_id, payment] : m_payments) {
            if (!id || payment_id == *id) result.payments.push_back(View(payment));
        }
        return result;
    }

    void Notify() EXCLUSIVE_LOCKS_REQUIRED(!m_operations_mutex)
    {
        LOCK(m_operations_mutex);
        if (m_lifecycle != Lifecycle::Running || m_observation_pending) return;

        m_observation_pending = true;
        m_executor.insert([weak = weak_from_this()] {
            const auto state = weak.lock();
            if (!state) return;

            LOCK(state->m_gate);
            {
                LOCK(state->m_operations_mutex);
                if (state->m_lifecycle != Lifecycle::Running) return;

                state->m_observation_pending = false;
            }

            state->RefreshPayments(std::nullopt);
        });
    }

    struct Notifications final : interfaces::Chain::Notifications {
        std::weak_ptr<State> m_state;

        explicit Notifications(const std::shared_ptr<State>& owner) : m_state{owner} {}

        void Changed()
        {
            if (auto owner = m_state.lock()) owner->Notify();
        }

        void transactionAddedToMempool(const CTransactionRef&) override { Changed(); }

        void transactionRemovedFromMempool(const CTransactionRef&, MemPoolRemovalReason) override { Changed(); }

        void blockConnected(const kernel::ChainstateRole&, const interfaces::BlockInfo&) override { Changed(); }

        void blockDisconnected(const interfaces::BlockInfo&) override { Changed(); }
    };

    void Subscribe() EXCLUSIVE_LOCKS_REQUIRED(m_gate)
    {
        AssertLockHeld(m_gate);
        if (!m_notifications) m_notifications = m_chain.handleNotifications(std::make_shared<Notifications>(shared_from_this()));
    }

    [[nodiscard]] bool Store(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LOCK(m_wallet.cs_wallet);
        if (m_wallet.GetDatabase().MakeBatch()->Write(RecordKey(payment.id), StoredRecord(payment))) return true;
        StorageFailure(payment, "payment save failed");
        return false;
    }

    bool HasPersistentMemoryLock(const COutPoint& out) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet)
    {
        AssertLockHeld(m_wallet.cs_wallet);
        const auto it = m_wallet.m_locked_coins.find(out);
        return it != m_wallet.m_locked_coins.end() && it->second;
    }

    [[nodiscard]] bool CheckInputs(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        AssertLockHeld(m_wallet.cs_wallet);
        if (payment.storage.uncertain || payment.storage.released || payment.settlement) {
            Update(payment);
            return false;
        }

        if (payment.observed_spend) {
            Fail(payment, PaymentIssue::ObservedSpend, "payment spend observed; reconcile before continuing");
            return false;
        }

        auto batch = m_wallet.GetDatabase().MakeBatch();
        for (const auto& input : payment.original->vin) {
            uint256 owner;
            if (!batch->Read(OwnerKey(input.prevout), owner) || owner != payment.id ||
                !HasPersistentMemoryLock(input.prevout) || m_wallet.IsSpent(input.prevout)) {
                payment.locks_verified = false;
                Fail(payment, PaymentIssue::Reservation, "payment inputs changed; reconciliation required");
                return false;
            }
        }

        payment.locks_verified = true;
        return true;
    }

    void Prepare(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex, !m_operations_mutex)
    {
        if (payment.phase != PaymentPhase::Queued) return;

        const auto& intent = payment.intent;
        const auto uri = ValidatePaymentIntent(intent);
        if (!uri) {
            Fail(payment, PaymentIssue::InvalidIntent, uri.error());
            return;
        }

        if (m_now() >= payment.deadline) {
            Fail(payment, PaymentIssue::Deadline, "payment deadline reached");
            return;
        }

        const auto destination = DecodeDestination(uri->address);
        LOCK(m_wallet.cs_wallet);
        if (m_wallet.IsLocked() || m_wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) ||
            m_wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            Fail(payment, PaymentIssue::Preparation, "Payjoin requires an unlocked wallet with local private keys");
            return;
        }

        CCoinControl control;
        control.m_feerate = intent.fee_rate;

        struct Excluded {
            CWallet& m_wallet;
            std::vector<COutPoint> m_coins;
            ~Excluded()
            {
                LOCK(m_wallet.cs_wallet);
                for (const auto& coin : m_coins) {
                    m_wallet.UnlockCoin(coin);
                }
            }
        };
        bool owner_read_failed{false};
        auto created = [&]() EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) -> util::Result<CreatedTransactionResult> {
            Excluded excluded{m_wallet, {}};
            try {
                auto batch = m_wallet.GetDatabase().MakeBatch();
                auto cursor = batch->GetNewPrefixCursor(DataStream{} << std::string{"payjoin/owner"});
                if (!cursor) throw std::runtime_error{"owner cursor unavailable"};

                while (true) {
                    DataStream key, value;
                    const auto status = cursor->Next(key, value);
                    if (status == DatabaseCursor::Status::DONE) break;
                    if (status != DatabaseCursor::Status::MORE) throw std::runtime_error{"owner cursor read failed"};

                    std::string type;
                    COutPoint out;
                    uint256 owner;
                    key >> type >> out;
                    value >> owner;
                    if (type != "payjoin/owner" || !key.empty() || !value.empty()) throw std::runtime_error{"invalid owner record"};

                    if (!m_wallet.IsLockedCoin(out)) {
                        excluded.m_coins.push_back(out);
                        m_wallet.LockCoin(out, false);
                    }
                }
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                owner_read_failed = true;
                return util::Error{Untranslated("payment ownership records could not be read")};
            }
            return CreateTransaction(m_wallet, {{destination, intent.amount, false}}, std::nullopt, control, false);
        }();
        if (!created) {
            Fail(payment, owner_read_failed ? PaymentIssue::Storage : PaymentIssue::Preparation, util::ErrorString(created).original);
            return;
        }

        if (created->fee > intent.max_fee) {
            Fail(payment, PaymentIssue::InvalidIntent, "original fee exceeds policy");
            return;
        }

        PartiallySignedTransaction psbt{CMutableTransaction{*created->tx}, 0};
        bool complete{false};
        CMutableTransaction original;
        if (m_wallet.FillPSBT(psbt, {}, complete) || !complete || !FinalizeAndExtractPSBT(psbt, original)) {
            Fail(payment, PaymentIssue::Signing, "original signing incomplete");
            return;
        }

        payment.original = MakeTransactionRef(std::move(original));

        auto batch = m_wallet.GetDatabase().MakeBatch();
        if (!batch->TxnBegin()) {
            Fail(payment, PaymentIssue::Storage, "registration transaction failed");
            return;
        }

        bool collision{false};
        bool saved = batch->Write(RecordKey(payment.id), StoredRecord(payment), false) && batch->Write(JournalKey(payment.id), JournalRecord{}, false);
        for (const auto& input : payment.original->vin) {
            collision = collision || batch->Exists(OwnerKey(input.prevout));
            saved = saved && !collision && !m_wallet.IsSpent(input.prevout) && !m_wallet.IsLockedCoin(input.prevout) &&
                    batch->Write(OwnerKey(input.prevout), payment.id, false);
        }

        if (!saved || !batch->TxnCommit()) {
            payment.storage.uncertain = !batch->TxnAbort();
            Fail(payment, collision ? PaymentIssue::Reservation : PaymentIssue::Storage, "registration failed");
            return;
        }
        payment.storage.registered = true;

        for (const auto& input : payment.original->vin) {
            if (!m_wallet.LockCoin(input.prevout, true)) {
                StorageFailure(payment, "persistent coin lock failed");
                return;
            }
        }

        if (!CheckInputs(payment)) return;

        auto session = SenderSession::Create(intent.uri, psbt, intent.fee_rate, std::make_shared<WalletJournal>(m_wallet, payment.id));
        if (!session) {
            payment.storage.uncertain = session.error().code == PayjoinErrorCode::Storage;
            Fail(payment, session.error().code == PayjoinErrorCode::Storage ? PaymentIssue::Storage : PaymentIssue::Protocol, session.error().message);
            return;
        }

        payment.session.emplace(std::move(*session));
        payment.phase = PaymentPhase::Ready;
        Update(payment);

        const auto generation = payment.generation;
        const auto deadline_delay = std::max(std::chrono::milliseconds::zero(), std::chrono::duration_cast<std::chrono::milliseconds>(payment.deadline - m_now()));
        m_schedule(deadline_delay, [weak = weak_from_this(), id = payment.id, generation] {
            if (auto locked_state = weak.lock()) {
                locked_state->Queue(id, [generation](State& queued_state, Payment& queued_payment) {
                    if (queued_payment.generation != generation || queued_payment.selected ||
                        (queued_payment.phase != PaymentPhase::Ready && queued_payment.phase != PaymentPhase::Negotiating)) {
                        return;
                    }

                    queued_state.RetireRequest(queued_payment);
                    queued_state.Fail(queued_payment, PaymentIssue::Deadline, "payment deadline reached");
                });
            }
        });

        Queue(payment.id, [](State& queued_state, Payment& queued_payment) EXCLUSIVE_LOCKS_REQUIRED(queued_state.m_gate) {
            queued_state.Dispatch(queued_payment);
        });
    }

    void ScheduleDispatch(Payment& payment)
    {
        const auto generation = payment.generation;
        m_schedule(payment.intent.poll_interval, [weak = weak_from_this(), id = payment.id, generation] {
            if (auto locked_state = weak.lock()) {
                locked_state->Queue(id, [generation](State& queued_state, Payment& queued_payment) EXCLUSIVE_LOCKS_REQUIRED(queued_state.m_gate) {
                    if (queued_payment.generation != generation) return;

                    queued_state.Dispatch(queued_payment);
                });
            }
        });
    }

    [[nodiscard]] bool RestoreDisclosure(Payment& payment, bool was_exposed) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (was_exposed) return true;

        payment.exposed = false;
        if (!Store(payment)) {
            payment.exposed = true;
            Update(payment);
            return false;
        }
        payment.storage.disclosure_saved = false;
        return true;
    }

    void Dispatch(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(m_gate, !m_views_mutex)
    {
        AssertLockHeld(m_gate);
        if (payment.phase != PaymentPhase::Ready && payment.phase != PaymentPhase::Negotiating) return;
        if (m_now() >= payment.deadline) {
            Fail(payment, PaymentIssue::Deadline, "payment deadline reached");
            return;
        }

        auto request = payment.session->PrepareRequest(payment.intent.relay);
        if (!request) {
            Fail(payment, PaymentIssue::Protocol, request.error().message);
            return;
        }

        LOCK(m_wallet.cs_wallet);

        const bool inputs_spent = std::any_of(payment.original->vin.begin(), payment.original->vin.end(), [&](const auto& input) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) {
            return m_wallet.IsSpent(input.prevout);
        });
        if (inputs_spent || payment.observed_spend) {
            Observe(payment);
            ApplySettlement(payment);
        }

        if (!CheckInputs(payment)) {
            Discard(payment);
            Update(payment);
            return;
        }

        if (m_now() >= payment.deadline) {
            Discard(payment);
            Fail(payment, PaymentIssue::Deadline, "payment deadline reached");
            return;
        }

        const bool was_exposed = payment.exposed;
        if (!payment.exposed) {
            payment.exposed = true;
            if (!Store(payment)) {
                Discard(payment);
                return;
            }
            payment.storage.disclosure_saved = true;
        }

        Update(payment);
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(payment.deadline - m_now());
        if (remaining <= std::chrono::milliseconds::zero()) {
            Discard(payment);
            if (!RestoreDisclosure(payment, was_exposed)) return;
            Fail(payment, PaymentIssue::Deadline, "payment deadline reached");
            return;
        }

        payment.request = std::make_shared<Payment::RequestEvidence>(++m_next_request, was_exposed);
        const auto request_id = payment.request->id;
        auto completion = [weak = weak_from_this(), id = payment.id, evidence = payment.request](TransportResult result) {
            if (result.delivery == Delivery::NotSent) evidence->not_sent = true;
            if (auto locked_state = weak.lock()) {
                locked_state->Queue(id, [request_id = evidence->id, result = std::move(result)](State& queued_state, Payment& queued_payment) {
                    if (queued_payment.request && queued_payment.request->id == request_id) {
                        queued_state.Response(queued_payment, result);
                    } else if (queued_payment.retired_request && queued_payment.retired_request->id == request_id) {
                        queued_state.RetiredResponse(queued_payment, result);
                    }
                });
            }
        };

        const auto accepted = m_transport->Submit(request_id, std::move(*request), remaining, std::move(completion));
        if (accepted != SubmitResult::Accepted) {
            payment.request.reset();
            Discard(payment);
            if (!RestoreDisclosure(payment, was_exposed)) return;
            if (accepted == SubmitResult::Busy) {
                payment.diagnostic = "waiting for transport capacity; no request accepted";
                ScheduleDispatch(payment);
                Update(payment);
            } else {
                Fail(payment, PaymentIssue::Delivery, accepted == SubmitResult::Stopped ? "transport stopped" : "transport rejected invalid request");
            }
        } else {
            payment.retired_request.reset();
            payment.transport_accepted = true;
            payment.phase = PaymentPhase::Negotiating;
            payment.diagnostic.clear();
            Update(payment);
        }
    }

    void Response(Payment& payment, const TransportResult& result) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (result.delivery != Delivery::Response) {
            LogDebug(BCLog::NET, "Payjoin transport result %d (retryable %d)\n", static_cast<int>(result.delivery), result.retryable);
        }
        const bool was_exposed = payment.request->was_exposed;
        payment.request.reset();

        if (payment.phase != PaymentPhase::Negotiating) return;
        if (result.delivery == Delivery::NotSent && !RestoreDisclosure(payment, was_exposed)) return;
        if (m_now() >= payment.deadline) {
            Discard(payment);
            Fail(payment, PaymentIssue::Deadline, "payment deadline reached");
            return;
        }

        if (result.delivery != Delivery::Response) {
            Discard(payment);
            if (payment.session->Phase() == SenderPhase::Polling && result.retryable &&
                (result.delivery == Delivery::Uncertain || result.delivery == Delivery::NotSent)) {
                ScheduleDispatch(payment);
            } else {
                Fail(payment, PaymentIssue::Delivery, result.diagnostic);
            }
            return;
        }

        auto response = payment.session->ProcessResponse(result.body);
        if (!response) {
            if (response.error().code == PayjoinErrorCode::Storage) payment.storage.uncertain = true;
            if (response.error().code == PayjoinErrorCode::Transient && payment.session->Phase() == SenderPhase::Polling) {
                ScheduleDispatch(payment);
            } else {
                Fail(payment, response.error().code == PayjoinErrorCode::Storage ? PaymentIssue::Storage : PaymentIssue::Protocol, response.error().message);
            }
            return;
        }

        if (auto* proposal = std::get_if<SenderProposal>(&*response)) {
            Sign(payment, std::move(proposal->psbt));
        } else {
            ScheduleDispatch(payment);
        }
    }

    void RetiredResponse(Payment& payment, const TransportResult& result) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        const bool was_exposed = payment.retired_request->was_exposed;
        payment.retired_request.reset();
        if (result.delivery != Delivery::NotSent || was_exposed || payment.selected ||
            payment.settlement || payment.storage.released) {
            return;
        }

        if (!RestoreDisclosure(payment, was_exposed)) return;
        if (payment.phase == PaymentPhase::Cancelled && !AbandonUnexposed(payment)) return;
        Update(payment);
    }

    void Sign(Payment& payment, PartiallySignedTransaction proposal) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LOCK(m_wallet.cs_wallet);
        if (m_wallet.IsLocked() || m_wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS) ||
            m_wallet.IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            Fail(payment, PaymentIssue::Signing, "Payjoin requires an unlocked wallet with local private keys");
            return;
        }

        Observe(payment);
        ApplySettlement(payment);
        if (!CheckInputs(payment)) return;

        auto tx = proposal.GetUnsignedTx();
        if (!tx) {
            Fail(payment, PaymentIssue::Signing, "missing proposal transaction");
            return;
        }

        std::set<COutPoint> allowed;
        for (const auto& input : payment.original->vin) {
            allowed.insert(input.prevout);
        }

        CAmount total{0};
        for (size_t i = 0; i < tx->vin.size(); ++i) {
            const auto& out = tx->vin[i].prevout;
            if (m_wallet.IsMine(out) && !allowed.contains(out)) {
                Fail(payment, PaymentIssue::Signing, "unexpected wallet input");
                return;
            }

            const auto& input = proposal.inputs[i];
            CTxOut utxo;
            if (!input.GetUTXO(utxo)) {
                Fail(payment, PaymentIssue::Signing, "invalid proposal UTXO");
                return;
            }
            if (input.non_witness_utxo && !input.witness_utxo.IsNull() && input.witness_utxo != utxo) {
                Fail(payment, PaymentIssue::Signing, "inconsistent proposal UTXO");
                return;
            }
            if (!MoneyRange(utxo.nValue) || total > MAX_MONEY - utxo.nValue) {
                Fail(payment, PaymentIssue::Signing, "invalid proposal input value");
                return;
            }
            if (m_wallet.IsMine(utxo) && !allowed.contains(out)) {
                Fail(payment, PaymentIssue::Signing, "unexpected wallet script");
                return;
            }

            total += utxo.nValue;
            allowed.erase(out);
        }

        const auto output_value = CheckedOutputValue(*tx);
        if (!output_value || !allowed.empty() || total < *output_value || total - *output_value > payment.intent.max_fee) {
            Fail(payment, PaymentIssue::Signing, "proposal inputs or fee exceed payment policy");
            return;
        }

        bool complete{false};
        CMutableTransaction finalized;
        if (m_wallet.FillPSBT(proposal, {}, complete) || !complete || !FinalizeAndExtractPSBT(proposal, finalized)) {
            Fail(payment, PaymentIssue::Signing, "proposal signing incomplete");
            return;
        }

        Publish(payment, MakeTransactionRef(std::move(finalized)));
    }

    void PublishChecked(Payment& payment, CTransactionRef tx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        AssertLockHeld(m_wallet.cs_wallet);
        const auto known = m_wallet.mapWallet.find(tx->GetHash());
        const bool already_known = known != m_wallet.mapWallet.end();
        if (already_known && !known->second.GetTx()->Equals(*tx)) {
            Fail(payment, PaymentIssue::Publication, "wallet witness identity differs");
            return;
        }
        if (already_known && !CheckPublicationState(payment, known->second)) return;

        payment.selected = tx;
        if (!Store(payment)) return;
        payment.storage.selection_saved = true;

        auto* wtx = already_known ? &known->second : m_wallet.AddToWallet(tx, TxState{TxStateInactive{}});
        if (!wtx) {
            StorageFailure(payment, "wallet transaction save failed");
            return;
        }
        payment.wallet_recorded = true;

        payment.locks_verified = true;
        for (const auto& input : payment.original->vin) {
            payment.locks_verified &= HasPersistentMemoryLock(input.prevout);
        }

        if (!already_known) {
            std::set<Txid> notified;
            for (const auto& input : tx->vin) {
                const auto parent = m_wallet.mapWallet.find(input.prevout.hash);
                if (parent == m_wallet.mapWallet.end() || !notified.insert(parent->first).second) continue;
                parent->second.MarkDirty();
                m_wallet.NotifyTransactionChanged(parent->first, CT_UPDATED);
            }
        }

        if (!m_wallet.GetBroadcastTransactions()) {
            Fail(payment, PaymentIssue::BroadcastDisabled, "wallet broadcast disabled");
            return;
        }

        std::string error;
        const bool accepted = m_wallet.SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL);
        PublicationResult(payment, accepted, std::move(error));
    }

    void Publish(Payment& payment, CTransactionRef tx) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LOCK(m_wallet.cs_wallet);
        if (payment.selected || payment.storage.uncertain || !CheckInputs(payment)) return;

        PublishChecked(payment, std::move(tx));
    }

    [[nodiscard]] bool CheckKnownOriginal(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        AssertLockHeld(m_wallet.cs_wallet);
        const auto* known = m_wallet.GetWalletTx(payment.original->GetHash());
        if (!known) {
            Fail(payment, PaymentIssue::Publication, "original transaction is not in the wallet");
            return false;
        }
        if (!known->GetTx()->Equals(*payment.original)) {
            Fail(payment, PaymentIssue::Publication, "wallet witness identity differs");
            return false;
        }

        auto batch = m_wallet.GetDatabase().MakeBatch();
        for (const auto& input : payment.original->vin) {
            uint256 owner;
            if (!batch->Read(OwnerKey(input.prevout), owner) || owner != payment.id) {
                Fail(payment, PaymentIssue::Reservation, "reservation changed before publication");
                return false;
            }
        }
        if (!CheckPublicationState(payment, *known)) return false;
        return true;
    }

    [[nodiscard]] bool CheckPublicationState(Payment& payment, const CWalletTx& known) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        AssertLockHeld(m_wallet.cs_wallet);

        if (known.isConfirmed()) {
            Fail(payment, PaymentIssue::Publication, "wallet confirmation requires synchronization before publication");
            return false;
        }
        if (known.isAbandoned() || known.isBlockConflicted() || known.isMempoolConflicted() ||
            !m_wallet.GetConflicts(known.GetHash()).empty()) {
            Fail(payment, PaymentIssue::Publication, "wallet transaction requires reconciliation before publication");
            return false;
        }
        return true;
    }

    void PublicationResult(Payment& payment, bool accepted, std::string error) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LogDebug(PAYJOIN_LOG_CATEGORY, "Payjoin publication accepted: %d\n", accepted);
        payment.node_accepted = accepted;
        payment.phase = accepted ? PaymentPhase::Published : PaymentPhase::Rejected;
        payment.issue = accepted ? std::nullopt : std::optional{PaymentIssue::Publication};
        payment.diagnostic = accepted ? std::string{} : std::move(error);
        Update(payment);
    }

    static void Discard(Payment& payment)
    {
        if (payment.session && payment.session->HasPendingRequest() && !payment.session->DiscardPendingRequest()) {
            LogDebug(BCLog::NET, "Payjoin pending context discard failed\n");
        }
    }

    void RetireRequest(Payment& payment)
    {
        ++payment.generation;
        if (payment.request) {
            payment.retired_request = std::move(payment.request);
            m_transport->Cancel(payment.retired_request->id);
        }
        Discard(payment);
    }

    [[nodiscard]] bool Release(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (!(payment.storage.registered && !payment.storage.released)) return true;

        LOCK(m_wallet.cs_wallet);
        auto batch = m_wallet.GetDatabase().MakeBatch();
        for (const auto& input : payment.original->vin) {
            uint256 owner;
            if (!batch->Read(OwnerKey(input.prevout), owner) || owner != payment.id) {
                Fail(payment, PaymentIssue::Reservation, "cannot release another payment's inputs");
                return false;
            }
        }

        payment.locks_verified = false;
        WalletBatch lock_batch{m_wallet.GetDatabase()};
        for (const auto& input : payment.original->vin) {
            if (!m_wallet.UnlockCoin(input.prevout)) {
                StorageFailure(payment, "coin unlock failed");
                return false;
            }

            if (!lock_batch.EraseLockedUTXO(input.prevout)) {
                StorageFailure(payment, "persistent coin unlock failed");
                return false;
            }
        }

        if (!batch->TxnBegin()) {
            StorageFailure(payment, "release transaction failed");
            return false;
        }

        bool erased{true};
        for (const auto& input : payment.original->vin) {
            erased = erased && batch->Erase(OwnerKey(input.prevout));
        }

        auto released_record = StoredRecord(payment);
        released_record.released = true;
        erased = erased && batch->Write(RecordKey(payment.id), released_record);
        if (!erased || !batch->TxnCommit()) {
            const bool aborted = batch->TxnAbort();

            StorageFailure(payment, aborted ? "ownership release rolled back after unlock" : "ownership release rollback failed");
            return false;
        }

        payment.storage.released = true;
        LogDebug(PAYJOIN_LOG_CATEGORY, "Payjoin ownership released\n");
        return true;
    }

    TransactionPresence Presence(const CWalletTx* wtx) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet)
    {
        AssertLockHeld(m_wallet.cs_wallet);
        if (!wtx) return TransactionPresence::Missing;
        if (const auto* confirmed = wtx->state<TxStateConfirmed>()) {
            bool active{false};
            if (m_wallet.chain().findBlock(confirmed->confirmed_block_hash, interfaces::FoundBlock().inActiveChain(active)) && active) {
                return TransactionPresence::Confirmed;
            }
        }

        if (wtx->isAbandoned()) return TransactionPresence::Abandoned;
        if (wtx->isBlockConflicted()) return TransactionPresence::BlockConflicted;
        if (wtx->isMempoolConflicted()) return TransactionPresence::MempoolConflicted;
        return wtx->InMempool() ? TransactionPresence::Mempool : TransactionPresence::Inactive;
    }

    void Observe(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(m_wallet.cs_wallet)
    {
        if (!payment.original) return;
        AssertLockHeld(m_wallet.cs_wallet);
        payment.original_presence = Presence(m_wallet.GetWalletTx(payment.original->GetHash()));
        payment.selected_presence = payment.selected ? Presence(m_wallet.GetWalletTx(payment.selected->GetHash())) : TransactionPresence::Missing;
        payment.observed_spend.reset();

        payment.locks_verified = true;
        std::set<Txid> candidates;
        for (const auto& input : payment.original->vin) {
            payment.locks_verified &= HasPersistentMemoryLock(input.prevout);
            const auto spenders = m_wallet.GetSpendingTxids(input.prevout);
            candidates.insert(spenders.begin(), spenders.end());
        }

        for (const auto& txid : candidates) {
            const auto* wtx = m_wallet.GetWalletTx(txid);
            if (!wtx) continue;

            const bool is_original = txid == payment.original->GetHash();
            const bool is_selected = !is_original && payment.selected && txid == payment.selected->GetHash();
            TransactionPresence presence;
            if (is_original) {
                presence = payment.original_presence;
            } else if (is_selected) {
                presence = payment.selected_presence;
            } else {
                presence = Presence(wtx);
            }

            if (presence != TransactionPresence::Confirmed && presence != TransactionPresence::Mempool) continue;

            SpendKind kind{SpendKind::Other};
            if (is_original) {
                kind = SpendKind::Original;
            } else if (is_selected) {
                kind = SpendKind::Selected;
            }

            payment.observed_spend = SpendObservation{wtx->GetTx(), kind, presence};
            if (presence != TransactionPresence::Confirmed) continue;
            break;
        }
    }

    void ApplySettlement(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (!payment.storage.registered) return;

        if (payment.settlement && (!payment.observed_spend || payment.observed_spend->presence != TransactionPresence::Confirmed)) {
            payment.settlement.reset();
            RetireRequest(payment);
            if (payment.issue == PaymentIssue::Storage || payment.issue == PaymentIssue::Reservation) {
                payment.phase = PaymentPhase::Attention;
            } else {
                Fail(payment, PaymentIssue::ObservedSpend, "confirmation left the active chain; reconciliation required");
            }
        }

        if (!(payment.phase == PaymentPhase::Cancelled && payment.storage.released && !payment.exposed) &&
            payment.observed_spend && payment.observed_spend->presence == TransactionPresence::Confirmed) {
            RetireRequest(payment);
            payment.settlement = payment.observed_spend;
            payment.phase = payment.settlement->kind == SpendKind::Other ? PaymentPhase::Conflicted : PaymentPhase::Confirmed;
        }

        if (!payment.settlement || payment.storage.uncertain) return;
        if (!payment.storage.released && !Release(payment)) return;

        payment.issue.reset();
        payment.diagnostic.clear();
    }

    CommandOutcome RetrySigning(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LOCK(m_wallet.cs_wallet);
        if (payment.storage.uncertain) return Refuse(CommandRefusal::StorageUncertain);
        if (payment.selected) return Refuse(CommandRefusal::Selected);
        if (payment.settlement || payment.storage.released) return Refuse(CommandRefusal::Settled);
        if (!payment.session || payment.phase == PaymentPhase::Cancelled || payment.phase == PaymentPhase::Stopped) {
            return Refuse(CommandRefusal::InvalidState);
        }

        auto outcome = payment.session->Outcome();
        auto* proposal = outcome ? std::get_if<SenderProposal>(&*outcome) : nullptr;
        if (!proposal) return Refuse(CommandRefusal::InvalidState);

        Sign(payment, std::move(proposal->psbt));
        if (payment.issue == PaymentIssue::Reservation) return Refuse(CommandRefusal::InputsChanged);
        return {payment.node_accepted && !payment.storage.uncertain ? CommandStatus::Completed : CommandStatus::Failed};
    }

    CommandOutcome RetryPublication(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        LOCK(m_wallet.cs_wallet);
        Observe(payment);
        ApplySettlement(payment);

        if (payment.storage.uncertain) return Refuse(CommandRefusal::StorageUncertain);
        if (payment.storage.released || payment.settlement) return Refuse(CommandRefusal::Settled);
        if (!payment.selected || !payment.storage.selection_saved || !payment.wallet_recorded) return Refuse(CommandRefusal::InvalidState);

        auto known = m_wallet.mapWallet.find(payment.selected->GetHash());
        if (known == m_wallet.mapWallet.end() || !known->second.GetTx()->Equals(*payment.selected)) {
            Fail(payment, PaymentIssue::Publication, "selected transaction requires reconciliation");
            return {CommandStatus::Failed};
        }

        auto batch = m_wallet.GetDatabase().MakeBatch();
        for (const auto& input : payment.original->vin) {
            uint256 owner;
            if (!batch->Read(OwnerKey(input.prevout), owner) || owner != payment.id) {
                Fail(payment, PaymentIssue::Reservation, "reservation changed before publication retry");
                return {CommandStatus::Failed};
            }
        }

        if (!CheckPublicationState(payment, known->second)) return {CommandStatus::Failed};
        if (!m_wallet.GetBroadcastTransactions()) {
            Fail(payment, PaymentIssue::BroadcastDisabled, "wallet broadcast disabled");
            return {CommandStatus::Failed};
        }

        std::string error;
        const bool accepted = m_wallet.SubmitTxMemoryPoolAndRelay(known->second, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL);
        PublicationResult(payment, accepted, std::move(error));
        return {accepted ? CommandStatus::Completed : CommandStatus::Failed};
    }

    [[nodiscard]] bool EndNegotiation(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        RetireRequest(payment);
        if (payment.session && (payment.session->Phase() == SenderPhase::Initial || payment.session->Phase() == SenderPhase::Polling)) {
            auto result = payment.session->Cancel();
            if (!result) {
                if (result.error().code == PayjoinErrorCode::Storage) payment.storage.uncertain = true;
                Fail(payment, result.error().code == PayjoinErrorCode::Storage ? PaymentIssue::Storage : PaymentIssue::Protocol, result.error().message);
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool AbandonUnexposed(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (!payment.exposed && !payment.storage.uncertain && !payment.settlement && (payment.storage.registered && !payment.storage.released)) {
            if (payment.session && payment.session->Phase() == SenderPhase::PendingFallback) {
                auto closed = payment.session->CloseFallback();
                if (!closed) {
                    StorageFailure(payment, closed.error().message);
                    return false;
                }
            }
            if (!Release(payment)) return false;
        }
        return true;
    }

    CommandOutcome CancelPayment(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (payment.settlement) return Refuse(CommandRefusal::Settled);
        if (payment.selected) return Refuse(CommandRefusal::Selected);

        if (!EndNegotiation(payment) || !AbandonUnexposed(payment)) return {CommandStatus::Failed};

        payment.phase = PaymentPhase::Cancelled;
        Update(payment);
        return {CommandStatus::Completed};
    }

    CommandOutcome Fallback(Payment& payment) EXCLUSIVE_LOCKS_REQUIRED(!m_views_mutex)
    {
        if (const auto refusal = FallbackRefusal(payment)) return Refuse(*refusal);

        LOCK(m_wallet.cs_wallet);
        Observe(payment);
        ApplySettlement(payment);
        if (const auto refusal = FallbackRefusal(payment)) return Refuse(*refusal);

        if (payment.original_presence != TransactionPresence::Missing) {
            if (!CheckKnownOriginal(payment) || !EndNegotiation(payment)) return {CommandStatus::Failed};

            PublishChecked(payment, payment.original);
        } else {
            if (!CheckInputs(payment) || !EndNegotiation(payment)) return {CommandStatus::Failed};

            Publish(payment, payment.original);
        }

        if (payment.wallet_recorded && payment.session->Phase() == SenderPhase::PendingFallback) {
            auto closed = payment.session->CloseFallback();
            if (!closed) StorageFailure(payment, closed.error().message);
        }
        return {payment.node_accepted && !payment.storage.uncertain ? CommandStatus::Completed : CommandStatus::Failed};
    }

    ManagerResult Command(const uint256& id, SenderCommand command) EXCLUSIVE_LOCKS_REQUIRED(m_gate, !m_views_mutex)
    {
        AssertLockHeld(m_gate);
        const auto found = m_payments.find(id);
        if (found == m_payments.end()) return {CommandStatus::NotFound};

        auto& payment = found->second;
        if (command != SenderCommand::Cancel && command != SenderCommand::Refresh && m_network_check) {
            if (auto error = m_network_check()) {
                auto result = Rejected(RequestError::NetworkPolicy, std::move(*error));
                result.payments.push_back(View(payment));
                return result;
            }
        }

        CommandOutcome outcome{CommandStatus::Failed};
        try {
            switch (command) {
            case SenderCommand::Cancel: outcome = CancelPayment(payment); break;
            case SenderCommand::Fallback: outcome = Fallback(payment); break;
            case SenderCommand::RetrySigning: outcome = RetrySigning(payment); break;
            case SenderCommand::RetryPublication: outcome = RetryPublication(payment); break;
            case SenderCommand::Refresh:
                RefreshPayments(id);
                outcome = {CommandStatus::Completed};
                break;
            }
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            StorageFailure(payment, "wallet operation failed; effects require reconciliation");
        }

        Update(payment);
        ManagerResult result{outcome.status, {View(payment)}};
        result.refusal = outcome.refusal;
        if (outcome.status == CommandStatus::Failed) result.diagnostic = payment.diagnostic;
        return result;
    }
};

SenderService::SenderService(CWallet& wallet, SerialTaskRunner& executor,
                             std::unique_ptr<SenderTransport> transport, Now now, Schedule schedule)
    : m_state{std::make_shared<State>(wallet, executor, std::move(transport), std::move(now), std::move(schedule))} {}

SenderService::SenderService(CWallet& wallet, SerialTaskRunner& executor,
                             TransportFactory transport, Now now, Schedule schedule, NetworkCheck network_check)
    : m_state{std::make_shared<State>(wallet, executor, std::move(transport), std::move(now), std::move(schedule), std::move(network_check))} {}

SenderService::~SenderService() { Stop(); }

uint256 SenderService::Start(PaymentIntent intent)
{
    LOCK(m_state->m_gate);
    if (!m_state->Running()) throw std::logic_error{"sender service stopped"};

    if (!m_state->m_transport) m_state->m_transport = m_state->m_transport_factory();
    if (!m_state->m_transport) throw std::runtime_error{"Payjoin transport creation failed"};

    PaymentRequest requested;
    requested.uri = intent.uri;
    requested.relay = intent.relay;
    requested.amount = intent.amount;
    requested.fee_rate = intent.fee_rate;
    requested.max_total_fee = intent.max_fee;
    requested.timeout_seconds = std::chrono::duration_cast<std::chrono::seconds>(intent.timeout).count();
    return m_state->RegisterPayment(std::move(intent), std::move(requested));
}

std::future<ManagerResult> SenderService::Send(PaymentRequest request)
{
    auto [operation, future] = m_state->Register(std::nullopt);
    if (operation) {
        m_state->RunOperation(operation, [request = std::move(request)](State& state) EXCLUSIVE_LOCKS_REQUIRED(state.m_gate) mutable {
            return state.Accept(std::move(request));
        });
    }
    return std::move(future);
}

std::future<ManagerResult> SenderService::Read(std::optional<uint256> id)
{
    auto [operation, future] = m_state->Register(id);
    if (operation && m_state->Running()) {
        try {
            m_state->m_chain.requestNotificationBarrier([weak = std::weak_ptr{m_state}, operation, id] {
                if (auto state = weak.lock()) {
                    state->RunOperation(operation, [id](State& running) EXCLUSIVE_LOCKS_REQUIRED(running.m_gate) {
                        return running.ReadPayments(id);
                    });
                }
            });
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            m_state->Finish(operation, {CommandStatus::Failed, {}, false, RequestError::Internal, "Payjoin read barrier failed"}, true);
        }
    }
    return std::move(future);
}

std::optional<PaymentSnapshot> SenderService::Snapshot(const uint256& id) const
{
    LOCK(m_state->m_views_mutex);
    const auto it = m_state->m_views.find(id);
    if (it == m_state->m_views.end()) return std::nullopt;
    return it->second;
}

void SenderService::Cancel(const uint256& id) { (void)Execute(id, SenderCommand::Cancel); }

void SenderService::PublishFallback(const uint256& id) { (void)Execute(id, SenderCommand::Fallback); }

void SenderService::RetryPublication(const uint256& id) { (void)Execute(id, SenderCommand::RetryPublication); }

void SenderService::RetrySigning(const uint256& id) { (void)Execute(id, SenderCommand::RetrySigning); }

void SenderService::Refresh(const uint256& id) { (void)Execute(id, SenderCommand::Refresh); }

std::future<ManagerResult> SenderService::Execute(const uint256& id, SenderCommand command)
{
    auto [operation, future] = m_state->Register(id);
    if (operation) {
        m_state->RunOperation(operation, [id, command](State& state) EXCLUSIVE_LOCKS_REQUIRED(state.m_gate) {
            return state.Command(id, command);
        });
    }
    return std::move(future);
}

void SenderService::Close()
{
    LOCK(m_state->m_operations_mutex);
    if (m_state->m_lifecycle == State::Lifecycle::Running) m_state->m_lifecycle = State::Lifecycle::Closing;
}

void SenderService::Stop()
{
    LOCK(m_state->m_stop_mutex);
    if (WITH_LOCK(m_state->m_operations_mutex, return m_state->m_lifecycle == State::Lifecycle::Stopped)) return;

    Close();

    std::unique_ptr<interfaces::Handler> notifications;
    {
        LOCK(m_state->m_gate);
        notifications = std::move(m_state->m_notifications);
        for (auto& [id, payment] : m_state->m_payments) {
            try {
                m_state->RetireRequest(payment);
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                m_state->StorageFailure(payment, "wallet shutdown operation failed; effects require reconciliation");
            }
        }
    }

    if (notifications) notifications->disconnect();

    if (m_state->m_transport) m_state->m_transport->Stop();

    auto archive = std::make_shared<std::vector<PaymentView>>();
    {
        LOCK(m_state->m_gate);
        for (auto& [id, payment] : m_state->m_payments) {
            try {
                auto retired = std::move(payment.retired_request);
                if (retired && retired->not_sent && !retired->was_exposed &&
                    !payment.selected && !payment.settlement && !payment.storage.released) {
                    (void)m_state->RestoreDisclosure(payment, false);
                }

                if (!payment.exposed && !payment.selected && !payment.settlement) {
                    if (m_state->EndNegotiation(payment)) (void)m_state->AbandonUnexposed(payment);
                }
            } catch (const std::bad_alloc&) {
                throw;
            } catch (const std::exception&) {
                m_state->StorageFailure(payment, "wallet shutdown operation failed; effects require reconciliation");
            }

            payment.session.reset();
            if (!payment.selected && !payment.settlement) payment.phase = PaymentPhase::Stopped;

            auto view = State::View(payment);
            view.payment.cancel_available = false;
            view.payment.fallback_available = false;
            view.payment.signing_available = false;
            view.payment.publication_retry_available = false;

            {
                LOCK(m_state->m_views_mutex);
                m_state->m_views[view.payment.id] = view.payment;
            }
            archive->push_back(std::move(view));
        }

        m_state->m_payments.clear();
        m_state->m_request_ids.clear();
        m_state->m_transport_factory = {};
        m_state->m_network_check = {};
        m_state->m_schedule = {};
        m_state->m_now = {};
    }
    notifications.reset();

    {
        LOCK(m_state->m_operations_mutex);
        m_state->m_archive = archive;
        for (const auto& operation : m_state->m_operations) {
            operation->promise.set_value(State::StoppedResult(*archive, operation->id));
        }
        m_state->m_operations.clear();

        m_state->m_lifecycle = State::Lifecycle::Stopped;
    }
}

std::shared_ptr<const std::vector<PaymentView>> SenderService::Archive() const
{
    LOCK(m_state->m_operations_mutex);
    return m_state->m_archive;
}
} // namespace wallet::payjoin
