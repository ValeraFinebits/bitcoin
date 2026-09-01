// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <payjoin/client.h>

#include <payjoin.hpp>
#include <policy/feerate.h>
#include <psbt.h>
#include <streams.h>
#include <util/check.h>
#include <util/overloaded.h>
#include <util/strencodings.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace wallet::payjoin {

class SenderEventLogLease
{
public:
    static std::optional<SenderEventLogLease> TryAcquire(std::shared_ptr<SenderEventLog> event_log)
    {
        Assert(event_log != nullptr);
        if (event_log->m_session_claim.test_and_set(std::memory_order_acquire)) return std::nullopt;
        return SenderEventLogLease{std::move(event_log)};
    }

    SenderEventLogLease(SenderEventLogLease&& other) noexcept
        : m_event_log(std::move(other.m_event_log))
    {
    }

    SenderEventLogLease& operator=(SenderEventLogLease&& other) noexcept
    {
        if (this != &other) {
            Release();
            m_event_log = std::move(other.m_event_log);
        }
        return *this;
    }

    ~SenderEventLogLease() { Release(); }

    SenderEventLogLease(const SenderEventLogLease&) = delete;
    SenderEventLogLease& operator=(const SenderEventLogLease&) = delete;

private:
    explicit SenderEventLogLease(std::shared_ptr<SenderEventLog> event_log)
        : m_event_log(std::move(event_log))
    {
    }

    void Release() noexcept
    {
        if (!m_event_log) return;
        m_event_log->m_session_claim.clear(std::memory_order_release);
        m_event_log.reset();
    }

    std::shared_ptr<SenderEventLog> m_event_log;
};

namespace {

PayjoinError MakeError(PayjoinErrorCode code, std::string message)
{
    return PayjoinError{code, std::move(message)};
}

template <typename T>
util::Expected<T, PayjoinError> Failure(PayjoinErrorCode code, std::string message)
{
    return util::Unexpected<PayjoinError>{MakeError(code, std::move(message))};
}

[[noreturn]] void ThrowForeignInternalError(std::string message)
{
    ::payjoin::foreign_error::InternalError error{message};
    error.v1 = std::move(message);
    throw error;
}

template <typename T>
class NonNullFfiHandle
{
public:
    static NonNullFfiHandle FromChecked(std::shared_ptr<T> handle)
    {
        Assert(handle != nullptr);
        return NonNullFfiHandle{std::move(handle)};
    }

    NonNullFfiHandle(NonNullFfiHandle&&) noexcept = default;
    NonNullFfiHandle& operator=(NonNullFfiHandle&&) noexcept = default;

    NonNullFfiHandle(const NonNullFfiHandle&) = delete;
    NonNullFfiHandle& operator=(const NonNullFfiHandle&) = delete;

    T* operator->() const
    {
        Assert(m_handle != nullptr);
        return m_handle.get();
    }

    const std::shared_ptr<T>& GetShared() const
    {
        Assert(m_handle != nullptr);
        return m_handle;
    }

    std::shared_ptr<T> TakeShared() &&
    {
        Assert(m_handle != nullptr);
        return std::move(m_handle);
    }

private:
    explicit NonNullFfiHandle(std::shared_ptr<T> handle) : m_handle(std::move(handle)) {}

    std::shared_ptr<T> m_handle;
};

class PendingOhttpContext
{
public:
    explicit PendingOhttpContext(NonNullFfiHandle<::payjoin::ClientResponse> context)
        : m_context(std::move(context))
    {
    }

    PendingOhttpContext(PendingOhttpContext&&) noexcept = default;
    PendingOhttpContext& operator=(PendingOhttpContext&&) noexcept = default;

    PendingOhttpContext(const PendingOhttpContext&) = delete;
    PendingOhttpContext& operator=(const PendingOhttpContext&) = delete;

    std::shared_ptr<::payjoin::ClientResponse> Consume() &&
    {
        return std::move(m_context).TakeShared();
    }

private:
    NonNullFfiHandle<::payjoin::ClientResponse> m_context;
};

struct InitialReadyState {
    NonNullFfiHandle<::payjoin::WithReplyKey> sender;
};

struct InitialPendingState {
    NonNullFfiHandle<::payjoin::WithReplyKey> sender;
    PendingOhttpContext context;
};

struct PollingReadyState {
    NonNullFfiHandle<::payjoin::PollingForProposal> sender;
};

struct PollingPendingState {
    NonNullFfiHandle<::payjoin::PollingForProposal> sender;
    PendingOhttpContext context;
};

struct UnusableState {
};

using State = std::variant<
    InitialReadyState,
    InitialPendingState,
    PollingReadyState,
    PollingPendingState,
    UnusableState>;

constexpr std::size_t MAX_PAYJOIN_RESPONSE_BYTES{1U << 20}; // 1 MiB

util::Expected<std::uint64_t, PayjoinError> GetMinFeeRate(const CFeeRate& fee_rate)
{
    const CAmount sat_per_kwu = fee_rate.GetFee(250);
    if (sat_per_kwu <= 0) {
        return Failure<std::uint64_t>(PayjoinErrorCode::InvalidPolicy, "Payjoin fee rate must be positive");
    }
    return static_cast<std::uint64_t>(sat_per_kwu);
}

bool SameUnsignedTransaction(const CMutableTransaction& lhs, const CMutableTransaction& rhs)
{
    return lhs.version == rhs.version &&
           lhs.nLockTime == rhs.nLockTime &&
           lhs.vin == rhs.vin &&
           lhs.vout == rhs.vout;
}

util::Expected<PartiallySignedTransaction, PayjoinError> NormalizePsbtV2ForFfi(const PartiallySignedTransaction& psbt)
{
    if (psbt.m_tx_modifiable.has_value()) {
        return Failure<PartiallySignedTransaction>(PayjoinErrorCode::InvalidSenderInput, "Payjoin PSBTv2 transaction modifiable flags cannot be represented in PSBTv0");
    }

    const auto unsigned_tx = psbt.GetUnsignedTx();
    if (!unsigned_tx) {
        return Failure<PartiallySignedTransaction>(PayjoinErrorCode::InvalidSenderInput, "Payjoin PSBTv2 unsigned transaction could not be constructed");
    }

    PartiallySignedTransaction normalized{*unsigned_tx, /*version=*/0};
    normalized.m_xpubs = psbt.m_xpubs;
    normalized.m_proprietary = psbt.m_proprietary;
    normalized.unknown = psbt.unknown;

    if (normalized.inputs.size() != psbt.inputs.size() || normalized.outputs.size() != psbt.outputs.size()) {
        return Failure<PartiallySignedTransaction>(PayjoinErrorCode::Internal, "Payjoin PSBTv2 normalization changed the input or output count");
    }

    for (std::size_t index = 0; index < psbt.inputs.size(); ++index) {
        if (!normalized.inputs[index].Merge(psbt.inputs[index])) {
            return Failure<PartiallySignedTransaction>(PayjoinErrorCode::Internal, "Payjoin PSBTv2 input records could not be normalized");
        }
        normalized.inputs[index].sighash_type = psbt.inputs[index].sighash_type;
        normalized.inputs[index].time_locktime.reset();
        normalized.inputs[index].height_locktime.reset();
    }
    for (std::size_t index = 0; index < psbt.outputs.size(); ++index) {
        if (!normalized.outputs[index].Merge(psbt.outputs[index])) {
            return Failure<PartiallySignedTransaction>(PayjoinErrorCode::Internal, "Payjoin PSBTv2 output records could not be normalized");
        }
    }

    const auto normalized_tx = normalized.GetUnsignedTx();
    if (!normalized_tx || !SameUnsignedTransaction(*unsigned_tx, *normalized_tx)) {
        return Failure<PartiallySignedTransaction>(PayjoinErrorCode::Internal, "Payjoin PSBTv2 normalization changed the unsigned transaction");
    }
    return normalized;
}

util::Expected<std::string, PayjoinError> SerializePsbtForFfi(const PartiallySignedTransaction& psbt)
{
    try {
        const PartiallySignedTransaction* ffi_psbt{&psbt};
        std::optional<PartiallySignedTransaction> normalized;
        if (psbt.GetVersion() == 2) {
            auto result = NormalizePsbtV2ForFfi(psbt);
            if (!result) return util::Unexpected<PayjoinError>{std::move(result).error()};
            normalized.emplace(std::move(result).value());
            ffi_psbt = &*normalized;
        } else if (psbt.GetVersion() != 0) {
            return Failure<std::string>(PayjoinErrorCode::InvalidPsbt, "Payjoin PSBT version is not supported by the FFI adapter");
        }

        DataStream stream{};
        stream << *ffi_psbt;
        return EncodeBase64(stream);
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return Failure<std::string>(PayjoinErrorCode::Internal, "Payjoin PSBT could not be serialized for FFI");
    }
}

struct CallbackFailure {
    enum class Operation { Save,
                           Load,
                           Close };
    Operation operation;
    std::string message;
};

const char* OperationName(CallbackFailure::Operation operation)
{
    switch (operation) {
    case CallbackFailure::Operation::Save: return "save";
    case CallbackFailure::Operation::Load: return "load";
    case CallbackFailure::Operation::Close: return "close";
    }
    return "operation";
}

PayjoinError MapCallbackFailure(const CallbackFailure& failure)
{
    return MakeError(PayjoinErrorCode::Storage,
                     "Payjoin event log " + std::string{OperationName(failure.operation)} +
                         " failed: " + failure.message);
}

class SenderEventLogAdapter final : public ::payjoin::JsonSenderSessionPersister
{
public:
    class Invocation
    {
    public:
        explicit Invocation(SenderEventLogAdapter& adapter) : m_adapter(adapter)
        {
            Assert(!m_adapter.m_invocation_active);
            m_adapter.m_failure.reset();
            m_adapter.m_invocation_active = true;
        }

        ~Invocation()
        {
            m_adapter.m_failure.reset();
            m_adapter.m_invocation_active = false;
        }

        Invocation(const Invocation&) = delete;
        Invocation& operator=(const Invocation&) = delete;
        Invocation(Invocation&&) = delete;
        Invocation& operator=(Invocation&&) = delete;

        std::optional<PayjoinError> GetError() const
        {
            if (!m_adapter.m_failure) return std::nullopt;
            return MapCallbackFailure(*m_adapter.m_failure);
        }

    private:
        SenderEventLogAdapter& m_adapter;
    };

    explicit SenderEventLogAdapter(std::shared_ptr<SenderEventLog> event_log)
        : m_event_log(std::move(event_log))
    {
        Assume(m_event_log != nullptr);
    }

    Invocation BeginInvocation() { return Invocation{*this}; }

    void save(const std::string& event) override
    {
        CheckInvocation();
        try {
            const auto result = m_event_log->Save(event);
            if (result) return;
            RecordFailure(CallbackFailure::Operation::Save, result.error());
        } catch (const std::exception& exception) {
            RecordFailure(CallbackFailure::Operation::Save, exception.what());
        } catch (...) {
            RecordFailure(CallbackFailure::Operation::Save, "unknown exception");
        }
        RaiseFailure();
    }

    std::vector<std::string> load() override
    {
        CheckInvocation();
        try {
            auto result = m_event_log->Load();
            if (result) return std::move(result).value();
            RecordFailure(CallbackFailure::Operation::Load, result.error());
        } catch (const std::exception& exception) {
            RecordFailure(CallbackFailure::Operation::Load, exception.what());
        } catch (...) {
            RecordFailure(CallbackFailure::Operation::Load, "unknown exception");
        }
        RaiseFailure();
    }

    void close() override
    {
        CheckInvocation();
        try {
            const auto result = m_event_log->Close();
            if (result) return;
            RecordFailure(CallbackFailure::Operation::Close, result.error());
        } catch (const std::exception& exception) {
            RecordFailure(CallbackFailure::Operation::Close, exception.what());
        } catch (...) {
            RecordFailure(CallbackFailure::Operation::Close, "unknown exception");
        }
        RaiseFailure();
    }

private:
    void CheckInvocation() const
    {
        if (!m_invocation_active) {
            ThrowForeignInternalError("Payjoin event log callback outside an invocation");
        }
        Assume(m_invocation_active);
    }

    void RecordFailure(CallbackFailure::Operation operation, std::string message)
    {
        if (message.empty()) message = "event log operation failed";
        if (!m_failure) m_failure.emplace(CallbackFailure{operation, std::move(message)});
    }

    [[noreturn]] void RaiseFailure()
    {
        if (!m_failure) {
            ThrowForeignInternalError("Payjoin event log callback failed");
        }
        Assume(m_failure.has_value());
        ThrowForeignInternalError(m_failure->message);
    }

    std::shared_ptr<SenderEventLog> m_event_log;
    std::optional<CallbackFailure> m_failure;
    bool m_invocation_active{false};
};

PayjoinError PersistenceError(const SenderEventLogAdapter::Invocation& invocation, PayjoinErrorCode fallback_code, const char* fallback_message)
{
    if (auto error = invocation.GetError()) return std::move(*error);
    return MakeError(fallback_code, fallback_message);
}

util::Expected<void, PayjoinError> RequireEmptyEventLog(const std::shared_ptr<SenderEventLogAdapter>& adapter)
{
    auto invocation = adapter->BeginInvocation();
    try {
        const auto events = adapter->load();
        if (auto error = invocation.GetError()) return util::Unexpected<PayjoinError>{std::move(*error)};
        if (!events.empty()) {
            return Failure<void>(PayjoinErrorCode::InvalidState, "Payjoin event log is not empty; use Replay()");
        }
        return {};
    } catch (const ::payjoin::ForeignError&) {
        return util::Unexpected<PayjoinError>{PersistenceError(invocation, PayjoinErrorCode::Storage, "Payjoin event log could not be loaded")};
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return util::Unexpected<PayjoinError>{PersistenceError(invocation, PayjoinErrorCode::Internal, "Payjoin event log could not be checked")};
    }
}

util::Expected<NonNullFfiHandle<::payjoin::PjUri>, PayjoinError> ParsePjUri(std::string_view uri)
{
    try {
        auto parsed_uri = ::payjoin::Uri::parse(std::string{uri});
        if (!parsed_uri) {
            return Failure<NonNullFfiHandle<::payjoin::PjUri>>(PayjoinErrorCode::Internal, "Payjoin parsed URI is empty");
        }
        auto checked_uri = NonNullFfiHandle<::payjoin::Uri>::FromChecked(std::move(parsed_uri));

        auto pj_uri = checked_uri->check_pj_supported();
        if (!pj_uri) {
            return Failure<NonNullFfiHandle<::payjoin::PjUri>>(PayjoinErrorCode::Internal, "Payjoin URI result is empty");
        }
        return NonNullFfiHandle<::payjoin::PjUri>::FromChecked(std::move(pj_uri));
    } catch (const ::payjoin::UriParseError&) {
        return Failure<NonNullFfiHandle<::payjoin::PjUri>>(PayjoinErrorCode::InvalidUri, "Payjoin URI is malformed");
    } catch (const ::payjoin::PjNotSupported&) {
        return Failure<NonNullFfiHandle<::payjoin::PjUri>>(PayjoinErrorCode::UnsupportedProtocol, "Payjoin URI is not supported");
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return Failure<NonNullFfiHandle<::payjoin::PjUri>>(PayjoinErrorCode::Internal, "Payjoin URI processing failed");
    }
}

util::Expected<NonNullFfiHandle<::payjoin::InitialSendTransition>, PayjoinError> BuildInitialTransition(
    const std::string& psbt,
    const NonNullFfiHandle<::payjoin::PjUri>& uri,
    std::uint64_t fee_rate)
{
    try {
        auto builder = ::payjoin::SenderBuilder::init(psbt, uri.GetShared());
        if (!builder) {
            return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::Internal, "Payjoin sender builder is empty");
        }
        auto checked_builder = NonNullFfiHandle<::payjoin::SenderBuilder>::FromChecked(std::move(builder));

        auto transition = checked_builder->build_recommended(fee_rate);
        if (!transition) {
            return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::Internal, "Payjoin sender transition is empty");
        }
        return NonNullFfiHandle<::payjoin::InitialSendTransition>::FromChecked(std::move(transition));
    } catch (const ::payjoin::sender_input_error::Psbt&) {
        return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::InvalidPsbt, "Payjoin PSBT is invalid");
    } catch (const ::payjoin::sender_input_error::Build&) {
        return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::InvalidSenderInput, "Payjoin sender input is invalid");
    } catch (const ::payjoin::sender_input_error::FfiValidation&) {
        return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::InvalidPolicy, "Payjoin sender policy is invalid");
    } catch (const ::payjoin::SenderInputError&) {
        return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::InvalidSenderInput, "Payjoin sender input is invalid");
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return Failure<NonNullFfiHandle<::payjoin::InitialSendTransition>>(PayjoinErrorCode::Internal, "Payjoin sender initialization failed");
    }
}

util::Expected<InitialReadyState, PayjoinError> PersistInitialState(
    const NonNullFfiHandle<::payjoin::InitialSendTransition>& transition,
    const std::shared_ptr<SenderEventLogAdapter>& adapter)
{
    auto invocation = adapter->BeginInvocation();
    try {
        auto sender = transition->save(adapter);
        if (auto error = invocation.GetError()) return util::Unexpected<PayjoinError>{std::move(*error)};
        if (!sender) return Failure<InitialReadyState>(PayjoinErrorCode::Internal, "Payjoin sender session is empty");
        return InitialReadyState{NonNullFfiHandle<::payjoin::WithReplyKey>::FromChecked(std::move(sender))};
    } catch (const ::payjoin::ForeignError&) {
        return util::Unexpected<PayjoinError>{PersistenceError(invocation, PayjoinErrorCode::Storage, "Payjoin event log could not be saved")};
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return util::Unexpected<PayjoinError>{PersistenceError(invocation, PayjoinErrorCode::Internal, "Payjoin sender transition failed")};
    }
}

PayjoinError MapReplayError(::payjoin::SenderReplayError& error)
{
    try {
        if (error.is_expired()) return MakeError(PayjoinErrorCode::Expired, "Payjoin sender session has expired");
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return MakeError(PayjoinErrorCode::Internal, "Payjoin replay expiration check failed");
    }
    return MakeError(PayjoinErrorCode::ReplayFailed, "Payjoin sender event log could not be replayed");
}

util::Expected<State, PayjoinError> ReplayState(const std::shared_ptr<SenderEventLogAdapter>& adapter)
{
    auto invocation = adapter->BeginInvocation();
    try {
        auto replay_result = ::payjoin::replay_sender_event_log(adapter);
        if (auto error = invocation.GetError()) return util::Unexpected<PayjoinError>{std::move(*error)};
        if (!replay_result) return Failure<State>(PayjoinErrorCode::Internal, "Payjoin replay result is empty");
        auto checked_replay = NonNullFfiHandle<::payjoin::SenderReplayResult>::FromChecked(std::move(replay_result));

        const auto replayed_state = checked_replay->state();
        return std::visit(
            util::Overloaded{
                [](const ::payjoin::SendSession::kWithReplyKey& state) -> util::Expected<State, PayjoinError> {
                    if (!state.inner) return Failure<State>(PayjoinErrorCode::Internal, "Payjoin replay state is empty");
                    return State{InitialReadyState{NonNullFfiHandle<::payjoin::WithReplyKey>::FromChecked(state.inner)}};
                },
                [](const ::payjoin::SendSession::kPollingForProposal& state) -> util::Expected<State, PayjoinError> {
                    if (!state.inner) return Failure<State>(PayjoinErrorCode::Internal, "Payjoin replay state is empty");
                    return State{PollingReadyState{NonNullFfiHandle<::payjoin::PollingForProposal>::FromChecked(state.inner)}};
                },
                [](const ::payjoin::SendSession::kSenderPendingFallback&) -> util::Expected<State, PayjoinError> {
                    return Failure<State>(PayjoinErrorCode::InvalidState, "Payjoin replay state is not ready for a request");
                },
                [](const ::payjoin::SendSession::kClosed&) -> util::Expected<State, PayjoinError> {
                    return Failure<State>(PayjoinErrorCode::InvalidState, "Payjoin replay state is not ready for a request");
                },
            },
            replayed_state.get_variant());
    } catch (::payjoin::SenderReplayError& error) {
        if (auto callback_error = invocation.GetError()) return util::Unexpected<PayjoinError>{std::move(*callback_error)};
        return util::Unexpected<PayjoinError>{MapReplayError(error)};
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return util::Unexpected<PayjoinError>{PersistenceError(invocation, PayjoinErrorCode::Internal, "Payjoin sender replay failed")};
    }
}

struct PreparedRequestData {
    SenderRequest request;
    PendingOhttpContext context;
};

util::Expected<PreparedRequestData, PayjoinError> CheckRequestContext(::payjoin::RequestOhttpContext request_context)
{
    if (!request_context.request) {
        return Failure<PreparedRequestData>(PayjoinErrorCode::Internal, "Payjoin request context is empty");
    }
    auto request = NonNullFfiHandle<::payjoin::Request>::FromChecked(std::move(request_context.request));

    if (!request_context.ohttp_ctx) {
        return Failure<PreparedRequestData>(PayjoinErrorCode::Internal, "Payjoin request context is empty");
    }
    PendingOhttpContext context{NonNullFfiHandle<::payjoin::ClientResponse>::FromChecked(std::move(request_context.ohttp_ctx))};

    return PreparedRequestData{
        .request = SenderRequest{
            .url = request->url,
            .content_type = request->content_type,
            .body = std::vector<unsigned char>{request->body.begin(), request->body.end()},
        },
        .context = std::move(context),
    };
}

PayjoinError MapCreateRequestError(::payjoin::CreateRequestError& error)
{
    try {
        if (error.is_expired()) return MakeError(PayjoinErrorCode::Expired, "Payjoin sender session has expired");
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return MakeError(PayjoinErrorCode::Internal, "Payjoin request expiration check failed");
    }
    return MakeError(PayjoinErrorCode::Internal, "Payjoin request could not be created");
}

util::Expected<PreparedRequestData, PayjoinError> PrepareInitialRequest(
    const NonNullFfiHandle<::payjoin::WithReplyKey>& sender,
    const std::string& relay)
{
    try {
        return CheckRequestContext(sender->create_v2_post_request(relay));
    } catch (::payjoin::CreateRequestError& error) {
        return util::Unexpected<PayjoinError>{MapCreateRequestError(error)};
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return Failure<PreparedRequestData>(PayjoinErrorCode::Internal, "Payjoin request creation failed");
    }
}

util::Expected<PreparedRequestData, PayjoinError> PreparePollingRequest(
    const NonNullFfiHandle<::payjoin::PollingForProposal>& sender,
    const std::string& relay)
{
    try {
        return CheckRequestContext(sender->create_poll_request(relay));
    } catch (::payjoin::CreateRequestError& error) {
        return util::Unexpected<PayjoinError>{MapCreateRequestError(error)};
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return Failure<PreparedRequestData>(PayjoinErrorCode::Internal, "Payjoin request creation failed");
    }
}

struct PreparedRequestTransition {
    SenderRequest request;
    State next_state;
};

struct InitialResponseInput {
    NonNullFfiHandle<::payjoin::WithReplyKey> sender;
    PendingOhttpContext context;
    std::vector<std::uint8_t> response;
};

struct InitialResponseOutcome {
    State next_state;
    util::Expected<SenderResponse, PayjoinError> response;
};

InitialResponseOutcome UnusableResponse(PayjoinError error)
{
    return InitialResponseOutcome{
        .next_state = State{UnusableState{}},
        .response = util::Unexpected<PayjoinError>{std::move(error)},
    };
}

InitialResponseOutcome ProcessInitialResponse(
    InitialResponseInput input,
    const std::shared_ptr<SenderEventLogAdapter>& adapter)
{
    auto invocation = adapter->BeginInvocation();
    try {
        auto context = std::move(input.context).Consume();
        auto transition = input.sender->process_response(input.response, context);
        if (!transition) {
            return UnusableResponse(MakeError(PayjoinErrorCode::Internal, "Payjoin response transition is empty"));
        }
        auto checked_transition = NonNullFfiHandle<::payjoin::WithReplyKeyTransition>::FromChecked(std::move(transition));

        auto polling = checked_transition->save(adapter);
        if (auto error = invocation.GetError()) return UnusableResponse(std::move(*error));
        if (!polling) {
            return UnusableResponse(MakeError(PayjoinErrorCode::Internal, "Payjoin polling state is empty"));
        }
        return InitialResponseOutcome{
            .next_state = State{PollingReadyState{NonNullFfiHandle<::payjoin::PollingForProposal>::FromChecked(std::move(polling))}},
            .response = SenderResponse{},
        };
    } catch (const ::payjoin::sender_persisted_error::Transient&) {
        if (auto error = invocation.GetError()) return UnusableResponse(std::move(*error));
        return InitialResponseOutcome{
            .next_state = State{InitialReadyState{std::move(input.sender)}},
            .response = Failure<SenderResponse>(PayjoinErrorCode::Transient, "Payjoin response was transiently rejected"),
        };
    } catch (const ::payjoin::sender_persisted_error::Fatal&) {
        return UnusableResponse(PersistenceError(invocation, PayjoinErrorCode::Fatal, "Payjoin response was fatally rejected"));
    } catch (const ::payjoin::sender_persisted_error::Storage&) {
        return UnusableResponse(PersistenceError(invocation, PayjoinErrorCode::Storage, "Payjoin response transition could not be persisted"));
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return UnusableResponse(PersistenceError(invocation, PayjoinErrorCode::Internal, "Payjoin response processing failed"));
    }
}

} // namespace

class SenderSession::Impl
{
public:
    Impl(State state, std::shared_ptr<SenderEventLogAdapter> event_log_adapter, SenderEventLogLease event_log_lease)
        : m_event_log_lease(std::move(event_log_lease)), m_state(std::move(state)), m_event_log_adapter(std::move(event_log_adapter))
    {
        Assume(m_event_log_adapter != nullptr);
    }

    SenderEventLogLease m_event_log_lease;
    State m_state;
    std::shared_ptr<SenderEventLogAdapter> m_event_log_adapter;
};

util::Expected<SenderSession, PayjoinError> SenderSession::Create(
    std::string_view uri,
    const PartiallySignedTransaction& psbt,
    const CFeeRate& min_fee_rate,
    std::shared_ptr<SenderEventLog> event_log)
{
    if (!event_log) return Failure<SenderSession>(PayjoinErrorCode::Storage, "Payjoin event log is null");

    auto event_log_lease = SenderEventLogLease::TryAcquire(event_log);
    if (!event_log_lease) {
        return Failure<SenderSession>(PayjoinErrorCode::InvalidState, "Payjoin event log is already in use");
    }

    auto adapter = std::make_shared<SenderEventLogAdapter>(std::move(event_log));
    auto empty_log = RequireEmptyEventLog(adapter);
    if (!empty_log) return util::Unexpected<PayjoinError>{std::move(empty_log).error()};

    auto psbt_base64 = SerializePsbtForFfi(psbt);
    if (!psbt_base64) return util::Unexpected<PayjoinError>{std::move(psbt_base64).error()};

    const auto fee_rate = GetMinFeeRate(min_fee_rate);
    if (!fee_rate) return util::Unexpected<PayjoinError>{fee_rate.error()};

    auto pj_uri = ParsePjUri(uri);
    if (!pj_uri) return util::Unexpected<PayjoinError>{std::move(pj_uri).error()};

    // TODO: Before wallet integration, validate the payment address and amount
    // against the active chain (including MoneyRange/MAX_MONEY), and replace
    // generic PjUri acceptance with a typed BIP77/v2 FFI check.

    auto transition = BuildInitialTransition(*psbt_base64, *pj_uri, *fee_rate);
    if (!transition) return util::Unexpected<PayjoinError>{std::move(transition).error()};

    auto initial_state = PersistInitialState(*transition, adapter);
    if (!initial_state) return util::Unexpected<PayjoinError>{std::move(initial_state).error()};

    return SenderSession{std::make_unique<Impl>(State{std::move(initial_state).value()}, std::move(adapter), std::move(*event_log_lease))};
}

util::Expected<SenderSession, PayjoinError> SenderSession::Replay(std::shared_ptr<SenderEventLog> event_log)
{
    if (!event_log) return Failure<SenderSession>(PayjoinErrorCode::Storage, "Payjoin event log is null");

    auto event_log_lease = SenderEventLogLease::TryAcquire(event_log);
    if (!event_log_lease) {
        return Failure<SenderSession>(PayjoinErrorCode::InvalidState, "Payjoin event log is already in use");
    }

    auto adapter = std::make_shared<SenderEventLogAdapter>(std::move(event_log));
    auto replayed_state = ReplayState(adapter);
    if (!replayed_state) return util::Unexpected<PayjoinError>{std::move(replayed_state).error()};

    return SenderSession{std::make_unique<Impl>(std::move(replayed_state).value(), std::move(adapter), std::move(*event_log_lease))};
}

util::Expected<SenderRequest, PayjoinError> SenderSession::PrepareRequest(std::string_view relay)
{
    if (!m_impl) {
        return Failure<SenderRequest>(PayjoinErrorCode::InvalidState, "Payjoin sender session is not ready for a request");
    }

    const std::string relay_url{relay};
    auto transition = std::visit(
        util::Overloaded{
            [&relay_url](const InitialReadyState& state) -> util::Expected<PreparedRequestTransition, PayjoinError> {
                auto prepared = PrepareInitialRequest(state.sender, relay_url);
                if (!prepared) return util::Unexpected<PayjoinError>{std::move(prepared).error()};
                auto data = std::move(prepared).value();
                auto sender = NonNullFfiHandle<::payjoin::WithReplyKey>::FromChecked(state.sender.GetShared());
                return PreparedRequestTransition{
                    .request = std::move(data.request),
                    .next_state = State{InitialPendingState{std::move(sender), std::move(data.context)}},
                };
            },
            [](const InitialPendingState&) -> util::Expected<PreparedRequestTransition, PayjoinError> {
                return Failure<PreparedRequestTransition>(PayjoinErrorCode::InvalidState, "Payjoin sender session is not ready for a request");
            },
            [&relay_url](const PollingReadyState& state) -> util::Expected<PreparedRequestTransition, PayjoinError> {
                auto prepared = PreparePollingRequest(state.sender, relay_url);
                if (!prepared) return util::Unexpected<PayjoinError>{std::move(prepared).error()};
                auto data = std::move(prepared).value();
                auto sender = NonNullFfiHandle<::payjoin::PollingForProposal>::FromChecked(state.sender.GetShared());
                return PreparedRequestTransition{
                    .request = std::move(data.request),
                    .next_state = State{PollingPendingState{std::move(sender), std::move(data.context)}},
                };
            },
            [](const PollingPendingState&) -> util::Expected<PreparedRequestTransition, PayjoinError> {
                return Failure<PreparedRequestTransition>(PayjoinErrorCode::InvalidState, "Payjoin sender session is not ready for a request");
            },
            [](const UnusableState&) -> util::Expected<PreparedRequestTransition, PayjoinError> {
                return Failure<PreparedRequestTransition>(PayjoinErrorCode::InvalidState, "Payjoin sender session is not ready for a request");
            },
        },
        m_impl->m_state);
    if (!transition) return util::Unexpected<PayjoinError>{std::move(transition).error()};

    auto data = std::move(transition).value();
    m_impl->m_state = std::move(data.next_state);
    return std::move(data.request);
}

util::Expected<SenderResponse, PayjoinError> SenderSession::ProcessResponse(std::span<const unsigned char> response)
{
    if (!m_impl) {
        return Failure<SenderResponse>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no response pending");
    }

    auto pending = std::visit(
        util::Overloaded{
            [](InitialReadyState&) -> util::Expected<InitialPendingState*, PayjoinError> {
                return Failure<InitialPendingState*>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no response pending");
            },
            [](InitialPendingState& state) -> util::Expected<InitialPendingState*, PayjoinError> { return &state; },
            [](PollingReadyState&) -> util::Expected<InitialPendingState*, PayjoinError> {
                return Failure<InitialPendingState*>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no response pending");
            },
            [](PollingPendingState&) -> util::Expected<InitialPendingState*, PayjoinError> {
                return Failure<InitialPendingState*>(PayjoinErrorCode::InvalidState, "Payjoin sender session is not waiting for an initial response");
            },
            [](UnusableState&) -> util::Expected<InitialPendingState*, PayjoinError> {
                return Failure<InitialPendingState*>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no response pending");
            },
        },
        m_impl->m_state);
    if (!pending) return util::Unexpected<PayjoinError>{std::move(pending).error()};

    InitialPendingState& state = **pending;
    if (response.size() > MAX_PAYJOIN_RESPONSE_BYTES) {
        auto sender = NonNullFfiHandle<::payjoin::WithReplyKey>::FromChecked(state.sender.GetShared());
        m_impl->m_state = InitialReadyState{std::move(sender)};
        return Failure<SenderResponse>(PayjoinErrorCode::Transient, "Payjoin response exceeds the 1 MiB safety limit");
    }

    std::vector<std::uint8_t> response_bytes{response.begin(), response.end()};
    InitialResponseInput input{
        .sender = NonNullFfiHandle<::payjoin::WithReplyKey>::FromChecked(state.sender.GetShared()),
        .context = std::move(state.context),
        .response = std::move(response_bytes),
    };

    m_impl->m_state = UnusableState{};
    auto outcome = ProcessInitialResponse(std::move(input), m_impl->m_event_log_adapter);
    m_impl->m_state = std::move(outcome.next_state);
    return std::move(outcome.response);
}

util::Expected<void, PayjoinError> SenderSession::DiscardPendingRequest()
{
    if (!m_impl) {
        return Failure<void>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no pending request");
    }

    auto next_state = std::visit(
        util::Overloaded{
            [](const InitialReadyState&) -> util::Expected<State, PayjoinError> {
                return Failure<State>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no pending request");
            },
            [](const InitialPendingState& state) -> util::Expected<State, PayjoinError> {
                return State{InitialReadyState{NonNullFfiHandle<::payjoin::WithReplyKey>::FromChecked(state.sender.GetShared())}};
            },
            [](const PollingReadyState&) -> util::Expected<State, PayjoinError> {
                return Failure<State>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no pending request");
            },
            [](const PollingPendingState& state) -> util::Expected<State, PayjoinError> {
                return State{PollingReadyState{NonNullFfiHandle<::payjoin::PollingForProposal>::FromChecked(state.sender.GetShared())}};
            },
            [](const UnusableState&) -> util::Expected<State, PayjoinError> {
                return Failure<State>(PayjoinErrorCode::InvalidState, "Payjoin sender session has no pending request");
            },
        },
        m_impl->m_state);
    if (!next_state) return util::Unexpected<PayjoinError>{std::move(next_state).error()};

    m_impl->m_state = std::move(next_state).value();
    return {};
}

SenderSession::SenderSession(std::unique_ptr<Impl> impl) : m_impl(std::move(impl)) {}
SenderSession::SenderSession(SenderSession&&) noexcept = default;
SenderSession& SenderSession::operator=(SenderSession&&) noexcept = default;
SenderSession::~SenderSession() = default;

} // namespace wallet::payjoin
