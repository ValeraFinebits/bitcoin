// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PAYJOIN_CLIENT_H
#define BITCOIN_PAYJOIN_CLIENT_H

#include <psbt.h>
#include <util/expected.h>

#include <atomic>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

class CFeeRate;

namespace wallet::payjoin {

enum class PayjoinErrorCode {
    InvalidUri,
    UnsupportedProtocol,
    InvalidPsbt,
    InvalidSenderInput,
    InvalidPolicy,
    Expired,
    Storage,
    Transient,
    Fatal,
    ReplayFailed,
    InvalidState,
    Internal,
};

struct PayjoinError {
    PayjoinErrorCode code;
    std::string message;
};

struct SenderRequest {
    std::string url;
    std::string content_type;
    std::vector<unsigned char> body;
};

struct SenderResponse {
    std::optional<PartiallySignedTransaction> proposal;
};

/**
 * Synchronous persistence backend for a sender session.
 *
 * Each SenderEventLog object represents one journal. SenderSession retains
 * shared ownership and an exclusive claim for its lifetime. The caller may
 * retain the same shared_ptr for a later Replay(), but cannot use the object in
 * another live session. Shared ownership does not make callbacks
 * concurrent-safe; they are invoked synchronously by session methods and
 * remain part of the session's single-owner interaction.
 *
 * The in-process claim coordinates one SenderEventLog object. A production
 * backend must additionally enforce exclusivity across distinct handles or
 * processes referring to the same durable journal.
 */
class SenderEventLog
{
public:
    virtual ~SenderEventLog() = default;

    virtual util::Expected<void, std::string> Save(std::string event) = 0;
    virtual util::Expected<std::vector<std::string>, std::string> Load() = 0;
    virtual util::Expected<void, std::string> Close() = 0;

private:
    friend class SenderEventLogLease;
    std::atomic_flag m_session_claim{};
};

/**
 * Move-only sender workflow state.
 *
 * SenderSession is not thread-safe. It must belong to one execution owner, and
 * its methods and event-log callbacks must not run concurrently. A pending
 * OHTTP context is one-shot and is consumed only by its matching response or
 * discarded explicitly. After a move, the source object is inactive and its
 * PrepareRequest(), ProcessResponse(), and DiscardPendingRequest() methods
 * return InvalidState; the destination retains the workflow state.
 */
class SenderSession
{
public:
    /**
     * Create a sender session using an unclaimed, empty event log.
     * min_fee_rate must be positive. Use Replay() for a non-empty log.
     */
    static util::Expected<SenderSession, PayjoinError> Create(
        std::string_view uri,
        const PartiallySignedTransaction& psbt,
        const CFeeRate& min_fee_rate,
        std::shared_ptr<SenderEventLog> event_log);
    /**
     * Reconstruct the last durably written sender state from an unclaimed log.
     *
     * The recovered state may precede a response that was already processed
     * before a storage failure. Replay alone does not authorize automatically
     * resending the original PSBT; the caller must apply an explicit recovery
     * policy.
     */
    static util::Expected<SenderSession, PayjoinError> Replay(std::shared_ptr<SenderEventLog> event_log);

    util::Expected<SenderRequest, PayjoinError> PrepareRequest(std::string_view relay);
    /**
     * Process the response to an initial BIP77 request.
     *
     * Only a response for an initial WithReplyKey request is supported. A
     * successful response persists the transition and moves the session to
     * PollingForProposal, but returns no proposal yet. Polling responses and
     * proposal extraction are not implemented.
     *
     * The maximum response body size is 1 MiB. A larger response returns
     * Transient before calling the FFI. Once processing of an initial response
     * is attempted, its pending OHTTP context becomes invalid: Rust may consume
     * it in the FFI, or C++ may discard it before the FFI for an oversized
     * response. After a transient result, the sender remains usable, but only a
     * new request with a new OHTTP context may be prepared.
     *
     * Fatal, storage, and internal errors make this C++ object unusable. A
     * storage error also leaves the transition result unknown; Replay()
     * reconstructs only the last durably written state, which may precede the
     * processed response. The caller must not automatically replay and resend
     * the original PSBT without a separate recovery policy. Calling this method
     * for a polling request returns InvalidState without consuming its pending
     * context; call DiscardPendingRequest() explicitly in that case.
     */
    util::Expected<SenderResponse, PayjoinError> ProcessResponse(std::span<const unsigned char> response);
    util::Expected<void, PayjoinError> DiscardPendingRequest();

    SenderSession(SenderSession&&) noexcept;
    SenderSession& operator=(SenderSession&&) noexcept;
    ~SenderSession();

    SenderSession(const SenderSession&) = delete;
    SenderSession& operator=(const SenderSession&) = delete;

private:
    class Impl;
    explicit SenderSession(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> m_impl;
};

} // namespace wallet::payjoin

#endif // BITCOIN_PAYJOIN_CLIENT_H
