// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PAYJOIN_CLIENT_H
#define BITCOIN_PAYJOIN_CLIENT_H

#include <primitives/transaction.h>
#include <psbt.h>
#include <util/expected.h>

#include <atomic>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
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

enum class SenderPhase {
    Initial,
    Polling,
    PendingFallback,
    Closed,
    Unusable,
};

struct SenderPosted {
};

struct SenderNoProposalYet {
};

struct SenderProposal {
    PartiallySignedTransaction psbt;
};

using SenderResponse = std::variant<SenderPosted, SenderNoProposalYet, SenderProposal>;

struct SenderSuccessWithoutProposal {
    PayjoinError error;
};

struct SenderAborted {
    std::optional<PayjoinError> diagnostic;
};

struct SenderUnknownOutcome {
    PayjoinError error;
};

/** Protocol success does not confirm signing or broadcast. Aborted does not
 * establish whether the fallback transaction was broadcast. */
using SenderOutcome = std::variant<SenderProposal, SenderSuccessWithoutProposal, SenderAborted, SenderUnknownOutcome>;

/**
 * Synchronous persistence backend for a sender session.
 *
 * Each object represents one journal. SenderSession retains shared ownership
 * and an exclusive claim for its lifetime; callers may retain it for later
 * Replay(). Backends must enforce exclusivity across other handles or processes
 * accessing the same journal.
 * Callbacks run synchronously and must not re-enter the invoking session
 * (including queries), move it, or destroy it.
 */
class SenderEventLog
{
public:
    virtual ~SenderEventLog() = default;

    virtual util::Expected<void, std::string> Save(std::string event) = 0;
    virtual util::Expected<std::vector<std::string>, std::string> Load() = 0;
    /** Close idempotently, preserving Load() for later Replay(). */
    virtual util::Expected<void, std::string> Close() = 0;

private:
    friend class SenderEventLogLease;
    std::atomic_flag m_session_claim{};
};

/**
 * Move-only, non-thread-safe sender workflow with one execution owner.
 *
 * Methods and event-log callbacks must not run concurrently. A pending OHTTP
 * context is one-shot: process its matching response or discard it explicitly.
 * After a move, instance methods returning Expected return InvalidState,
 * Phase() returns Unusable, HasPendingRequest() returns false, and Outcome()
 * and LastError() return nullopt.
 */
class SenderSession
{
public:
    /**
     * Create with an unclaimed, empty writable journal and positive min_fee_rate.
     * Normalize PSBTv2 to v0 before checking finalized inputs and the UTXO data
     * required by FinalizeAndExtractPSBT(); extraction does not guarantee signature validity.
     * URI expiration is checked by PrepareRequest().
     *
     * Save() may fail after persisting Created. Inspect the journal before retrying;
     * recover non-empty logs with Replay().
     */
    [[nodiscard]] static util::Expected<SenderSession, PayjoinError> Create(
        std::string_view uri,
        const PartiallySignedTransaction& psbt,
        const CFeeRate& min_fee_rate,
        std::shared_ptr<SenderEventLog> event_log);
    /**
     * Restore the last durable state from an unclaimed journal; it may lag
     * processed responses. Do not automatically resend the original PSBT.
     * Expired non-Closed sessions return Expired without a session or fallback;
     * Closed sessions remain replayable. See PrepareRequest() for recovery records.
     *
     * Terminal replay calls Close(); successful nonterminal replay does not.
     * Failed replay may close empty or invalid journals. Close errors return
     * Storage with the callback reason and no session, possibly after closure.
     * Replay() adds no events and does not broadcast transactions.
     */
    [[nodiscard]] static util::Expected<SenderSession, PayjoinError> Replay(std::shared_ptr<SenderEventLog> event_log);

    /**
     * Prepare the next BIP77 request. Check the HTTP(S) prefix case-insensitively
     * and pass the relay unchanged to Rust for parsing. Missing or unsupported
     * prefixes return InvalidUri; expiration returns Expired; other construction
     * errors return Internal. InvalidState takes precedence over relay errors.
     * Returned errors leave session state and the journal unchanged.
     *
     * Before sending the first request (encrypted signed PSBT), persist the signed
     * original and payment/session records, and account for it as outgoing.
     * The receiver may broadcast the original even if the response is lost.
     * SenderPosted confirms delivery only.
     */
    [[nodiscard]] util::Expected<SenderRequest, PayjoinError> PrepareRequest(std::string_view relay);
    /**
     * Process the pending BIP77 response; return InvalidState if none is pending.
     * Initial responses return SenderPosted and enter Polling. Polling responses
     * return SenderNoProposalYet or close with SenderProposal containing PSBTv0.
     *
     * Processing invalidates the pending OHTTP context, including on errors.
     * Responses over 1 MiB return Transient before FFI processing. Transient
     * leaves the session usable, but requires preparing a new request.
     *
     * Fatal closes as SenderAborted with a LastError() diagnostic. Storage makes
     * the session Unusable and leaves the durable transition uncertain; see Replay().
     * Internal also makes it Unusable, except proposal decoding failure after
     * persisted success: this leaves Closed with SenderSuccessWithoutProposal
     * and LastError()==Internal. Do not rewrite the successful journal as Aborted.
     */
    [[nodiscard]] util::Expected<SenderResponse, PayjoinError> ProcessResponse(std::span<const unsigned char> response);
    [[nodiscard]] util::Expected<void, PayjoinError> DiscardPendingRequest();

    SenderPhase Phase() const;
    bool HasPendingRequest() const;
    /** Return the terminal outcome, if the session is Closed. */
    std::optional<SenderOutcome> Outcome() const;
    /**
     * Return the current object's diagnostic, not a persisted error history.
     * Replay() does not restore abort diagnostics but may rediscover decode errors.
     */
    std::optional<PayjoinError> LastError() const;

    /**
     * Return the original signed transaction in every phase, including Unusable;
     * moved-from objects return InvalidState. Reconcile wallet records before
     * broadcast or handoff. After success with a proposal, use it for reconciliation
     * only: broadcasting it conflicts with the Payjoin transaction's inputs.
     */
    [[nodiscard]] util::Expected<CTransactionRef, PayjoinError> FallbackTransaction() const;

    /**
     * Persist PendingFallback from Initial or Polling with no pending request.
     * CloseFallback() is still required if canceled before sending; the caller
     * may abandon the payment without broadcasting.
     */
    [[nodiscard]] util::Expected<void, PayjoinError> Cancel();
    /**
     * Close a PendingFallback session after fallback broadcast or handoff;
     * Rust treats both as terminal fallback completion.
     */
    [[nodiscard]] util::Expected<void, PayjoinError> CloseFallback();

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
