// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PAYJOIN_TRANSPORT_H
#define BITCOIN_PAYJOIN_TRANSPORT_H

#include <payjoin/client.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace wallet::payjoin {

enum class SubmitResult {
    Accepted,
    Busy,
    Stopped,
    InvalidRequest,
};

enum class Delivery {
    Response,
    Uncertain,
    Cancelled,
    /** This request's body was not sent; earlier requests may still have disclosed the payment. */
    NotSent,
};

struct TransportResult {
    Delivery delivery{Delivery::Uncertain};
    std::vector<unsigned char> body;
    std::string diagnostic;
    /** Transient failure hint; does not authorize repeating the initial signed-PSBT POST. */
    bool retryable{false};
};

class SenderTransport
{
public:
    /**
     * May run inline during Submit, Cancel or Stop, or on another thread.
     * Must not synchronously wait for work on the transport's worker, including
     * calling Stop or destroying the transport from its own completion.
     */
    using Completion = std::function<void(TransportResult)>;

    virtual ~SenderTransport() = default;

    /**
     * Accepted guarantees exactly one completion, which may precede this return.
     * Any other result creates no transfer and never invokes completion.
     * Callers must keep callback dependencies alive until completion or Stop returns.
     */
    [[nodiscard]] virtual SubmitResult Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion completion) = 0;

    /** Request cancellation; completion still reports the final delivery outcome. Cancel alone does not prove NotSent. */
    virtual void Cancel(uint64_t id) = 0;

    /**
     * Close admission and finish all accepted requests and their completions before
     * returning. No completions run afterwards; valid new submissions return Stopped.
     * Repeated calls are safe. Must not be called from this transport's completion.
     */
    virtual void Stop() = 0;
};
} // namespace wallet::payjoin
#endif // BITCOIN_PAYJOIN_TRANSPORT_H
