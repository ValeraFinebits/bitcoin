// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PAYJOIN_HTTP_TRANSPORT_H
#define BITCOIN_PAYJOIN_HTTP_TRANSPORT_H

#include <payjoin/client.h>
#include <payjoin/transport.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace wallet::payjoin {
struct HttpTransportOptions {
    /** PEM CA bundle; empty uses libcurl's configured trust store. TLS verification remains enabled. */
    std::string ca_file;
    /** Explicit libcurl proxy; empty disables environment proxies. Core proxy settings are not used. */
    std::string proxy;
    size_t max_response_bytes{1024 * 1024};
    /** Maximum number of queued and active requests. Both limits must be nonzero. */
    size_t max_requests{32};
};

/** HTTP(S) POST transport with TLS verification, no redirects, and one worker for completions.
 * MakeDirectTransport() separately enforces wallet network policy.
 */
class HttpSenderTransport final : public SenderTransport
{
public:
    explicit HttpSenderTransport(HttpTransportOptions options = {});

    ~HttpSenderTransport() override;

    [[nodiscard]] SubmitResult Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion completion) override;

    void Cancel(uint64_t id) override;

    void Stop() override;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace wallet::payjoin
#endif // BITCOIN_PAYJOIN_HTTP_TRANSPORT_H
