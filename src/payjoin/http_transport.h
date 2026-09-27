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
    std::string ca_file;
    std::string proxy;
    size_t max_response_bytes{1024 * 1024};
    size_t max_requests{32};
};

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
