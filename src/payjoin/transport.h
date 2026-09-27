// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PAYJOIN_TRANSPORT_H
#define BITCOIN_PAYJOIN_TRANSPORT_H

#include <payjoin/client.h>
#include <util/expected.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace wallet::payjoin {

[[nodiscard]] util::Expected<void, PayjoinError> CheckRelayUrl(std::string_view relay);

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
    NotSent,
};

struct TransportResult {
    Delivery delivery{Delivery::Uncertain};
    std::vector<unsigned char> body;
    std::string diagnostic;
    bool retryable{false};
};

class SenderTransport
{
public:
    using Completion = std::function<void(TransportResult)>;

    virtual ~SenderTransport() = default;

    [[nodiscard]] virtual SubmitResult Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion completion) = 0;

    virtual void Cancel(uint64_t id) = 0;

    virtual void Stop() = 0;
};
} // namespace wallet::payjoin
#endif // BITCOIN_PAYJOIN_TRANSPORT_H
