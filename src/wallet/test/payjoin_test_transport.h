// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_TEST_PAYJOIN_TEST_TRANSPORT_H
#define BITCOIN_WALLET_TEST_PAYJOIN_TEST_TRANSPORT_H

#include <payjoin/client.h>
#include <payjoin/transport.h>

#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace wallet::payjoin::test {
template <typename... Args>
class ScopedHook
{
    std::function<void(Args...)>& m_hook;
    std::optional<std::function<void(Args...)>> m_previous;

public:
    explicit ScopedHook(std::function<void(Args...)>& hook) : m_hook{hook}, m_previous{std::move(hook)} {}

    ScopedHook(const ScopedHook&) = delete;

    ScopedHook& operator=(const ScopedHook&) = delete;

    ~ScopedHook() { Reset(); }

    void Reset()
    {
        if (!m_previous) return;

        m_hook = std::move(*m_previous);
        m_previous.reset();
    }
};

class ControlledTransport : public SenderTransport
{
public:
    struct Pending {
        uint64_t id;
        SenderRequest request;
        Completion complete;
        std::chrono::steady_clock::time_point accepted_at;
        std::chrono::milliseconds timeout;
    };

    std::deque<Pending> m_pending;
    std::vector<uint64_t> m_cancelled;
    std::function<void()> m_on_dispatch;
    SubmitResult m_acceptance{SubmitResult::Accepted};
    size_t m_attempts{0};

    SubmitResult Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion completion) override
    {
        if (m_stopped) return SubmitResult::Stopped;

        ++m_attempts;

        assert(timeout > std::chrono::milliseconds::zero());
        if (m_on_dispatch) m_on_dispatch();
        if (m_acceptance != SubmitResult::Accepted) return m_acceptance;

        m_pending.push_back({id, std::move(request), std::move(completion), std::chrono::steady_clock::now(), timeout});
        return SubmitResult::Accepted;
    }

    void Cancel(uint64_t id) override
    {
        m_cancelled.push_back(id);
    }

    void Stop() override
    {
        if (m_stopped) return;

        m_stopped = true;
        for (auto& request : m_pending) {
            request.complete({Delivery::NotSent, {}, "held request stopped"});
        }

        m_pending.clear();
    }

protected:
    bool m_stopped{false};
};

} // namespace wallet::payjoin::test
#endif // BITCOIN_WALLET_TEST_PAYJOIN_TEST_TRANSPORT_H
