// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit-license.php.

#include <wallet/payjoin/manager.h>

#include <common/args.h>
#include <interfaces/chain.h>
#include <netaddress.h>
#include <netbase.h>
#include <payjoin/client.h>
#include <payjoin/http_transport.h>
#include <payjoin/transport.h>
#include <scheduler.h>
#include <sync.h>
#include <util/thread.h>
#include <wallet/context.h>
#include <wallet/payjoin/sender.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace wallet {
void UnloadPayjoinWallet(WalletContext& context, const std::shared_ptr<CWallet>& wallet)
{
    if (context.payjoin) context.payjoin->Unload(wallet);
}

namespace payjoin {
namespace {
std::optional<std::string> DirectNetworkError(interfaces::Chain& chain, const ArgsManager& args)
{
    if (!chain.isNetworkActive()) return "Payjoin direct networking requires active node networking";
    if (!fNameLookup) return "Payjoin direct networking requires DNS";
    if (GetNameProxy()) return "Payjoin direct networking does not support a Core name proxy";
    for (int network = 0; network < NET_MAX; ++network) {
        if (GetProxy(static_cast<Network>(network))) return "Payjoin direct networking does not support a Core network proxy";
    }
    if (!args.GetArg("-i2psam", "").empty()) return "Payjoin direct networking does not support I2P SAM";
    if (!args.GetArgs("-onlynet").empty()) return "Payjoin direct networking does not support -onlynet";
    return std::nullopt;
}

class DirectTransport final : public SenderTransport
{
    interfaces::Chain& m_chain;
    const ArgsManager& m_args;
    HttpSenderTransport m_http;
    Mutex m_mutex;
    std::condition_variable m_idle;
    bool m_stopped GUARDED_BY(m_mutex){false};
    size_t m_submissions GUARDED_BY(m_mutex){0};

public:
    explicit DirectTransport(interfaces::Chain& chain, const ArgsManager& args) : m_chain{chain}, m_args{args} {}

    ~DirectTransport() override { Stop(); }

    SubmitResult Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion completion) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            if (m_stopped) return SubmitResult::Stopped;
            ++m_submissions;
        }
        struct Submission {
            DirectTransport& transport;
            ~Submission()
            {
                LOCK(transport.m_mutex);
                --transport.m_submissions;
                transport.m_idle.notify_all();
            }
        } submission{*this};

        if (auto error = DirectNetworkError(m_chain, m_args)) {
            completion({Delivery::NotSent, {}, std::move(*error), false});
            return SubmitResult::Accepted;
        }

        return m_http.Submit(id, std::move(request), timeout, std::move(completion));
    }

    void Cancel(uint64_t id) override { m_http.Cancel(id); }

    void Stop() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            WAIT_LOCK(m_mutex, lock);
            m_stopped = true;
            m_idle.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_submissions == 0; });
        }
        m_http.Stop();
    }
};

std::future<ManagerResult> Ready(ManagerResult result)
{
    std::promise<ManagerResult> promise;
    auto future = promise.get_future();
    promise.set_value(std::move(result));
    return future;
}
} // namespace

std::unique_ptr<SenderTransport> MakeDirectTransport(interfaces::Chain& chain, const ArgsManager& args)
{
    return std::make_unique<DirectTransport>(chain, args);
}

struct SenderManager::State {
    struct Entry {
        std::shared_ptr<CWallet> wallet;
        std::shared_ptr<SenderService> service;
        std::shared_ptr<const std::vector<PaymentView>> archive;
        bool closing{false};
        std::promise<void> stopped;
        std::shared_future<void> stop_complete{stopped.get_future().share()};

        explicit Entry(std::shared_ptr<CWallet> loaded_wallet) : wallet{std::move(loaded_wallet)} {}
    };

    interfaces::Chain& m_chain;
    const ArgsManager& m_args;
    CScheduler m_scheduler;

    std::unique_ptr<SerialTaskRunner> m_runner{std::make_unique<SerialTaskRunner>(m_scheduler)};
    Mutex m_mutex;
    bool m_stopped GUARDED_BY(m_mutex){false};
    std::map<std::weak_ptr<CWallet>, std::shared_ptr<Entry>, std::owner_less<std::weak_ptr<CWallet>>> m_entries GUARDED_BY(m_mutex);
    std::promise<void> m_stop;
    std::shared_future<void> m_stop_complete{m_stop.get_future().share()};

    explicit State(interfaces::Chain& chain, const ArgsManager& args) : m_chain{chain}, m_args{args}
    {
        m_scheduler.m_service_thread = std::thread{util::TraceThread, "payjoin", [this] { m_scheduler.serviceQueue(); }};
    }

    static ManagerResult StoppedView(const Entry& entry, std::optional<uint256> id)
    {
        ManagerResult result{CommandStatus::Stopped};
        if (entry.archive) {
            for (const auto& view : *entry.archive) {
                if (!id || view.payment.id == *id) result.payments.push_back(view);
            }
        }
        return result;
    }

    void PruneExpiredEntries() EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        AssertLockHeld(m_mutex);
        std::erase_if(m_entries, [](const auto& item) {
            return item.first.expired() && item.second->stop_complete.wait_for(std::chrono::seconds::zero()) == std::future_status::ready;
        });
    }

    std::pair<std::shared_ptr<SenderService>, ManagerResult> Find(const std::shared_ptr<CWallet>& wallet, std::optional<uint256> id, bool create)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        PruneExpiredEntries();
        const auto key = std::weak_ptr{wallet};
        auto found = m_entries.find(key);
        if (found == m_entries.end()) {
            if (m_stopped || !create) {
                CommandStatus status{CommandStatus::Completed};
                if (m_stopped) {
                    status = CommandStatus::Stopped;
                } else if (id) {
                    status = CommandStatus::NotFound;
                }
                return {{}, {status}};
            }
            found = m_entries.emplace(key, std::make_shared<Entry>(wallet)).first;
        }

        auto& entry = *found->second;
        if (entry.service) return {entry.service, {}};
        if (entry.closing || m_stopped) return {{}, StoppedView(entry, id)};
        if (!create) return {{}, {id ? CommandStatus::NotFound : CommandStatus::Completed}};

        auto transport = [this] { return MakeDirectTransport(m_chain, m_args); };
        auto schedule = [this](std::chrono::milliseconds delay, std::function<void()> work) {
            m_scheduler.scheduleFromNow(std::move(work), delay);
        };
        auto network_check = [this] { return DirectNetworkError(m_chain, m_args); };
        entry.service = std::make_shared<SenderService>(
            *wallet, *m_runner, std::move(transport), SenderService::Clock::now,
            std::move(schedule), std::move(network_check));
        return {entry.service, {}};
    }

    void Unload(const std::shared_ptr<Entry>& entry) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::shared_ptr<SenderService> service;
        bool wait;
        {
            LOCK(m_mutex);
            wait = entry->closing;
            if (!wait) {
                service = entry->service;

                if (service) service->Close();
                entry->closing = true;
            }
        }
        if (wait) {
            entry->stop_complete.wait();
            return;
        }

        if (service) service->Stop();

        std::shared_ptr<CWallet> wallet;
        {
            LOCK(m_mutex);
            if (service) entry->archive = service->Archive();
            entry->service.reset();
            wallet = std::move(entry->wallet);
        }

        wallet.reset();
        service.reset();
        entry->stopped.set_value();
    }

    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        std::vector<std::shared_ptr<Entry>> entries;
        bool wait;
        {
            LOCK(m_mutex);
            PruneExpiredEntries();
            wait = m_stopped;
            if (!wait) {
                for (const auto& [wallet, entry] : m_entries) {
                    if (entry->service) entry->service->Close();
                    entries.push_back(entry);
                }
                m_stopped = true;
            }
        }
        if (wait) {
            m_stop_complete.wait();
            return;
        }

        for (const auto& entry : entries) {
            Unload(entry);
        }

        m_scheduler.stop();
        m_runner.reset();
        {
            LOCK(m_mutex);
            PruneExpiredEntries();
        }
        m_stop.set_value();
    }
};

void SenderManagerDeleter::operator()(SenderManager* manager) const { delete manager; }

SenderManager::SenderManager(interfaces::Chain& chain, const ArgsManager& args) : m_state{std::make_shared<State>(chain, args)} {}

SenderManager::~SenderManager() { Stop(); }

std::future<ManagerResult> SenderManager::Send(const std::shared_ptr<CWallet>& wallet, PaymentRequest request)
{
    auto [service, result] = m_state->Find(wallet, std::nullopt, true);
    return service ? service->Send(std::move(request)) : Ready(std::move(result));
}

std::future<ManagerResult> SenderManager::Read(const std::shared_ptr<CWallet>& wallet, std::optional<uint256> id)
{
    auto [service, result] = m_state->Find(wallet, id, false);
    return service ? service->Read(id) : Ready(std::move(result));
}

std::future<ManagerResult> SenderManager::Execute(const std::shared_ptr<CWallet>& wallet, const uint256& id, SenderCommand command)
{
    auto [service, result] = m_state->Find(wallet, id, false);
    return service ? service->Execute(id, command) : Ready(std::move(result));
}

void SenderManager::Unload(const std::shared_ptr<CWallet>& wallet)
{
    std::shared_ptr<State::Entry> entry;
    {
        LOCK(m_state->m_mutex);
        m_state->PruneExpiredEntries();
        const auto key = std::weak_ptr{wallet};
        auto found = m_state->m_entries.find(key);
        if (found == m_state->m_entries.end()) {
            if (m_state->m_stopped) return;

            found = m_state->m_entries.emplace(key, std::make_shared<State::Entry>(wallet)).first;
        }
        entry = found->second;
    }

    m_state->Unload(entry);
}

void SenderManager::Stop() { m_state->Stop(); }
} // namespace payjoin
} // namespace wallet
