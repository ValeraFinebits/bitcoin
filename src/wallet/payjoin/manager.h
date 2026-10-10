// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit-license.php.

#ifndef BITCOIN_WALLET_PAYJOIN_MANAGER_H
#define BITCOIN_WALLET_PAYJOIN_MANAGER_H

#include <uint256.h>
#include <wallet/payjoin/sender.h>

#include <future>
#include <memory>
#include <optional>

class ArgsManager;
namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
class CWallet;
namespace payjoin {
std::unique_ptr<SenderTransport> MakeDirectTransport(interfaces::Chain& chain, const ArgsManager& args);

class SenderManager
{
public:
    explicit SenderManager(interfaces::Chain& chain, const ArgsManager& args);
    ~SenderManager();

    SenderManager(const SenderManager&) = delete;
    SenderManager& operator=(const SenderManager&) = delete;

    std::future<ManagerResult> Send(const std::shared_ptr<CWallet>& wallet, PaymentRequest request);

    std::future<ManagerResult> Read(const std::shared_ptr<CWallet>& wallet, std::optional<uint256> id = std::nullopt);

    std::future<ManagerResult> Execute(const std::shared_ptr<CWallet>& wallet, const uint256& id, SenderCommand command);

    void Unload(const std::shared_ptr<CWallet>& wallet);

    void Stop();

private:
    struct State;
    std::shared_ptr<State> m_state;
};
} // namespace payjoin
} // namespace wallet

#endif // BITCOIN_WALLET_PAYJOIN_MANAGER_H
