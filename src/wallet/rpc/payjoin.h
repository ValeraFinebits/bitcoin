// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_RPC_PAYJOIN_H
#define BITCOIN_WALLET_RPC_PAYJOIN_H

#include <span.h>

class CRPCCommand;

namespace wallet {
std::span<const CRPCCommand> GetPayjoinRPCCommands();
} // namespace wallet

#endif // BITCOIN_WALLET_RPC_PAYJOIN_H
