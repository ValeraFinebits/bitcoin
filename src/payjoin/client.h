// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_PAYJOIN_CLIENT_H
#define BITCOIN_PAYJOIN_CLIENT_H

#include <consensus/amount.h>
#include <util/result.h>

#include <optional>
#include <string>
#include <string_view>

namespace wallet::payjoin {

struct ParsedUri {
    std::string address;
    std::string endpoint;
    std::optional<CAmount> amount;
};

util::Result<ParsedUri> ParseUri(std::string_view uri);

} // namespace wallet::payjoin

#endif // BITCOIN_PAYJOIN_CLIENT_H
