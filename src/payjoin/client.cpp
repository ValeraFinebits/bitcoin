// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <payjoin/client.h>

#include <payjoin.hpp>
#include <util/translation.h>

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>

namespace wallet::payjoin {

util::Result<ParsedUri> ParseUri(std::string_view uri)
{
    try {
        auto parsed_uri = ::payjoin::Uri::parse(std::string{uri});
        auto pj_uri = parsed_uri->check_pj_supported();
        std::optional<CAmount> amount;
        if (const auto amount_sats = pj_uri->amount_sats()) {
            if (*amount_sats > static_cast<std::uint64_t>(MAX_MONEY)) {
                return util::Error{Untranslated("Payjoin URI amount exceeds MAX_MONEY")};
            }
            amount = static_cast<CAmount>(*amount_sats);
        }
        return ParsedUri{
            .address = pj_uri->address(),
            .endpoint = pj_uri->pj_endpoint(),
            .amount = amount,
        };
    } catch (...) {
        return util::Error{Untranslated("Exception from Payjoin Rust FFI")};
    }
}

} // namespace wallet::payjoin
