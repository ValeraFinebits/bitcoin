// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/client.h>
#include <rpc/request.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <wallet/rpc/util.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

namespace wallet {
static std::string TestWalletName(const std::string& endpoint, std::optional<std::string> parameter = std::nullopt)
{
    JSONRPCRequest req;
    req.URI = endpoint;
    return EnsureUniqueWalletName(req, parameter);
}

BOOST_FIXTURE_TEST_SUITE(wallet_rpc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ensure_unique_wallet_name)
{
    // EnsureUniqueWalletName should only return if exactly one unique wallet name is provided
    BOOST_CHECK_EQUAL(TestWalletName("/wallet/foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/wallet/foo", "foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/", "foo"), "foo");
    BOOST_CHECK_EQUAL(TestWalletName("/bar", "foo"), "foo");

    BOOST_CHECK_THROW(TestWalletName("/"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/foo"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foo", "bar"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foo", "foobar"), UniValue);
    BOOST_CHECK_THROW(TestWalletName("/wallet/foobar", "foo"), UniValue);
}

BOOST_AUTO_TEST_CASE(payjoin_cli_conversion_preserves_opaque_strings)
{
    const std::string uri{"bitcoin:address?amount=1&pj=endpoint#key=value"};
    const std::string relay{"https://relay.example/path?key=value"};
    const auto positional = RPCConvertValues("sendpayjoin", {uri, relay, "1.00000000", "1.001", "0.001", "120", " request=ID "});
    BOOST_CHECK_EQUAL(positional[0].get_str(), uri);
    BOOST_CHECK_EQUAL(positional[1].get_str(), relay);
    BOOST_CHECK(positional[2].isNum());
    BOOST_CHECK(positional[3].isNum());
    BOOST_CHECK_EQUAL(positional[5].getInt<int>(), 120);
    BOOST_CHECK_EQUAL(positional[6].get_str(), " request=ID ");

    const auto named = RPCConvertNamedValues("sendpayjoin", {"uri=" + uri, "relay=" + relay, "fee_rate=1.001", "request_id= request=ID "});
    BOOST_CHECK_EQUAL(named["uri"].get_str(), uri);
    BOOST_CHECK_EQUAL(named["relay"].get_str(), relay);
    BOOST_CHECK(named["fee_rate"].isNum());
    BOOST_CHECK_EQUAL(named["request_id"].get_str(), " request=ID ");
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
