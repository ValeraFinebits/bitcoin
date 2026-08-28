// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <payjoin/client.h>
#include <util/result.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace wallet::payjoin {
namespace {

constexpr char VALID_URI[] =
    "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4?amount=1&pj=https://example.com/pj";

BOOST_AUTO_TEST_SUITE(payjoin_tests)

BOOST_AUTO_TEST_CASE(production_ffi_parses_payjoin_uri)
{
    auto result = ParseUri(VALID_URI);

    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(result->address, "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4");
    BOOST_CHECK_EQUAL(result->endpoint, "https://example.com/pj");
    BOOST_REQUIRE(result->amount);
    BOOST_CHECK_EQUAL(*result->amount, CAmount{COIN});
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet::payjoin
