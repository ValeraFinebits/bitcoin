// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <payjoin/client.h>
#include <policy/feerate.h>
#include <psbt.h>
#include <streams.h>
#include <util/expected.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <barrier>
#include <cstddef>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace wallet::payjoin {
namespace {

constexpr std::string_view VALID_URI{
    "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?pjos=0&pj="
    "HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1QPTCDAQ-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-"
    "RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV"};

constexpr std::string_view PSBT_BASE64{
    "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA="};

constexpr std::size_t OHTTP_ENCAPSULATED_MESSAGE_BYTES{8192};
constexpr std::string_view POSTED_ORIGINAL_PSBT_EVENT{"{\"PostedOriginalPsbt\":[]}"};
constexpr std::string_view CANCELLED_EVENT{"{\"Cancelled\":[]}"};
constexpr std::string_view CLOSED_ABORTED_EVENT{"{\"Closed\":\"Aborted\"}"};
// Generated with payjoin/payjoin/src/core/send/v2/session.rs using
// SessionOutcome::Success(PARSED_ORIGINAL_PSBT). Regenerate after a
// rust-bitcoin major-version change if its serde representation changes.
constexpr std::string_view CLOSED_SUCCESS_EVENT{"{\"Closed\":{\"Success\":{\"unsigned_tx\":{\"version\":2,\"lock_time\":211,\"input\":[{\"previous_output\":\"833b085de288cda6ff614c6e8655f61e7ae4f84604a2751998dc25a0d1ba278f:0\",\"script_sig\":\"\",\"sequence\":4294967294,\"witness\":[]}],\"output\":[{\"value\":95983068,\"script_pubkey\":\"a9141de849f069d274150e3afeae8d72eb5a6b09443087\"},{\"value\":2000000,\"script_pubkey\":\"a914774096dbcf486743c22f4347e9b469febe8b677a87\"}]},\"version\":0,\"xpub\":{},\"proprietary\":[],\"unknown\":[],\"inputs\":[{\"non_witness_utxo\":null,\"witness_utxo\":{\"value\":97983400,\"script_pubkey\":\"a914de4e1e9061ca59135b035ad5e6d47990454354d087\"},\"partial_sigs\":{},\"sighash_type\":null,\"redeem_script\":null,\"witness_script\":null,\"bip32_derivation\":[],\"final_script_sig\":\"160014c78a45725355828d5658074dd5260d5fcb698530\",\"final_script_witness\":[\"304402207c43e03a75ea7e473f76be1cb6ea54f4023667e0f44b8bc05ff6aa01fc2324d302203ff463d8f599de01235244e584344d010d205f04ceeedf67f95d78a59ea8963501\",\"03159ac01aa0d58754c4b4d8b7d349ed1edfcf0b362b4f6b55106723a2858f8516\"],\"ripemd160_preimages\":{},\"sha256_preimages\":{},\"hash160_preimages\":{},\"hash256_preimages\":{},\"tap_key_sig\":null,\"tap_script_sigs\":[],\"tap_scripts\":[],\"tap_key_origins\":[],\"tap_internal_key\":null,\"tap_merkle_root\":null,\"proprietary\":[],\"unknown\":[]}],\"outputs\":[{\"redeem_script\":\"001446f61a2bba73828ee585b4a5fc37946a7d8cc514\",\"witness_script\":null,\"bip32_derivation\":[],\"tap_internal_key\":null,\"tap_tree\":null,\"tap_key_origins\":[],\"proprietary\":[],\"unknown\":[]},{\"redeem_script\":null,\"witness_script\":null,\"bip32_derivation\":[],\"tap_internal_key\":null,\"tap_tree\":null,\"tap_key_origins\":[],\"proprietary\":[],\"unknown\":[]}]}}}"};
// EX1QRSSKHS encodes 2020-01-01, before the test date. Regenerate this
// fragment if the URI encoding or the expiration representation changes.
constexpr std::string_view EXPIRED_URI{
    "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?pjos=0&pj="
    "HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1QRSSKHS-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-"
    "RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV"};

static_assert(!std::is_copy_constructible_v<SenderSession>);
static_assert(std::is_move_constructible_v<SenderSession>);
static_assert(!std::is_copy_assignable_v<SenderSession>);
static_assert(std::is_move_assignable_v<SenderSession>);

class InMemoryEventLog final : public SenderEventLog
{
public:
    enum class FailureMode { None,
                             ReturnBefore,
                             ReturnAfter,
                             ThrowBefore,
                             ThrowAfter,
                             UnknownBefore };

    util::Expected<void, std::string> Save(std::string event) override
    {
        std::lock_guard lock{m_mutex};
        ++m_save_count;
        if (auto result = InjectFailure(m_fail_save, false, "save failed"); !result) return result;
        if (m_closed) return util::Unexpected<std::string>{"event log is closed"};
        m_events.push_back(std::move(event));
        return InjectFailure(m_fail_save, true, "save failed");
    }

    util::Expected<std::vector<std::string>, std::string> Load() override
    {
        std::lock_guard lock{m_mutex};
        ++m_load_count;
        if (m_fail_load) return util::Unexpected<std::string>{"load failed"};
        return m_events;
    }

    util::Expected<void, std::string> Close() override
    {
        std::lock_guard lock{m_mutex};
        ++m_close_count;
        if (m_closed) return {};
        if (auto result = InjectFailure(m_fail_close, false, "close failed"); !result) return result;
        m_closed = true;
        return InjectFailure(m_fail_close, true, "close failed");
    }

    void FailSave(FailureMode mode = FailureMode::ReturnBefore)
    {
        std::lock_guard lock{m_mutex};
        m_fail_save = mode;
    }
    void AllowSave()
    {
        std::lock_guard lock{m_mutex};
        m_fail_save = FailureMode::None;
    }
    void FailLoad()
    {
        std::lock_guard lock{m_mutex};
        m_fail_load = true;
    }
    void AllowLoad()
    {
        std::lock_guard lock{m_mutex};
        m_fail_load = false;
    }
    void FailClose(FailureMode mode = FailureMode::ReturnBefore)
    {
        std::lock_guard lock{m_mutex};
        m_fail_close = mode;
    }
    void AllowClose()
    {
        std::lock_guard lock{m_mutex};
        m_fail_close = FailureMode::None;
    }
    void AddEvent(std::string event)
    {
        std::lock_guard lock{m_mutex};
        m_events.push_back(std::move(event));
    }
    std::size_t EventCount() const
    {
        std::lock_guard lock{m_mutex};
        return m_events.size();
    }
    std::string Event(std::size_t index) const
    {
        std::lock_guard lock{m_mutex};
        return m_events.at(index);
    }
    std::size_t SaveCount() const
    {
        std::lock_guard lock{m_mutex};
        return m_save_count;
    }
    std::size_t LoadCount() const
    {
        std::lock_guard lock{m_mutex};
        return m_load_count;
    }
    std::size_t CloseCount() const
    {
        std::lock_guard lock{m_mutex};
        return m_close_count;
    }
    bool IsClosed() const
    {
        std::lock_guard lock{m_mutex};
        return m_closed;
    }

private:
    static util::Expected<void, std::string> InjectFailure(FailureMode mode, bool after, const char* message)
    {
        if (mode == FailureMode::None) return {};
        if (after != (mode == FailureMode::ReturnAfter || mode == FailureMode::ThrowAfter)) return {};
        if (mode == FailureMode::UnknownBefore) throw 42;
        if (mode == FailureMode::ThrowBefore || mode == FailureMode::ThrowAfter) throw std::runtime_error{message};
        return util::Unexpected<std::string>{message};
    }

    mutable std::mutex m_mutex;
    std::vector<std::string> m_events;
    std::size_t m_save_count{0};
    std::size_t m_load_count{0};
    std::size_t m_close_count{0};
    FailureMode m_fail_save{FailureMode::None};
    bool m_fail_load{false};
    FailureMode m_fail_close{FailureMode::None};
    bool m_closed{false};
};

PartiallySignedTransaction ParseValidPsbt()
{
    auto result = DecodeBase64PSBT(std::string{PSBT_BASE64});
    BOOST_REQUIRE(result);
    return std::move(result).value();
}

bool SameUnsignedTransaction(const CMutableTransaction& lhs, const CMutableTransaction& rhs)
{
    return lhs.version == rhs.version &&
           lhs.nLockTime == rhs.nLockTime &&
           lhs.vin == rhs.vin &&
           lhs.vout == rhs.vout;
}

PartiallySignedTransaction MakeEquivalentPsbtV2(const PartiallySignedTransaction& psbt_v0)
{
    const auto unsigned_tx = psbt_v0.GetUnsignedTx();
    BOOST_REQUIRE(unsigned_tx);

    PartiallySignedTransaction psbt_v2{*unsigned_tx, /*version=*/2};
    psbt_v2.m_xpubs = psbt_v0.m_xpubs;
    psbt_v2.m_proprietary = psbt_v0.m_proprietary;
    psbt_v2.unknown = psbt_v0.unknown;
    BOOST_REQUIRE_EQUAL(psbt_v2.inputs.size(), psbt_v0.inputs.size());
    BOOST_REQUIRE_EQUAL(psbt_v2.outputs.size(), psbt_v0.outputs.size());

    for (std::size_t index = 0; index < psbt_v0.inputs.size(); ++index) {
        psbt_v2.inputs[index].Merge(psbt_v0.inputs[index]);
        psbt_v2.inputs[index].sighash_type = psbt_v0.inputs[index].sighash_type;
    }
    for (std::size_t index = 0; index < psbt_v0.outputs.size(); ++index) {
        psbt_v2.outputs[index].Merge(psbt_v0.outputs[index]);
    }
    return psbt_v2;
}

void ClearFinalizedInputs(PartiallySignedTransaction& psbt)
{
    for (auto& input : psbt.inputs) {
        input.final_script_sig.clear();
        input.final_script_witness.stack.clear();
    }
}

void CheckFallbackEquals(const SenderSession& session, const CTransactionRef& expected, std::string_view label)
{
    auto fallback = session.FallbackTransaction();
    BOOST_REQUIRE_MESSAGE(fallback, std::string{label} + ": fallback transaction unavailable");
    if (fallback) BOOST_CHECK_MESSAGE((*fallback)->Equals(*expected), std::string{label} + ": fallback transaction differs");
}

CTransactionRef ExtractFallback(const PartiallySignedTransaction& psbt)
{
    auto fallback_psbt = psbt;
    CMutableTransaction fallback_transaction;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(fallback_psbt, fallback_transaction));
    return MakeTransactionRef(std::move(fallback_transaction));
}

std::string SerializePsbtForComparison(const PartiallySignedTransaction& psbt)
{
    DataStream stream{};
    stream << psbt;
    return EncodeBase64(stream);
}

std::vector<unsigned char> UndersizedOhttpResponse()
{
    return {0};
}

std::vector<unsigned char> CorrectlySizedUndecodableOhttpResponse()
{
    return std::vector<unsigned char>(OHTTP_ENCAPSULATED_MESSAGE_BYTES, 0);
}

const char* ErrorCodeName(PayjoinErrorCode code)
{
    switch (code) {
    case PayjoinErrorCode::InvalidUri: return "InvalidUri";
    case PayjoinErrorCode::UnsupportedProtocol: return "UnsupportedProtocol";
    case PayjoinErrorCode::InvalidPsbt: return "InvalidPsbt";
    case PayjoinErrorCode::InvalidSenderInput: return "InvalidSenderInput";
    case PayjoinErrorCode::InvalidPolicy: return "InvalidPolicy";
    case PayjoinErrorCode::Expired: return "Expired";
    case PayjoinErrorCode::Storage: return "Storage";
    case PayjoinErrorCode::Transient: return "Transient";
    case PayjoinErrorCode::Fatal: return "Fatal";
    case PayjoinErrorCode::ReplayFailed: return "ReplayFailed";
    case PayjoinErrorCode::InvalidState: return "InvalidState";
    case PayjoinErrorCode::Internal: return "Internal";
    }
    return "unknown";
}

template <typename T>
void CheckError(const util::Expected<T, PayjoinError>& result, PayjoinErrorCode code, std::string_view label)
{
    BOOST_REQUIRE_MESSAGE(!result, std::string{label} + " unexpectedly succeeded");
    BOOST_CHECK_MESSAGE(result.error().code == code,
                        std::string{label} + ": expected " + ErrorCodeName(code) + ", got " +
                            ErrorCodeName(result.error().code) + ": " + result.error().message);
    BOOST_CHECK(!result.error().message.empty());
}

template <typename T>
void CheckErrorContains(const util::Expected<T, PayjoinError>& result, PayjoinErrorCode code, std::string_view text, std::string_view label)
{
    CheckError(result, code, label);
    if (!result) {
        BOOST_CHECK_MESSAGE(result.error().message.find(text) != std::string::npos,
                            std::string{label} + ": message does not contain " + std::string{text});
    }
}

void CheckNoTransitions(SenderSession& session, std::string_view label)
{
    const std::string prefix{label};
    CheckError(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, prefix + " prepare");
    CheckError(session.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::InvalidState, prefix + " response");
    CheckError(session.DiscardPendingRequest(), PayjoinErrorCode::InvalidState, prefix + " discard");
    CheckError(session.Cancel(), PayjoinErrorCode::InvalidState, prefix + " cancel");
    CheckError(session.CloseFallback(), PayjoinErrorCode::InvalidState, prefix + " close fallback");
}

void CheckMovedFrom(SenderSession& session, std::string_view label)
{
    const std::string prefix{label};
    BOOST_CHECK(session.Phase() == SenderPhase::Unusable);
    BOOST_CHECK(!session.HasPendingRequest());
    BOOST_CHECK(!session.Outcome());
    BOOST_CHECK(!session.LastError());
    CheckNoTransitions(session, prefix);
    CheckError(session.FallbackTransaction(), PayjoinErrorCode::InvalidState, prefix + " fallback");
}

BOOST_AUTO_TEST_SUITE(payjoin_tests)

BOOST_AUTO_TEST_CASE(sender_create_and_request_lifecycle)
{
    auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();

    auto session_result = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
    if (!session_result) BOOST_TEST_MESSAGE(session_result.error().message);
    BOOST_REQUIRE(static_cast<bool>(session_result));
    BOOST_CHECK_EQUAL(event_log->EventCount(), 1);
    const auto initial_event_count = event_log->EventCount();

    auto session = std::move(session_result).value();
    CheckError(session.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::InvalidState, "response before request");
    CheckError(session.DiscardPendingRequest(), PayjoinErrorCode::InvalidState, "discard before request");

    auto request_result = session.PrepareRequest("https://relay.example");
    if (!request_result) BOOST_TEST_MESSAGE(request_result.error().message);
    BOOST_REQUIRE(static_cast<bool>(request_result));
    BOOST_CHECK(!request_result->url.empty());
    BOOST_CHECK(!request_result->content_type.empty());
    BOOST_CHECK(!request_result->body.empty());
    const auto first_body = request_result->body;
    BOOST_CHECK_EQUAL(event_log->EventCount(), initial_event_count);

    CheckError(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, "duplicate request");

    BOOST_REQUIRE(session.DiscardPendingRequest());
    BOOST_CHECK_EQUAL(event_log->EventCount(), initial_event_count);
    auto second_request = session.PrepareRequest("https://relay.example");
    BOOST_REQUIRE(second_request);
    BOOST_CHECK(!second_request->body.empty());
    BOOST_CHECK(first_body != second_request->body);
    BOOST_REQUIRE(session.DiscardPendingRequest());
    BOOST_CHECK_EQUAL(event_log->EventCount(), initial_event_count);
    CheckError(session.DiscardPendingRequest(), PayjoinErrorCode::InvalidState, "duplicate discard");
}

BOOST_AUTO_TEST_CASE(sender_rejects_invalid_input_and_policy)
{
    PartiallySignedTransaction empty_psbt{CMutableTransaction{}, /*version=*/0};
    auto event_log = std::make_shared<InMemoryEventLog>();

    auto invalid_input = SenderSession::Create(VALID_URI, empty_psbt, CFeeRate{1000}, event_log);
    CheckError(invalid_input, PayjoinErrorCode::InvalidSenderInput, "invalid sender input");

    auto psbt = ParseValidPsbt();
    CheckError(SenderSession::Create(VALID_URI, psbt, CFeeRate{-1}, event_log), PayjoinErrorCode::InvalidPolicy, "negative fee");
    CheckError(SenderSession::Create(VALID_URI, psbt, CFeeRate{0}, event_log), PayjoinErrorCode::InvalidPolicy, "zero fee");

    auto rounded_fee_log = std::make_shared<InMemoryEventLog>();
    auto rounded_fee = SenderSession::Create(VALID_URI, psbt, CFeeRate{FeePerVSize{2001, 2000}}, rounded_fee_log);
    if (!rounded_fee) BOOST_TEST_MESSAGE(rounded_fee.error().message);
    BOOST_REQUIRE(rounded_fee);
    BOOST_REQUIRE_EQUAL(rounded_fee_log->EventCount(), 1);
    BOOST_CHECK(rounded_fee_log->Event(0).find("\"min_fee_rate\":251") != std::string::npos);

    auto tiny_fee_log = std::make_shared<InMemoryEventLog>();
    auto tiny_fee = SenderSession::Create(VALID_URI, psbt, CFeeRate{FeePerVSize{1, 2000}}, tiny_fee_log);
    if (!tiny_fee) BOOST_TEST_MESSAGE(tiny_fee.error().message);
    BOOST_REQUIRE(tiny_fee);
}

BOOST_AUTO_TEST_CASE(sender_accepts_equivalent_psbt_v2)
{
    const auto psbt_v0 = ParseValidPsbt();
    auto psbt_v2 = MakeEquivalentPsbtV2(psbt_v0);
    BOOST_CHECK_EQUAL(psbt_v2.GetVersion(), 2);

    const auto unsigned_v0 = psbt_v0.GetUnsignedTx();
    const auto unsigned_v2 = psbt_v2.GetUnsignedTx();
    BOOST_REQUIRE(unsigned_v0);
    BOOST_REQUIRE(unsigned_v2);
    BOOST_CHECK(SameUnsignedTransaction(*unsigned_v0, *unsigned_v2));

    auto event_log = std::make_shared<InMemoryEventLog>();
    auto created = SenderSession::Create(VALID_URI, psbt_v2, CFeeRate{1000}, event_log);
    if (!created) BOOST_TEST_MESSAGE(created.error().message);
    BOOST_REQUIRE(created);

    auto session = std::move(created).value();
    BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
    BOOST_REQUIRE(session.DiscardPendingRequest());
}

BOOST_AUTO_TEST_CASE(sender_requires_finalized_original_psbt)
{
    const auto psbt = ParseValidPsbt();
    auto unfinished = psbt;
    ClearFinalizedInputs(unfinished);
    auto event_log = std::make_shared<InMemoryEventLog>();
    CheckError(SenderSession::Create(VALID_URI, unfinished, CFeeRate{1000}, event_log), PayjoinErrorCode::InvalidSenderInput, "unfinished PSBTv0");
    BOOST_CHECK_EQUAL(event_log->EventCount(), 0);

    auto unfinished_v2 = MakeEquivalentPsbtV2(psbt);
    ClearFinalizedInputs(unfinished_v2);
    auto event_log_v2 = std::make_shared<InMemoryEventLog>();
    CheckError(SenderSession::Create(VALID_URI, unfinished_v2, CFeeRate{1000}, event_log_v2), PayjoinErrorCode::InvalidSenderInput, "unfinished PSBTv2");
    BOOST_CHECK_EQUAL(event_log_v2->EventCount(), 0);
}

BOOST_AUTO_TEST_CASE(sender_requires_utxo_data_for_fallback_extraction)
{
    auto psbt = ParseValidPsbt();
    for (auto& input : psbt.inputs) {
        input.witness_utxo.SetNull();
        input.non_witness_utxo = nullptr;
    }
    BOOST_REQUIRE(!psbt.inputs.empty());
    BOOST_CHECK(!psbt.inputs.front().final_script_sig.empty());
    BOOST_CHECK(!psbt.inputs.front().final_script_witness.stack.empty());
    const auto expected_psbt = SerializePsbtForComparison(psbt);

    auto event_log = std::make_shared<InMemoryEventLog>();
    CheckErrorContains(
        SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log),
        PayjoinErrorCode::InvalidSenderInput,
        "fallback transaction",
        "PSBT without UTXO data");
    BOOST_CHECK_EQUAL(event_log->EventCount(), 0);
    BOOST_CHECK_EQUAL(SerializePsbtForComparison(psbt), expected_psbt);
}

BOOST_AUTO_TEST_CASE(sender_rejects_unrepresentable_psbt_v2_fields)
{
    for (const auto flags : {1, 2, 3, 5, 6, 7}) {
        auto psbt_v2 = MakeEquivalentPsbtV2(ParseValidPsbt());
        psbt_v2.m_tx_modifiable.emplace(flags);
        const auto original = SerializePsbtForComparison(psbt_v2);
        auto event_log = std::make_shared<InMemoryEventLog>();
        CheckErrorContains(
            SenderSession::Create(VALID_URI, psbt_v2, CFeeRate{1000}, event_log),
            PayjoinErrorCode::InvalidSenderInput,
            "modifiable",
            "PSBTv2 transaction modifiable flags");
        BOOST_CHECK_EQUAL(event_log->EventCount(), 0);
        BOOST_CHECK_EQUAL(event_log->SaveCount(), 0);
        BOOST_CHECK_EQUAL(event_log->CloseCount(), 0);
        BOOST_CHECK(!event_log->IsClosed());
        BOOST_CHECK_EQUAL(SerializePsbtForComparison(psbt_v2), original);
    }
}

BOOST_AUTO_TEST_CASE(sender_accepts_nonmodifiable_psbt_v2)
{
    const auto psbt_v0 = ParseValidPsbt();
    const auto fallback = ExtractFallback(psbt_v0);
    BOOST_REQUIRE(fallback->HasWitness());
    for (const auto flags : {-1, 0, 4}) {
        auto psbt_v2 = MakeEquivalentPsbtV2(psbt_v0);
        if (flags >= 0) psbt_v2.m_tx_modifiable.emplace(flags);
        const auto original = SerializePsbtForComparison(psbt_v2);
        const auto unsigned_tx = psbt_v2.GetUnsignedTx();
        BOOST_REQUIRE(unsigned_tx);
        auto log = std::make_shared<InMemoryEventLog>();
        {
            auto session = SenderSession::Create(VALID_URI, psbt_v2, CFeeRate{1000}, log);
            BOOST_REQUIRE(session);
            CheckFallbackEquals(*session, fallback, "PSBTv2 create");
            BOOST_CHECK(session->FallbackTransaction().value()->GetWitnessHash() == fallback->GetWitnessHash());
            BOOST_REQUIRE(session->PrepareRequest("https://relay.example"));
            BOOST_REQUIRE(session->DiscardPendingRequest());
        }
        auto session = SenderSession::Replay(log);
        BOOST_REQUIRE(session);
        CheckFallbackEquals(*session, fallback, "PSBTv2 replay");
        BOOST_CHECK(session->FallbackTransaction().value()->GetWitnessHash() == fallback->GetWitnessHash());
        BOOST_REQUIRE(session->PrepareRequest("https://relay.example"));
        BOOST_REQUIRE(session->DiscardPendingRequest());
        BOOST_CHECK_EQUAL(SerializePsbtForComparison(psbt_v2), original);
        BOOST_REQUIRE(psbt_v2.GetUnsignedTx());
        BOOST_CHECK(SameUnsignedTransaction(*psbt_v2.GetUnsignedTx(), *unsigned_tx));
        BOOST_CHECK_EQUAL(log->EventCount(), 1);
        BOOST_CHECK_EQUAL(log->CloseCount(), 0);
    }
}

BOOST_AUTO_TEST_CASE(sender_rejects_null_event_log)
{
    auto psbt = ParseValidPsbt();

    auto create_result = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, nullptr);
    CheckErrorContains(create_result, PayjoinErrorCode::Storage, "null", "create with null event log");

    auto replay_result = SenderSession::Replay(nullptr);
    CheckErrorContains(replay_result, PayjoinErrorCode::Storage, "null", "replay with null event log");
}

BOOST_AUTO_TEST_CASE(sender_event_log_is_exclusive_and_create_requires_empty)
{
    auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();
    auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
    BOOST_REQUIRE(created);

    {
        auto session = std::move(created).value();
        const auto event_count = event_log->EventCount();
        const auto save_count = event_log->SaveCount();
        const auto load_count = event_log->LoadCount();
        const auto close_count = event_log->CloseCount();

        CheckErrorContains(
            SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log),
            PayjoinErrorCode::InvalidState,
            "already in use",
            "duplicate create");
        CheckErrorContains(
            SenderSession::Replay(event_log),
            PayjoinErrorCode::InvalidState,
            "already in use",
            "replay live session");

        BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
        BOOST_CHECK_EQUAL(event_log->SaveCount(), save_count);
        BOOST_CHECK_EQUAL(event_log->LoadCount(), load_count);
        BOOST_CHECK_EQUAL(event_log->CloseCount(), close_count);
        BOOST_CHECK(!event_log->IsClosed());
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        BOOST_REQUIRE(session.DiscardPendingRequest());
    }

    const auto event_count = event_log->EventCount();
    const auto save_count = event_log->SaveCount();
    const auto close_count = event_log->CloseCount();
    CheckErrorContains(
        SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log),
        PayjoinErrorCode::InvalidState,
        "Replay()",
        "create with non-empty log");
    BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
    BOOST_CHECK_EQUAL(event_log->SaveCount(), save_count);
    BOOST_CHECK_EQUAL(event_log->CloseCount(), close_count);
    BOOST_CHECK(!event_log->IsClosed());

    auto replayed = SenderSession::Replay(event_log);
    BOOST_REQUIRE(replayed);
    auto session = std::move(replayed).value();
    BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
    BOOST_REQUIRE(session.DiscardPendingRequest());
}

BOOST_AUTO_TEST_CASE(sender_event_log_claim_is_released_after_failures)
{
    auto psbt = ParseValidPsbt();

    auto validation_log = std::make_shared<InMemoryEventLog>();
    CheckError(
        SenderSession::Create(VALID_URI, psbt, CFeeRate{0}, validation_log),
        PayjoinErrorCode::InvalidPolicy,
        "create validation failure");
    auto created_after_validation = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, validation_log);
    BOOST_REQUIRE(created_after_validation);

    auto create_load_log = std::make_shared<InMemoryEventLog>();
    create_load_log->FailLoad();
    CheckErrorContains(
        SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, create_load_log),
        PayjoinErrorCode::Storage,
        "load failed",
        "create load failure");
    create_load_log->AllowLoad();
    auto created_after_load = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, create_load_log);
    BOOST_REQUIRE(created_after_load);

    auto create_save_log = std::make_shared<InMemoryEventLog>();
    create_save_log->FailSave();
    CheckErrorContains(
        SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, create_save_log),
        PayjoinErrorCode::Storage,
        "save failed",
        "create save failure");
    BOOST_CHECK_EQUAL(create_save_log->EventCount(), 0);
    BOOST_CHECK(!create_save_log->IsClosed());
    create_save_log->AllowSave();
    auto created_after_save = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, create_save_log);
    BOOST_REQUIRE(created_after_save);

    auto replay_log = std::make_shared<InMemoryEventLog>();
    {
        auto replay_source = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, replay_log);
        BOOST_REQUIRE(replay_source);
    }
    replay_log->FailLoad();
    CheckErrorContains(
        SenderSession::Replay(replay_log),
        PayjoinErrorCode::Storage,
        "load failed",
        "replay load failure");
    replay_log->AllowLoad();
    BOOST_REQUIRE(SenderSession::Replay(replay_log));
}

BOOST_AUTO_TEST_CASE(sender_event_log_claim_is_atomic)
{
    auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();
    std::barrier<> start{3};

    auto first_future = std::async(std::launch::async, [&] {
        start.arrive_and_wait();
        return SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
    });
    auto second_future = std::async(std::launch::async, [&] {
        start.arrive_and_wait();
        return SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
    });
    start.arrive_and_wait();

    auto first = first_future.get();
    auto second = second_future.get();
    const bool first_succeeded = static_cast<bool>(first);
    const bool second_succeeded = static_cast<bool>(second);
    BOOST_REQUIRE(first_succeeded != second_succeeded);

    if (first_succeeded) {
        CheckErrorContains(second, PayjoinErrorCode::InvalidState, "already in use", "concurrent create");
        auto session = std::move(first).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        BOOST_REQUIRE(session.DiscardPendingRequest());
    } else {
        CheckErrorContains(first, PayjoinErrorCode::InvalidState, "already in use", "concurrent create");
        auto session = std::move(second).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        BOOST_REQUIRE(session.DiscardPendingRequest());
    }
    BOOST_CHECK_EQUAL(event_log->EventCount(), 1);
    BOOST_CHECK_EQUAL(event_log->LoadCount(), 1);
    BOOST_CHECK_EQUAL(event_log->SaveCount(), 1);
    BOOST_CHECK_EQUAL(event_log->CloseCount(), 0);
}

BOOST_AUTO_TEST_CASE(sender_moved_from_object_is_inactive)
{
    auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();
    auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
    BOOST_REQUIRE(created);

    auto source = std::move(created).value();
    SenderSession destination{std::move(source)};

    CheckMovedFrom(source, "moved-from");
    CheckErrorContains(SenderSession::Replay(event_log), PayjoinErrorCode::InvalidState, "already in use", "replay moved session");

    BOOST_REQUIRE(destination.PrepareRequest("https://relay.example"));
    BOOST_REQUIRE(destination.DiscardPendingRequest());
}

BOOST_AUTO_TEST_CASE(sender_move_assignment_transfers_event_log_claim)
{
    auto psbt = ParseValidPsbt();
    auto source_log = std::make_shared<InMemoryEventLog>();
    auto destination_log = std::make_shared<InMemoryEventLog>();
    auto created_source = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, source_log);
    auto created_destination = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, destination_log);
    BOOST_REQUIRE(created_source);
    BOOST_REQUIRE(created_destination);

    auto source = std::move(created_source).value();
    auto destination = std::move(created_destination).value();
    destination = std::move(source);

    CheckMovedFrom(source, "move-assigned source");
    CheckErrorContains(SenderSession::Replay(source_log), PayjoinErrorCode::InvalidState, "already in use", "replay move-assigned session");
    BOOST_REQUIRE(SenderSession::Replay(destination_log));
    BOOST_REQUIRE(destination.PrepareRequest("https://relay.example"));
    BOOST_REQUIRE(destination.DiscardPendingRequest());
}

BOOST_AUTO_TEST_CASE(sender_processes_initial_response_outcomes)
{
    auto psbt = ParseValidPsbt();

    auto transient_log = std::make_shared<InMemoryEventLog>();
    auto transient_session = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, transient_log);
    BOOST_REQUIRE(transient_session);
    auto transient_sender = std::move(transient_session).value();
    BOOST_REQUIRE(transient_sender.PrepareRequest("https://relay.example"));

    CheckError(transient_sender.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::Transient, "transient response");
    BOOST_CHECK_EQUAL(transient_log->EventCount(), 1);
    BOOST_CHECK(!transient_log->IsClosed());
    BOOST_REQUIRE(transient_sender.PrepareRequest("https://relay.example"));
    BOOST_REQUIRE(transient_sender.DiscardPendingRequest());
    BOOST_CHECK_EQUAL(transient_log->EventCount(), 1);

    auto fatal_log = std::make_shared<InMemoryEventLog>();
    {
        auto fatal_session = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, fatal_log);
        BOOST_REQUIRE(fatal_session);
        auto fatal_sender = std::move(fatal_session).value();
        BOOST_REQUIRE(fatal_sender.PrepareRequest("https://relay.example"));

        auto fatal_result = fatal_sender.ProcessResponse(CorrectlySizedUndecodableOhttpResponse());
        CheckErrorContains(fatal_result, PayjoinErrorCode::Fatal, "decapsulation", "fatal response");
        BOOST_CHECK_EQUAL(fatal_log->EventCount(), 2);
        BOOST_CHECK(fatal_log->IsClosed());
        BOOST_CHECK(fatal_sender.Phase() == SenderPhase::Closed);
        BOOST_CHECK(!fatal_sender.HasPendingRequest());
        const auto fatal_outcome = fatal_sender.Outcome();
        BOOST_REQUIRE(fatal_outcome);
        BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*fatal_outcome));
        const auto& diagnostic = std::get<SenderAborted>(*fatal_outcome).diagnostic;
        BOOST_CHECK_EQUAL(diagnostic.has_value(), fatal_sender.LastError().has_value());
        if (diagnostic) {
            BOOST_REQUIRE(fatal_sender.LastError());
            BOOST_CHECK(diagnostic->code == fatal_sender.LastError()->code);
            BOOST_CHECK_EQUAL(diagnostic->message, fatal_sender.LastError()->message);
        }
        const auto fatal_error = fatal_sender.LastError();
        BOOST_REQUIRE(fatal_error);
        BOOST_CHECK(fatal_error->code == PayjoinErrorCode::Fatal);
        BOOST_CHECK_EQUAL(fatal_error->message, fatal_result.error().message);
        BOOST_REQUIRE(fatal_sender.FallbackTransaction());
        CheckNoTransitions(fatal_sender, "fatal response");
    }
    auto replayed = SenderSession::Replay(fatal_log);
    BOOST_REQUIRE(replayed);
    auto replayed_sender = std::move(replayed).value();
    BOOST_CHECK(replayed_sender.Phase() == SenderPhase::Closed);
    const auto replayed_outcome = replayed_sender.Outcome();
    BOOST_REQUIRE(replayed_outcome);
    BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*replayed_outcome));
    BOOST_CHECK(!std::get<SenderAborted>(*replayed_outcome).diagnostic);
    BOOST_REQUIRE(replayed_sender.FallbackTransaction());
}

BOOST_AUTO_TEST_CASE(sender_rejects_oversized_response_before_ffi)
{
    auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();
    auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
    BOOST_REQUIRE(created);

    auto session = std::move(created).value();
    BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
    const auto initial_event_count = event_log->EventCount();

    const std::vector<unsigned char> oversized_response((1U << 20) + 1, 0);
    CheckErrorContains(session.ProcessResponse(oversized_response), PayjoinErrorCode::Transient, "exceeds", "oversized response");
    BOOST_CHECK_EQUAL(event_log->EventCount(), initial_event_count);
    BOOST_CHECK(!event_log->IsClosed());

    auto next_request = session.PrepareRequest("https://relay.example");
    BOOST_REQUIRE(next_request);
    BOOST_CHECK(!next_request->body.empty());
    BOOST_REQUIRE(session.DiscardPendingRequest());
}

BOOST_AUTO_TEST_CASE(sender_processes_polling_response_outcomes)
{
    const auto psbt = ParseValidPsbt();

    auto transient_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, transient_log);
        BOOST_REQUIRE(created);
    }
    transient_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto transient_replayed = SenderSession::Replay(transient_log);
    BOOST_REQUIRE(transient_replayed);
    {
        auto session = std::move(transient_replayed).value();
        auto first_request = session.PrepareRequest("https://relay.example");
        BOOST_REQUIRE(first_request);
        const auto first_body = first_request->body;
        CheckError(session.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::Transient, "polling transient response");
        BOOST_CHECK(session.Phase() == SenderPhase::Polling);
        BOOST_CHECK(!session.HasPendingRequest());
        BOOST_CHECK_EQUAL(transient_log->EventCount(), 2);

        auto second_request = session.PrepareRequest("https://relay.example");
        BOOST_REQUIRE(second_request);
        BOOST_CHECK(first_body != second_request->body);
        BOOST_REQUIRE(session.DiscardPendingRequest());
    }

    auto fatal_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, fatal_log);
        BOOST_REQUIRE(created);
    }
    fatal_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto fatal_replayed = SenderSession::Replay(fatal_log);
    BOOST_REQUIRE(fatal_replayed);
    {
        auto session = std::move(fatal_replayed).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        auto fatal_result = session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse());
        CheckError(fatal_result, PayjoinErrorCode::Fatal, "polling fatal response");
        BOOST_CHECK(!fatal_result.error().message.empty());
        BOOST_CHECK(session.Phase() == SenderPhase::Closed);
        BOOST_CHECK(!session.HasPendingRequest());
        const auto outcome = session.Outcome();
        BOOST_REQUIRE(outcome);
        BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*outcome));
        const auto& diagnostic = std::get<SenderAborted>(*outcome).diagnostic;
        BOOST_CHECK_EQUAL(diagnostic.has_value(), session.LastError().has_value());
        if (diagnostic) {
            BOOST_REQUIRE(session.LastError());
            BOOST_CHECK(diagnostic->code == session.LastError()->code);
            BOOST_CHECK_EQUAL(diagnostic->message, session.LastError()->message);
        }
        const auto last_error = session.LastError();
        BOOST_REQUIRE(last_error);
        BOOST_CHECK(last_error->code == PayjoinErrorCode::Fatal);
        BOOST_CHECK_EQUAL(last_error->message, fatal_result.error().message);
        BOOST_CHECK_EQUAL(fatal_log->EventCount(), 3);
        BOOST_CHECK(fatal_log->IsClosed());
    }
    auto fatal_closed = SenderSession::Replay(fatal_log);
    BOOST_REQUIRE(fatal_closed);
    auto fatal_closed_session = std::move(fatal_closed).value();
    BOOST_CHECK(fatal_closed_session.Phase() == SenderPhase::Closed);
    const auto fatal_closed_outcome = fatal_closed_session.Outcome();
    BOOST_REQUIRE(fatal_closed_outcome);
    BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*fatal_closed_outcome));
    BOOST_CHECK(!std::get<SenderAborted>(*fatal_closed_outcome).diagnostic);
}

BOOST_AUTO_TEST_CASE(sender_polling_persistence_failures)
{
    const auto psbt = ParseValidPsbt();

    auto save_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, save_log);
        BOOST_REQUIRE(created);
    }
    save_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto save_replayed = SenderSession::Replay(save_log);
    BOOST_REQUIRE(save_replayed);
    {
        auto session = std::move(save_replayed).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        save_log->FailSave();
        CheckErrorContains(session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse()), PayjoinErrorCode::Storage, "save failed", "polling save failure");
        BOOST_CHECK(session.Phase() == SenderPhase::Unusable);
        const auto last_error = session.LastError();
        BOOST_REQUIRE(last_error);
        BOOST_CHECK(last_error->code == PayjoinErrorCode::Storage);
    }
    auto save_recovered = SenderSession::Replay(save_log);
    BOOST_REQUIRE(save_recovered);
    auto save_recovered_session = std::move(save_recovered).value();
    BOOST_CHECK(save_recovered_session.Phase() == SenderPhase::Polling);

    auto close_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, close_log);
        BOOST_REQUIRE(created);
    }
    close_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto close_replayed = SenderSession::Replay(close_log);
    BOOST_REQUIRE(close_replayed);
    {
        auto session = std::move(close_replayed).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        close_log->FailClose();
        CheckErrorContains(session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse()), PayjoinErrorCode::Storage, "close failed", "polling close failure");
        BOOST_CHECK(session.Phase() == SenderPhase::Unusable);
        const auto last_error = session.LastError();
        BOOST_REQUIRE(last_error);
        BOOST_CHECK(last_error->code == PayjoinErrorCode::Storage);
    }
    BOOST_CHECK_EQUAL(close_log->EventCount(), 3);
    BOOST_CHECK(!close_log->IsClosed());
    const auto event_count = close_log->EventCount();
    const auto first_event = close_log->Event(0);
    const auto second_event = close_log->Event(1);
    const auto third_event = close_log->Event(2);
    for (int attempt = 0; attempt < 2; ++attempt) {
        CheckErrorContains(
            SenderSession::Replay(close_log),
            PayjoinErrorCode::Storage,
            "close failed",
            "polling replay close failure");
        BOOST_CHECK_EQUAL(close_log->EventCount(), event_count);
        BOOST_CHECK_EQUAL(close_log->Event(0), first_event);
        BOOST_CHECK_EQUAL(close_log->Event(1), second_event);
        BOOST_CHECK_EQUAL(close_log->Event(2), third_event);
        BOOST_CHECK(!close_log->IsClosed());
    }
    close_log->AllowClose();
    {
        auto close_recovered = SenderSession::Replay(close_log);
        BOOST_REQUIRE(close_recovered);
        auto close_recovered_session = std::move(close_recovered).value();
        BOOST_CHECK(close_recovered_session.Phase() == SenderPhase::Closed);
        const auto close_recovered_outcome = close_recovered_session.Outcome();
        BOOST_REQUIRE(close_recovered_outcome);
        BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*close_recovered_outcome));
        BOOST_CHECK(!std::get<SenderAborted>(*close_recovered_outcome).diagnostic);
        BOOST_CHECK(!close_recovered_session.LastError());
    }
    BOOST_CHECK(close_log->IsClosed());
    BOOST_CHECK_EQUAL(close_log->EventCount(), event_count);
    BOOST_CHECK_EQUAL(close_log->Event(0), first_event);
    BOOST_CHECK_EQUAL(close_log->Event(1), second_event);
    BOOST_CHECK_EQUAL(close_log->Event(2), third_event);
    auto close_replayed_again = SenderSession::Replay(close_log);
    BOOST_REQUIRE(close_replayed_again);
    BOOST_CHECK(close_replayed_again->Phase() == SenderPhase::Closed);
    BOOST_CHECK_EQUAL(close_log->EventCount(), event_count);
}

BOOST_AUTO_TEST_CASE(sender_rejects_oversized_polling_response_before_ffi)
{
    const auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
        BOOST_REQUIRE(created);
    }
    event_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto replayed = SenderSession::Replay(event_log);
    BOOST_REQUIRE(replayed);
    auto session = std::move(replayed).value();
    BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
    const auto initial_event_count = event_log->EventCount();

    const std::vector<unsigned char> oversized_response((1U << 20) + 1, 0);
    CheckErrorContains(session.ProcessResponse(oversized_response), PayjoinErrorCode::Transient, "exceeds", "oversized polling response");
    BOOST_CHECK(session.Phase() == SenderPhase::Polling);
    BOOST_CHECK(!session.HasPendingRequest());
    BOOST_CHECK_EQUAL(event_log->EventCount(), initial_event_count);
    BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
    BOOST_REQUIRE(session.DiscardPendingRequest());
}

BOOST_AUTO_TEST_CASE(sender_response_save_failure_replays_previous_ready_state)
{
    auto psbt = ParseValidPsbt();
    auto save_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, save_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));

        save_log->FailSave();
        auto result = session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse());
        CheckErrorContains(result, PayjoinErrorCode::Storage, "save failed", "process response save failure");
        BOOST_CHECK_EQUAL(save_log->EventCount(), 1);
        BOOST_CHECK(!save_log->IsClosed());
        CheckNoTransitions(session, "save failure");
    }

    auto replayed = SenderSession::Replay(save_log);
    BOOST_REQUIRE(replayed);
    {
        auto session = std::move(replayed).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        BOOST_REQUIRE(session.DiscardPendingRequest());
    }
}

BOOST_AUTO_TEST_CASE(sender_response_close_failure_replays_closed_state)
{
    auto psbt = ParseValidPsbt();
    auto close_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, close_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));

        close_log->FailClose();
        auto result = session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse());
        CheckErrorContains(result, PayjoinErrorCode::Storage, "close failed", "process response close failure");
        BOOST_CHECK_EQUAL(close_log->EventCount(), 2);
        BOOST_CHECK(!close_log->IsClosed());
        CheckNoTransitions(session, "close failure");
    }

    const auto event_count = close_log->EventCount();
    const auto first_event = close_log->Event(0);
    const auto second_event = close_log->Event(1);
    for (int attempt = 0; attempt < 2; ++attempt) {
        CheckErrorContains(
            SenderSession::Replay(close_log),
            PayjoinErrorCode::Storage,
            "close failed",
            "replay close failure");
        BOOST_CHECK_EQUAL(close_log->EventCount(), event_count);
        BOOST_CHECK_EQUAL(close_log->Event(0), first_event);
        BOOST_CHECK_EQUAL(close_log->Event(1), second_event);
        BOOST_CHECK(!close_log->IsClosed());
    }
    close_log->AllowClose();
    {
        auto replayed = SenderSession::Replay(close_log);
        BOOST_REQUIRE(replayed);
        auto replayed_sender = std::move(replayed).value();
        BOOST_CHECK(replayed_sender.Phase() == SenderPhase::Closed);
        const auto replayed_outcome = replayed_sender.Outcome();
        BOOST_REQUIRE(replayed_outcome);
        BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*replayed_outcome));
        BOOST_CHECK(!std::get<SenderAborted>(*replayed_outcome).diagnostic);
        BOOST_CHECK(!replayed_sender.LastError());
    }
    BOOST_CHECK(close_log->IsClosed());
    BOOST_CHECK_EQUAL(close_log->EventCount(), event_count);
    BOOST_CHECK_EQUAL(close_log->Event(0), first_event);
    BOOST_CHECK_EQUAL(close_log->Event(1), second_event);
    auto replayed_again = SenderSession::Replay(close_log);
    BOOST_REQUIRE(replayed_again);
    BOOST_CHECK(replayed_again->Phase() == SenderPhase::Closed);
    BOOST_CHECK_EQUAL(close_log->EventCount(), event_count);
}

BOOST_AUTO_TEST_CASE(sender_maps_persistence_failures)
{
    auto psbt = ParseValidPsbt();
    auto save_log = std::make_shared<InMemoryEventLog>();
    save_log->FailSave();

    auto save_result = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, save_log);
    CheckErrorContains(save_result, PayjoinErrorCode::Storage, "save failed", "save failure");
    BOOST_CHECK_EQUAL(save_log->EventCount(), 0);

    auto load_log = std::make_shared<InMemoryEventLog>();
    load_log->FailLoad();
    CheckErrorContains(SenderSession::Replay(load_log), PayjoinErrorCode::Storage, "load failed", "load failure");

    auto empty_log = std::make_shared<InMemoryEventLog>();
    CheckError(SenderSession::Replay(empty_log), PayjoinErrorCode::ReplayFailed, "empty log");

    auto corrupted_log = std::make_shared<InMemoryEventLog>();
    corrupted_log->AddEvent("corrupted payjoin event");
    CheckError(SenderSession::Replay(corrupted_log), PayjoinErrorCode::ReplayFailed, "corrupted log");
}

BOOST_AUTO_TEST_CASE(sender_session_owns_event_log)
{
    auto psbt = ParseValidPsbt();

    std::weak_ptr<InMemoryEventLog> created_log;
    {
        auto event_log = std::make_shared<InMemoryEventLog>();
        created_log = event_log;
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        event_log.reset();
        BOOST_CHECK(!created_log.expired());
    }
    BOOST_CHECK(created_log.expired());

    auto replay_log = std::make_shared<InMemoryEventLog>();
    auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, replay_log);
    BOOST_REQUIRE(created);
    {
        auto session = std::move(created).value();
    }

    std::weak_ptr<InMemoryEventLog> replayed_log = replay_log;
    auto replayed = SenderSession::Replay(replay_log);
    BOOST_REQUIRE(replayed);
    replay_log.reset();
    BOOST_CHECK(!replayed_log.expired());
    {
        auto session = std::move(replayed).value();
    }
    BOOST_CHECK(replayed_log.expired());
}

BOOST_AUTO_TEST_CASE(sender_replays_polling_state_and_creates_poll_request)
{
    auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();

    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
        if (!created) BOOST_TEST_MESSAGE(created.error().message);
        BOOST_REQUIRE(static_cast<bool>(created));
        auto session = std::move(created).value();
    }
    BOOST_CHECK_EQUAL(event_log->EventCount(), 1);

    event_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    BOOST_CHECK_EQUAL(event_log->EventCount(), 2);

    auto replayed = SenderSession::Replay(event_log);
    if (!replayed) BOOST_TEST_MESSAGE(replayed.error().message);
    BOOST_REQUIRE(static_cast<bool>(replayed));
    BOOST_CHECK_EQUAL(event_log->CloseCount(), 0);

    std::weak_ptr<InMemoryEventLog> replayed_log = event_log;
    {
        auto session = std::move(replayed).value();
        auto first_request = session.PrepareRequest("https://relay.example");
        if (!first_request) BOOST_TEST_MESSAGE(first_request.error().message);
        BOOST_REQUIRE(static_cast<bool>(first_request));
        BOOST_CHECK(!first_request->url.empty());
        BOOST_CHECK(!first_request->content_type.empty());
        BOOST_CHECK(!first_request->body.empty());
        const auto first_body = first_request->body;

        CheckError(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, "duplicate poll request");
        CheckError(session.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::Transient, "transient poll response");
        BOOST_CHECK(session.Phase() == SenderPhase::Polling);
        BOOST_CHECK(!session.HasPendingRequest());
        BOOST_CHECK_EQUAL(event_log->EventCount(), 2);

        auto second_request = session.PrepareRequest("https://relay.example");
        BOOST_REQUIRE(second_request);
        BOOST_CHECK(!second_request->url.empty());
        BOOST_CHECK(!second_request->content_type.empty());
        BOOST_CHECK(!second_request->body.empty());
        BOOST_CHECK(first_body != second_request->body);
        BOOST_REQUIRE(session.DiscardPendingRequest());
        BOOST_CHECK_EQUAL(event_log->EventCount(), 2);

        event_log.reset();
        BOOST_CHECK(!replayed_log.expired());
    }
    BOOST_CHECK(replayed_log.expired());
}

BOOST_AUTO_TEST_CASE(sender_cancel_yields_fallback)
{
    const auto psbt = ParseValidPsbt();
    const auto expected_fallback = ExtractFallback(psbt);

    auto initial_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, initial_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();

        CheckError(session.DiscardPendingRequest(), PayjoinErrorCode::InvalidState, "discard with no pending request");
        BOOST_REQUIRE(session.Cancel());
        BOOST_CHECK(session.Phase() == SenderPhase::PendingFallback);
        BOOST_CHECK(!session.HasPendingRequest());
        CheckFallbackEquals(session, expected_fallback, "initial cancel fallback");
        BOOST_CHECK_EQUAL(initial_log->EventCount(), 2);
        BOOST_CHECK(initial_log->Event(1) == CANCELLED_EVENT);
        CheckError(session.Cancel(), PayjoinErrorCode::InvalidState, "duplicate cancel");

        BOOST_REQUIRE(session.CloseFallback());
        BOOST_CHECK(session.Phase() == SenderPhase::Closed);
        const auto outcome = session.Outcome();
        BOOST_REQUIRE(outcome);
        BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*outcome));
        const auto& diagnostic = std::get<SenderAborted>(*outcome).diagnostic;
        BOOST_CHECK(!diagnostic);
        BOOST_CHECK(!session.LastError());
        BOOST_CHECK_EQUAL(initial_log->EventCount(), 3);
        BOOST_CHECK(initial_log->Event(2) == CLOSED_ABORTED_EVENT);
        BOOST_CHECK(initial_log->IsClosed());
        CheckError(session.CloseFallback(), PayjoinErrorCode::InvalidState, "duplicate fallback close");
    }
    auto initial_replayed = SenderSession::Replay(initial_log);
    BOOST_REQUIRE(initial_replayed);
    BOOST_CHECK(initial_replayed->Phase() == SenderPhase::Closed);
    CheckFallbackEquals(*initial_replayed, expected_fallback, "replayed initial cancel fallback");

    auto pending_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, pending_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        CheckError(session.Cancel(), PayjoinErrorCode::InvalidState, "cancel with pending request");
        BOOST_REQUIRE(session.DiscardPendingRequest());
        BOOST_REQUIRE(session.Cancel());
        BOOST_CHECK(session.Phase() == SenderPhase::PendingFallback);
        CheckFallbackEquals(session, expected_fallback, "post-discard cancel fallback");
        BOOST_REQUIRE(session.CloseFallback());
    }

    auto polling_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, polling_log);
        BOOST_REQUIRE(created);
    }
    polling_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto polling_replayed = SenderSession::Replay(polling_log);
    BOOST_REQUIRE(polling_replayed);
    {
        auto session = std::move(polling_replayed).value();
        BOOST_CHECK(session.Phase() == SenderPhase::Polling);
        BOOST_REQUIRE(session.Cancel());
        BOOST_CHECK(session.Phase() == SenderPhase::PendingFallback);
        CheckFallbackEquals(session, expected_fallback, "polling cancel fallback");
        BOOST_CHECK(polling_log->Event(2) == CANCELLED_EVENT);
        BOOST_REQUIRE(session.CloseFallback());
        BOOST_CHECK(polling_log->Event(3) == CLOSED_ABORTED_EVENT);
    }
    BOOST_CHECK(polling_log->IsClosed());
}

BOOST_AUTO_TEST_CASE(sender_replays_pending_fallback)
{
    const auto psbt = ParseValidPsbt();
    const auto expected_fallback = ExtractFallback(psbt);
    auto event_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
        BOOST_REQUIRE(created);
    }
    event_log->AddEvent(std::string{CANCELLED_EVENT});

    auto replayed = SenderSession::Replay(event_log);
    BOOST_REQUIRE(replayed);
    auto session = std::move(replayed).value();
    BOOST_CHECK(session.Phase() == SenderPhase::PendingFallback);
    BOOST_CHECK_EQUAL(event_log->CloseCount(), 0);
    CheckFallbackEquals(session, expected_fallback, "replayed pending fallback");
    CheckError(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, "request in pending fallback");
    BOOST_REQUIRE(session.CloseFallback());
    BOOST_CHECK(session.Phase() == SenderPhase::Closed);
    BOOST_CHECK(event_log->IsClosed());
}

BOOST_AUTO_TEST_CASE(sender_replays_closed_success_with_proposal)
{
    const auto psbt = ParseValidPsbt();
    auto event_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
        BOOST_REQUIRE(created);
    }
    event_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    event_log->AddEvent(std::string{CLOSED_SUCCESS_EVENT});

    const auto event_count = event_log->EventCount();
    const auto first_event = event_log->Event(0);
    const auto second_event = event_log->Event(1);
    {
        auto replayed = SenderSession::Replay(event_log);
        if (!replayed) BOOST_TEST_MESSAGE(replayed.error().message);
        BOOST_REQUIRE(replayed);
        auto session = std::move(replayed).value();
        BOOST_CHECK(session.Phase() == SenderPhase::Closed);
        BOOST_CHECK(!session.HasPendingRequest());
        const auto outcome = session.Outcome();
        BOOST_REQUIRE(outcome);
        BOOST_CHECK(std::holds_alternative<SenderProposal>(*outcome));
        const auto last_error = session.LastError();
        BOOST_CHECK(!last_error);
        BOOST_REQUIRE(std::holds_alternative<SenderProposal>(*outcome));
        BOOST_CHECK_EQUAL(
            SerializePsbtForComparison(std::get<SenderProposal>(*outcome).psbt),
            SerializePsbtForComparison(psbt));
        CheckError(session.Cancel(), PayjoinErrorCode::InvalidState, "cancel closed success");
    }
    BOOST_CHECK(event_log->IsClosed());
    BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
    BOOST_CHECK_EQUAL(event_log->Event(0), first_event);
    BOOST_CHECK_EQUAL(event_log->Event(1), second_event);
    BOOST_CHECK_EQUAL(event_log->CloseCount(), 1);
    auto replayed_again = SenderSession::Replay(event_log);
    BOOST_REQUIRE(replayed_again);
    BOOST_CHECK(replayed_again->Phase() == SenderPhase::Closed);
    BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
    BOOST_CHECK_EQUAL(event_log->CloseCount(), 2);
}

BOOST_AUTO_TEST_CASE(sender_replays_closed_success_with_undecodable_proposal)
{
    const auto psbt = ParseValidPsbt();
    const auto expected_fallback = ExtractFallback(psbt);
    auto event_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, event_log);
        BOOST_REQUIRE(created);
    }

    event_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    std::string undecodable_event{CLOSED_SUCCESS_EVENT};
    constexpr std::string_view PSBT_VERSION{"\"version\":0,\"xpub\""};
    const auto psbt_version_pos = undecodable_event.find(PSBT_VERSION);
    BOOST_REQUIRE(psbt_version_pos != std::string::npos);
    BOOST_REQUIRE(undecodable_event.find(PSBT_VERSION, psbt_version_pos + PSBT_VERSION.size()) == std::string::npos);
    undecodable_event.replace(psbt_version_pos, PSBT_VERSION.size(), "\"version\":1,\"xpub\"");
    event_log->AddEvent(std::move(undecodable_event));

    const auto event_count = event_log->EventCount();
    const auto first_event = event_log->Event(0);
    const auto second_event = event_log->Event(1);
    event_log->FailClose();
    for (int attempt = 0; attempt < 2; ++attempt) {
        CheckErrorContains(
            SenderSession::Replay(event_log),
            PayjoinErrorCode::Storage,
            "close failed",
            "undecodable proposal replay close failure");
        BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
        BOOST_CHECK_EQUAL(event_log->Event(0), first_event);
        BOOST_CHECK_EQUAL(event_log->Event(1), second_event);
        BOOST_CHECK(!event_log->IsClosed());
    }
    event_log->AllowClose();
    {
        auto replayed = SenderSession::Replay(event_log);
        if (!replayed) BOOST_TEST_MESSAGE(replayed.error().message);
        BOOST_REQUIRE(replayed);
        auto session = std::move(replayed).value();
        BOOST_CHECK(session.Phase() == SenderPhase::Closed);
        BOOST_CHECK(!session.HasPendingRequest());
        const auto outcome = session.Outcome();
        BOOST_REQUIRE(outcome);
        BOOST_REQUIRE(std::holds_alternative<SenderSuccessWithoutProposal>(*outcome));
        const auto& outcome_error = std::get<SenderSuccessWithoutProposal>(*outcome).error;
        BOOST_REQUIRE(session.LastError());
        BOOST_CHECK(outcome_error.code == session.LastError()->code);
        BOOST_CHECK_EQUAL(outcome_error.message, session.LastError()->message);
        const auto last_error = session.LastError();
        BOOST_REQUIRE(last_error);
        BOOST_CHECK(last_error->code == PayjoinErrorCode::Internal);
        const auto& error_message = last_error->message;
        BOOST_CHECK(error_message.find("base64 chars") != std::string::npos);
        BOOST_CHECK(error_message.find("session log") != std::string::npos);
        BOOST_CHECK(error_message.find("base64=") == std::string::npos);
        BOOST_CHECK(error_message.find("cHNidP") == std::string::npos);
        BOOST_CHECK(error_message.size() < 256);
        CheckFallbackEquals(session, expected_fallback, "undecodable proposal fallback");
        CheckError(session.Cancel(), PayjoinErrorCode::InvalidState, "cancel closed undecodable success");
    }
    BOOST_CHECK(event_log->IsClosed());
    BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
    BOOST_CHECK_EQUAL(event_log->Event(0), first_event);
    BOOST_CHECK_EQUAL(event_log->Event(1), second_event);
    auto replayed_again = SenderSession::Replay(event_log);
    BOOST_REQUIRE(replayed_again);
    BOOST_CHECK(replayed_again->Phase() == SenderPhase::Closed);
    BOOST_CHECK_EQUAL(event_log->EventCount(), event_count);
}

BOOST_AUTO_TEST_CASE(sender_expired_session)
{
    const auto psbt = ParseValidPsbt();
    const auto expected_fallback = ExtractFallback(psbt);

    auto live_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(EXPIRED_URI, psbt, CFeeRate{1000}, live_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        CheckErrorContains(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::Expired, "expired", "expired request");
        BOOST_CHECK(session.Phase() == SenderPhase::Initial);
        BOOST_CHECK(!session.HasPendingRequest());
        CheckFallbackEquals(session, expected_fallback, "expired session fallback");
        BOOST_REQUIRE(session.Cancel());
        BOOST_CHECK(session.Phase() == SenderPhase::PendingFallback);
        BOOST_REQUIRE(session.CloseFallback());
        BOOST_CHECK(session.Phase() == SenderPhase::Closed);
        BOOST_CHECK(live_log->IsClosed());
    }
    auto closed_replayed = SenderSession::Replay(live_log);
    BOOST_REQUIRE(closed_replayed);
    BOOST_CHECK(closed_replayed->Phase() == SenderPhase::Closed);
    CheckFallbackEquals(*closed_replayed, expected_fallback, "replayed closed expired session fallback");

    auto expired_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(EXPIRED_URI, psbt, CFeeRate{1000}, expired_log);
        BOOST_REQUIRE(created);
    }
    CheckError(SenderSession::Replay(expired_log), PayjoinErrorCode::Expired, "replay of open expired session");
    BOOST_CHECK(!expired_log->IsClosed());

    auto cancelled_expired_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(EXPIRED_URI, psbt, CFeeRate{1000}, cancelled_expired_log);
        BOOST_REQUIRE(created);
    }
    cancelled_expired_log->AddEvent(std::string{CANCELLED_EVENT});
    CheckError(SenderSession::Replay(cancelled_expired_log), PayjoinErrorCode::Expired, "replay of canceled expired session");
    BOOST_CHECK(!cancelled_expired_log->IsClosed());
}

BOOST_AUTO_TEST_CASE(sender_fallback_transaction_in_all_phases)
{
    const auto psbt = ParseValidPsbt();
    const auto expected_fallback = ExtractFallback(psbt);

    auto initial_log = std::make_shared<InMemoryEventLog>();
    auto initial_created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, initial_log);
    BOOST_REQUIRE(initial_created);
    auto source = std::move(initial_created).value();
    CheckFallbackEquals(source, expected_fallback, "initial fallback");
    auto destination = std::move(source);
    CheckError(source.FallbackTransaction(), PayjoinErrorCode::InvalidState, "moved-from fallback");
    BOOST_REQUIRE(destination.Cancel());
    BOOST_REQUIRE(destination.CloseFallback());

    auto polling_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, polling_log);
        BOOST_REQUIRE(created);
    }
    polling_log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
    auto polling_replayed = SenderSession::Replay(polling_log);
    BOOST_REQUIRE(polling_replayed);
    auto polling = std::move(polling_replayed).value();
    CheckFallbackEquals(polling, expected_fallback, "polling fallback");

    auto closed_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, closed_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        CheckError(session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse()), PayjoinErrorCode::Fatal, "closed fallback");
        CheckFallbackEquals(session, expected_fallback, "closed fallback transaction");
    }

    auto unusable_log = std::make_shared<InMemoryEventLog>();
    {
        auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, unusable_log);
        BOOST_REQUIRE(created);
        auto session = std::move(created).value();
        BOOST_REQUIRE(session.PrepareRequest("https://relay.example"));
        unusable_log->FailSave();
        CheckError(session.ProcessResponse(CorrectlySizedUndecodableOhttpResponse()), PayjoinErrorCode::Storage, "unusable fallback");
        CheckFallbackEquals(session, expected_fallback, "unusable fallback transaction");
    }
}

BOOST_AUTO_TEST_CASE(sender_replay_failure_side_effects)
{
    const auto psbt = ParseValidPsbt();
    auto source = std::make_shared<InMemoryEventLog>();
    {
        BOOST_REQUIRE(SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, source));
    }
    const auto created = source->Event(0);
    const std::vector<std::vector<std::string>> sequences{
        {}, {std::string{POSTED_ORIGINAL_PSBT_EVENT}}, {created, created}};
    for (const auto& events : sequences) {
        for (bool fail_close : {false, true}) {
            auto log = std::make_shared<InMemoryEventLog>();
            for (const auto& event : events)
                log->AddEvent(event);
            if (fail_close) log->FailClose();
            auto result = SenderSession::Replay(log);
            CheckError(result, fail_close ? PayjoinErrorCode::Storage : PayjoinErrorCode::ReplayFailed, "invalid sequence");
            if (fail_close) CheckErrorContains(result, PayjoinErrorCode::Storage, "close failed", "close callback");
            BOOST_CHECK_EQUAL(log->LoadCount(), 1);
            BOOST_CHECK_EQUAL(log->SaveCount(), 0);
            BOOST_CHECK_EQUAL(log->CloseCount(), 1);
            BOOST_CHECK_EQUAL(log->IsClosed(), !fail_close);
            BOOST_REQUIRE_EQUAL(log->EventCount(), events.size());
            for (std::size_t i = 0; i < events.size(); ++i)
                BOOST_CHECK_EQUAL(log->Event(i), events[i]);
            if (events.empty() && !fail_close) {
                CheckErrorContains(SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, log),
                                   PayjoinErrorCode::Storage, "event log is closed", "reuse closed empty log");
                BOOST_CHECK_EQUAL(log->EventCount(), 0);
                BOOST_CHECK_EQUAL(log->SaveCount(), 1);
                BOOST_CHECK_EQUAL(log->CloseCount(), 1);
            }
        }
    }
    auto malformed = std::make_shared<InMemoryEventLog>();
    malformed->AddEvent("{invalid json");
    CheckError(SenderSession::Replay(malformed), PayjoinErrorCode::ReplayFailed, "malformed JSON");
    BOOST_CHECK_EQUAL(malformed->CloseCount(), 0);
    BOOST_CHECK_EQUAL(malformed->LoadCount(), 1);
    BOOST_CHECK_EQUAL(malformed->SaveCount(), 0);
    BOOST_CHECK(!malformed->IsClosed());
    BOOST_REQUIRE_EQUAL(malformed->EventCount(), 1);
    BOOST_CHECK_EQUAL(malformed->Event(0), "{invalid json");
    const auto loads = source->LoadCount();
    const auto saves = source->SaveCount();
    BOOST_REQUIRE(SenderSession::Replay(source));
    BOOST_CHECK_EQUAL(source->LoadCount(), loads + 1);
    BOOST_CHECK_EQUAL(source->SaveCount(), saves);
    BOOST_CHECK_EQUAL(source->CloseCount(), 0);
    BOOST_CHECK(!source->IsClosed());
    BOOST_REQUIRE_EQUAL(source->EventCount(), 1);
    BOOST_CHECK_EQUAL(source->Event(0), created);
}

BOOST_AUTO_TEST_CASE(sender_checks_relay_scheme_without_changing_state)
{
    const auto psbt = ParseValidPsbt();
    const auto fallback = ExtractFallback(psbt);
    for (const auto phase : {SenderPhase::Initial, SenderPhase::Polling}) {
        auto log = std::make_shared<InMemoryEventLog>();
        {
            BOOST_REQUIRE(SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, log));
        }
        if (phase == SenderPhase::Polling) log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
        auto session = SenderSession::Replay(log);
        BOOST_REQUIRE(session);
        const auto events = log->Load().value();
        const auto saves = log->SaveCount();
        for (const auto& [relay, code] : std::vector<std::pair<std::string, PayjoinErrorCode>>{
                 {"", PayjoinErrorCode::InvalidUri},
                 {"not a url", PayjoinErrorCode::InvalidUri},
                 {"ftp://relay.example", PayjoinErrorCode::InvalidUri},
                 {"httpsx://relay.example", PayjoinErrorCode::InvalidUri},
                 {"https://", PayjoinErrorCode::Internal},
                 {"https:///missing-host", PayjoinErrorCode::Internal}}) {
            auto rejected = session->PrepareRequest(relay);
            CheckError(rejected, code, "invalid relay");
            if (code == PayjoinErrorCode::InvalidUri) {
                BOOST_CHECK_EQUAL(rejected.error().message, "Payjoin relay URL must use HTTP or HTTPS");
            }
            BOOST_CHECK(session->Phase() == phase);
            BOOST_CHECK(!session->Outcome());
            BOOST_CHECK(!session->LastError());
            BOOST_CHECK(!session->HasPendingRequest());
            CheckFallbackEquals(*session, fallback, "invalid relay");
            BOOST_CHECK_EQUAL(log->SaveCount(), saves);
            BOOST_CHECK_EQUAL(log->CloseCount(), 0);
            BOOST_CHECK(!log->IsClosed());
            BOOST_REQUIRE_EQUAL(log->EventCount(), events.size());
            for (std::size_t i = 0; i < events.size(); ++i)
                BOOST_CHECK_EQUAL(log->Event(i), events[i]);
            BOOST_REQUIRE(session->PrepareRequest("https://relay.example"));
            CheckError(session->PrepareRequest("not a url"), PayjoinErrorCode::InvalidState, "pending wins over relay");
            BOOST_REQUIRE(session->DiscardPendingRequest());
        }
        for (const auto& [relay, expected_authority] : std::vector<std::pair<std::string, std::string>>{
                 {"http://relay.example", "relay.example"},
                 {"https://relay.example", "relay.example"},
                 {"hTtP://relay.example", "relay.example"},
                 {"hTtPs://relay.example", "relay.example"},
                 {"http://relay.example:8080/path?q=1", "relay.example:8080"},
                 {"https://[::1]:8443/path?q=1", "[0:0:0:0:0:0:0:1]:8443"}}) {
            auto request = session->PrepareRequest(relay);
            BOOST_REQUIRE(request);
            const auto start = request->url.find("://");
            BOOST_REQUIRE(start != std::string::npos);
            const auto end = request->url.find_first_of("/?#", start + 3);
            BOOST_CHECK_EQUAL(request->url.substr(start + 3, end - (start + 3)), expected_authority);
            BOOST_REQUIRE(session->DiscardPendingRequest());
        }
        BOOST_REQUIRE(session->Cancel());
        CheckError(session->PrepareRequest("not a url"), PayjoinErrorCode::InvalidState, "cancelled wins over relay");
        BOOST_REQUIRE(session->CloseFallback());
        CheckError(session->PrepareRequest("not a url"), PayjoinErrorCode::InvalidState, "closed wins over relay");
    }
}

BOOST_AUTO_TEST_CASE(sender_cancel_and_close_fallback_storage_failures)
{
    using FailureMode = InMemoryEventLog::FailureMode;
    enum class FailurePoint { CancelInitial,
                              CancelPolling,
                              SaveClosed,
                              CloseJournal };
    const auto psbt = ParseValidPsbt();
    const auto fallback = ExtractFallback(psbt);
    for (const auto point : {FailurePoint::CancelInitial, FailurePoint::CancelPolling, FailurePoint::SaveClosed, FailurePoint::CloseJournal}) {
        for (const auto mode : {FailureMode::ReturnBefore, FailureMode::ReturnAfter, FailureMode::ThrowBefore, FailureMode::ThrowAfter, FailureMode::UnknownBefore}) {
            BOOST_TEST_CONTEXT("failure point " << static_cast<int>(point) << ", mode " << static_cast<int>(mode))
            {
                const bool after = mode == FailureMode::ReturnAfter || mode == FailureMode::ThrowAfter;
                const bool cancel = point == FailurePoint::CancelInitial || point == FailurePoint::CancelPolling;
                const bool close_callback = point == FailurePoint::CloseJournal;
                auto log = std::make_shared<InMemoryEventLog>();
                {
                    BOOST_REQUIRE(SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, log));
                }
                if (point == FailurePoint::CancelPolling) log->AddEvent(std::string{POSTED_ORIGINAL_PSBT_EVENT});
                std::vector<std::string> prefix;
                std::vector<std::string> persisted;
                {
                    auto session = SenderSession::Replay(log);
                    BOOST_REQUIRE(session);
                    if (!cancel) BOOST_REQUIRE(session->Cancel());
                    prefix = log->Load().value();
                    const auto saves = log->SaveCount();
                    const auto closes = log->CloseCount();
                    if (close_callback)
                        log->FailClose(mode);
                    else
                        log->FailSave(mode);
                    auto result = cancel ? session->Cancel() : session->CloseFallback();
                    CheckError(result, PayjoinErrorCode::Storage, "transition callback failure");
                    BOOST_CHECK(!session->Outcome());
                    const std::string operation = close_callback ? "close" : "save";
                    const std::string reason = mode == FailureMode::UnknownBefore ? "unknown exception" : operation + " failed";
                    BOOST_CHECK_EQUAL(result.error().message, "Payjoin event log " + operation + " failed: " + reason);
                    BOOST_REQUIRE(session->LastError());
                    BOOST_CHECK(session->LastError()->code == PayjoinErrorCode::Storage);
                    BOOST_CHECK_EQUAL(session->LastError()->message, result.error().message);
                    BOOST_CHECK(session->Phase() == SenderPhase::Unusable);
                    BOOST_CHECK(!session->HasPendingRequest());
                    CheckFallbackEquals(*session, fallback, "failed transition");
                    BOOST_CHECK(session->FallbackTransaction().value()->GetWitnessHash() == fallback->GetWitnessHash());
                    CheckNoTransitions(*session, "failed transition");
                    BOOST_CHECK_EQUAL(log->SaveCount(), saves + 1);
                    BOOST_CHECK_EQUAL(log->CloseCount(), closes + (close_callback ? 1 : 0));
                    BOOST_CHECK_EQUAL(log->IsClosed(), close_callback && after);
                    persisted = log->Load().value();
                    BOOST_REQUIRE_EQUAL(persisted.size(), prefix.size() + ((after || close_callback) ? 1 : 0));
                    for (std::size_t i = 0; i < prefix.size(); ++i)
                        BOOST_CHECK_EQUAL(persisted[i], prefix[i]);
                    if (persisted.size() > prefix.size()) {
                        BOOST_CHECK_EQUAL(persisted.back(), cancel ? CANCELLED_EVENT : CLOSED_ABORTED_EVENT);
                    }
                }
                log->AllowSave();
                log->AllowClose();
                const auto saves = log->SaveCount();
                const auto closes = log->CloseCount();
                const auto expected_phase = cancel ? (after ? SenderPhase::PendingFallback :
                                                              (point == FailurePoint::CancelInitial ? SenderPhase::Initial : SenderPhase::Polling)) :
                                                     ((after || close_callback) ? SenderPhase::Closed : SenderPhase::PendingFallback);
                // Replaying twice checks claim release and idempotent terminal closure.
                for (std::size_t replay = 0; replay < 2; ++replay) {
                    auto session = SenderSession::Replay(log);
                    BOOST_REQUIRE(session);
                    BOOST_CHECK(session->Phase() == expected_phase);
                    const auto outcome = session->Outcome();
                    if (expected_phase == SenderPhase::Closed) {
                        BOOST_REQUIRE(outcome);
                        BOOST_REQUIRE(std::holds_alternative<SenderAborted>(*outcome));
                        BOOST_CHECK(!std::get<SenderAborted>(*outcome).diagnostic);
                    } else {
                        BOOST_CHECK(!outcome);
                    }
                    BOOST_CHECK(!session->LastError());
                    BOOST_CHECK(!session->HasPendingRequest());
                    CheckFallbackEquals(*session, fallback, "recovered transition");
                    BOOST_CHECK(session->FallbackTransaction().value()->GetWitnessHash() == fallback->GetWitnessHash());
                    BOOST_CHECK_EQUAL(log->SaveCount(), saves);
                    BOOST_CHECK_EQUAL(log->CloseCount(), closes + (expected_phase == SenderPhase::Closed ? replay + 1 : 0));
                    BOOST_CHECK_EQUAL(log->IsClosed(), expected_phase == SenderPhase::Closed);
                    BOOST_REQUIRE_EQUAL(log->EventCount(), persisted.size());
                    for (std::size_t i = 0; i < persisted.size(); ++i)
                        BOOST_CHECK_EQUAL(log->Event(i), persisted[i]);
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_closed_session_retains_event_log_claim)
{
    auto log = std::make_shared<InMemoryEventLog>();
    {
        auto session = SenderSession::Create(VALID_URI, ParseValidPsbt(), CFeeRate{1000}, log);
        BOOST_REQUIRE(session);
        BOOST_REQUIRE(session->Cancel());
        BOOST_REQUIRE(session->CloseFallback());
        BOOST_CHECK(session->Phase() == SenderPhase::Closed);
        BOOST_CHECK(log->IsClosed());
        const auto saves = log->SaveCount();
        const auto loads = log->LoadCount();
        const auto closes = log->CloseCount();
        CheckError(SenderSession::Replay(log), PayjoinErrorCode::InvalidState, "closed session retains claim");
        BOOST_CHECK_EQUAL(log->SaveCount(), saves);
        BOOST_CHECK_EQUAL(log->LoadCount(), loads);
        BOOST_CHECK_EQUAL(log->CloseCount(), closes);
    }
    auto replayed = SenderSession::Replay(log);
    BOOST_REQUIRE(replayed);
    BOOST_CHECK(replayed->Phase() == SenderPhase::Closed);
}

BOOST_AUTO_TEST_CASE(sender_unusable_session_retains_event_log_claim)
{
    auto log = std::make_shared<InMemoryEventLog>();
    {
        auto session = SenderSession::Create(VALID_URI, ParseValidPsbt(), CFeeRate{1000}, log);
        BOOST_REQUIRE(session);
        log->FailSave();
        CheckError(session->Cancel(), PayjoinErrorCode::Storage, "cancel save failure");
        BOOST_CHECK(session->Phase() == SenderPhase::Unusable);
        log->AllowSave();
        const auto saves = log->SaveCount();
        const auto loads = log->LoadCount();
        const auto closes = log->CloseCount();
        CheckError(SenderSession::Replay(log), PayjoinErrorCode::InvalidState, "unusable session retains claim");
        BOOST_CHECK_EQUAL(log->SaveCount(), saves);
        BOOST_CHECK_EQUAL(log->LoadCount(), loads);
        BOOST_CHECK_EQUAL(log->CloseCount(), closes);
    }
    auto replayed = SenderSession::Replay(log);
    BOOST_REQUIRE(replayed);
    BOOST_CHECK(replayed->Phase() == SenderPhase::Initial);
}

BOOST_AUTO_TEST_CASE(sender_create_failure_after_save_replays_created_session)
{
    using FailureMode = InMemoryEventLog::FailureMode;
    const auto psbt = ParseValidPsbt();
    const auto expected_fallback = ExtractFallback(psbt);
    BOOST_REQUIRE(expected_fallback->HasWitness());
    for (const auto mode : {FailureMode::ReturnAfter, FailureMode::ThrowAfter}) {
        BOOST_TEST_CONTEXT("failure mode " << static_cast<int>(mode))
        {
            auto log = std::make_shared<InMemoryEventLog>();
            log->FailSave(mode);
            auto created = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, log);
            CheckErrorContains(created, PayjoinErrorCode::Storage, "save failed", "create after saved event");
            BOOST_REQUIRE_EQUAL(log->EventCount(), 1);
            const auto event = log->Event(0);
            BOOST_CHECK(event.starts_with("{\"Created\":"));
            BOOST_CHECK_EQUAL(log->SaveCount(), 1);
            BOOST_CHECK_EQUAL(log->CloseCount(), 0);
            BOOST_CHECK(!log->IsClosed());

            log->AllowSave();
            auto retried = SenderSession::Create(VALID_URI, psbt, CFeeRate{1000}, log);
            CheckErrorContains(retried, PayjoinErrorCode::InvalidState, "not empty", "retry create with saved event");
            BOOST_REQUIRE_EQUAL(log->EventCount(), 1);
            BOOST_CHECK_EQUAL(log->Event(0), event);
            BOOST_CHECK_EQUAL(log->SaveCount(), 1);
            BOOST_CHECK_EQUAL(log->CloseCount(), 0);

            auto replayed = SenderSession::Replay(log);
            BOOST_REQUIRE(replayed);
            BOOST_CHECK(replayed->Phase() == SenderPhase::Initial);
            BOOST_CHECK(!replayed->HasPendingRequest());
            BOOST_CHECK(!replayed->Outcome());
            BOOST_CHECK(!replayed->LastError());
            CheckFallbackEquals(*replayed, expected_fallback, "replay after failed create");
            BOOST_CHECK(replayed->FallbackTransaction().value()->GetWitnessHash() == expected_fallback->GetWitnessHash());
            BOOST_REQUIRE_EQUAL(log->EventCount(), 1);
            BOOST_CHECK_EQUAL(log->Event(0), event);
            BOOST_CHECK_EQUAL(log->SaveCount(), 1);
            BOOST_CHECK_EQUAL(log->CloseCount(), 0);
            BOOST_CHECK(!log->IsClosed());
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet::payjoin
