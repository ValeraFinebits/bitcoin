// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <payjoin/client.h>
#include <policy/feerate.h>
#include <psbt.h>
#include <util/expected.h>

#include <boost/test/unit_test.hpp>

#include <barrier>
#include <cstddef>
#include <future>
#include <memory>
#include <mutex>
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

static_assert(!std::is_copy_constructible_v<SenderSession>);
static_assert(std::is_move_constructible_v<SenderSession>);
static_assert(!std::is_copy_assignable_v<SenderSession>);
static_assert(std::is_move_assignable_v<SenderSession>);

class InMemoryEventLog final : public SenderEventLog
{
public:
    util::Expected<void, std::string> Save(std::string event) override
    {
        std::lock_guard lock{m_mutex};
        ++m_save_count;
        if (m_fail_save) return util::Unexpected<std::string>{"save failed"};
        m_events.push_back(std::move(event));
        return {};
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
        if (m_fail_close) return util::Unexpected<std::string>{"close failed"};
        m_closed = true;
        return {};
    }

    void FailSave()
    {
        std::lock_guard lock{m_mutex};
        m_fail_save = true;
    }
    void AllowSave()
    {
        std::lock_guard lock{m_mutex};
        m_fail_save = false;
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
    void FailClose()
    {
        std::lock_guard lock{m_mutex};
        m_fail_close = true;
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
    mutable std::mutex m_mutex;
    std::vector<std::string> m_events;
    std::size_t m_save_count{0};
    std::size_t m_load_count{0};
    std::size_t m_close_count{0};
    bool m_fail_save{false};
    bool m_fail_load{false};
    bool m_fail_close{false};
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
        BOOST_REQUIRE(psbt_v2.inputs[index].Merge(psbt_v0.inputs[index]));
        psbt_v2.inputs[index].sighash_type = psbt_v0.inputs[index].sighash_type;
    }
    for (std::size_t index = 0; index < psbt_v0.outputs.size(); ++index) {
        BOOST_REQUIRE(psbt_v2.outputs[index].Merge(psbt_v0.outputs[index]));
    }
    return psbt_v2;
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

void CheckUnusable(SenderSession& session, std::string_view label)
{
    const std::string prefix{label};
    CheckError(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, prefix + " prepare");
    CheckError(session.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::InvalidState, prefix + " response");
    CheckError(session.DiscardPendingRequest(), PayjoinErrorCode::InvalidState, prefix + " discard");
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

BOOST_AUTO_TEST_CASE(sender_rejects_unrepresentable_psbt_v2_fields)
{
    auto psbt_v2 = MakeEquivalentPsbtV2(ParseValidPsbt());
    psbt_v2.m_tx_modifiable.emplace();

    auto event_log = std::make_shared<InMemoryEventLog>();
    CheckErrorContains(
        SenderSession::Create(VALID_URI, psbt_v2, CFeeRate{1000}, event_log),
        PayjoinErrorCode::InvalidSenderInput,
        "modifiable",
        "PSBTv2 transaction modifiable flags");
    BOOST_CHECK_EQUAL(event_log->EventCount(), 0);
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

    CheckError(source.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, "moved-from prepare");
    CheckError(source.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::InvalidState, "moved-from response");
    CheckError(source.DiscardPendingRequest(), PayjoinErrorCode::InvalidState, "moved-from discard");
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

        CheckError(fatal_sender.ProcessResponse(CorrectlySizedUndecodableOhttpResponse()), PayjoinErrorCode::Fatal, "fatal response");
        BOOST_CHECK_EQUAL(fatal_log->EventCount(), 2);
        BOOST_CHECK(fatal_log->IsClosed());
        CheckUnusable(fatal_sender, "fatal response");
    }
    CheckError(SenderSession::Replay(fatal_log), PayjoinErrorCode::InvalidState, "replay closed session");
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
        CheckUnusable(session, "save failure");
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
        CheckUnusable(session, "close failure");
    }

    CheckError(SenderSession::Replay(close_log), PayjoinErrorCode::InvalidState, "replay closed event");
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
        CheckError(session.ProcessResponse(UndersizedOhttpResponse()), PayjoinErrorCode::InvalidState, "unsupported poll response");
        CheckError(session.PrepareRequest("https://relay.example"), PayjoinErrorCode::InvalidState, "poll request remains pending");
        BOOST_CHECK_EQUAL(event_log->EventCount(), 2);

        BOOST_REQUIRE(session.DiscardPendingRequest());
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

BOOST_AUTO_TEST_SUITE_END()

} // namespace
} // namespace wallet::payjoin
