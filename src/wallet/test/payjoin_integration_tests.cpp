// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chain.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <node/types.h>
#include <payjoin.hpp>
#include <payjoin/client.h>
#include <payjoin/http_transport.h>
#include <payjoin/transport.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <pubkey.h>
#include <scheduler.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>
#include <util/btcsignals.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <validation.h>
#include <wallet/db.h>
#include <wallet/payjoin/sender.h>
#include <wallet/scan.h>
#include <wallet/test/payjoin_sender_fixture.h>
#include <wallet/test/payjoin_test_transport.h>
#include <wallet/test/util.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace wallet::payjoin {
using namespace test;

namespace {
size_t CountEvent(const std::vector<std::string>& events, const std::string& name)
{
    return std::count_if(events.begin(), events.end(), [&name](const auto& event) {
        UniValue value;
        BOOST_REQUIRE(value.read(event));
        return value.isObject() && value.exists(name);
    });
}

class ForwardingTransport final : public ControlledTransport
{
    std::unique_ptr<HttpSenderTransport> m_http;

public:
    void Cancel(uint64_t id) override
    {
        ControlledTransport::Cancel(id);
        if (m_http) m_http->Cancel(id);
    }

    void Stop() override
    {
        if (m_http) m_http->Stop();
        ControlledTransport::Stop();
    }

    struct Captured {
        uint64_t id;
        Completion complete;
        TransportResult result;
    };

    size_t m_forwarded{0};

    Captured Capture()
    {
        BOOST_REQUIRE(!m_pending.empty());

        auto request = std::move(m_pending.front());
        m_pending.pop_front();
        const auto remaining = request.timeout - std::chrono::duration_cast<std::chrono::milliseconds>(
                                                     std::chrono::steady_clock::now() - request.accepted_at);
        if (m_stopped || std::find(m_cancelled.begin(), m_cancelled.end(), request.id) != m_cancelled.end() || remaining <= std::chrono::milliseconds::zero()) {
            return {request.id, std::move(request.complete), {Delivery::NotSent, {}, "held request expired"}};
        }

        if (!m_http) m_http = std::make_unique<HttpSenderTransport>();
        auto promise = std::make_shared<std::promise<TransportResult>>();
        auto result = promise->get_future();
        BOOST_REQUIRE(m_http->Submit(request.id, std::move(request.request), remaining,
                                     [promise](TransportResult response) { promise->set_value(std::move(response)); }) == SubmitResult::Accepted);
        ++m_forwarded;

        BOOST_REQUIRE_MESSAGE(result.wait_for(std::min(remaining, std::chrono::milliseconds{20000})) == std::future_status::ready,
                              "real HTTP completion did not arrive before the test deadline");
        return {request.id, std::move(request.complete), result.get()};
    }
};

class ReceiverLog final : public ::payjoin::JsonReceiverSessionPersister
{
    std::vector<std::string> m_events;

public:
    void save(const std::string& event) override { m_events.push_back(event); }

    std::vector<std::string> load() override { return m_events; }

    void close() override {}
};

class BroadcastCheck final : public ::payjoin::CanBroadcast
{
    ChainstateManager& m_chainman;

public:
    explicit BroadcastCheck(ChainstateManager& chainman) : m_chainman{chainman} {}

    bool callback(const std::vector<uint8_t>& bytes) override
    {
        DataStream stream{bytes};
        CTransactionRef tx;
        stream >> TX_WITH_WITNESS(tx);
        LOCK(cs_main);
        return m_chainman.ProcessTransaction(tx, true).m_result_type == MempoolAcceptResult::ResultType::VALID;
    }
};

class InputNotOwned final : public ::payjoin::IsInputOwned
{
    CWallet& m_wallet;

public:
    explicit InputNotOwned(CWallet& wallet) : m_wallet{wallet} {}

    bool callback(const ::payjoin::OutPoint& out) override
    {
        LOCK(m_wallet.cs_wallet);
        return m_wallet.IsMine(COutPoint{Txid::FromUint256(*uint256::FromHex(out.txid)), out.vout});
    }
};

class NotSeen final : public ::payjoin::IsOutputKnown
{
public:
    bool callback(const ::payjoin::OutPoint&) override { return false; }
};

class ScriptOwned final : public ::payjoin::IsScriptOwned
{
    CWallet& m_wallet;

public:
    explicit ScriptOwned(CWallet& wallet) : m_wallet{wallet} {}

    bool callback(const std::vector<uint8_t>& bytes) override
    {
        LOCK(m_wallet.cs_wallet);
        return m_wallet.IsMine(CScript{bytes.begin(), bytes.end()});
    }
};

class ReceiverSign final : public ::payjoin::ProcessPsbt
{
    CWallet& m_wallet;
    bool m_expect_complete;

public:
    std::optional<PartiallySignedTransaction> m_signed_psbt;
    std::optional<COutPoint> m_keep_only;
    std::function<void(PartiallySignedTransaction&)> m_modify_psbt;

    explicit ReceiverSign(CWallet& wallet, bool expect_complete = false) : m_wallet{wallet}, m_expect_complete{expect_complete} {}

    std::string callback(const std::string& encoded) override
    {
        auto psbt = DecodeBase64PSBT(encoded);
        BOOST_REQUIRE(psbt);
        const auto unsigned_inputs = psbt->inputs;
        LOCK(m_wallet.cs_wallet);
        bool complete{false};
        BOOST_REQUIRE(!m_wallet.FillPSBT(*psbt, {}, complete));
        BOOST_CHECK_EQUAL(complete, m_expect_complete);

        if (m_keep_only) {
            const auto tx = psbt->GetUnsignedTx();
            BOOST_REQUIRE(tx);
            for (size_t i = 0; i < tx->vin.size(); ++i) {
                if (tx->vin[i].prevout != *m_keep_only) psbt->inputs[i] = unsigned_inputs[i];
            }
        }

        if (m_modify_psbt) m_modify_psbt(*psbt);
        m_signed_psbt = *psbt;
        DataStream stream;
        stream << *psbt;
        return EncodeBase64(stream);
    }
};

TransportResult Post(HttpSenderTransport& http, const SenderRequest& request,
                     std::chrono::milliseconds timeout = std::chrono::seconds{10}, bool cancel = false)
{
    static uint64_t sequence{100000};
    const auto id = ++sequence;
    auto promise = std::make_shared<std::promise<TransportResult>>();
    auto result = promise->get_future();
    BOOST_REQUIRE(http.Submit(id, request, timeout, [promise](TransportResult response) { promise->set_value(std::move(response)); }) == SubmitResult::Accepted);
    if (cancel) http.Cancel(id);
    BOOST_REQUIRE(result.wait_for(std::chrono::seconds{15}) == std::future_status::ready);
    return result.get();
}

std::string Certificate(const std::vector<unsigned char>& bytes, const fs::path& directory)
{
    const auto path = directory / "payjoin-test-ca.pem";
    std::ofstream file{fs::PathToString(path)};
    const auto base64 = EncodeBase64(bytes);
    file << "-----BEGIN CERTIFICATE-----\n";
    for (size_t i = 0; i < base64.size(); i += 64) {
        file << base64.substr(i, 64) << '\n';
    }
    file << "-----END CERTIFICATE-----\n";
    file.close();
    BOOST_REQUIRE(file.good());
    return fs::PathToString(path);
}

std::unique_ptr<SenderTransport> MakeSenderTransport(SenderFixture::Execution execution)
{
    if (execution == SenderFixture::Execution::Controlled) return std::make_unique<ForwardingTransport>();
    return std::make_unique<HttpSenderTransport>();
}

struct IntegrationFixture : SenderFixture {
    ForwardingTransport& Forwarder()
    {
        BOOST_REQUIRE(m_transport);
        return static_cast<ForwardingTransport&>(*m_transport);
    }

    std::shared_ptr<ReceiverLog> m_log{std::make_shared<ReceiverLog>()};
    std::shared_ptr<::payjoin::TestServices> m_services{::payjoin::TestServices::initialize()};
    std::shared_ptr<::payjoin::Initialized> m_receive_session;
    HttpSenderTransport m_receiver_http;

    explicit IntegrationFixture(Execution execution = Execution::Controlled)
        : SenderFixture{execution, MakeSenderTransport(execution)}
    {
        m_services->wait_for_services_ready();
        m_relay = m_services->ohttp_relay_url();
        ResetReceiver();
    }

    ~IntegrationFixture() { Shutdown(); }

    void ResetReceiver()
    {
        m_log = std::make_shared<ReceiverLog>();
        m_receive_session = ::payjoin::ReceiverBuilder::init(
                                EncodeDestination(WitnessV0KeyHash{m_receiver_key.GetPubKey()}),
                                m_services->directory_url(), m_services->fetch_ohttp_keys())
                                ->build()
                                ->save(m_log);
        m_uri = m_receive_session->pj_uri()->set_amount_sats(COIN)->as_string();
    }

    void Deliver()
    {
        auto held = Forwarder().Capture();
        BOOST_REQUIRE_MESSAGE(held.result.delivery == Delivery::Response, held.result.diagnostic);
        held.complete(held.result);
        Flush();
    }

    std::shared_ptr<::payjoin::UncheckedOriginalPayload> ReceiverOriginal()
    {
        const auto deadline = SenderService::Clock::now() + std::chrono::seconds{20};
        do {
            auto poll = m_receive_session->create_poll_request(m_relay);
            auto response = Post(m_receiver_http, {poll.request->url, poll.request->content_type, poll.request->body});
            BOOST_REQUIRE_MESSAGE(response.delivery == Delivery::Response, response.diagnostic);
            auto outcome = m_receive_session->process_response(response.body, poll.client_response)->save(m_log);
            if (const auto* progress = std::get_if<::payjoin::InitializedTransitionOutcome::kProgress>(&outcome.get_variant())) {
                return progress->inner;
            }
        } while (SenderService::Clock::now() < deadline);
        BOOST_FAIL("receiver did not observe original before deadline");
        return nullptr;
    }

    auto BuildProposal(const std::shared_ptr<::payjoin::UncheckedOriginalPayload>& unchecked,
                       std::function<void(PartiallySignedTransaction&)> modify_psbt = {})
    {
        auto owned = unchecked->check_broadcast_suitability(std::nullopt, std::make_shared<BroadcastCheck>(*m_node.chainman))->save(m_log);
        auto seen = owned->check_inputs_not_owned(std::make_shared<InputNotOwned>(*m_receiver))->save(m_log);
        auto outputs = seen->check_no_inputs_seen_before(std::make_shared<NotSeen>())->save(m_log);
        auto wants_outputs = outputs->identify_receiver_outputs(std::make_shared<ScriptOwned>(*m_receiver))->save(m_log);
        auto inputs = wants_outputs->commit_outputs()->save(m_log);

        const auto coin = m_receiver_input_override ? m_receiver_input_override : m_receiver_coin;
        const auto& utxo = coin->vout[0];
        ::payjoin::TxIn input{std::make_shared<::payjoin::OutPoint>(::payjoin::OutPoint{coin->GetHash().ToString(), 0}), {}, 0xfffffffe, {}};
        ::payjoin::PsbtInput psbt_input{std::make_shared<::payjoin::TxOut>(::payjoin::TxOut{static_cast<uint64_t>(utxo.nValue), {utxo.scriptPubKey.begin(), utxo.scriptPubKey.end()}}), std::nullopt, std::nullopt};
        auto fees = inputs->contribute_inputs({::payjoin::InputPair::init(input, psbt_input, std::nullopt)})->commit_inputs()->save(m_log);
        auto provisional = fees->apply_fee_range(1, 10)->save(m_log);

        auto signer = std::make_shared<ReceiverSign>(m_receiver_input_override ? *m_sender : *m_receiver, bool(m_receiver_input_override));
        if (m_receiver_input_override) signer->m_keep_only = COutPoint{coin->GetHash(), 0};
        signer->m_modify_psbt = std::move(modify_psbt);
        auto proposal = provisional->finalize_proposal(signer)->save(m_log);
        BOOST_REQUIRE(signer->m_signed_psbt);
        return std::pair{proposal, *signer->m_signed_psbt};
    }

    PartiallySignedTransaction SendProposal(const std::shared_ptr<::payjoin::UncheckedOriginalPayload>& original,
                                            std::function<void(PartiallySignedTransaction&)> modify_psbt = {}, bool corrupt_response = false)
    {
        auto [proposal, signed_psbt] = BuildProposal(original, std::move(modify_psbt));
        auto post = proposal->create_post_request(m_relay);
        auto response = Post(m_receiver_http, {post.request->url, post.request->content_type, post.request->body});
        BOOST_REQUIRE_MESSAGE(response.delivery == Delivery::Response, response.diagnostic);
        const auto posted = CountEvent(m_log->load(), "PostedPayjoinProposal");
        if (corrupt_response) response.body.clear();
        auto monitor = proposal->process_response(response.body, post.client_response)->save(m_log);
        BOOST_REQUIRE(monitor);
        BOOST_CHECK_EQUAL(CountEvent(m_log->load(), "PostedPayjoinProposal"), posted + 1);
        return signed_psbt;
    }

    PartiallySignedTransaction Proposal(std::function<void(PartiallySignedTransaction&)> modify_psbt = {})
    {
        return SendProposal(ReceiverOriginal(), std::move(modify_psbt));
    }
};

struct AsyncIntegrationFixture : IntegrationFixture {
    AsyncIntegrationFixture() : IntegrationFixture{Execution::Asynchronous} {}

    PaymentSnapshot QueueSnapshot(const uint256& id)
    {
        auto promise = std::make_shared<std::promise<std::optional<PaymentSnapshot>>>();
        auto result = promise->get_future();
        m_queue->insert([this, id, promise] { promise->set_value(m_service->Snapshot(id)); });
        BOOST_REQUIRE(result.wait_for(std::chrono::seconds{20}) == std::future_status::ready);
        auto view = result.get();
        BOOST_REQUIRE(view);
        return *view;
    }

    void WaitForTimer(std::chrono::milliseconds delay)
    {
        auto promise = std::make_shared<std::promise<void>>();
        auto result = promise->get_future();
        m_scheduler.scheduleFromNow(
            [this, promise] {
                m_queue->insert([promise] { promise->set_value(); });
            },
            delay);
        BOOST_REQUIRE(result.wait_for(std::chrono::seconds{20}) == std::future_status::ready);
    }

    void CheckReservations(const uint256& id, const PaymentSnapshot& view)
    {
        BOOST_REQUIRE(view.original);
        BOOST_CHECK(view.original_saved);
        BOOST_CHECK(view.disclosure_saved);
        BOOST_CHECK(view.possibly_exposed);
        BOOST_CHECK(view.owns_inputs);

        LOCK(m_sender->cs_wallet);
        const auto stored = ReadStoredPayment(id);
        BOOST_CHECK(stored.exposed);
        BOOST_CHECK(!stored.released);

        CheckOwnedInputs(id, *view.original);
    }
};

enum class UtxoFields {
    WitnessOnly,
    NonWitnessOnly,
    BothMatching,
    AmountMismatch,
    ScriptMismatch,
    PreviousTransactionHash,
    WalletScript,
    ValueAboveMaxMoney,
    InputTotalAboveMaxMoney,
};

void CheckReceiverUtxoFields(IntegrationFixture& fixture, UtxoFields fields)
{
    const auto id = fixture.m_service->Start(fixture.Intent());
    fixture.Flush();
    fixture.Deliver();

    if (fields == UtxoFields::WalletScript) {
        LOCK(fixture.m_sender->cs_wallet);

        CreateDescriptor(*fixture.m_sender, "wpkh(" + EncodeSecret(fixture.m_receiver_key) + ")", true);
        const auto script = fixture.m_receiver_coin->vout[0].scriptPubKey;
        BOOST_REQUIRE(!fixture.m_sender->GetWalletTx(fixture.m_receiver_coin->GetHash()));
        for (const auto& input : fixture.m_service->Snapshot(id)->original->vin) {
            const auto* parent = fixture.m_sender->GetWalletTx(input.prevout.hash);
            BOOST_REQUIRE(parent);
            BOOST_REQUIRE(script != parent->GetTx()->vout.at(input.prevout.n).scriptPubKey);
        }
    }

    bool modified{false};
    const auto psbt = fixture.Proposal([&](PartiallySignedTransaction& proposal) {
        for (auto& input : proposal.inputs) {
            if (input.GetOutPoint() != COutPoint{fixture.m_receiver_coin->GetHash(), 0}) continue;
            BOOST_REQUIRE(!input.final_script_witness.IsNull());
            input.non_witness_utxo = fixture.m_receiver_coin;
            input.witness_utxo = fixture.m_receiver_coin->vout[0];
            switch (fields) {
            case UtxoFields::WitnessOnly:
                input.non_witness_utxo.reset();
                break;
            case UtxoFields::NonWitnessOnly:
                input.witness_utxo.SetNull();
                break;
            case UtxoFields::BothMatching:
                break;
            case UtxoFields::AmountMismatch:
                ++input.witness_utxo.nValue;
                break;
            case UtxoFields::ScriptMismatch:
                BOOST_REQUIRE(!input.witness_utxo.scriptPubKey.empty());
                input.witness_utxo.scriptPubKey.back() ^= 1;
                break;
            case UtxoFields::PreviousTransactionHash: {
                CMutableTransaction previous{*fixture.m_receiver_coin};
                previous.version ^= 1;
                input.non_witness_utxo = MakeTransactionRef(std::move(previous));
                BOOST_REQUIRE(input.non_witness_utxo->GetHash() != input.prev_txid);
                break;
            }
            case UtxoFields::WalletScript:
                input.non_witness_utxo.reset();
                BOOST_REQUIRE(!WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsMine(input.GetOutPoint())));
                BOOST_REQUIRE(WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsMine(input.witness_utxo)));
                break;
            case UtxoFields::ValueAboveMaxMoney:
            case UtxoFields::InputTotalAboveMaxMoney:
                input.non_witness_utxo.reset();
                input.witness_utxo.nValue = fields == UtxoFields::ValueAboveMaxMoney ? MAX_MONEY + 1 : MAX_MONEY;
                BOOST_REQUIRE_EQUAL(MoneyRange(input.witness_utxo.nValue), fields == UtxoFields::InputTotalAboveMaxMoney);
                break;
            }
            modified = true;
        }
    });
    BOOST_REQUIRE(modified);

    if (fields == UtxoFields::WalletScript) {
        const auto tx = psbt.GetUnsignedTx();
        BOOST_REQUIRE(tx);
        const auto receiver_out = COutPoint{fixture.m_receiver_coin->GetHash(), 0};
        const auto input = std::find_if(tx->vin.begin(), tx->vin.end(), [&](const auto& in) { return in.prevout == receiver_out; });
        BOOST_REQUIRE(input != tx->vin.end());

        const size_t index = input - tx->vin.begin();
        const auto& utxo = fixture.m_receiver_coin->vout[0];
        BOOST_REQUIRE(psbt.inputs[index].witness_utxo == utxo);
        BOOST_REQUIRE(VerifyScript(psbt.inputs[index].final_script_sig, utxo.scriptPubKey,
                                   &psbt.inputs[index].final_script_witness, STANDARD_SCRIPT_VERIFY_FLAGS,
                                   MutableTransactionSignatureChecker{&*tx, static_cast<unsigned int>(index), utxo.nValue, MissingDataBehavior::FAIL}));
    }

    if (fields == UtxoFields::PreviousTransactionHash) {
        DataStream bytes;
        bytes << psbt;
        const auto decoded = DecodeBase64PSBT(EncodeBase64(bytes));
        BOOST_REQUIRE(!decoded);
        BOOST_CHECK(util::ErrorString(decoded).original.starts_with("Non-witness UTXO does not match outpoint hash"));
    }

    if (fields == UtxoFields::InputTotalAboveMaxMoney) {
        CAmount total{MAX_MONEY};
        LOCK(fixture.m_sender->cs_wallet);
        for (const auto& input : fixture.m_service->Snapshot(id)->original->vin) {
            const auto value = fixture.m_sender->GetWalletTx(input.prevout.hash)->GetTx()->vout.at(input.prevout.n).nValue;
            BOOST_REQUIRE(MoneyRange(value));
            total += value;
        }
        BOOST_REQUIRE(total > MAX_MONEY);
    }

    fixture.Tick();
    fixture.Deliver();

    const auto view = *fixture.m_service->Snapshot(id);
    const bool rejected = fields != UtxoFields::WitnessOnly && fields != UtxoFields::NonWitnessOnly && fields != UtxoFields::BothMatching;
    if (rejected) {
        const bool adapter_rejection = fields == UtxoFields::PreviousTransactionHash;
        BOOST_CHECK(view.issue == (adapter_rejection ? PaymentIssue::Protocol : PaymentIssue::Signing));
        const char* diagnostic{"inconsistent proposal UTXO"};
        if (fields == UtxoFields::WalletScript) {
            diagnostic = "unexpected wallet script";
        } else if (fields == UtxoFields::ValueAboveMaxMoney || fields == UtxoFields::InputTotalAboveMaxMoney) {
            diagnostic = "invalid proposal input value";
        }

        if (adapter_rejection) {
            BOOST_CHECK(view.diagnostic.starts_with("Payjoin proposal PSBT could not be decoded ("));
        } else {
            BOOST_CHECK_EQUAL(view.diagnostic, diagnostic);
        }
        BOOST_CHECK(!view.selected);
        BOOST_CHECK(!view.selection_saved);
        BOOST_CHECK(!view.wallet_recorded);
        BOOST_CHECK(!view.node_accepted);

        const auto tx = psbt.GetUnsignedTx();
        BOOST_REQUIRE(tx);

        BOOST_CHECK(!fixture.m_node.mempool->exists(tx->GetHash()));
        BOOST_CHECK(!fixture.m_node.mempool->exists(view.original->GetHash()));

        LOCK(fixture.m_sender->cs_wallet);
        BOOST_CHECK(fixture.ReadStoredPayment(id).selected.empty());

        BOOST_CHECK(!fixture.m_sender->mapWallet.contains(tx->GetHash()));
        BOOST_CHECK(!fixture.m_sender->mapWallet.contains(view.original->GetHash()));

        fixture.CheckOwnedInputs(id, *view.original);
    } else {
        BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
        BOOST_REQUIRE(view.selected);
        BOOST_CHECK(view.phase == PaymentPhase::Published);
        BOOST_CHECK(view.selected->GetHash() != view.original->GetHash());

        BOOST_CHECK(fixture.m_node.mempool->exists(view.selected->GetHash()));
    }
    BOOST_CHECK(view.owns_inputs);
}

void CheckQueuedProposal(IntegrationFixture& fixture, bool cancel)
{
    const auto id = fixture.m_service->Start(fixture.Intent());
    fixture.Flush();
    fixture.Deliver();

    const auto psbt = fixture.Proposal();
    const auto proposal_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(proposal_tx);

    fixture.Tick();
    auto pending = fixture.Forwarder().Capture();
    BOOST_REQUIRE_MESSAGE(pending.result.delivery == Delivery::Response, pending.result.diagnostic);

    if (!cancel) {
        pending.complete(std::move(pending.result));
        fixture.Flush();

        const auto view = *fixture.m_service->Snapshot(id);
        BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
        BOOST_REQUIRE(view.selected);
        BOOST_CHECK(view.phase == PaymentPhase::Published);
        BOOST_CHECK(view.selected->GetHash() == proposal_tx->GetHash());
        BOOST_CHECK(view.selected->GetHash() != view.original->GetHash());

        BOOST_CHECK(fixture.m_node.mempool->exists(view.selected->GetHash()));
        return;
    }

    const auto wallet_transactions = WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->mapWallet.size());
    const auto mempool_transactions = fixture.m_node.mempool->size();
    std::optional<PaymentSnapshot> after_cancel;
    std::pair<std::vector<std::string>, bool> journal_after_cancel;

    fixture.m_service->Cancel(id);
    fixture.m_queue->insert([&] {
        after_cancel = fixture.m_service->Snapshot(id);
        journal_after_cancel = fixture.Journal(id);
    });
    pending.complete(std::move(pending.result));
    fixture.Flush();

    BOOST_REQUIRE(after_cancel);
    BOOST_REQUIRE(after_cancel->phase == PaymentPhase::Cancelled);
    BOOST_REQUIRE(!after_cancel->selected);
    BOOST_REQUIRE(after_cancel->possibly_exposed);
    BOOST_REQUIRE(after_cancel->owns_inputs);

    const auto view = *fixture.m_service->Snapshot(id);
    BOOST_CHECK(view.phase == after_cancel->phase);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK(view.possibly_exposed == after_cancel->possibly_exposed);
    BOOST_CHECK(view.owns_inputs == after_cancel->owns_inputs);
    BOOST_CHECK(view.issue == after_cancel->issue);
    BOOST_CHECK_EQUAL(view.diagnostic, after_cancel->diagnostic);

    BOOST_CHECK(fixture.Journal(id) == journal_after_cancel);

    BOOST_CHECK_EQUAL(fixture.m_node.mempool->size(), mempool_transactions);
    BOOST_CHECK(!fixture.m_node.mempool->exists(proposal_tx->GetHash()));
    BOOST_CHECK(!fixture.m_node.mempool->exists(view.original->GetHash()));

    LOCK(fixture.m_sender->cs_wallet);
    BOOST_CHECK_EQUAL(fixture.m_sender->mapWallet.size(), wallet_transactions);
    BOOST_CHECK(!fixture.m_sender->mapWallet.contains(proposal_tx->GetHash()));
    fixture.CheckOwnedInputs(id, *view.original);
}

void CheckProposalDeadline(IntegrationFixture& fixture, std::chrono::milliseconds offset)
{
    auto intent = fixture.Intent();
    intent.timeout = std::chrono::seconds{10};
    const auto id = fixture.m_service->Start(intent);
    fixture.Flush();
    fixture.Deliver();
    const auto psbt = fixture.Proposal();
    const auto proposal_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(proposal_tx);

    fixture.Tick();
    auto pending = fixture.Forwarder().Capture();
    BOOST_REQUIRE_MESSAGE(pending.result.delivery == Delivery::Response, pending.result.diagnostic);
    BOOST_REQUIRE(!pending.result.body.empty());
    const auto journal = fixture.Journal(id);

    fixture.m_now = SenderService::Clock::time_point{} + intent.timeout + offset;
    pending.complete(std::move(pending.result));
    fixture.Flush();

    const auto view = *fixture.m_service->Snapshot(id);
    BOOST_REQUIRE(view.original);
    if (offset < std::chrono::milliseconds::zero()) {
        BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
        BOOST_REQUIRE(view.selected);
        BOOST_CHECK(view.selected->GetHash() == proposal_tx->GetHash());

        BOOST_CHECK(fixture.m_node.mempool->exists(proposal_tx->GetHash()));
    } else {
        BOOST_CHECK(view.issue == PaymentIssue::Deadline);
        BOOST_CHECK_EQUAL(view.diagnostic, "payment deadline reached");
        BOOST_CHECK(!view.selected);
        BOOST_CHECK(!view.selection_saved);
        BOOST_CHECK(!view.wallet_recorded);
        BOOST_CHECK(!view.node_accepted);

        BOOST_CHECK(fixture.Journal(id) == journal);

        BOOST_CHECK(!fixture.m_node.mempool->exists(proposal_tx->GetHash()));

        LOCK(fixture.m_sender->cs_wallet);
        const auto stored = fixture.ReadStoredPayment(id);
        BOOST_CHECK(stored.selected.empty());
        BOOST_CHECK(stored.exposed);
        BOOST_CHECK(!stored.released);

        BOOST_CHECK(!fixture.m_sender->mapWallet.contains(proposal_tx->GetHash()));
        BOOST_CHECK(!fixture.m_sender->mapWallet.contains(view.original->GetHash()));
        fixture.CheckOwnedInputs(id, *view.original);
    }
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(view.possibly_exposed);

    BOOST_CHECK(!fixture.m_node.mempool->exists(view.original->GetHash()));
}

} // namespace

BOOST_AUTO_TEST_SUITE(payjoin_integration_tests)

BOOST_FIXTURE_TEST_CASE(sender_async_scheduler_http_exchange, AsyncIntegrationFixture)
{
    auto notice = std::make_shared<std::promise<Txid>>();
    auto published = notice->get_future();
    auto notified = std::make_shared<std::atomic<bool>>(false);
    btcsignals::scoped_connection connection{m_sender->NotifyTransactionChanged.connect(
        [notice, notified](const Txid& txid, ChangeType status) {
            if (status == CT_NEW && !notified->exchange(true)) notice->set_value(txid);
        })};

    auto intent = Intent();
    intent.poll_interval = std::chrono::milliseconds{20};
    const auto id = m_service->Start(intent);

    const auto original = ReceiverOriginal();
    BOOST_REQUIRE(original);

    const auto before = QueueSnapshot(id);
    BOOST_REQUIRE(before.original);
    BOOST_CHECK(!before.selected);

    BOOST_CHECK(!m_node.mempool->exists(before.original->GetHash()));
    CheckReservations(id, before);

    const auto psbt = SendProposal(original);
    const auto proposal_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(proposal_tx);

    BOOST_REQUIRE(published.wait_for(std::chrono::seconds{20}) == std::future_status::ready);
    const auto notified_txid = published.get();

    const auto view = QueueSnapshot(id);
    BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
    BOOST_REQUIRE(view.selected);
    BOOST_CHECK(view.phase == PaymentPhase::Published);
    BOOST_CHECK(view.selection_saved);
    BOOST_CHECK(view.wallet_recorded);
    BOOST_CHECK(view.selected->GetHash() == notified_txid);
    BOOST_CHECK(view.selected->GetHash() == proposal_tx->GetHash());
    BOOST_CHECK(view.selected->GetHash() != view.original->GetHash());

    BOOST_CHECK(m_node.mempool->exists(view.selected->GetHash()));
    BOOST_CHECK(!m_node.mempool->exists(view.original->GetHash()));

    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        if (!psbt.inputs[i].final_script_witness.IsNull()) {
            BOOST_CHECK(view.selected->vin[i].scriptWitness == psbt.inputs[i].final_script_witness);
        }
    }

    LOCK(m_sender->cs_wallet);
    const auto stored = ReadStoredPayment(id);
    BOOST_CHECK(!stored.released);
    DataStream selected;
    selected << TX_WITH_WITNESS(view.selected);
    BOOST_CHECK(stored.selected == std::vector<unsigned char>(UCharCast(selected.data()), UCharCast(selected.data()) + selected.size()));
    for (const auto& input : view.original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
    }
}

BOOST_FIXTURE_TEST_CASE(sender_async_stop_after_receiver_observes_original, AsyncIntegrationFixture)
{
    auto intent = Intent();
    intent.poll_interval = std::chrono::milliseconds{20};
    const auto id = m_service->Start(intent);

    const auto original = ReceiverOriginal();
    BOOST_REQUIRE(original);

    const auto before = QueueSnapshot(id);
    BOOST_REQUIRE(before.original);
    BOOST_REQUIRE(!before.selected);
    CheckReservations(id, before);

    auto promise = std::make_shared<std::promise<void>>();
    auto stopped = promise->get_future();
    std::jthread stopper{[this, promise] { m_service->Stop(); promise->set_value(); }};
    BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{20}) == std::future_status::ready);
    stopper.join();

    const auto psbt = SendProposal(original);
    const auto proposal_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(proposal_tx);
    WaitForTimer(2 * intent.poll_interval);

    const auto view = QueueSnapshot(id);
    BOOST_CHECK(view.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK(!view.selection_saved);
    BOOST_CHECK(!view.wallet_recorded);
    BOOST_CHECK(!view.node_accepted);

    BOOST_CHECK(!m_node.mempool->exists(proposal_tx->GetHash()));
    BOOST_CHECK(!m_node.mempool->exists(view.original->GetHash()));
    CheckReservations(id, view);

    LOCK(m_sender->cs_wallet);
    BOOST_CHECK(!m_sender->mapWallet.contains(proposal_tx->GetHash()));
    BOOST_CHECK(!m_sender->mapWallet.contains(view.original->GetHash()));
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_before_network_deadline_is_usable, IntegrationFixture)
{
    CheckProposalDeadline(*this, std::chrono::milliseconds{-1});
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_at_network_deadline_is_ignored, IntegrationFixture)
{
    CheckProposalDeadline(*this, std::chrono::milliseconds{0});
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_after_network_deadline_is_ignored, IntegrationFixture)
{
    CheckProposalDeadline(*this, std::chrono::milliseconds{1});
}

BOOST_FIXTURE_TEST_CASE(sender_retry_signing_after_network_deadline, IntegrationFixture)
{
    const SecureString passphrase{"test-only-passphrase"};
    BOOST_REQUIRE(m_sender->EncryptWallet(passphrase));

    BOOST_REQUIRE(m_sender->Unlock(passphrase));

    auto intent = Intent();
    intent.timeout = std::chrono::seconds{10};
    const auto id = m_service->Start(intent);
    Flush();
    Deliver();
    const auto psbt = Proposal();
    const auto proposal_tx = psbt.GetUnsignedTx();
    BOOST_REQUIRE(proposal_tx);

    Tick();
    BOOST_REQUIRE(m_now < SenderService::Clock::time_point{} + intent.timeout);
    BOOST_REQUIRE(m_sender->Lock());
    Deliver();

    const auto unsigned_view = *m_service->Snapshot(id);
    BOOST_REQUIRE(unsigned_view.issue == PaymentIssue::Signing);
    BOOST_CHECK_EQUAL(unsigned_view.diagnostic, "Payjoin requires an unlocked wallet with local private keys");
    BOOST_REQUIRE(!unsigned_view.selected);
    BOOST_CHECK(unsigned_view.owns_inputs);

    m_now = SenderService::Clock::time_point{} + intent.timeout + std::chrono::milliseconds{1};
    while (!m_timers.empty() && m_timers.begin()->first <= m_now) {
        auto timer = std::move(m_timers.begin()->second);
        m_timers.erase(m_timers.begin());
        timer();
        Flush();
    }
    BOOST_CHECK(!m_service->Snapshot(id)->selected);

    BOOST_CHECK(!m_node.mempool->exists(proposal_tx->GetHash()));
    BOOST_CHECK(!m_node.mempool->exists(unsigned_view.original->GetHash()));
    {
        LOCK(m_sender->cs_wallet);
        CheckOwnedInputs(id, *unsigned_view.original);
    }

    BOOST_REQUIRE(m_sender->Unlock(passphrase));
    m_service->RetrySigning(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
    BOOST_REQUIRE(view.selected);
    BOOST_CHECK(view.selected->GetHash() == proposal_tx->GetHash());
    BOOST_CHECK(view.selection_saved);
    BOOST_CHECK(!view.issue);

    BOOST_CHECK(m_node.mempool->exists(proposal_tx->GetHash()));
    BOOST_CHECK(!m_node.mempool->exists(view.original->GetHash()));
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_witness_utxo_only, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::WitnessOnly);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_non_witness_utxo_only, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::NonWitnessOnly);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_matching_utxo_fields, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::BothMatching);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_utxo_amount_mismatch, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::AmountMismatch);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_utxo_script_mismatch, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::ScriptMismatch);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_previous_transaction_hash_rejected_by_adapter, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::PreviousTransactionHash);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_unexpected_wallet_script, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::WalletScript);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_input_value_above_max_money, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::ValueAboveMaxMoney);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_input_total_above_max_money, IntegrationFixture)
{
    CheckReceiverUtxoFields(*this, UtxoFields::InputTotalAboveMaxMoney);
}

BOOST_FIXTURE_TEST_CASE(sender_signs_receiver_proposal_and_publishes, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Queued);

    PaymentSnapshot prepared;
    ScopedHook dispatch_hook{m_transport->m_on_dispatch};
    m_queue->insert([&] {
        prepared = *m_service->Snapshot(id);
        BOOST_REQUIRE_MESSAGE(prepared.phase == PaymentPhase::Ready, prepared.diagnostic);
        BOOST_REQUIRE(prepared.original);
        BOOST_CHECK(prepared.original->HasWitness());
        BOOST_CHECK(prepared.original_saved);
        BOOST_CHECK(prepared.owns_inputs);
        BOOST_CHECK(prepared.locks_verified);
        BOOST_CHECK(!prepared.possibly_exposed);
        BOOST_CHECK(m_transport->m_pending.empty());
        {
            LOCK(m_sender->cs_wallet);
            BOOST_CHECK(!m_sender->GetWalletTx(prepared.original->GetHash()));
            BOOST_CHECK(!m_sender->GetWalletTx(m_receiver_coin->GetHash()));
            m_sender->ResubmitWalletTransactions(node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL, true);
        }

        BOOST_CHECK(!m_node.mempool->exists(prepared.original->GetHash()));
    });
    m_transport->m_on_dispatch = [&] {
        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.original_saved);
        BOOST_CHECK(view.owns_inputs);
        BOOST_CHECK(view.locks_verified);
        BOOST_CHECK(view.possibly_exposed);
        BOOST_CHECK(view.disclosure_saved);

        LOCK(m_sender->cs_wallet);
        const auto record = ReadStoredPayment(id);
        BOOST_CHECK(record.exposed);
        BOOST_CHECK(!record.released);
        DataStream bytes;
        bytes << TX_WITH_WITNESS(view.original);
        BOOST_CHECK(record.original == std::vector<unsigned char>(UCharCast(bytes.data()), UCharCast(bytes.data()) + bytes.size()));
        for (const auto& input : view.original->vin) {
            auto owner = ReadOwner(input.prevout);
            BOOST_CHECK(owner == id);
            BOOST_CHECK(m_sender->IsLockedCoin(input.prevout));
        }
    };

    Flush();
    dispatch_hook.Reset();

    Deliver();
    Tick();
    Deliver();

    const auto signed_proposal = Proposal();
    std::set<Txid> updated_parents;
    btcsignals::scoped_connection connection{m_sender->NotifyTransactionChanged.connect([&](const Txid& txid, ChangeType status) {
        if (status == CT_UPDATED) updated_parents.insert(txid);
    })};

    Tick();
    Deliver();
    connection.disconnect();

    const auto result = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(result.phase == PaymentPhase::Published, result.diagnostic);
    BOOST_REQUIRE(result.selected);
    BOOST_CHECK(result.wallet_recorded);
    BOOST_CHECK(result.node_accepted);
    BOOST_CHECK(result.original->GetWitnessHash() == prepared.original->GetWitnessHash());
    BOOST_CHECK(result.selected->GetHash() != prepared.original->GetHash());

    BOOST_CHECK(m_node.mempool->exists(result.selected->GetHash()));
    BOOST_CHECK(!m_node.mempool->exists(prepared.original->GetHash()));

    const auto unsigned_proposal = signed_proposal.GetUnsignedTx();
    BOOST_REQUIRE(unsigned_proposal);
    bool checked_receiver{false};
    for (size_t i = 0; i < unsigned_proposal->vin.size(); ++i) {
        if (unsigned_proposal->vin[i].prevout.hash == m_receiver_coin->GetHash()) {
            checked_receiver = true;
            BOOST_CHECK(!signed_proposal.inputs[i].final_script_witness.IsNull());
            BOOST_CHECK(result.selected->vin[i].scriptWitness.stack == signed_proposal.inputs[i].final_script_witness.stack);
        }
    }

    BOOST_CHECK(checked_receiver);
    for (const auto& input : prepared.original->vin) {
        BOOST_CHECK(updated_parents.contains(input.prevout.hash));
    }
    BOOST_CHECK(!updated_parents.contains(m_receiver_coin->GetHash()));
}

BOOST_FIXTURE_TEST_CASE(sender_lost_initial_response_requires_attention, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    auto held = Forwarder().Capture();
    BOOST_REQUIRE(held.result.delivery == Delivery::Response);
    BOOST_REQUIRE(ReceiverOriginal());

    held.complete({Delivery::Uncertain, {}, "lost real response"});
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Delivery);
    BOOST_CHECK(view.possibly_exposed);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.selected);

    Tick();
    BOOST_CHECK(m_transport->m_pending.empty());
    BOOST_CHECK_EQUAL(Forwarder().m_forwarded, 1);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_settlement_erases_only_original_stale_markers, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    const auto proposal = Proposal();
    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    const COutPoint receiver_input{m_receiver_coin->GetHash(), 0};
    const auto proposed_tx = proposal.GetUnsignedTx();
    BOOST_REQUIRE(proposed_tx);
    BOOST_REQUIRE(std::any_of(proposed_tx->vin.begin(), proposed_tx->vin.end(),
                              [&](const auto& input) { return input.prevout == receiver_input; }));
    BOOST_REQUIRE(std::none_of(original->vin.begin(), original->vin.end(),
                               [&](const auto& input) { return input.prevout == receiver_input; }));

    const uint256 foreign_owner{uint256::ONE};
    BOOST_REQUIRE(WalletBatch{m_sender->GetDatabase()}.WriteLockedUTXO(receiver_input));
    WriteOwner(receiver_input, foreign_owner);
    BOOST_REQUIRE(LockedMarker(receiver_input));
    BOOST_REQUIRE(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(receiver_input)));

    m_database->SetEraseFailure(DBKeys::LOCKED_UTXO);
    Tick();
    Deliver();

    const auto published = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(published.node_accepted, published.diagnostic);
    BOOST_REQUIRE(published.selected);
    BOOST_REQUIRE(published.selected->GetHash() != original->GetHash());
    for (const auto& input : original->vin) {
        BOOST_REQUIRE(LockedMarker(input.prevout));
        BOOST_REQUIRE(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
    }

    m_database->CheckEraseFailed();
    m_database->ClearEraseFailure();
    Confirm(published.selected);
    for (const auto& input : original->vin) {
        BOOST_REQUIRE(LockedMarker(input.prevout));
    }

    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();
        CheckReleased(id);
        BOOST_CHECK(m_service->Snapshot(id)->settlement->kind == SpendKind::Selected);
        BOOST_CHECK(LockedMarker(receiver_input));
        BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(receiver_input)));
        auto owner = ReadOwner(receiver_input);
        BOOST_CHECK(owner == foreign_owner);
    }
}

BOOST_FIXTURE_TEST_CASE(sender_poll_trusts_persistent_memory_lock, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);

    const auto input = original->vin[0].prevout;
    BOOST_REQUIRE(LockedMarker(input));
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(WalletBatch{m_sender->GetDatabase()}.EraseLockedUTXO(input));
        BOOST_REQUIRE(m_sender->m_locked_coins.at(input));
    }
    BOOST_REQUIRE(!LockedMarker(input));
    auto owner = ReadOwner(input);
    BOOST_REQUIRE(owner == id);

    const auto attempts = m_transport->m_attempts;
    BOOST_REQUIRE(m_transport->m_pending.empty());

    Tick();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(!view.issue);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(view.locks_verified);
    BOOST_CHECK(view.transport_accepted);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts + 1);
    BOOST_CHECK_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_CHECK(!LockedMarker(input));
    owner = ReadOwner(input);
    BOOST_CHECK(owner == id);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins.at(input)));
}

BOOST_FIXTURE_TEST_CASE(sender_poll_retry_uses_fresh_context_and_ignores_duplicate, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();

    Tick();
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    const auto old = m_transport->m_pending.front();
    m_transport->m_pending.pop_front();
    old.complete({Delivery::Uncertain, {}, "temporary polling failure", true});
    Flush();

    Tick();
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_CHECK(old.request.body != m_transport->m_pending.front().request.body);
    BOOST_CHECK(old.id != m_transport->m_pending.front().id);

    old.complete({Delivery::Response, {}, "duplicate"});
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Negotiating);

    auto real = Forwarder().Capture();
    real.complete(real.result);
    Flush();

    const auto journal = Journal(id);
    real.complete(real.result);
    Flush();

    BOOST_CHECK(Journal(id) == journal);
    BOOST_CHECK(!m_service->Snapshot(id)->issue);
}

BOOST_FIXTURE_TEST_CASE(sender_manual_unlock_blocks_publication_without_releasing_ownership, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    const auto view = *m_service->Snapshot(id);
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->UnlockCoin(view.original->vin[0].prevout));
    }

    Tick();
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Reservation);
    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);

    const auto other = m_service->Start(Intent());
    Flush();
    BOOST_CHECK(!m_service->Snapshot(other)->selected);
}

BOOST_FIXTURE_TEST_CASE(sender_cancellation_wins_before_queued_proposal, IntegrationFixture)
{
    CheckQueuedProposal(*this, /*cancel=*/true);
}

BOOST_FIXTURE_TEST_CASE(sender_queued_proposal_is_usable_without_cancellation, IntegrationFixture)
{
    CheckQueuedProposal(*this, /*cancel=*/false);
}

BOOST_FIXTURE_TEST_CASE(sender_mempool_fallback_ignores_late_proposal, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    Proposal();

    Tick();
    auto pending = Forwarder().Capture();
    BOOST_REQUIRE_MESSAGE(pending.result.delivery == Delivery::Response, pending.result.diagnostic);
    BOOST_REQUIRE(!pending.result.body.empty());

    const auto original = m_service->Snapshot(id)->original;
    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    m_service->PublishFallback(id);
    Flush();

    const auto published = *m_service->Snapshot(id);
    BOOST_REQUIRE(published.selected);
    BOOST_CHECK(published.selected->GetWitnessHash() == original->GetWitnessHash());
    BOOST_CHECK(published.phase == PaymentPhase::Published);
    BOOST_CHECK(published.node_accepted);
    BOOST_CHECK(std::find(m_transport->m_cancelled.begin(), m_transport->m_cancelled.end(), pending.id) != m_transport->m_cancelled.end());
    const auto journal = Journal(id);
    BOOST_CHECK(journal.second);
    const auto attempts = m_transport->m_attempts;

    pending.complete(std::move(pending.result));
    Flush();

    const auto after = *m_service->Snapshot(id);
    BOOST_REQUIRE(after.selected);
    BOOST_CHECK(after.selected->GetWitnessHash() == original->GetWitnessHash());
    BOOST_CHECK(after.phase == PaymentPhase::Published);
    BOOST_CHECK(after.node_accepted);
    BOOST_CHECK(after.owns_inputs);
    BOOST_CHECK(!after.issue);
    BOOST_CHECK(after.diagnostic.empty());

    BOOST_CHECK(Journal(id) == journal);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);
}

BOOST_FIXTURE_TEST_CASE(sender_proposal_publication_wins_before_fallback, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    Proposal();

    Tick();
    auto pending = Forwarder().Capture();
    pending.complete(pending.result);
    m_service->PublishFallback(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
    BOOST_CHECK(view.selected->GetHash() != view.original->GetHash());
}

BOOST_FIXTURE_TEST_CASE(sender_signing_failure_allows_explicit_choice_or_retry, IntegrationFixture)
{
    const SecureString passphrase{"test-only-passphrase"};
    BOOST_REQUIRE(m_sender->EncryptWallet(passphrase));

    BOOST_REQUIRE(m_sender->Unlock(passphrase));

    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_MESSAGE(m_service->Snapshot(id)->transport_accepted, m_service->Snapshot(id)->diagnostic);
    Deliver();
    Proposal();

    Tick();
    BOOST_REQUIRE(m_sender->Lock());
    Deliver();
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Signing);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);
    BOOST_CHECK(m_service->Snapshot(id)->fallback_available);
    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);

    m_service->RetrySigning(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Signing);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);

    BOOST_REQUIRE(m_sender->Unlock(passphrase));
    m_now += std::chrono::hours{1};

    m_service->RetrySigning(id);
    Flush();

    BOOST_REQUIRE_MESSAGE(m_service->Snapshot(id)->node_accepted, m_service->Snapshot(id)->diagnostic);
    BOOST_CHECK(m_service->Snapshot(id)->selection_saved);
}

BOOST_FIXTURE_TEST_CASE(sender_does_not_sign_extra_wallet_input, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE(view.original);
    BOOST_REQUIRE_EQUAL(view.original->vin.size(), 1);
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& [txid, wtx] : m_sender->mapWallet) {
            if (txid != view.original->vin[0].prevout.hash && wtx.IsCoinBase()) m_receiver_input_override = wtx.GetTx();
        }
    }

    BOOST_REQUIRE(m_receiver_input_override);
    Deliver();
    const auto psbt = Proposal();

    Tick();
    Deliver();
    BOOST_REQUIRE_MESSAGE(m_service->Snapshot(id)->issue == PaymentIssue::Signing, m_service->Snapshot(id)->diagnostic);
    BOOST_CHECK_EQUAL(m_service->Snapshot(id)->diagnostic, "unexpected wallet input");
    BOOST_CHECK(!m_service->Snapshot(id)->selected);
    BOOST_CHECK(!m_service->Snapshot(id)->wallet_recorded);
    BOOST_CHECK(!m_service->Snapshot(id)->node_accepted);

    BOOST_CHECK(!m_node.mempool->exists(psbt.GetUnsignedTx()->GetHash()));
    BOOST_CHECK(m_service->Snapshot(id)->fallback_available);

    const auto journal = Journal(id);
    m_service->Cancel(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->fallback_available);

    auto signing_future = m_service->Execute(id, SenderCommand::RetrySigning);
    Flush();

    const auto signing_result = signing_future.get();
    BOOST_CHECK(signing_result.refusal == CommandRefusal::InvalidState);

    auto fallback_future = m_service->Execute(id, SenderCommand::Fallback);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->selected);
    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == view.original->GetWitnessHash());
    BOOST_CHECK(m_service->Snapshot(id)->node_accepted);
    const auto fallback_result = fallback_future.get();
    BOOST_CHECK(!fallback_result.refusal);

    BOOST_CHECK(Journal(id) == journal);
}

BOOST_FIXTURE_TEST_CASE(sender_publication_retry_and_confirmed_cleanup, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    Proposal();

    Tick();
    const auto max_fee = m_sender->m_max_tx_fee;
    m_sender->m_max_tx_fee = 1;
    Deliver();

    const auto rejected = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(rejected.phase == PaymentPhase::Rejected, rejected.diagnostic);
    BOOST_CHECK(rejected.wallet_recorded);
    BOOST_CHECK(!rejected.node_accepted);
    BOOST_CHECK(rejected.selected);

    auto fallback_future = m_service->Execute(id, SenderCommand::Fallback);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == rejected.selected->GetWitnessHash());
    const auto fallback_result = fallback_future.get();
    BOOST_CHECK(fallback_result.refusal == CommandRefusal::Selected);

    m_sender->m_max_tx_fee = max_fee;
    auto publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    BOOST_REQUIRE_MESSAGE(m_service->Snapshot(id)->node_accepted, m_service->Snapshot(id)->diagnostic);
    const auto publication_result = publication_future.get();
    BOOST_CHECK(!publication_result.refusal);

    const auto block = Confirm(rejected.selected);

    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Confirmed);
    BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);

    m_service->RetryPublication(id);
    Flush();
    {
        LOCK(m_sender->cs_wallet);
        const auto* confirmed = m_sender->GetWalletTx(rejected.selected->GetHash())->state<TxStateConfirmed>();
        BOOST_REQUIRE(confirmed);
        BOOST_CHECK(confirmed->confirmed_block_hash == block.GetHash());
    }

    Disconnect(block);
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(!view.settlement);
        BOOST_CHECK(view.phase == PaymentPhase::Attention);
        BOOST_CHECK(!view.owns_inputs);
        BOOST_CHECK(view.selected_presence == TransactionPresence::Inactive);
    }

    auto settled_publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto settled_publication_result = settled_publication_future.get();
    BOOST_CHECK(settled_publication_result.refusal == CommandRefusal::Settled);
}

BOOST_FIXTURE_TEST_CASE(sender_selection_write_failure_forbids_publication, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    Proposal();

    Tick();
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment, FaultDatabase::WriteFailure::AfterWrite);
    Deliver();
    m_database->CheckWriteFailed();

    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE(view.selected);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(!view.wallet_recorded);
    BOOST_CHECK(!view.node_accepted);
    BOOST_CHECK(!view.fallback_available);
    BOOST_CHECK(view.owns_inputs);

    m_service->PublishFallback(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == view.selected->GetWitnessHash());

    LOCK(m_sender->cs_wallet);
    BOOST_CHECK(!m_sender->GetWalletTx(view.selected->GetHash()));
}

BOOST_FIXTURE_TEST_CASE(sender_requires_persistent_lock_and_excludes_owned_coins, IntegrationFixture)
{
    const auto first = m_service->Start(Intent());
    Flush();

    const auto coin = m_service->Snapshot(first)->original->vin.front().prevout;
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->UnlockCoin(coin));
        BOOST_REQUIRE(m_sender->LockCoin(coin, false));
    }

    Deliver();
    Tick();
    BOOST_CHECK(m_service->Snapshot(first)->issue == PaymentIssue::Reservation);
    BOOST_CHECK(!m_service->Snapshot(first)->locks_verified);
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->UnlockCoin(coin));
    }

    const auto second = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_MESSAGE(m_service->Snapshot(second)->transport_accepted, m_service->Snapshot(second)->diagnostic);
    for (const auto& input : m_service->Snapshot(second)->original->vin) {
        BOOST_CHECK(input.prevout != coin);
    }
    auto owner = ReadOwner(coin);
    BOOST_CHECK(owner == first);

    LOCK(m_sender->cs_wallet);
    BOOST_CHECK(!m_sender->IsLockedCoin(coin));
}

BOOST_FIXTURE_TEST_CASE(sender_original_settles_after_proposal_selection, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    Deliver();
    Proposal();

    Tick();
    m_sender->m_max_tx_fee = 1;
    Deliver();

    const auto selected = m_service->Snapshot(id)->selected;
    BOOST_REQUIRE(selected);
    BOOST_REQUIRE(!m_service->Snapshot(id)->node_accepted);

    Confirm(original);
    m_service->Refresh(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.phase == PaymentPhase::Confirmed);
    BOOST_REQUIRE(view.settlement);
    BOOST_CHECK(view.settlement->kind == SpendKind::Original);
    BOOST_CHECK(view.selected->GetWitnessHash() == selected->GetWitnessHash());
    BOOST_CHECK(!view.owns_inputs);
}

BOOST_FIXTURE_TEST_CASE(sender_wallet_change_before_signing_wins, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    Proposal();

    Tick();
    auto request = Forwarder().Capture();
    request.complete(request.result);

    std::future<void> run;
    {
        LOCK(m_sender->cs_wallet);
        std::promise<void> started;
        auto start = started.get_future();
        run = std::async(std::launch::async, [&] {
            started.set_value();
            Flush();
        });
        start.wait();
        BOOST_REQUIRE(m_sender->UnlockCoin(m_service->Snapshot(id)->original->vin[0].prevout));
    }

    run.get();
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Reservation);

    auto signing_future = m_service->Execute(id, SenderCommand::RetrySigning);
    Flush();

    const auto signing_result = signing_future.get();
    BOOST_CHECK(signing_result.refusal == CommandRefusal::InputsChanged);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);
}

BOOST_FIXTURE_TEST_CASE(sender_total_fee_policy_boundary, IntegrationFixture)
{
    CreateAndProcessBlock({}, GetScriptForDestination(WitnessV0KeyHash{m_sender_key.GetPubKey()}));
    mineBlocks(100);
    uint256 genesis;
    {
        LOCK(m_sender->cs_wallet);
        LOCK(cs_main);
        const auto& chain = m_node.chainman->ActiveChain();
        m_sender->SetLastBlockProcessed(chain.Height(), chain.Tip()->GetBlockHash());
        genesis = chain.Genesis()->GetBlockHash();
    }
    {
        WalletRescanReserver reserver{*m_sender};
        BOOST_REQUIRE(reserver.reserve());
        BOOST_REQUIRE(m_sender->Scanner().Scan(genesis, 0, std::nullopt, reserver, false).status == ScanResult::SUCCESS);
    }

    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->transport_accepted);
    Deliver();
    const auto psbt = Proposal();

    CAmount total{0};
    for (const auto& input : psbt.inputs) {
        BOOST_REQUIRE(!input.witness_utxo.IsNull());
        total += input.witness_utxo.nValue;
    }
    const CAmount fee = total - CTransaction{*psbt.GetUnsignedTx()}.GetValueOut();
    BOOST_REQUIRE(fee > 0);

    m_service->Cancel(id);
    Flush();

    for (const CAmount maximum : {fee - 1, fee}) {
        BOOST_TEST_CONTEXT("max total fee=" << maximum)
        {
            ResetReceiver();
            auto intent = Intent();
            intent.max_fee = maximum;
            const auto payment = m_service->Start(intent);
            Flush();

            BOOST_REQUIRE_MESSAGE(m_service->Snapshot(payment)->transport_accepted, m_service->Snapshot(payment)->diagnostic);
            Deliver();
            const auto checked = Proposal();
            CAmount input_value{0};
            for (const auto& input : checked.inputs) {
                input_value += input.witness_utxo.nValue;
            }
            BOOST_REQUIRE_EQUAL(input_value - CTransaction{*checked.GetUnsignedTx()}.GetValueOut(), fee);

            while (m_transport->m_pending.empty()) {
                Tick();
            }
            Deliver();

            const auto view = *m_service->Snapshot(payment);
            if (maximum < fee) {
                BOOST_CHECK(view.issue == PaymentIssue::Signing);
                BOOST_CHECK_EQUAL(view.diagnostic, "proposal inputs or fee exceed payment policy");
                BOOST_CHECK(!view.selected);
            } else {
                BOOST_CHECK_MESSAGE(view.node_accepted, view.diagnostic);
            }

            m_service->Cancel(payment);
            Flush();
        }
    }
}

BOOST_FIXTURE_TEST_CASE(receiver_rejects_malformed_proposal_response, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();

    auto original = ReceiverOriginal();
    const auto posted = CountEvent(m_log->load(), "PostedPayjoinProposal");
    BOOST_CHECK_THROW(SendProposal(original, {}, true), ::payjoin::ReceiverPersistedError);
    BOOST_CHECK_EQUAL(CountEvent(m_log->load(), "PostedPayjoinProposal"), posted);
    const auto view = m_service->Snapshot(id);
    BOOST_REQUIRE(view);
    BOOST_CHECK(!view->selected);
    BOOST_CHECK(!view->node_accepted);
}

BOOST_FIXTURE_TEST_CASE(sender_command_results_are_independent, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();

    auto publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto publication_result = publication_future.get();
    BOOST_CHECK(publication_result.refusal == CommandRefusal::InvalidState);

    BOOST_CHECK_EQUAL(CountEvent(Journal(id).first, "PostedOriginalPsbt"), 0);
    Deliver();
    BOOST_CHECK_EQUAL(CountEvent(Journal(id).first, "PostedOriginalPsbt"), 1);
    const auto view = m_service->Snapshot(id);
    BOOST_REQUIRE(view);
    BOOST_CHECK(!view->issue);
    BOOST_CHECK(!view->selected);
    BOOST_CHECK(!view->node_accepted);

    auto refresh_future = m_service->Execute(id, SenderCommand::Refresh);
    Flush();

    const auto refresh_result = refresh_future.get();
    BOOST_CHECK(!refresh_result.refusal);

    m_service->RetryPublication(id);
    auto cancel_future = m_service->Execute(id, SenderCommand::Cancel);
    Flush();

    const auto cancel_result = cancel_future.get();
    BOOST_CHECK(!cancel_result.refusal);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);
}

BOOST_FIXTURE_TEST_CASE(sender_services_exclusively_own_their_transports, IntegrationFixture)
{
    auto owned = std::make_unique<ForwardingTransport>();
    auto* other_transport = owned.get();
    auto other = MakeService(std::move(owned));

    const auto first = m_service->Start(Intent());
    const auto second = other->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_REQUIRE_EQUAL(other_transport->m_pending.size(), 1);
    BOOST_CHECK_EQUAL(m_transport->m_pending.front().id, other_transport->m_pending.front().id);

    m_service->Stop();

    BOOST_CHECK(other_transport->m_cancelled.empty());

    auto request = other_transport->Capture();
    request.complete(request.result);
    Flush();
    Tick();
    BOOST_CHECK_EQUAL(other_transport->m_pending.size(), 1);
    BOOST_CHECK(other->Snapshot(second)->phase == PaymentPhase::Negotiating);
    BOOST_CHECK(m_service->Snapshot(first)->phase == PaymentPhase::Stopped);

    auto poll = other_transport->Capture();
    poll.complete(poll.result);
    Flush();

    other_transport->m_acceptance = SubmitResult::Busy;
    Tick();
    const auto attempts = other_transport->m_attempts;
    BOOST_CHECK(other_transport->m_pending.empty());

    other->Stop();
    while (!m_timers.empty()) {
        Tick();
    }

    BOOST_CHECK_EQUAL(other_transport->m_attempts, attempts);
}

BOOST_FIXTURE_TEST_CASE(sender_poll_checks_only_original_reservations, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);

    const COutPoint unrelated{m_receiver_coin->GetHash(), 0};
    const uint256 foreign_owner{uint256::ONE};
    WriteOwner(unrelated, foreign_owner);

    Tick();
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Negotiating);
    BOOST_CHECK(m_service->Snapshot(id)->locks_verified);
    BOOST_CHECK(ReadOwner(unrelated) == foreign_owner);
    for (const auto& input : original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
        BOOST_CHECK(LockedMarker(input.prevout));
        BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
    }

    Deliver();
    WriteOwner(original->vin.front().prevout, foreign_owner);
    const auto attempts = m_transport->m_attempts;

    Tick();
    const auto refused = *m_service->Snapshot(id);
    BOOST_CHECK(refused.issue == PaymentIssue::Reservation);
    BOOST_CHECK_EQUAL(refused.diagnostic, "payment inputs changed; reconciliation required");
    BOOST_CHECK(!refused.locks_verified);
    BOOST_CHECK(refused.owns_inputs);
    BOOST_CHECK(!refused.selected);
    BOOST_CHECK(!refused.node_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);
    BOOST_CHECK(ReadOwner(original->vin.front().prevout) == foreign_owner);
    BOOST_CHECK(LockedMarker(original->vin.front().prevout));

    BOOST_CHECK(!m_node.mempool->exists(original->GetHash()));
}

BOOST_AUTO_TEST_CASE(http_transport_tls_proxy_deadline_and_cancellation)
{
    BasicTestingSetup setup;
    auto services = ::payjoin::TestServices::initialize();
    services->wait_for_services_ready();
    auto log = std::make_shared<ReceiverLog>();
    auto receive_session = ::payjoin::ReceiverBuilder::init("2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7",
                                                            services->directory_url(), services->fetch_ohttp_keys())
                               ->build()
                               ->save(log);
    const auto request = [&] {
        auto poll = receive_session->create_poll_request(services->ohttp_relay_url());
        return SenderRequest{services->ohttp_gateway_url(), poll.request->content_type, poll.request->body};
    };

    HttpTransportOptions options;
    options.ca_file = Certificate(services->cert(), setup.m_path_root);
    HttpSenderTransport trusted{options};
    BOOST_CHECK(Post(trusted, request()).delivery == Delivery::Response);

    HttpSenderTransport untrusted;
    BOOST_CHECK(Post(untrusted, request()).delivery == Delivery::Uncertain);

    auto wrong_name = request();
    wrong_name.url.replace(wrong_name.url.find("localhost"), 9, "127.0.0.1");
    BOOST_CHECK(Post(trusted, wrong_name).delivery == Delivery::Uncertain);

    const auto expired = Post(trusted, request(), std::chrono::milliseconds{1});
    BOOST_CHECK(expired.delivery == Delivery::NotSent || expired.delivery == Delivery::Uncertain);
    if (expired.delivery == Delivery::NotSent) BOOST_CHECK(!expired.retryable);

    const auto cancelled = Post(trusted, request(), std::chrono::seconds{5}, true);
    BOOST_CHECK(cancelled.delivery == Delivery::Cancelled || cancelled.delivery == Delivery::NotSent);

    options.proxy = services->ohttp_relay_url();
    HttpSenderTransport through_proxy{options};
    BOOST_CHECK(Post(through_proxy, request()).delivery == Delivery::Response);
}

BOOST_FIXTURE_TEST_CASE(sender_real_network_explicit_fallback, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    BOOST_REQUIRE(ReceiverOriginal());

    const auto original = m_service->Snapshot(id)->original;

    m_service->Cancel(id);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->selected);

    m_service->PublishFallback(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(view.node_accepted, view.diagnostic);
    BOOST_REQUIRE(view.selected);
    BOOST_CHECK(view.selected->GetWitnessHash() == original->GetWitnessHash());

    BOOST_CHECK(m_node.mempool->exists(original->GetHash()));

    m_service->Stop();
}

BOOST_AUTO_TEST_CASE(forwarding_transport_expired_held_request_never_reaches_http)
{
    ForwardingTransport transport;
    int callbacks{0};
    BOOST_REQUIRE(transport.Submit(1, {"http://not-used.invalid", "text/plain", {}}, std::chrono::seconds{1},
                                   [&](const TransportResult& result) { ++callbacks; BOOST_CHECK(result.delivery == Delivery::NotSent); }) == SubmitResult::Accepted);

    transport.m_pending.front().accepted_at -= std::chrono::seconds{2};
    auto held = transport.Capture();
    held.complete(held.result);

    BOOST_CHECK_EQUAL(transport.m_forwarded, 0);
    BOOST_CHECK_EQUAL(callbacks, 1);
}

BOOST_FIXTURE_TEST_CASE(sender_poll_retryable_not_sent_and_terminal_delivery, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();

    Tick();
    auto pending = std::move(m_transport->m_pending.front());
    m_transport->m_pending.pop_front();
    pending.complete({Delivery::NotSent, {}, "temporary pre-dispatch failure", true});
    Flush();

    Tick();
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_CHECK(pending.request.body != m_transport->m_pending.front().request.body);

    auto terminal = std::move(m_transport->m_pending.front());
    m_transport->m_pending.pop_front();
    terminal.complete({Delivery::NotSent, {}, "permanent transport configuration failure", false});
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Delivery);

    const auto original = m_service->Snapshot(id)->original;
    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    const auto attempts = m_transport->m_attempts;
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.phase == PaymentPhase::Attention);
        BOOST_CHECK(view.issue == PaymentIssue::Delivery);
        BOOST_CHECK(!view.diagnostic.empty());
        BOOST_CHECK(!view.selected);
        BOOST_CHECK(!view.node_accepted);
    }

    m_service->PublishFallback(id);
    Flush();

    const auto published = *m_service->Snapshot(id);
    BOOST_REQUIRE(published.selected);
    BOOST_CHECK(published.selected->GetWitnessHash() == original->GetWitnessHash());
    BOOST_CHECK(published.phase == PaymentPhase::Published);
    BOOST_CHECK(published.node_accepted);
    BOOST_CHECK(!published.issue);
    BOOST_CHECK(published.diagnostic.empty());
    BOOST_CHECK(published.owns_inputs);
    const auto journal = Journal(id);
    BOOST_CHECK(journal.second);

    Tick();
    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);

    BOOST_CHECK(Journal(id) == journal);
}

BOOST_FIXTURE_TEST_CASE(sender_busy_poll_preserves_previous_disclosure, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);
    BOOST_REQUIRE(m_service->Snapshot(id)->disclosure_saved);
    BOOST_REQUIRE(ReadStoredPayment(id).exposed);

    m_transport->m_acceptance = SubmitResult::Busy;
    Tick();

    const auto busy = *m_service->Snapshot(id);
    BOOST_CHECK(busy.possibly_exposed);
    BOOST_CHECK(busy.disclosure_saved);
    BOOST_CHECK(busy.transport_accepted);
    BOOST_CHECK(!busy.storage_uncertain);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
    BOOST_CHECK(!busy.selected);
    BOOST_CHECK(!busy.node_accepted);
}

BOOST_FIXTURE_TEST_CASE(sender_not_sent_poll_preserves_previous_disclosure, IntegrationFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();
    Deliver();
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);
    BOOST_REQUIRE(ReadStoredPayment(id).exposed);

    Tick();
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    m_transport->m_pending.front().complete({Delivery::NotSent, {}, "local URL rejected", false});
    Flush();

    const auto failed = *m_service->Snapshot(id);
    BOOST_CHECK(failed.issue == PaymentIssue::Delivery);
    BOOST_CHECK(failed.possibly_exposed);
    BOOST_CHECK(failed.disclosure_saved);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
    BOOST_CHECK(failed.owns_inputs);

    m_service->Cancel(id);
    Flush();

    const auto cancelled = *m_service->Snapshot(id);
    BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(cancelled.owns_inputs);
    BOOST_CHECK(!cancelled.selected);
    BOOST_CHECK(!cancelled.node_accepted);

    m_service->Stop();

    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(stopped.possibly_exposed);
    BOOST_CHECK(stopped.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet::payjoin
