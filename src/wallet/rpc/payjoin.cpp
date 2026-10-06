// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/rpc/payjoin.h>

#include <consensus/amount.h>
#include <core_io.h>
#include <interfaces/chain.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <span.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/check.h>
#include <wallet/context.h>
#include <wallet/payjoin/manager.h>
#include <wallet/payjoin/sender.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace wallet {
namespace {
using namespace payjoin;
using namespace std::chrono_literals;

template <typename T>
T WaitForPayjoin(const JSONRPCRequest& request, std::future<T> future)
{
    auto& chain = *CHECK_NONFATAL(EnsureWalletContext(request.context).chain);
    while (future.wait_for(50ms) != std::future_status::ready) {
        chain.rpcInterruptionPoint();
    }

    chain.rpcInterruptionPoint();
    return future.get();
}

SenderManager& Manager(const JSONRPCRequest& request)
{
    auto& context = EnsureWalletContext(request.context);
    if (!context.payjoin) throw JSONRPCError(RPC_WALLET_ERROR, "Payjoin service is not running");
    return *context.payjoin;
}

void CheckResult(const ManagerResult& result)
{
    if (result.status == CommandStatus::NotFound) throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown Payjoin payment_id in this wallet load");
    if (result.status == CommandStatus::Stopped) throw JSONRPCError(RPC_WALLET_ERROR, "Payjoin service is stopped for this wallet load");
    if (!result.error) {
        if (result.status == CommandStatus::Failed) throw JSONRPCError(RPC_WALLET_ERROR, result.diagnostic);
        return;
    }

    int code{RPC_WALLET_ERROR};
    switch (*result.error) {
    case RequestError::InvalidParameter:
    case RequestError::IdempotencyConflict: code = RPC_INVALID_PARAMETER; break;
    case RequestError::Locked: code = RPC_WALLET_UNLOCK_NEEDED; break;
    case RequestError::NetworkPolicy: code = RPC_CLIENT_NOT_CONNECTED; break;
    case RequestError::UnsupportedWallet:
    case RequestError::FeePolicy:
    case RequestError::Internal: break;
    }
    throw JSONRPCError(code, result.diagnostic);
}

const char* Phase(PaymentPhase phase)
{
    switch (phase) {
    case PaymentPhase::Queued: return "queued";
    case PaymentPhase::Ready: return "ready";
    case PaymentPhase::Negotiating: return "negotiating";
    case PaymentPhase::Cancelled: return "cancelled";
    case PaymentPhase::Attention: return "attention";
    case PaymentPhase::Published: return "published";
    case PaymentPhase::Rejected: return "rejected";
    case PaymentPhase::Confirmed: return "confirmed";
    case PaymentPhase::Conflicted: return "conflicted";
    case PaymentPhase::Stopped: return "stopped";
    }
    return "unknown";
}

const char* Presence(TransactionPresence presence)
{
    switch (presence) {
    case TransactionPresence::Missing: return "missing";
    case TransactionPresence::Inactive: return "inactive";
    case TransactionPresence::Mempool: return "mempool";
    case TransactionPresence::Abandoned: return "abandoned";
    case TransactionPresence::MempoolConflicted: return "mempool_conflicted";
    case TransactionPresence::BlockConflicted: return "block_conflicted";
    case TransactionPresence::Confirmed: return "confirmed";
    }
    return "unknown";
}

const char* Issue(PaymentIssue issue)
{
    switch (issue) {
    case PaymentIssue::InvalidIntent: return "invalid_intent";
    case PaymentIssue::Preparation: return "preparation";
    case PaymentIssue::Storage: return "storage";
    case PaymentIssue::Reservation: return "reservation";
    case PaymentIssue::Protocol: return "protocol";
    case PaymentIssue::Delivery: return "delivery";
    case PaymentIssue::Deadline: return "deadline";
    case PaymentIssue::Signing: return "signing";
    case PaymentIssue::Publication: return "publication";
    case PaymentIssue::BroadcastDisabled: return "broadcast_disabled";
    case PaymentIssue::ObservedSpend: return "observed_spend";
    }
    return "unknown";
}

UniValue FeeRate(const CFeeRate& rate)
{
    const auto per_k = rate.GetFeePerK();
    return UniValue{UniValue::VNUM, strprintf("%d.%03d", per_k / 1000, per_k % 1000)};
}

UniValue Transaction(const CTransaction& tx, TransactionPresence presence)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("txid", tx.GetHash().GetHex());
    result.pushKV("wtxid", tx.GetWitnessHash().GetHex());
    result.pushKV("presence", Presence(presence));
    return result;
}

UniValue Observation(const SpendObservation& spend)
{
    auto result = Transaction(*spend.transaction, spend.presence);
    switch (spend.kind) {
    case SpendKind::Original: result.pushKV("kind", "original"); break;
    case SpendKind::Selected: result.pushKV("kind", "selected"); break;
    case SpendKind::Other: result.pushKV("kind", "other"); break;
    }
    return result;
}

UniValue PaymentJSON(const PaymentView& view)
{
    const auto& payment = view.payment;
    const auto& request = view.requested;
    UniValue result{UniValue::VOBJ};
    result.pushKV("payment_id", payment.id.GetHex());
    result.pushKV("phase", Phase(payment.phase));

    UniValue parameters{UniValue::VOBJ};
    parameters.pushKV("uri", request.uri);
    parameters.pushKV("relay", request.relay);
    if (request.amount) parameters.pushKV("amount", ValueFromAmount(*request.amount));
    if (request.fee_rate) parameters.pushKV("fee_rate", FeeRate(*request.fee_rate));
    if (request.max_total_fee) parameters.pushKV("max_total_fee", ValueFromAmount(*request.max_total_fee));
    if (request.timeout_seconds) parameters.pushKV("timeout", *request.timeout_seconds);
    if (request.request_id) parameters.pushKV("request_id", *request.request_id);
    result.pushKV("parameters", std::move(parameters));

    UniValue effective{UniValue::VOBJ};
    effective.pushKV("amount", ValueFromAmount(view.effective.amount));
    effective.pushKV("fee_rate", FeeRate(view.effective.fee_rate));
    effective.pushKV("max_total_fee", ValueFromAmount(view.effective.max_fee));
    effective.pushKV("timeout", std::chrono::duration_cast<std::chrono::seconds>(view.effective.timeout).count());
    effective.pushKV("seconds_remaining", std::max<int64_t>(0, std::chrono::ceil<std::chrono::seconds>(payment.deadline - SenderService::Clock::now()).count()));
    result.pushKV("effective", std::move(effective));

    if (payment.original) result.pushKV("original", Transaction(*payment.original, payment.original_presence));
    if (payment.selected) result.pushKV("selected", Transaction(*payment.selected, payment.selected_presence));
    if (payment.observed_spend) result.pushKV("observed_spend", Observation(*payment.observed_spend));
    if (payment.settlement) result.pushKV("settlement", Observation(*payment.settlement));

    UniValue reservations{UniValue::VOBJ};
    reservations.pushKV("owned", payment.owns_inputs);
    reservations.pushKV("locks_verified", payment.locks_verified);
    result.pushKV("reservations", std::move(reservations));
    result.pushKV("possibly_exposed", payment.possibly_exposed);
    result.pushKV("storage_uncertain", payment.storage_uncertain);

    if (payment.issue) {
        UniValue problem{UniValue::VOBJ};
        problem.pushKV("code", Issue(*payment.issue));
        problem.pushKV("message", payment.diagnostic);
        result.pushKV("problem", std::move(problem));
    }

    UniValue actions{UniValue::VARR};
    if (payment.cancel_available) actions.push_back("cancel");
    if (payment.fallback_available) actions.push_back("fallback");
    if (payment.signing_available) actions.push_back("retry_signing");
    if (payment.publication_retry_available) actions.push_back("retry_publication");
    result.pushKV("available_actions", std::move(actions));
    return result;
}

RPCResult TransactionResult(std::string key, bool spend = false)
{
    std::vector<RPCResult> fields{
        {RPCResult::Type::STR_HEX, "txid", "Transaction identifier"},
        {RPCResult::Type::STR_HEX, "wtxid", "Witness transaction identifier"},
        {RPCResult::Type::STR, "presence", "missing, inactive, mempool, abandoned, mempool_conflicted, block_conflicted, or confirmed"},
    };
    if (spend) fields.emplace_back(RPCResult::Type::STR, "kind", "original, selected, or other");
    return {RPCResult::Type::OBJ, std::move(key), true, "Current transaction observation", std::move(fields)};
}

RPCResult PaymentResult(std::string key)
{
    return {
        RPCResult::Type::OBJ,
        std::move(key),
        "Payment in this wallet load (no restart recovery)",
        {
            {RPCResult::Type::STR_HEX, "payment_id", "Payment identifier"},
            {RPCResult::Type::STR, "phase", "queued, ready, negotiating, cancelled, attention, published, rejected, confirmed, conflicted, or stopped"},
            {
                RPCResult::Type::OBJ,
                "parameters",
                "Accepted user parameters; omitted and null arguments are both omitted here",
                {
                    {RPCResult::Type::STR, "uri", "Original URI, unchanged"},
                    {RPCResult::Type::STR, "relay", "Original relay, unchanged"},
                    {RPCResult::Type::STR_AMOUNT, "amount", true, "Explicit amount in BTC"},
                    {RPCResult::Type::NUM, "fee_rate", true, "Explicit rate in sat/vB"},
                    {RPCResult::Type::STR_AMOUNT, "max_total_fee", true, "Explicit total fee limit in BTC"},
                    {RPCResult::Type::NUM, "timeout", true, "Explicit timeout in seconds"},
                    {RPCResult::Type::STR, "request_id", true, "Opaque idempotency key"},
                },
            },
            {
                RPCResult::Type::OBJ,
                "effective",
                "Values fixed at acceptance; repeats do not extend the deadline",
                {
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount in BTC"},
                    {RPCResult::Type::NUM, "fee_rate", "Fee rate in sat/vB"},
                    {RPCResult::Type::STR_AMOUNT, "max_total_fee", "Total fee limit in BTC"},
                    {RPCResult::Type::NUM, "timeout", "Timeout in seconds"},
                    {RPCResult::Type::NUM, "seconds_remaining", "Remaining negotiation time, rounded up and clamped to zero"},
                },
            },
            TransactionResult("original"),
            TransactionResult("selected"),
            TransactionResult("observed_spend", true),
            TransactionResult("settlement", true),
            {
                RPCResult::Type::OBJ,
                "reservations",
                "Reservation is independent of phase or transaction presence",
                {
                    {RPCResult::Type::BOOL, "owned", "Sender still owns the reserved inputs"},
                    {RPCResult::Type::BOOL, "locks_verified", "Current wallet in-memory locks were verified"},
                },
            },
            {RPCResult::Type::BOOL, "possibly_exposed", "The receiver may hold and broadcast the original"},
            {RPCResult::Type::BOOL, "storage_uncertain", "Uncertain storage prevents unsafe actions"},
            {
                RPCResult::Type::OBJ,
                "problem",
                true,
                "Latest payment problem, not a command result",
                {
                    {RPCResult::Type::STR, "code", "Stable problem category"},
                    {RPCResult::Type::STR, "message", "Diagnostic"},
                },
            },
            {
                RPCResult::Type::ARR,
                "available_actions",
                "Informational only; conditions are checked again when executing",
                {
                    {RPCResult::Type::STR, "", "cancel, fallback, retry_signing, or retry_publication"},
                },
            },
        },
    };
}

const char* Refusal(CommandRefusal refusal)
{
    switch (refusal) {
    case CommandRefusal::InvalidState: return "invalid_state";
    case CommandRefusal::StorageUncertain: return "storage_uncertain";
    case CommandRefusal::Selected: return "selected";
    case CommandRefusal::Settled: return "settled";
    case CommandRefusal::InputsChanged: return "inputs_changed";
    }
    return "unknown";
}

UniValue CommandJSON(const ManagerResult& result)
{
    if (result.payments.empty()) CheckResult(result);

    UniValue response{UniValue::VOBJ};
    switch (result.status) {
    case CommandStatus::Completed: response.pushKV("result", "completed"); break;
    case CommandStatus::Refused: response.pushKV("result", "refused"); break;
    case CommandStatus::Failed: response.pushKV("result", "failed"); break;
    case CommandStatus::Stopped: response.pushKV("result", "stopped"); break;
    case CommandStatus::NotFound: CheckResult(result); break;
    }

    const auto& payment = result.payments.front();
    response.pushKV("payment", PaymentJSON(payment));
    if (result.status == CommandStatus::Refused) {
        if (result.error == RequestError::NetworkPolicy) {
            response.pushKV("refusal", "network_policy");
            response.pushKV("diagnostic", result.diagnostic);
        } else if (result.refusal) {
            response.pushKV("refusal", Refusal(*result.refusal));
        }
    } else if (result.status == CommandStatus::Failed) {
        response.pushKV("diagnostic", result.diagnostic.empty() ? payment.payment.diagnostic : result.diagnostic);
    }
    return response;
}

RPCResult CommandResultHelp()
{
    return {
        RPCResult::Type::OBJ,
        "",
        "Result of this particular invocation, including partial effects",
        {
            {RPCResult::Type::STR, "result", "completed, refused, failed, or stopped"},
            PaymentResult("payment"),
            {RPCResult::Type::STR, "refusal", true, "Stable command refusal reason"},
            {RPCResult::Type::STR, "diagnostic", true, "Command diagnostic, when available"},
        },
    };
}

RPCMethod PaymentCommand(std::string name, std::string description, SenderCommand command)
{
    auto examples = RPCExamples{HelpExampleCli(name, "\"payment_id\"")};
    return RPCMethod{
        std::move(name),
        std::move(description),
        {{"payment_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Payment identifier in this wallet load"}},
        CommandResultHelp(),
        std::move(examples),
        [command](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            const auto id = ParseHashV(request.params[0], "payment_id");
            return CommandJSON(WaitForPayjoin(request, Manager(request).Execute(wallet, id, command)));
        },
    };
}
} // namespace

RPCMethod sendpayjoin()
{
    return RPCMethod{
        "sendpayjoin",
        "EXPERIMENTAL: accept an asynchronous Payjoin v2 payment for this wallet load.\n"
        "Requires local private keys, an unlocked wallet, and supported direct networking.\n"
        "No automatic fallback or recovery after wallet reload/restart is provided.\n"
        "Identical request_id repeats return the accepted payment before mutable admission checks.\n"
        "Null and omitted arguments are equal; an explicit default differs from an omitted default.\n",
        {
            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "Payjoin v2 Bitcoin URI"},
            {"relay", RPCArg::Type::STR, RPCArg::Optional::NO, "Explicit HTTP(S) relay address"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"URI amount"}, "BTC; required if absent from URI, otherwise must match"},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet policy"}, "sat/vB, at most 3 decimal places"},
            {"max_total_fee", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet maximum"}, "Positive total fee limit in BTC, no greater than the wallet maximum"},
            {"timeout", RPCArg::Type::NUM, RPCArg::Default{120}, "Negotiation timeout in integer seconds, 1 to 86400"},
            {"request_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Case-sensitive opaque key, 1 to 128 bytes without NUL, scoped to this wallet load"},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "Accepted request (preparation may later fail)",
            {
                {RPCResult::Type::STR_HEX, "payment_id", "Payment identifier"},
                {RPCResult::Type::BOOL, "duplicate", "Existing accepted request was returned"},
                PaymentResult("payment"),
            },
        },
        RPCExamples{HelpExampleCli("-named sendpayjoin", "uri=\"bitcoin:ADDRESS?amount=1&pj=V2_ENDPOINT\" relay=\"https://relay.example\" request_id=invoice-1")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            PaymentRequest parsed;
            parsed.uri = request.params[0].get_str();
            parsed.relay = request.params[1].get_str();
            if (!request.params[2].isNull()) parsed.amount = AmountFromValue(request.params[2]);
            if (!request.params[3].isNull()) parsed.fee_rate = CFeeRate{AmountFromValue(request.params[3], 3)};
            if (!request.params[4].isNull()) parsed.max_total_fee = AmountFromValue(request.params[4]);
            if (!request.params[5].isNull()) {
                try {
                    parsed.timeout_seconds = request.params[5].getInt<int64_t>();
                } catch (const std::exception&) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "timeout must be an integer from 1 to 86400 seconds");
                }
            }
            if (!request.params[6].isNull()) parsed.request_id = request.params[6].get_str();

            const auto result = WaitForPayjoin(request, Manager(request).Send(wallet, std::move(parsed)));
            CheckResult(result);

            UniValue response{UniValue::VOBJ};
            response.pushKV("payment_id", result.payments.front().payment.id.GetHex());
            response.pushKV("duplicate", result.duplicate);
            response.pushKV("payment", PaymentJSON(result.payments.front()));
            return response;
        },
    };
}

RPCMethod getpayjoin()
{
    return RPCMethod{
        "getpayjoin",
        "EXPERIMENTAL: read a Payjoin payment from this wallet load.\n"
        "Accounts for validation notifications before the read barrier; later events may appear on the next read.\n"
        "Refresh does not resume negotiation. No recovery after reload/restart is provided.\n",
        {{"payment_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Payment identifier returned by sendpayjoin"}},
        PaymentResult(""),
        RPCExamples{HelpExampleCli("getpayjoin", "\"payment_id\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            const auto id = ParseHashV(request.params[0], "payment_id");
            const auto result = WaitForPayjoin(request, Manager(request).Read(wallet, id));
            CheckResult(result);
            return PaymentJSON(result.payments.front());
        },
    };
}

RPCMethod listpayjoins()
{
    return RPCMethod{
        "listpayjoins",
        "EXPERIMENTAL: list Payjoin payments in this wallet load, after a notification barrier.\n"
        "Does not restore prior loads or start a transport for an empty wallet.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "Payments in this load", {PaymentResult("")}},
        RPCExamples{HelpExampleCli("listpayjoins", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            const auto result = WaitForPayjoin(request, Manager(request).Read(wallet));
            CheckResult(result);

            UniValue response{UniValue::VARR};
            for (const auto& payment : result.payments) {
                response.push_back(PaymentJSON(payment));
            }
            return response;
        },
    };
}

RPCMethod cancelpayjoin()
{
    return PaymentCommand("cancelpayjoin",
                          "EXPERIMENTAL: stop negotiation without automatically broadcasting fallback.\n"
                          "Cancellation is not proof of non-delivery; exposed inputs may remain reserved.\n",
                          SenderCommand::Cancel);
}

RPCMethod publishpayjoinfallback()
{
    return PaymentCommand("publishpayjoinfallback",
                          "EXPERIMENTAL: explicitly select and publish the saved original transaction.\n"
                          "Conditions, ownership, storage, and current transaction state are rechecked.\n",
                          SenderCommand::Fallback);
}

RPCMethod retrypayjoin()
{
    return RPCMethod{
        "retrypayjoin",
        "EXPERIMENTAL: retry signing of a saved receiver proposal or publication of the selected transaction.\n"
        "Does not restart preparation or negotiation. An expired negotiation deadline does not itself forbid these actions.\n",
        {
            {"payment_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Payment identifier in this wallet load"},
            {"action", RPCArg::Type::STR, RPCArg::Optional::NO, "Required: signing or publication"},
        },
        CommandResultHelp(),
        RPCExamples{HelpExampleCli("retrypayjoin", "\"payment_id\" signing")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            const auto id = ParseHashV(request.params[0], "payment_id");
            const auto action = request.params[1].get_str();
            if (action != "signing" && action != "publication") throw JSONRPCError(RPC_INVALID_PARAMETER, "action must be signing or publication");

            return CommandJSON(WaitForPayjoin(request, Manager(request).Execute(wallet, id,
                                                                                action == "signing" ? SenderCommand::RetrySigning : SenderCommand::RetryPublication)));
        },
    };
}

std::span<const CRPCCommand> GetPayjoinRPCCommands()
{
    static const CRPCCommand commands[]{
        {"wallet", &sendpayjoin},
        {"wallet", &getpayjoin},
        {"wallet", &listpayjoins},
        {"wallet", &cancelpayjoin},
        {"wallet", &publishpayjoinfallback},
        {"wallet", &retrypayjoin},
    };
    return commands;
}
} // namespace wallet
