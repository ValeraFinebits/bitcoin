// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <net.h>
#include <netbase.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/context.h>
#include <wallet/payjoin/manager.h>
#include <wallet/payjoin/sender.h>
#include <wallet/rpc/payjoin.h>
#include <wallet/rpc/wallet.h>
#include <wallet/scan.h>
#include <wallet/test/payjoin_sender_fixture.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace wallet::payjoin {
namespace {
using namespace std::chrono_literals;

template <typename T>
T Await(std::future<T> future)
{
    BOOST_REQUIRE(future.wait_for(10s) == std::future_status::ready);
    return future.get();
}

struct Barrier {
    std::promise<void> m_entered;
    std::promise<void> m_release;
    std::shared_future<void> m_released{m_release.get_future().share()};
    std::atomic<bool> m_used{false};
    bool m_opened{false};

    void Pause()
    {
        if (m_used.exchange(true)) return;

        m_entered.set_value();
        if (m_released.wait_for(10s) != std::future_status::ready) throw std::runtime_error{"test barrier timed out"};
    }

    void Open()
    {
        if (m_opened) return;

        m_opened = true;
        m_release.set_value();
    }

    ~Barrier() { Open(); }
};

struct ReleaseOnExit {
    std::shared_ptr<Barrier> m_barrier;

    ~ReleaseOnExit() { m_barrier->Open(); }
};

struct ManagerFixture : test::SenderFixture {
    std::shared_ptr<CWallet> m_loaded{m_sender.get(), [](CWallet*) {}};
    std::shared_ptr<CWallet> m_other{m_receiver.get(), [](CWallet*) {}};
    SenderManager m_manager{*m_node.chain, *m_node.args};

    ManagerFixture()
    {
        m_service->Stop();
        m_node.connman->SetNetworkActive(true);

        LOCK(m_sender->cs_wallet);
        m_sender->m_fallback_fee = CFeeRate{1000};
    }

    PaymentRequest Request()
    {
        PaymentRequest request;
        request.uri = m_uri;

        request.relay = "ftp://relay.example";
        request.request_id = "request";
        return request;
    }

    ManagerResult ReadUntil(const uint256& id, PaymentPhase phase)
    {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        ManagerResult result;
        do {
            result = Await(m_manager.Read(m_loaded, id));
            BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
        } while (result.payments.front().payment.phase != phase && std::chrono::steady_clock::now() < deadline);
        BOOST_REQUIRE(result.payments.front().payment.phase == phase);
        return result;
    }

    ~ManagerFixture() { m_manager.Stop(); }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(payjoin_manager_tests, ManagerFixture)

BOOST_AUTO_TEST_CASE(manager_empty_reads_and_unknown_commands_do_not_write)
{
    const auto writes = m_database->WriteCount();

    auto list = Await(m_manager.Read(m_loaded));
    BOOST_CHECK(list.status == CommandStatus::Completed);
    BOOST_CHECK(list.payments.empty());
    BOOST_CHECK(Await(m_manager.Read(m_loaded, uint256::ONE)).status == CommandStatus::NotFound);
    BOOST_CHECK(Await(m_manager.Execute(m_loaded, uint256::ONE, SenderCommand::Cancel)).status == CommandStatus::NotFound);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
}

BOOST_AUTO_TEST_CASE(manager_preaccept_failure_does_not_claim_request_id)
{
    auto request = Request();
    request.timeout_seconds = 0;
    const auto writes = m_database->WriteCount();

    const auto rejected = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE(rejected.error == RequestError::InvalidParameter);
    BOOST_CHECK(rejected.payments.empty());
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);

    request.timeout_seconds.reset();
    const auto accepted = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    BOOST_CHECK(!accepted.duplicate);
    const auto id = accepted.payments.front().payment.id;
    const auto current = ReadUntil(id, PaymentPhase::Attention);
    BOOST_REQUIRE_EQUAL(current.payments.size(), 1);
    BOOST_CHECK(current.payments.front().payment.phase == PaymentPhase::Attention);
    BOOST_CHECK(current.payments.front().payment.original);

    const auto duplicate = Await(m_manager.Send(m_loaded, request));
    BOOST_CHECK(duplicate.duplicate);
    BOOST_CHECK(duplicate.payments.front().payment.id == id);
}

BOOST_AUTO_TEST_CASE(manager_concurrent_idempotency_and_default_identity)
{
    const auto request = Request();

    auto first = std::async(std::launch::async, [&] { return m_manager.Send(m_loaded, request).get(); });
    auto second = std::async(std::launch::async, [&] { return m_manager.Send(m_loaded, request).get(); });
    const auto a = Await(std::move(first));
    const auto b = Await(std::move(second));
    BOOST_REQUIRE_EQUAL(a.payments.size(), 1);
    BOOST_REQUIRE_EQUAL(b.payments.size(), 1);
    BOOST_CHECK(a.payments.front().payment.id == b.payments.front().payment.id);
    BOOST_CHECK(a.duplicate != b.duplicate);

    auto explicit_default = request;
    explicit_default.timeout_seconds = 120;
    const auto conflict = Await(m_manager.Send(m_loaded, explicit_default));
    BOOST_CHECK(conflict.error == RequestError::IdempotencyConflict);
    BOOST_CHECK_EQUAL(Await(m_manager.Read(m_loaded)).payments.size(), 1);
}

BOOST_AUTO_TEST_CASE(manager_concurrent_different_requests_claim_only_one_identifier)
{
    const auto request = Request();
    auto changed = request;
    changed.timeout_seconds = 20;

    auto first = std::async(std::launch::async, [&] { return m_manager.Send(m_loaded, request).get(); });
    auto second = std::async(std::launch::async, [&] { return m_manager.Send(m_loaded, changed).get(); });
    const auto a = Await(std::move(first));
    const auto b = Await(std::move(second));
    BOOST_CHECK((a.error == RequestError::IdempotencyConflict) != (b.error == RequestError::IdempotencyConflict));
    BOOST_CHECK_EQUAL(Await(m_manager.Read(m_loaded)).payments.size(), 1);
}

BOOST_AUTO_TEST_CASE(manager_rechecks_network_policy_before_http_handoff)
{
    auto barrier = std::make_shared<Barrier>();
    auto entered = barrier->m_entered.get_future();
    ReleaseOnExit release{barrier};

    m_database->m_on_write = [barrier](const std::string& type) {
        if (type == test::PAYMENT_RECORD) barrier->Pause();
    };
    auto request = Request();
    request.relay = "https://relay.example";

    const auto accepted = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    Await(std::move(entered));

    m_node.connman->SetNetworkActive(false);
    barrier->Open();

    const auto deadline = std::chrono::steady_clock::now() + 10s;
    ManagerResult current;
    do {
        current = Await(m_manager.Read(m_loaded, id));
    } while (current.payments.front().payment.issue != PaymentIssue::Delivery && std::chrono::steady_clock::now() < deadline);
    BOOST_REQUIRE_EQUAL(current.payments.size(), 1);
    const auto& payment = current.payments.front().payment;
    BOOST_CHECK(payment.issue == PaymentIssue::Delivery);
    BOOST_CHECK(!payment.possibly_exposed);
    BOOST_CHECK(!payment.storage_uncertain);
    BOOST_CHECK(payment.owns_inputs);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);

    const auto cancelled = Await(m_manager.Execute(m_loaded, id, SenderCommand::Cancel));
    BOOST_CHECK(cancelled.status == CommandStatus::Completed);
    BOOST_CHECK(ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(manager_notification_during_settlement_causes_follow_up_without_explicit_refresh)
{
    const auto request = Request();
    const auto accepted = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    (void)Await(m_manager.Read(m_loaded, id));
    const auto published = Await(m_manager.Execute(m_loaded, id, SenderCommand::Fallback));
    BOOST_REQUIRE(published.status == CommandStatus::Completed);
    const auto original = published.payments.front().payment.original;

    auto barrier = std::make_shared<Barrier>();
    auto entered = barrier->m_entered.get_future();
    ReleaseOnExit release{barrier};
    m_database->m_on_write = [barrier](const std::string& type) {
        if (type == test::PAYMENT_RECORD) barrier->Pause();
    };

    CBlock block;
    {
        LOCK(m_sender->cs_wallet);
        block = Confirm(original);
    }
    m_node.validation_signals->TransactionRemovedFromMempool(original, MemPoolRemovalReason::BLOCK, 0);
    Await(std::move(entered));

    auto* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip->GetBlockHash() == block.GetHash());
    BlockValidationState validation;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(validation, tip));
    auto notified = std::make_shared<std::promise<void>>();
    auto notification_done = notified->get_future();
    m_node.chain->requestNotificationBarrier([notified] { notified->set_value(); });
    Await(std::move(notification_done));
    barrier->Open();

    const auto deadline = std::chrono::steady_clock::now() + 10s;
    PaymentSnapshot observed;
    do {
        const auto duplicate = Await(m_manager.Send(m_loaded, request));
        BOOST_REQUIRE(duplicate.duplicate);
        observed = duplicate.payments.front().payment;
    } while (observed.phase != PaymentPhase::Attention && std::chrono::steady_clock::now() < deadline);
    BOOST_CHECK(observed.phase == PaymentPhase::Attention);
    BOOST_CHECK(observed.issue == PaymentIssue::ObservedSpend);
    BOOST_CHECK(!observed.settlement);
    BOOST_CHECK(!observed.storage_uncertain);
    BOOST_CHECK(ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(manager_rpc_shutdown_interrupts_wait_before_service_stop)
{
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;
    WITH_LOCK(context.wallets_mutex, context.wallets.push_back(m_loaded));
    context.payjoin.reset(new SenderManager{*m_node.chain, *m_node.args});
    BOOST_REQUIRE(!IsRPCRunning());

    CRPCTable table;
    for (const auto& command : GetWalletRPCCommands()) {
        table.appendCommand(command.name, &command);
    }
    for (const auto& command : GetPayjoinRPCCommands()) {
        table.appendCommand(command.name, &command);
    }

    struct RpcState {
        node::NodeContext& m_node;
        std::function<void()> m_previous;

        explicit RpcState(node::NodeContext& node)
            : m_node{node}, m_previous{std::exchange(node.rpc_interruption_point, RpcInterruptionPoint)}
        {
            StartRPC();
        }

        ~RpcState()
        {
            InterruptRPC();
            m_node.rpc_interruption_point = std::move(m_previous);
        }
    } rpc_state{m_node};

    if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();

    auto barrier = std::make_shared<Barrier>();
    ReleaseOnExit early_release{barrier};
    auto entered = barrier->m_entered.get_future();
    m_database->m_on_write = [barrier](const std::string& type) {
        if (type == test::PAYMENT_RECORD) barrier->Pause();
    };
    const auto accepted = Await(context.payjoin->Send(m_loaded, Request()));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    Await(std::move(entered));

    auto validation = std::make_shared<Barrier>();
    ReleaseOnExit early_validation_release{validation};
    auto validation_entered = validation->m_entered.get_future();
    m_node.chain->requestNotificationBarrier([validation] { validation->Pause(); });
    Await(std::move(validation_entered));

    auto rpc = std::async(std::launch::async, [&] {
        JSONRPCRequest request;
        request.context = &context;
        request.strMethod = "getpayjoin";
        request.params = UniValue::VARR;
        request.params.push_back(id.GetHex());
        try {
            (void)table.execute(request);
            return 0;
        } catch (const UniValue& error) {
            return error["code"].getInt<int>();
        }
    });
    ReleaseOnExit release{barrier};
    ReleaseOnExit release_validation{validation};
    const auto registration_deadline = std::chrono::steady_clock::now() + 10s;
    while (m_node.validation_signals->CallbacksPending() == 0 && std::chrono::steady_clock::now() < registration_deadline) {
        std::this_thread::yield();
    }

    BOOST_REQUIRE_GT(m_node.validation_signals->CallbacksPending(), 0);
    InterruptRPC();
    BOOST_CHECK_EQUAL(Await(std::move(rpc)), RPC_CLIENT_NOT_CONNECTED);

    barrier->Open();
    validation->Open();

    ManagerResult current;
    const auto observation_deadline = std::chrono::steady_clock::now() + 10s;
    do {
        current = Await(context.payjoin->Read(m_loaded, id));
        BOOST_REQUIRE_EQUAL(current.payments.size(), 1);
    } while (current.payments.front().payment.phase != PaymentPhase::Attention && std::chrono::steady_clock::now() < observation_deadline);
    BOOST_REQUIRE_EQUAL(current.payments.size(), 1);
    BOOST_CHECK(!current.payments.front().payment.storage_uncertain);
    BOOST_CHECK(current.payments.front().payment.phase == PaymentPhase::Attention);
    BOOST_CHECK(Await(context.payjoin->Send(m_loaded, Request())).duplicate);
}

BOOST_AUTO_TEST_CASE(manager_duplicate_ignores_changed_mutable_admission_conditions)
{
    const auto request = Request();
    const auto accepted = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    (void)Await(m_manager.Read(m_loaded, id));
    {
        LOCK(m_sender->cs_wallet);
        m_sender->m_fallback_fee = CFeeRate{3000};
        m_sender->m_max_tx_fee /= 2;
    }
    m_node.connman->SetNetworkActive(false);
    const auto duplicate = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE(duplicate.duplicate);
    BOOST_CHECK(duplicate.payments.front().payment.id == id);
    BOOST_CHECK_EQUAL(duplicate.payments.front().effective.fee_rate.GetFeePerK(), 1000);
    BOOST_CHECK(duplicate.payments.front().payment.deadline == accepted.payments.front().payment.deadline);

    auto new_request = request;
    new_request.request_id = "another";
    BOOST_CHECK(Await(m_manager.Send(m_loaded, new_request)).error == RequestError::NetworkPolicy);

    BOOST_CHECK(Await(m_manager.Execute(m_loaded, id, SenderCommand::Cancel)).status == CommandStatus::Completed);
}

BOOST_AUTO_TEST_CASE(manager_remove_wallet_releases_managed_wallet)
{
    WalletContext context;
    context.args = m_node.args;
    context.chain = m_node.chain.get();
    context.payjoin.reset(new SenderManager{*context.chain, *context.args});
    auto wallet = TestCreateWallet(CreateMockableWalletDatabase(), context, WALLET_FLAG_DESCRIPTORS);
    struct WalletCleanup {
        WalletContext& context;
        std::shared_ptr<CWallet>& wallet;

        ~WalletCleanup()
        {
            context.payjoin->Stop();
            if (wallet) RemoveWallet(context, wallet, std::nullopt);
        }
    } cleanup{context, wallet};
    BOOST_REQUIRE(AddWallet(context, wallet));
    {
        LOCK(wallet->cs_wallet);
        CreateDescriptor(*wallet, "combo(" + EncodeSecret(m_sender_key) + ")", true);
        wallet->m_fallback_fee = CFeeRate{1000};
        wallet->SetBroadcastTransactions(true);
    }
    {
        WalletRescanReserver reserver{*wallet};
        BOOST_REQUIRE(reserver.reserve());
        BOOST_REQUIRE(wallet->Scanner().Scan(context.chain->getBlockHash(0), 0, std::nullopt, reserver, false).status == ScanResult::SUCCESS);
    }
    const auto accepted = Await(context.payjoin->Send(wallet, Request()));
    BOOST_REQUIRE(accepted.status == CommandStatus::Completed);
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    const auto prepared = Await(context.payjoin->Read(wallet, id));
    BOOST_REQUIRE_EQUAL(prepared.payments.size(), 1);
    BOOST_REQUIRE(prepared.payments.front().payment.original);
    BOOST_REQUIRE(prepared.payments.front().payment.owns_inputs);
    std::weak_ptr<CWallet> released = wallet;

    BOOST_REQUIRE(RemoveWallet(context, wallet, std::nullopt));
    BOOST_CHECK(WITH_LOCK(context.wallets_mutex, return context.wallets.empty()));
    const auto stopped = Await(context.payjoin->Read(wallet, id));
    BOOST_CHECK(stopped.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(stopped.payments.size(), 1);
    BOOST_CHECK(stopped.payments.front().payment.phase == PaymentPhase::Stopped);
    m_node.chain->waitForNotifications();
    wallet.reset();
    BOOST_CHECK(released.expired());
}

BOOST_AUTO_TEST_CASE(manager_unload_rejects_old_instance_and_isolates_same_name)
{
    const auto request = Request();
    const auto accepted = Await(m_manager.Send(m_loaded, request));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    (void)Await(m_manager.Read(m_loaded, id));
    m_manager.Unload(m_loaded);
    const auto stopped = Await(m_manager.Execute(m_loaded, id, SenderCommand::Cancel));
    BOOST_CHECK(stopped.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(stopped.payments.size(), 1);
    BOOST_CHECK(stopped.payments.front().payment.phase == PaymentPhase::Stopped);
    BOOST_CHECK(Await(m_manager.Send(m_loaded, request)).status == CommandStatus::Stopped);

    BOOST_CHECK_EQUAL(m_loaded->GetName(), m_other->GetName());
    BOOST_CHECK(Await(m_manager.Read(m_other)).payments.empty());
    auto other_request = request;
    other_request.fee_rate = CFeeRate{1000};
    const auto other = Await(m_manager.Send(m_other, other_request));
    BOOST_REQUIRE_EQUAL(other.payments.size(), 1);
    BOOST_CHECK(!other.duplicate);
    BOOST_CHECK(other.payments.front().payment.id != id);
}

BOOST_AUTO_TEST_CASE(manager_prunes_expired_wallet_archives_but_keeps_live_callers)
{
    std::vector<std::weak_ptr<const CTransaction>> originals;
    std::shared_ptr<CWallet> old_caller;
    uint256 old_id;
    for (int i = 0; i < 8; ++i) {
        m_loaded = std::shared_ptr<CWallet>{m_sender.get(), [](CWallet*) {}};
        const auto accepted = Await(m_manager.Send(m_loaded, Request()));
        BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
        const auto id = accepted.payments.front().payment.id;
        const auto current = ReadUntil(id, PaymentPhase::Attention);
        BOOST_REQUIRE(current.payments.front().payment.original);
        originals.emplace_back(current.payments.front().payment.original);
        m_manager.Unload(m_loaded);
        if (i == 0) {
            old_caller = m_loaded;
            old_id = id;
        }
        m_loaded.reset();
    }

    BOOST_CHECK(Await(m_manager.Read(m_other)).payments.empty());
    for (size_t i = 1; i < originals.size(); ++i) {
        BOOST_CHECK(originals[i].expired());
    }
    BOOST_REQUIRE(!originals.front().expired());
    {
        const auto archived = Await(m_manager.Read(old_caller, old_id));
        BOOST_CHECK(archived.status == CommandStatus::Stopped);
        BOOST_REQUIRE_EQUAL(archived.payments.size(), 1);
        BOOST_CHECK(archived.payments.front().payment.original == originals.front().lock());
    }

    m_manager.Stop();
    {
        const auto archived = Await(m_manager.Read(old_caller, old_id));
        BOOST_CHECK(archived.status == CommandStatus::Stopped);
        BOOST_REQUIRE_EQUAL(archived.payments.size(), 1);
        BOOST_CHECK(archived.payments.front().payment.original == originals.front().lock());
    }
    old_caller.reset();
    BOOST_CHECK(Await(m_manager.Read(m_other)).status == CommandStatus::Stopped);
    BOOST_CHECK(originals.front().expired());
}

BOOST_AUTO_TEST_CASE(manager_unload_waits_for_current_wallet_work_and_finishes_pending_commands)
{
    auto barrier = std::make_shared<Barrier>();
    ReleaseOnExit early_release{barrier};
    auto entered = barrier->m_entered.get_future();
    m_database->m_on_write = [barrier](const std::string& type) {
        if (type == test::PAYMENT_RECORD) barrier->Pause();
    };

    const auto accepted = Await(m_manager.Send(m_loaded, Request()));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    Await(std::move(entered));

    auto command = m_manager.Execute(m_loaded, id, SenderCommand::Cancel);
    auto unload = std::async(std::launch::async, [&] { m_manager.Unload(m_loaded); });
    ReleaseOnExit release{barrier};
    BOOST_CHECK(command.wait_for(0s) == std::future_status::timeout);
    BOOST_CHECK(unload.wait_for(0s) == std::future_status::timeout);
    barrier->Open();
    Await(std::move(unload));

    const auto result = Await(std::move(command));
    BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
    BOOST_CHECK(result.status == CommandStatus::Completed || result.status == CommandStatus::Stopped);
    BOOST_CHECK(!result.payments.front().payment.storage_uncertain);
    BOOST_CHECK_EQUAL(m_loaded.use_count(), 1);
    BOOST_CHECK(Await(m_manager.Read(m_loaded, id)).status == CommandStatus::Stopped);
}

BOOST_AUTO_TEST_CASE(manager_stop_returns_final_snapshots_without_restarting_worker)
{
    const auto accepted = Await(m_manager.Send(m_loaded, Request()));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    (void)Await(m_manager.Read(m_loaded, id));
    m_manager.Stop();

    for (const auto command : {SenderCommand::Cancel, SenderCommand::Fallback, SenderCommand::RetryPublication}) {
        const auto stopped = Await(m_manager.Execute(m_loaded, id, command));
        BOOST_CHECK(stopped.status == CommandStatus::Stopped);
        BOOST_REQUIRE_EQUAL(stopped.payments.size(), 1);
        BOOST_CHECK(stopped.payments.front().payment.phase == PaymentPhase::Stopped);
        BOOST_CHECK(!stopped.payments.front().payment.storage_uncertain);
    }
    BOOST_REQUIRE_EQUAL(Await(m_manager.Read(m_loaded, id)).payments.size(), 1);
    BOOST_CHECK(Await(m_manager.Execute(m_other, uint256::ONE, SenderCommand::Cancel)).status == CommandStatus::Stopped);
    BOOST_CHECK_EQUAL(m_loaded.use_count(), 1);
}

BOOST_AUTO_TEST_CASE(manager_preparation_barrier_does_not_delay_stop_or_touch_destroyed_runner)
{
    auto barrier = std::make_shared<Barrier>();
    auto entered = barrier->m_entered.get_future();
    ReleaseOnExit release{barrier};
    m_node.chain->requestNotificationBarrier([barrier] { barrier->Pause(); });
    Await(std::move(entered));
    const auto writes = m_database->WriteCount();
    const auto accepted = Await(m_manager.Send(m_loaded, Request()));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    const auto queued = Await(m_manager.Execute(m_loaded, id, SenderCommand::Refresh));
    BOOST_REQUIRE_EQUAL(queued.payments.size(), 1);
    BOOST_CHECK(queued.payments.front().payment.phase == PaymentPhase::Queued);
    BOOST_CHECK(!queued.payments.front().payment.original);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);

    m_manager.Stop();
    BOOST_CHECK_EQUAL(m_loaded.use_count(), 1);
    BOOST_CHECK(!HasStoredPayment(id));
    const auto archived = Await(m_manager.Read(m_loaded, id));
    BOOST_CHECK(archived.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(archived.payments.size(), 1);
    BOOST_CHECK(archived.payments.front().payment.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!archived.payments.front().payment.original);
    BOOST_CHECK(!archived.payments.front().payment.owns_inputs);

    barrier->Open();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    const auto final = Await(m_manager.Read(m_loaded, id));
    BOOST_REQUIRE_EQUAL(final.payments.size(), 1);
    BOOST_CHECK(final.payments.front().payment.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!final.payments.front().payment.original);
}

BOOST_AUTO_TEST_CASE(manager_read_barrier_does_not_delay_stop_or_touch_destroyed_runner)
{
    const auto accepted = Await(m_manager.Send(m_loaded, Request()));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    (void)Await(m_manager.Read(m_loaded, id));

    auto barrier = std::make_shared<Barrier>();
    auto entered = barrier->m_entered.get_future();
    ReleaseOnExit release{barrier};
    m_node.chain->requestNotificationBarrier([barrier] { barrier->Pause(); });
    Await(std::move(entered));
    auto read = m_manager.Read(m_loaded, id);
    m_manager.Stop();
    BOOST_REQUIRE(read.wait_for(0s) == std::future_status::ready);
    const auto final = read.get();
    BOOST_CHECK(final.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(final.payments.size(), 1);
    BOOST_CHECK(final.payments.front().payment.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!final.payments.front().payment.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).released);
    BOOST_CHECK_EQUAL(m_loaded.use_count(), 1);
    const auto writes = m_database->WriteCount();

    barrier->Open();
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    const auto archived = Await(m_manager.Read(m_loaded, id));
    BOOST_CHECK(archived.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(archived.payments.size(), 1);
    BOOST_CHECK(archived.payments.front().payment.original->Equals(*final.payments.front().payment.original));
    BOOST_CHECK(!archived.payments.front().payment.owns_inputs);
}

BOOST_AUTO_TEST_CASE(manager_read_accounts_for_mempool_changes_without_external_barrier)
{
    const auto accepted = Await(m_manager.Send(m_loaded, Request()));
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    (void)Await(m_manager.Read(m_loaded, id));
    const auto published = Await(m_manager.Execute(m_loaded, id, SenderCommand::Fallback));
    BOOST_REQUIRE(published.status == CommandStatus::Completed);
    const auto selected = published.payments.front().payment.selected;
    BOOST_REQUIRE(selected);
    BOOST_REQUIRE(m_node.mempool->exists(selected->GetHash()));

    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*selected, MemPoolRemovalReason::EXPIRY);
    }
    m_sender->transactionRemovedFromMempool(selected, MemPoolRemovalReason::EXPIRY);
    m_node.validation_signals->TransactionRemovedFromMempool(selected, MemPoolRemovalReason::EXPIRY, 0);

    const auto read = Await(m_manager.Read(m_loaded, id));
    BOOST_REQUIRE_EQUAL(read.payments.size(), 1);
    BOOST_CHECK(read.payments.front().payment.selected_presence == TransactionPresence::Inactive);
    BOOST_CHECK(read.payments.front().payment.node_accepted);
    BOOST_CHECK(read.payments.front().payment.owns_inputs);
    BOOST_CHECK(!read.payments.front().payment.settlement);
    BOOST_CHECK(!m_node.mempool->exists(selected->GetHash()));
    BOOST_CHECK(!ReadStoredPayment(id).released);

    LOCK(m_sender->cs_wallet);

    for (const auto& input : read.payments.front().payment.original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
        BOOST_CHECK(!m_sender->IsLockedCoin(input.prevout));
        BOOST_CHECK(!LockedMarker(input.prevout));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet::payjoin
