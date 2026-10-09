// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <common/types.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <interfaces/chain.h>
#include <kernel/chain.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <node/context.h>
#include <node/types.h>
#include <payjoin/client.h>
#include <payjoin/transport.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <scheduler.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/btcsignals.h>
#include <util/task_runner.h>
#include <util/ui_change_type.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/db.h>
#include <wallet/payjoin/sender.h>
#include <wallet/spend.h>
#include <wallet/test/payjoin_sender_fixture.h>
#include <wallet/test/payjoin_test_transport.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <initializer_list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace wallet::payjoin {
using namespace test;

namespace {
size_t WriteCount(const std::map<std::string, size_t>& writes, const std::string& type)
{
    const auto count = writes.find(type);
    return count == writes.end() ? 0 : count->second;
}

class ValidationQueuePause
{
    interfaces::Chain& m_chain;
    std::shared_ptr<std::promise<void>> m_release{std::make_shared<std::promise<void>>()};
    std::future<void> m_entered;

public:
    explicit ValidationQueuePause(interfaces::Chain& chain) : m_chain{chain}
    {
        auto entered = std::make_shared<std::promise<void>>();
        m_entered = entered->get_future();
        m_chain.requestNotificationBarrier([entered, release = m_release->get_future().share()] {
            entered->set_value();
            release.wait();
        });
    }

    void Wait() { BOOST_REQUIRE(m_entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready); }

    void Open()
    {
        if (!m_release) return;

        m_release->set_value();
        m_release.reset();
    }

    ~ValidationQueuePause()
    {
        Open();
        m_chain.waitForNotifications();
    }
};
} // namespace

class InlineCompletionTransport final : public ControlledTransport
{
public:
    bool m_complete_on_submit{false};
    bool m_complete_on_cancel{false};
    size_t m_completions{0};

    SubmitResult Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion callback) override
    {
        auto counted = [this, callback = std::move(callback)](TransportResult result) {
            ++m_completions;
            callback(std::move(result));
        };
        const auto result = ControlledTransport::Submit(id, std::move(request), timeout, std::move(counted));
        if (result == SubmitResult::Accepted && m_complete_on_submit) {
            auto complete = std::move(m_pending.back().complete);
            m_pending.pop_back();
            complete({Delivery::NotSent, {}, "inline submit completion"});
        }
        return result;
    }

    void Cancel(uint64_t id) override
    {
        ControlledTransport::Cancel(id);
        if (!m_complete_on_cancel) return;

        const auto pending = std::find_if(m_pending.begin(), m_pending.end(), [id](const auto& request) { return request.id == id; });
        if (pending == m_pending.end()) return;

        auto complete = std::move(pending->complete);
        m_pending.erase(pending);
        complete({Delivery::NotSent, {}, "inline cancel completion"});
    }
};

struct InlineCompletionFixture : SenderFixture {
    InlineCompletionFixture() : SenderFixture{Execution::Controlled, std::make_unique<InlineCompletionTransport>()} {}

    InlineCompletionTransport& InlineTransport() { return static_cast<InlineCompletionTransport&>(*m_transport); }
};

class BlockingCompletionTransport final : public ControlledTransport
{
public:
    std::promise<void> m_entered;
    std::shared_future<void> m_release;
    Completion m_completion;

    explicit BlockingCompletionTransport(std::shared_future<void> unblock) : m_release{std::move(unblock)} {}

    SubmitResult Submit(uint64_t, SenderRequest, std::chrono::milliseconds, Completion callback) override
    {
        if (m_stopped) return SubmitResult::Stopped;

        m_completion = std::move(callback);
        m_entered.set_value();
        m_release.wait();
        return SubmitResult::Accepted;
    }

    void Cancel(uint64_t id) override
    {
        ControlledTransport::Cancel(id);
        if (auto complete = std::exchange(m_completion, {})) complete({Delivery::NotSent, {}, "inline cancel during stop"});
    }

    void Stop() override
    {
        if (m_stopped) return;

        ControlledTransport::Stop();
        if (auto complete = std::exchange(m_completion, {})) complete({Delivery::NotSent, {}, "stop completion"});
    }
};

class BlockingStopTransport final : public ControlledTransport
{
public:
    std::promise<void> m_entered;
    std::shared_future<void> m_release;

    explicit BlockingStopTransport(std::shared_future<void> unblock) : m_release{std::move(unblock)} {}

    void Stop() override
    {
        if (m_stopped) return;

        m_entered.set_value();
        m_release.wait();
        ControlledTransport::Stop();
    }
};

class SchedulerTestCleanup
{
    CScheduler& m_scheduler;
    std::unique_ptr<SenderService>& m_service;
    std::promise<void>* m_barrier;

public:
    std::thread m_stopper;

    explicit SchedulerTestCleanup(CScheduler& scheduler, std::unique_ptr<SenderService>& service, std::promise<void>* barrier = nullptr)
        : m_scheduler{scheduler}, m_service{service}, m_barrier{barrier} {}

    void Release()
    {
        if (auto* barrier = std::exchange(m_barrier, nullptr)) barrier->set_value();
    }

    ~SchedulerTestCleanup()
    {
        Release();
        if (m_stopper.joinable()) m_stopper.join();
        if (m_service) m_service->Stop();
        m_scheduler.stop();
    }
};

class DestructionObservedTransport final : public ControlledTransport
{
    bool& m_destroyed;

public:
    explicit DestructionObservedTransport(bool& destroyed) : m_destroyed{destroyed} {}

    ~DestructionObservedTransport() override { m_destroyed = true; }
};

#ifdef DEBUG_LOCKCONTENTION
class StopLockProbe
{
    const bool m_enabled{LogInstance().WillLogCategory(BCLog::LOCK)};
    const std::unordered_map<BCLog::LogFlags, BCLog::Level> m_levels{LogInstance().CategoryLevels()};
    std::promise<void> m_entered;
    DebugLogHelper m_log{"lock contention m_state->m_gate, ", [this](const std::string* line) {
                             if (!line || line->find("sender.cpp:") == std::string::npos ||
                                 line->find(" started") == std::string::npos) return false;
                             m_entered.set_value();
                             return true;
                         }};

public:
    StopLockProbe()
    {
        LogInstance().EnableCategory(BCLog::LOCK);
        LogInstance().AddCategoryLogLevel(BCLog::LOCK, BCLog::Level::Debug);
    }

    ~StopLockProbe()
    {
        LogInstance().SetCategoryLogLevel(m_levels);
        if (!m_enabled) LogInstance().DisableCategory(BCLog::LOCK);
    }

    auto Entered() { return m_entered.get_future(); }
};
#endif

class UncertainStopTransport final : public ControlledTransport
{
public:
    void Stop() override
    {
        if (m_stopped) return;
        m_stopped = true;
        for (auto& request : m_pending) {
            request.complete({Delivery::Uncertain, {}, "delivery unknown at stop"});
        }
        m_pending.clear();
    }
};

struct UncertainStopFixture : SenderFixture {
    UncertainStopFixture() : SenderFixture{Execution::Controlled, std::make_unique<UncertainStopTransport>()} {}
};

std::map<std::string, std::string> ReadRecords(FaultDatabase& database, std::initializer_list<std::string> types)
{
    std::map<std::string, std::string> records;
    auto batch = database.MakeBatch();
    for (const auto& type : types) {
        auto cursor = batch->GetNewPrefixCursor(DataStream{} << type);
        BOOST_REQUIRE(cursor);
        while (true) {
            DataStream key, value;
            const auto status = cursor->Next(key, value);
            if (status == DatabaseCursor::Status::DONE) break;
            BOOST_REQUIRE(status == DatabaseCursor::Status::MORE);
            BOOST_REQUIRE(records.emplace(key.str(), value.str()).second);
        }
    }
    return records;
}

COutPoint ReserveForeignCoin(SenderFixture& fixture)
{
    LOCK(fixture.m_sender->cs_wallet);
    BOOST_REQUIRE(!fixture.m_sender->mapWallet.empty());
    const auto& tx = fixture.m_sender->mapWallet.begin()->second.GetTx();
    BOOST_REQUIRE(fixture.m_sender->IsMine(tx->vout[0]));
    const COutPoint coin{tx->GetHash(), 0};
    fixture.WriteOwner(coin, uint256::ONE);
    BOOST_REQUIRE(fixture.m_sender->LockCoin(coin, true));
    return coin;
}

void CheckNoPublication(SenderFixture& fixture, const PaymentSnapshot& view)
{
    BOOST_REQUIRE(view.original);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK(!view.selection_saved);
    BOOST_CHECK(!view.wallet_recorded);
    BOOST_CHECK(!view.node_accepted);

    BOOST_CHECK(!fixture.m_node.mempool->exists(view.original->GetHash()));

    LOCK(fixture.m_sender->cs_wallet);
    BOOST_CHECK(!fixture.m_sender->mapWallet.contains(view.original->GetHash()));
}

void CheckRetainedReservations(SenderFixture& fixture, const PaymentSnapshot& view)
{
    BOOST_REQUIRE(view.original);
    BOOST_CHECK(view.original_saved);
    BOOST_CHECK(view.owns_inputs);

    BOOST_CHECK(!fixture.ReadStoredPayment(view.id).released);

    LOCK(fixture.m_sender->cs_wallet);
    fixture.CheckOwnedInputs(view.id, *view.original);
}

void CheckJournalCreationFailure(SenderFixture& fixture, const uint256& id, const std::string& diagnostic)
{
    const auto view = *fixture.m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK_EQUAL(view.diagnostic, diagnostic);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(fixture.m_transport->m_attempts, 0);
    BOOST_CHECK(fixture.m_transport->m_pending.empty());

    CheckNoPublication(fixture, view);
    CheckRetainedReservations(fixture, view);

    const auto stored = fixture.ReadStoredPayment(id);
    BOOST_CHECK(stored.selected.empty());
    BOOST_CHECK(!stored.exposed);

    auto fallback_future = fixture.m_service->Execute(id, SenderCommand::Fallback);
    fixture.Flush();

    const auto fallback_result = fallback_future.get();
    BOOST_CHECK(fallback_result.refusal == CommandRefusal::StorageUncertain);
    CheckNoPublication(fixture, *fixture.m_service->Snapshot(id));
}

void CheckPreparationWithPendingBlock(SenderFixture& fixture, bool send)
{
    CTransactionRef spend;
    {
        LOCK(fixture.m_sender->cs_wallet);
        CCoinControl control;
        control.m_feerate = CFeeRate{1000};
        const auto created = CreateTransaction(*fixture.m_sender, {{WitnessV0KeyHash{fixture.m_receiver_key.GetPubKey()}, 99 * COIN, false}}, std::nullopt, control);
        BOOST_REQUIRE(created);
        spend = created->tx;
        BOOST_REQUIRE_EQUAL(spend->vin.size(), 2);
    }

    auto notifications = fixture.m_node.chain->handleNotifications(std::shared_ptr<CWallet>{fixture.m_sender.get(), [](CWallet*) {}});
    ValidationQueuePause validation{*fixture.m_node.chain};
    validation.Wait();
    const auto wallet_tip = WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->GetLastBlockHash());
    const auto block = fixture.CreateAndProcessBlock({CMutableTransaction{*spend}}, GetScriptForDestination(WitnessV0KeyHash{fixture.m_receiver_key.GetPubKey()}));
    BOOST_REQUIRE(WITH_LOCK(cs_main, return fixture.m_node.chainman->ActiveChain().Tip()->GetBlockHash()) == block.GetHash());
    BOOST_REQUIRE(WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->GetLastBlockHash()) == wallet_tip);

    std::map<COutPoint, Coin> coins;
    for (const auto& input : spend->vin) {
        coins.emplace(input.prevout, Coin{});
        BOOST_REQUIRE(!WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsSpent(input.prevout)));
    }
    fixture.m_node.chain->findCoins(coins);
    for (const auto& [outpoint, coin] : coins) {
        BOOST_REQUIRE(coin.IsSpent());
    }
    const auto writes = fixture.m_database->WriteCount();

    uint256 id;
    if (send) {
        PaymentRequest request;
        request.uri = fixture.m_uri;
        request.relay = fixture.m_relay;
        request.fee_rate = CFeeRate{1000};
        auto accepted = fixture.m_service->Send(std::move(request));
        fixture.m_queue->flush();
        BOOST_REQUIRE(accepted.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
        const auto result = accepted.get();
        BOOST_REQUIRE(result.status == CommandStatus::Completed);
        BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
        id = result.payments.front().payment.id;
    } else {
        id = fixture.m_service->Start(fixture.Intent());
        fixture.m_queue->flush();
    }

    const auto queued = *fixture.m_service->Snapshot(id);
    BOOST_CHECK(queued.phase == PaymentPhase::Queued);
    BOOST_CHECK(!queued.original);
    BOOST_CHECK(!queued.original_saved);
    BOOST_CHECK(!queued.possibly_exposed);
    BOOST_CHECK(!queued.transport_accepted);
    BOOST_CHECK(!fixture.HasStoredPayment(id));
    BOOST_CHECK_EQUAL(fixture.m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(fixture.m_transport->m_attempts, 0);
    for (const auto& input : spend->vin) {
        BOOST_CHECK(!fixture.HasOwner(input.prevout));
        BOOST_CHECK(!fixture.LockedMarker(input.prevout));
        BOOST_CHECK(!WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsLockedCoin(input.prevout)));
    }

    validation.Open();
    fixture.Flush();

    BOOST_REQUIRE(WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->GetLastBlockHash()) == block.GetHash());
    for (const auto& input : spend->vin) {
        BOOST_CHECK(WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsSpent(input.prevout)));
    }
    const auto failed = *fixture.m_service->Snapshot(id);
    BOOST_CHECK(failed.phase == PaymentPhase::Attention);
    BOOST_CHECK(failed.issue == PaymentIssue::Preparation);
    BOOST_CHECK(!failed.original);
    BOOST_CHECK(!failed.owns_inputs);
    BOOST_CHECK(!failed.possibly_exposed);
    BOOST_CHECK(!fixture.HasStoredPayment(id));
    BOOST_CHECK_EQUAL(fixture.m_transport->m_attempts, 0);
    BOOST_CHECK(fixture.m_transport->m_pending.empty());
}

BOOST_FIXTURE_TEST_SUITE(payjoin_sender_tests, SenderFixture)

BOOST_AUTO_TEST_CASE(sender_start_preparation_accounts_for_pending_block)
{
    CheckPreparationWithPendingBlock(*this, false);
}

BOOST_AUTO_TEST_CASE(sender_send_preparation_accounts_for_pending_block)
{
    CheckPreparationWithPendingBlock(*this, true);
}

BOOST_AUTO_TEST_CASE(sender_preparation_barrier_preserves_idempotency)
{
    ValidationQueuePause validation{*m_node.chain};
    validation.Wait();
    const auto writes = m_database->WriteCount();
    PaymentRequest request;
    request.uri = m_uri;
    request.relay = m_relay;
    request.fee_rate = CFeeRate{1000};
    request.request_id = "pending-preparation";
    auto first = m_service->Send(request);
    auto repeat = m_service->Send(request);
    m_queue->flush();
    BOOST_REQUIRE(first.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    BOOST_REQUIRE(repeat.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    const auto accepted = first.get();
    const auto duplicate = repeat.get();
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    BOOST_REQUIRE_EQUAL(duplicate.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    BOOST_CHECK(!accepted.duplicate);
    BOOST_CHECK(duplicate.duplicate);
    BOOST_CHECK(duplicate.payments.front().payment.id == id);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Queued);
    BOOST_CHECK(!m_service->Snapshot(id)->original);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);

    request.relay = "https://other-relay.example";
    auto conflict = m_service->Send(request);
    m_queue->flush();
    BOOST_CHECK(conflict.get().error == RequestError::IdempotencyConflict);

    validation.Open();
    Flush();
    const auto prepared = *m_service->Snapshot(id);
    BOOST_REQUIRE(prepared.original);
    BOOST_CHECK(prepared.original_saved);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);
    BOOST_CHECK_EQUAL(m_transport->m_pending.size(), 1);
    LOCK(m_sender->cs_wallet);
    CheckOwnedInputs(id, *prepared.original);
}

BOOST_AUTO_TEST_CASE(sender_cancel_before_preparation_barrier_prevents_wallet_work)
{
    ValidationQueuePause validation{*m_node.chain};
    validation.Wait();
    const auto writes = m_database->WriteCount();
    const auto id = m_service->Start(Intent());
    auto cancellation = m_service->Execute(id, SenderCommand::Cancel);
    m_queue->flush();
    BOOST_REQUIRE(cancellation.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    BOOST_CHECK(cancellation.get().status == CommandStatus::Completed);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);

    validation.Open();
    Flush();
    const auto cancelled = *m_service->Snapshot(id);
    BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!cancelled.original);
    BOOST_CHECK(!cancelled.owns_inputs);
    BOOST_CHECK(!cancelled.possibly_exposed);
    BOOST_CHECK(!HasStoredPayment(id));
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
}

BOOST_AUTO_TEST_CASE(sender_preparation_barrier_wait_counts_towards_deadline)
{
    ValidationQueuePause validation{*m_node.chain};
    validation.Wait();
    auto intent = Intent();
    const auto writes = m_database->WriteCount();
    const auto timeout = intent.timeout;
    const auto id = m_service->Start(std::move(intent));
    m_now += timeout;

    validation.Open();
    Flush();
    const auto expired = *m_service->Snapshot(id);
    BOOST_CHECK(expired.phase == PaymentPhase::Attention);
    BOOST_CHECK(expired.issue == PaymentIssue::Deadline);
    BOOST_CHECK(!expired.original);
    BOOST_CHECK(!expired.owns_inputs);
    BOOST_CHECK(!expired.possibly_exposed);
    BOOST_CHECK(!HasStoredPayment(id));
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
}

BOOST_AUTO_TEST_CASE(sender_command_results_belong_to_each_invocation)
{
    const auto id = m_service->Start(Intent());
    Flush();
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    auto request = std::move(m_transport->m_pending.front());
    m_transport->m_pending.pop_front();
    request.complete({Delivery::NotSent, {}, "delivery failed"});
    Flush();
    auto refused = m_service->Execute(id, SenderCommand::RetryPublication);
    auto cancelled = m_service->Execute(id, SenderCommand::Cancel);
    Flush();

    const auto first = refused.get();
    const auto second = cancelled.get();
    BOOST_CHECK(first.status == CommandStatus::Refused);
    BOOST_REQUIRE_EQUAL(first.payments.size(), 1);
    BOOST_CHECK(first.refusal == CommandRefusal::InvalidState);

    // A command refusal must not overwrite the payment's delivery problem.
    BOOST_CHECK(first.payments.front().payment.issue == PaymentIssue::Delivery);
    BOOST_CHECK(second.status == CommandStatus::Completed);
    BOOST_REQUIRE_EQUAL(second.payments.size(), 1);
    const auto& payment = second.payments.front().payment;
    BOOST_CHECK(payment.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!second.refusal);
    BOOST_CHECK(!payment.owns_inputs);
    BOOST_REQUIRE(payment.original);
    BOOST_CHECK(ReadStoredPayment(id).released);
    for (const auto& input : payment.original->vin) {
        BOOST_CHECK(!HasOwner(input.prevout));
        BOOST_CHECK(!LockedMarker(input.prevout));
    }
}

BOOST_AUTO_TEST_CASE(sender_unknown_command_completes_without_storage_effects)
{
    const auto writes = m_database->WriteCount();
    auto future = m_service->Execute(uint256::ONE, SenderCommand::Cancel);
    Flush();

    const auto result = future.get();
    BOOST_CHECK(result.status == CommandStatus::NotFound);
    BOOST_CHECK(result.payments.empty());
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_stop_completes_commands_that_never_started)
{
    const auto id = m_service->Start(Intent());
    auto future = m_service->Execute(id, SenderCommand::Cancel);
    m_service->Stop();

    BOOST_REQUIRE(future.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    const auto result = future.get();
    BOOST_CHECK(result.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
    BOOST_CHECK(result.payments.front().payment.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!result.payments.front().payment.storage_uncertain);
    BOOST_CHECK(!result.payments.front().payment.original);
    Flush();
    const auto after = m_service->Execute(id, SenderCommand::Refresh).get();
    BOOST_CHECK(after.status == CommandStatus::Stopped);
    BOOST_CHECK(after.payments.front().payment.phase == result.payments.front().payment.phase);
}

BOOST_AUTO_TEST_CASE(sender_stop_waits_for_active_operation_without_draining_timers)
{
    CScheduler scheduler;
    SerialTaskRunner executor{scheduler};
    std::promise<void> unblock;
    const auto released = unblock.get_future().share();
    std::promise<void> entered;
    auto operation_entered = entered.get_future();
    auto transport = [&] {
        entered.set_value();
        released.wait();
        return std::make_unique<ControlledTransport>();
    };
    auto schedule = [&scheduler](std::chrono::milliseconds delay, std::function<void()> fn) {
        scheduler.scheduleFromNow(std::move(fn), delay);
    };
    auto scheduled = std::make_unique<SenderService>(
        *m_sender, executor, std::move(transport), SenderService::Clock::now,
        std::move(schedule), SenderService::NetworkCheck{});
    std::promise<void> closed;
    auto admission_closed = closed.get_future();
    std::promise<void> finished;
    auto stopped = finished.get_future();
    SchedulerTestCleanup cleanup{scheduler, scheduled, &unblock};
    scheduler.m_service_thread = std::thread{[&] { scheduler.serviceQueue(); }};
    scheduler.scheduleFromNow([] { BOOST_ERROR("future timer must not be drained during Stop"); }, std::chrono::hours{24});

    PaymentRequest request;
    request.uri = m_uri;
    request.relay = m_relay;
    request.fee_rate = CFeeRate{1000};
    auto accepted = scheduled->Send(request);
    BOOST_REQUIRE(operation_entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    cleanup.m_stopper = std::thread{[&] {
        scheduled->Close();
        closed.set_value();
        scheduled->Stop();
        finished.set_value();
    }};
    BOOST_REQUIRE(admission_closed.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    auto during_stop = scheduled->Execute(uint256::ONE, SenderCommand::Cancel);
    BOOST_CHECK(during_stop.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    BOOST_CHECK(stopped.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    cleanup.Release();

    BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_REQUIRE(accepted.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    const auto result = accepted.get();

    BOOST_CHECK(result.status == CommandStatus::Completed);
    BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
    BOOST_CHECK(result.payments.front().payment.phase == PaymentPhase::Queued);
    BOOST_CHECK(during_stop.get().status == CommandStatus::Stopped);
    const auto id = result.payments.front().payment.id;
    BOOST_CHECK(scheduled->Read(id).get().payments.front().payment.phase == PaymentPhase::Stopped);
    cleanup.m_stopper.join();
}

BOOST_AUTO_TEST_CASE(sender_command_reports_partial_storage_failure)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_queue->insert([&] { m_database->FailNextWrite(FaultDatabase::WriteTarget::JournalClose); });
    auto future = m_service->Execute(id, SenderCommand::Cancel);
    Flush();

    m_database->CheckWriteFailed();
    const auto result = future.get();
    BOOST_CHECK(result.status == CommandStatus::Failed);
    BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
    BOOST_CHECK(result.payments.front().payment.storage_uncertain);
    BOOST_CHECK(result.payments.front().payment.owns_inputs);
    BOOST_CHECK(result.payments.front().payment.issue == PaymentIssue::Storage);
}

BOOST_AUTO_TEST_CASE(sender_api_registration_does_not_wait_for_wallet_execution)
{
    CScheduler scheduler;
    SerialTaskRunner executor{scheduler};
    std::promise<void> unblock;
    auto transport = std::make_unique<BlockingCompletionTransport>(unblock.get_future().share());
    auto entered = transport->m_entered.get_future();
    auto* controlled = transport.get();
    auto scheduled = std::make_unique<SenderService>(
        *m_sender, executor, std::move(transport), SenderService::Clock::now,
        [&scheduler](std::chrono::milliseconds delay, std::function<void()> fn) { scheduler.scheduleFromNow(std::move(fn), delay); });
    SchedulerTestCleanup cleanup{scheduler, scheduled, &unblock};
    scheduler.m_service_thread = std::thread{[&] { scheduler.serviceQueue(); }};
    const auto id = scheduled->Start(Intent());
    BOOST_REQUIRE(entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    const auto duplicate_completion = controlled->m_completion;

    auto registration = std::async(std::launch::async, [&] {
        std::vector<std::future<ManagerResult>> operations;
        operations.push_back(scheduled->Send({}));
        operations.push_back(scheduled->Read(id));
        operations.push_back(scheduled->Execute(id, SenderCommand::Cancel));
        return operations;
    });

    struct ReleaseOnExit {
        SchedulerTestCleanup& m_cleanup;

        ~ReleaseOnExit() { m_cleanup.Release(); }
    } release{cleanup};

    BOOST_REQUIRE(registration.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    auto operations = registration.get();
    scheduled->Close();
    cleanup.Release();
    scheduled->Stop();
    for (auto& operation : operations) {
        BOOST_REQUIRE(operation.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
        const auto result = operation.get();
        BOOST_CHECK(result.status == CommandStatus::Stopped);
        BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
        BOOST_CHECK(!result.payments.front().payment.possibly_exposed);
        BOOST_CHECK(!result.payments.front().payment.owns_inputs);
    }
    const auto final = scheduled->Snapshot(id);
    BOOST_REQUIRE(final && final->original);
    BOOST_CHECK(ReadStoredPayment(id).released);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);
    for (const auto& input : final->original->vin) {
        BOOST_CHECK(!HasOwner(input.prevout));
        BOOST_CHECK(!LockedMarker(input.prevout));
        BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
    }
    const auto writes = m_database->WriteCount();
    BOOST_CHECK(!controlled->m_completion);
    duplicate_completion({Delivery::Response, {1, 2, 3}, "late protocol response"});
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
}

BOOST_AUTO_TEST_CASE(sender_transport_creation_failure_does_not_accept_or_claim_identifier)
{
    m_service->Stop();
    bool fail{true};
    size_t creations{0};
    m_transport = nullptr;
    auto factory = [&] {
        ++creations;
        if (fail) throw std::runtime_error{"transport creation failed"};
        auto transport = std::make_unique<ControlledTransport>();
        m_transport = transport.get();
        return transport;
    };
    auto schedule = [this](std::chrono::milliseconds delay, std::function<void()> fn) {
        m_timers.emplace(m_now + delay, std::move(fn));
    };
    m_service = std::make_unique<SenderService>(*m_sender, *m_queue, std::move(factory), [this] { return m_now; }, std::move(schedule), SenderService::NetworkCheck{});

    PaymentRequest request;
    request.uri = m_uri;
    request.relay = m_relay;
    request.fee_rate = CFeeRate{1000};
    request.request_id = "transport-failure";
    const auto writes = m_database->WriteCount();
    auto invalid = request;
    invalid.timeout_seconds = 0;
    auto rejected = m_service->Send(invalid);
    Flush();
    BOOST_CHECK(rejected.get().error == RequestError::InvalidParameter);
    BOOST_CHECK_EQUAL(creations, 0);

    auto first = m_service->Send(request);
    Flush();
    const auto failed = first.get();
    BOOST_CHECK(failed.status == CommandStatus::Failed);
    BOOST_CHECK(failed.error == RequestError::Internal);
    BOOST_CHECK(failed.payments.empty());
    BOOST_CHECK_EQUAL(creations, 1);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);

    fail = false;

    (void)m_service->Send(request);
    Flush();
    auto repeat = m_service->Send(request);
    Flush();
    const auto duplicate = repeat.get();
    BOOST_REQUIRE(duplicate.duplicate);
    BOOST_REQUIRE_EQUAL(duplicate.payments.size(), 1);
    BOOST_CHECK_EQUAL(creations, 2);
    const auto& payment = duplicate.payments.front().payment;
    BOOST_REQUIRE(payment.original);
    BOOST_CHECK(HasStoredPayment(payment.id));
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);
    LOCK(m_sender->cs_wallet);
    CheckOwnedInputs(payment.id, *payment.original);
}

BOOST_AUTO_TEST_CASE(sender_operations_during_transport_stop_receive_final_delivery_state)
{
    m_service->Stop();
    std::promise<void> unblock;
    auto transport = std::make_unique<BlockingStopTransport>(unblock.get_future().share());
    auto entered = transport->m_entered.get_future();
    m_transport = transport.get();
    auto schedule = [this](std::chrono::milliseconds delay, std::function<void()> fn) {
        m_timers.emplace(m_now + delay, std::move(fn));
    };
    m_service = std::make_unique<SenderService>(*m_sender, *m_queue, std::move(transport), [this] { return m_now; }, std::move(schedule));
    std::promise<void> finished;
    auto stopped = finished.get_future();
    SchedulerTestCleanup cleanup{m_scheduler, m_service, &unblock};
    const auto id = m_service->Start(Intent());
    Flush();
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);

    cleanup.m_stopper = std::thread{[&] {
        m_service->Stop();
        finished.set_value();
    }};
    BOOST_REQUIRE(entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    auto registration = std::async(std::launch::async, [&] {
        std::vector<std::future<ManagerResult>> operations;
        operations.push_back(m_service->Send({}));
        operations.push_back(m_service->Read(id));
        operations.push_back(m_service->Execute(id, SenderCommand::Cancel));
        return operations;
    });

    struct ReleaseOnExit {
        SchedulerTestCleanup& m_cleanup;

        ~ReleaseOnExit() { m_cleanup.Release(); }
    } release{cleanup};

    BOOST_REQUIRE(registration.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    auto operations = registration.get();

    for (auto& operation : operations) {
        BOOST_CHECK(operation.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    }
    BOOST_CHECK(!ReadStoredPayment(id).released);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
    cleanup.Release();
    BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

    for (auto& operation : operations) {
        BOOST_REQUIRE(operation.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
        const auto result = operation.get();
        BOOST_CHECK(result.status == CommandStatus::Stopped);
        BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
        BOOST_CHECK(result.payments.front().payment.id == id);
        BOOST_CHECK(!result.payments.front().payment.possibly_exposed);
        BOOST_CHECK(!result.payments.front().payment.owns_inputs);
    }
    const auto final = m_service->Snapshot(id);
    BOOST_REQUIRE(final && final->original);
    BOOST_CHECK(ReadStoredPayment(id).released);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);
    for (const auto& input : final->original->vin) {
        BOOST_CHECK(!HasOwner(input.prevout));
        BOOST_CHECK(!LockedMarker(input.prevout));
        BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
    }
    cleanup.m_stopper.join();
    Flush();
}

BOOST_AUTO_TEST_CASE(sender_read_accepts_an_inline_notification_barrier)
{
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    struct RestoreSignals {
        std::unique_ptr<ValidationSignals>& m_signals;
        std::unique_ptr<ValidationSignals> m_saved;

        ~RestoreSignals() { m_signals = std::move(m_saved); }
    } restore{m_node.validation_signals, std::move(m_node.validation_signals)};

    m_node.validation_signals = std::make_unique<ValidationSignals>(std::make_unique<util::ImmediateTaskRunner>());
    const auto writes = m_database->WriteCount();
    auto future = m_service->Read(uint256::ONE);

    BOOST_CHECK(future.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    Flush();
    BOOST_CHECK(future.get().status == CommandStatus::NotFound);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_preparation_accepts_an_inline_notification_barrier)
{
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    struct RestoreSignals {
        SenderService& m_service;
        std::unique_ptr<ValidationSignals>& m_signals;
        std::unique_ptr<ValidationSignals> m_saved;

        ~RestoreSignals()
        {
            m_service.Stop();
            m_signals = std::move(m_saved);
        }
    } restore{*m_service, m_node.validation_signals, std::move(m_node.validation_signals)};

    m_node.validation_signals = std::make_unique<ValidationSignals>(std::make_unique<util::ImmediateTaskRunner>());
    const auto writes = m_database->WriteCount();
    const auto id = m_service->Start(Intent());
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Queued);
    BOOST_CHECK(!m_service->Snapshot(id)->original);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    Flush();
    BOOST_REQUIRE(m_service->Snapshot(id)->original);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);

    PaymentRequest request;
    request.uri = m_uri;
    request.relay = m_relay;
    request.fee_rate = CFeeRate{1000};
    auto accepted = m_service->Send(std::move(request));
    BOOST_CHECK(accepted.wait_for(std::chrono::seconds{0}) == std::future_status::timeout);
    Flush();
    const auto result = accepted.get();
    BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
    BOOST_REQUIRE(m_service->Snapshot(result.payments.front().payment.id)->original);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 2);
}

BOOST_AUTO_TEST_CASE(sender_preparation_barrier_failure_does_not_leave_queued_payment)
{
    m_node.validation_signals->SyncWithValidationInterfaceQueue();

    struct RestoreSignals {
        std::unique_ptr<ValidationSignals>& m_signals;
        std::unique_ptr<ValidationSignals> m_saved;

        ~RestoreSignals() { m_signals = std::move(m_saved); }
    } restore{m_node.validation_signals, std::move(m_node.validation_signals)};

    class FailingBarrierRunner final : public util::ImmediateTaskRunner
    {
        void insert(std::function<void()>) override { throw std::runtime_error{"barrier unavailable"}; }
    };

    m_node.validation_signals = std::make_unique<ValidationSignals>(std::make_unique<FailingBarrierRunner>());
    const auto writes = m_database->WriteCount();
    const auto id = m_service->Start(Intent());
    const auto failed = *m_service->Snapshot(id);
    BOOST_CHECK(failed.phase == PaymentPhase::Attention);
    BOOST_CHECK(failed.issue == PaymentIssue::Preparation);
    BOOST_CHECK_EQUAL(failed.diagnostic, "Payjoin preparation barrier failed");
    BOOST_CHECK(!failed.storage_uncertain);
    BOOST_CHECK(!failed.original);
    BOOST_CHECK(!HasStoredPayment(id));
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
}

BOOST_FIXTURE_TEST_CASE(sender_inline_submit_completion_is_deferred, InlineCompletionFixture)
{
    InlineTransport().m_complete_on_submit = true;

    const auto failed = m_service->Start(Intent());
    Flush();

    const auto failed_view = *m_service->Snapshot(failed);
    BOOST_CHECK(failed_view.issue == PaymentIssue::Delivery);
    BOOST_CHECK_EQUAL(failed_view.diagnostic, "inline submit completion");
    BOOST_CHECK(failed_view.transport_accepted);
    BOOST_CHECK(m_transport->m_pending.empty());
    m_service->Stop();
    BOOST_CHECK_EQUAL(InlineTransport().m_completions, 1);
}

BOOST_FIXTURE_TEST_CASE(sender_inline_cancel_completion_is_deferred, InlineCompletionFixture)
{
    InlineTransport().m_complete_on_cancel = true;

    const auto cancelled = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(cancelled)->phase == PaymentPhase::Negotiating);

    m_service->Cancel(cancelled);
    Flush();

    BOOST_CHECK(m_service->Snapshot(cancelled)->phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!m_service->Snapshot(cancelled)->issue);
    BOOST_CHECK(m_transport->m_pending.empty());
    m_service->Stop();
    BOOST_CHECK_EQUAL(InlineTransport().m_completions, 1);
}

BOOST_AUTO_TEST_CASE(sender_pending_executor_task_does_not_keep_service_alive)
{
    CScheduler scheduler;
    SerialTaskRunner executor{scheduler};
    bool destroyed{false};
    std::promise<void> drained;
    auto completed = drained.get_future();

    auto schedule = [this](std::chrono::milliseconds delay, std::function<void()> fn) {
        m_timers.emplace(m_now + delay, std::move(fn));
    };
    auto scheduled = std::make_unique<SenderService>(*m_sender, executor, std::make_unique<DestructionObservedTransport>(destroyed), [this] { return m_now; }, std::move(schedule));
    SchedulerTestCleanup cleanup{scheduler, scheduled};
    const auto id = scheduled->Start(Intent());
    BOOST_REQUIRE(scheduled->Snapshot(id)->phase == PaymentPhase::Queued);

    scheduled.reset();
    BOOST_REQUIRE(destroyed);
    BOOST_CHECK(m_timers.empty());

    executor.insert([&] { drained.set_value(); });
    scheduler.m_service_thread = std::thread{[&] { scheduler.serviceQueue(); }};
    BOOST_REQUIRE(completed.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
}

BOOST_AUTO_TEST_CASE(sender_scheduler_dispatches_without_inline_execution)
{
    CScheduler scheduler;
    SerialTaskRunner executor{scheduler};
    auto owned = std::make_unique<ControlledTransport>();
    std::promise<std::thread::id> submitted;
    auto dispatched = submitted.get_future();
    owned->m_on_dispatch = [&] { submitted.set_value(std::this_thread::get_id()); };

    auto schedule = [this](std::chrono::milliseconds delay, std::function<void()> fn) {
        m_timers.emplace(m_now + delay, std::move(fn));
    };
    auto scheduled = std::make_unique<SenderService>(*m_sender, executor, std::move(owned), [this] { return m_now; }, std::move(schedule));
    SchedulerTestCleanup cleanup{scheduler, scheduled};
    scheduler.m_service_thread = std::thread{[&] { scheduler.serviceQueue(); }};

    const auto caller = std::this_thread::get_id();
    const auto id = scheduled->Start(Intent());
    BOOST_REQUIRE(dispatched.wait_for(std::chrono::seconds{30}) == std::future_status::ready);
    BOOST_CHECK(dispatched.get() == scheduler.m_service_thread.get_id());
    BOOST_CHECK(scheduler.m_service_thread.get_id() != caller);

    scheduled->Stop();
    BOOST_CHECK(scheduled->Snapshot(id)->transport_accepted);
}

#ifdef DEBUG_LOCKCONTENTION
BOOST_AUTO_TEST_CASE(sender_stop_waits_for_running_dispatch_and_ignores_late_completion)
{
    CScheduler scheduler;
    SerialTaskRunner executor{scheduler};
    std::promise<void> unblock;
    std::promise<void> stop_completed;
    auto stopped = stop_completed.get_future();
    std::promise<void> drained;
    auto completed = drained.get_future();
    auto owned = std::make_unique<BlockingCompletionTransport>(unblock.get_future().share());
    auto* blocking = owned.get();
    auto entered = blocking->m_entered.get_future();

    auto schedule = [this](std::chrono::milliseconds delay, std::function<void()> fn) {
        m_timers.emplace(m_now + delay, std::move(fn));
    };
    auto scheduled = std::make_unique<SenderService>(*m_sender, executor, std::move(owned), [this] { return m_now; }, std::move(schedule));
    StopLockProbe probe;
    auto stopping = probe.Entered();
    SchedulerTestCleanup cleanup{scheduler, scheduled, &unblock};
    scheduler.m_service_thread = std::thread{[&] { scheduler.serviceQueue(); }};

    const auto id = scheduled->Start(Intent());
    BOOST_REQUIRE(entered.wait_for(std::chrono::seconds{30}) == std::future_status::ready);
    const auto duplicate_completion = blocking->m_completion;

    cleanup.m_stopper = std::thread{[&] {
        scheduled->Stop();
        stop_completed.set_value();
    }};
    const auto attempted = stopping.wait_for(std::chrono::seconds{5});
    BOOST_CHECK_MESSAGE(stopped.wait_for(std::chrono::milliseconds{0}) == std::future_status::timeout,
                        "Stop returned while dispatch remained blocked");
    BOOST_REQUIRE_MESSAGE(attempted == std::future_status::ready, "Stop did not reach gate contention");

    cleanup.Release();
    BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    cleanup.m_stopper.join();

    BOOST_CHECK(!blocking->m_completion);
    duplicate_completion({Delivery::NotSent, {}, "duplicate completion after stop"});
    scheduled->Cancel(id);
    executor.insert([&] { drained.set_value(); });
    BOOST_REQUIRE(completed.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_CHECK(scheduled->Snapshot(id)->phase == PaymentPhase::Stopped);
    BOOST_CHECK(!scheduled->Snapshot(id)->selected);
}
#endif

BOOST_AUTO_TEST_CASE(sender_retains_exposed_original_until_explicit_fallback)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    auto late = m_transport->m_pending.front().complete;
    m_service->Cancel(id);
    Flush();

    const auto cancelled = *m_service->Snapshot(id);
    BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(cancelled.possibly_exposed);
    BOOST_CHECK(cancelled.owns_inputs);
    BOOST_CHECK(!cancelled.selected);
    BOOST_REQUIRE(cancelled.original->HasWitness());

    DataStream expected;
    expected << TX_WITH_WITNESS(cancelled.original);
    const auto stored_cancelled = ReadStoredPayment(id);
    BOOST_CHECK_EQUAL_COLLECTIONS(stored_cancelled.original.begin(), stored_cancelled.original.end(),
                                  UCharCast(expected.data()), UCharCast(expected.data()) + expected.size());
    BOOST_CHECK(stored_cancelled.selected.empty());

    BOOST_CHECK(!m_node.mempool->exists(cancelled.original->GetHash()));

    late({Delivery::Uncertain, {}, "late completion"});
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);

    m_service->PublishFallback(id);
    Flush();

    const auto result = *m_service->Snapshot(id);
    BOOST_REQUIRE_MESSAGE(result.node_accepted, result.diagnostic);
    BOOST_CHECK(result.selected->GetWitnessHash() == cancelled.original->GetWitnessHash());

    const auto stored_result = ReadStoredPayment(id);
    BOOST_CHECK_EQUAL_COLLECTIONS(stored_result.original.begin(), stored_result.original.end(),
                                  UCharCast(expected.data()), UCharCast(expected.data()) + expected.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(stored_result.selected.begin(), stored_result.selected.end(),
                                  UCharCast(expected.data()), UCharCast(expected.data()) + expected.size());
}

BOOST_AUTO_TEST_CASE(sender_stop_invalidates_queued_and_late_work)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    auto late = m_transport->m_pending.front().complete;
    m_service->Stop();
    m_sender.reset();
    late({Delivery::Uncertain, {}, "late completion after wallet destruction"});
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Stopped);
}

BOOST_AUTO_TEST_CASE(sender_stop_uses_not_sent_without_draining_executor)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);

    m_service->Stop();

    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!stopped.possibly_exposed);
    BOOST_CHECK(!stopped.owns_inputs);
    BOOST_CHECK(!stopped.storage_uncertain);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);
    BOOST_CHECK(ReadStoredPayment(id).released);
    BOOST_REQUIRE(stopped.original);
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& input : stopped.original->vin) {
            BOOST_CHECK(!m_sender->IsLockedCoin(input.prevout));
            BOOST_CHECK(!LockedMarker(input.prevout));
            BOOST_CHECK(!HasOwner(input.prevout));
        }
    }

    const auto writes = m_database->WriteCount();
    Flush();
    m_service->Stop();

    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
}

BOOST_AUTO_TEST_CASE(sender_stop_uses_not_sent_queued_before_stop)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    auto complete = std::move(m_transport->m_pending.front().complete);
    m_transport->m_pending.pop_front();
    complete({Delivery::NotSent, {}, "not sent before stop"});

    m_service->Stop();

    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!stopped.possibly_exposed);
    BOOST_CHECK(!stopped.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(sender_stop_uses_not_sent_after_deadline)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    Tick();
    BOOST_REQUIRE(m_service->Snapshot(id)->issue == PaymentIssue::Deadline);
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);

    m_service->Stop();

    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!stopped.possibly_exposed);
    BOOST_CHECK(!stopped.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(sender_stop_uses_not_sent_after_cancel)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    m_service->Cancel(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);
    BOOST_REQUIRE(m_service->Snapshot(id)->owns_inputs);

    m_service->Stop();

    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!stopped.possibly_exposed);
    BOOST_CHECK(!stopped.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(sender_stop_not_sent_save_failure_keeps_reservation)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment);

    m_service->Stop();
    m_database->CheckWriteFailed();
    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(stopped.issue == PaymentIssue::Storage);
    BOOST_CHECK(stopped.storage_uncertain);
    BOOST_CHECK(stopped.possibly_exposed);
    BOOST_CHECK(stopped.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
    BOOST_CHECK(!ReadStoredPayment(id).released);
}

BOOST_FIXTURE_TEST_CASE(sender_stop_uncertain_keeps_reservation, UncertainStopFixture)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    m_service->Stop();

    const auto stopped = *m_service->Snapshot(id);
    BOOST_CHECK(stopped.phase == PaymentPhase::Stopped);
    BOOST_CHECK(stopped.possibly_exposed);
    BOOST_CHECK(stopped.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
    BOOST_CHECK(!ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(sender_stop_races_with_completion_snapshot_and_commands)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto complete = m_transport->m_pending.front().complete;
    std::promise<void> start;
    auto ready = start.get_future().share();
    std::atomic<bool> snapshot_missing{false};
    std::jthread observer{[&] {
        ready.wait();
        for (int i = 0; i < 100; ++i) {
            if (!m_service->Snapshot(id)) snapshot_missing = true;
            m_service->Refresh(id);
            m_service->Cancel(id);
            complete({Delivery::Uncertain, {}, "late response", true});
        }
    }};
    std::jthread stopper{[&] {
        ready.wait();
        m_service->Stop();
    }};

    start.set_value();
    m_service->Stop();
    observer.join();
    stopper.join();
    Flush();

    BOOST_CHECK(!snapshot_missing);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Stopped);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);
}

BOOST_AUTO_TEST_CASE(sender_cancel_before_dispatch_releases_only_its_inputs)
{
    const auto first = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_service->Cancel(first);
    const auto second = m_service->Start(Intent());
    Flush();

    const auto cancelled = *m_service->Snapshot(first);
    const auto active = *m_service->Snapshot(second);
    BOOST_REQUIRE_MESSAGE(active.transport_accepted, active.diagnostic);
    BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!cancelled.possibly_exposed);
    BOOST_CHECK(!cancelled.owns_inputs);
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);

    LOCK(m_sender->cs_wallet);
    for (const auto& input : active.original->vin) {
        BOOST_CHECK(m_sender->IsLockedCoin(input.prevout));
    }
}

BOOST_AUTO_TEST_CASE(sender_cancelled_payment_stays_cancelled_after_coin_reuse)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_service->Cancel(id);
    Flush();

    const auto cancelled = *m_service->Snapshot(id);
    BOOST_REQUIRE(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_REQUIRE(cancelled.original);
    BOOST_REQUIRE(!cancelled.owns_inputs);
    BOOST_REQUIRE(!cancelled.possibly_exposed);

    auto next_intent = Intent();
    next_intent.amount = 99 * COIN;
    next_intent.uri.replace(next_intent.uri.find("amount=1"), 8, "amount=99");
    const auto next = m_service->Start(next_intent);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(next)->owns_inputs);
    Confirm(m_service->Snapshot(next)->original);
    const auto input = cancelled.original->vin[0].prevout;
    const bool locked = WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input));

    m_service->Refresh(id);
    Flush();
    m_service->Refresh(id);
    Flush();

    const auto after = *m_service->Snapshot(id);
    BOOST_CHECK(after.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!after.settlement);
    BOOST_CHECK(!after.owns_inputs);

    LOCK(m_sender->cs_wallet);
    auto owner = ReadOwner(input);
    BOOST_CHECK(owner == next);
    BOOST_CHECK_EQUAL(m_sender->IsLockedCoin(input), locked);
}

BOOST_AUTO_TEST_CASE(sender_concurrent_payments_use_distinct_reservations)
{
    const auto first = m_service->Start(Intent());
    const auto second = m_service->Start(Intent());
    Flush();

    const auto a = *m_service->Snapshot(first), b = *m_service->Snapshot(second);
    BOOST_REQUIRE_MESSAGE(a.transport_accepted, a.diagnostic);
    BOOST_REQUIRE_MESSAGE(b.transport_accepted, b.diagnostic);
    for (const auto& x : a.original->vin) {
        for (const auto& y : b.original->vin) {
            BOOST_CHECK(x.prevout != y.prevout);
        }
    }

    m_service->Cancel(first);
    Flush();

    BOOST_CHECK(m_service->Snapshot(second)->phase == PaymentPhase::Negotiating);

    LOCK(m_sender->cs_wallet);
    for (const auto& input : b.original->vin) {
        BOOST_CHECK(m_sender->IsLockedCoin(input.prevout));
    }
}

BOOST_AUTO_TEST_CASE(sender_pending_request_deadline_preserves_original)
{
    const auto id = m_service->Start(Intent());
    Flush();

    Tick();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Deadline);
    BOOST_CHECK(view.possibly_exposed);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK_EQUAL(m_transport->m_cancelled.size(), 1);
}

BOOST_AUTO_TEST_CASE(sender_handoff_and_busy_retry_deadline_boundaries)
{
    for (const bool retry : {false, true}) {
        for (const auto offset : {std::chrono::milliseconds{-1}, std::chrono::milliseconds{0}, std::chrono::milliseconds{1}}) {
            BOOST_TEST_CONTEXT("busy retry=" << retry << ", deadline offset ms=" << offset.count())
            {
                m_timers.clear();
                m_now = {};
                auto intent = Intent();
                intent.timeout = std::chrono::seconds{10};
                m_transport->m_acceptance = retry ? SubmitResult::Busy : SubmitResult::Accepted;
                const auto attempts = m_transport->m_attempts;

                const auto id = m_service->Start(intent);
                m_node.chain->waitForNotifications();
                if (!retry) m_queue->insert([&] { m_now = SenderService::Clock::time_point{} + intent.timeout + offset; });
                Flush();
                if (retry) {
                    BOOST_REQUIRE_EQUAL(m_transport->m_attempts, attempts + 1);
                    BOOST_REQUIRE(m_transport->m_pending.empty());
                    BOOST_REQUIRE(!m_timers.empty());
                    BOOST_REQUIRE(m_timers.begin()->first < SenderService::Clock::time_point{} + intent.timeout);
                    auto dispatch = std::move(m_timers.begin()->second);
                    m_timers.erase(m_timers.begin());
                    m_transport->m_acceptance = SubmitResult::Accepted;
                    m_now = SenderService::Clock::time_point{} + intent.timeout + offset;
                    dispatch();
                    Flush();
                }

                const auto view = *m_service->Snapshot(id);
                BOOST_REQUIRE(view.original);
                BOOST_CHECK(!view.selected);
                BOOST_CHECK(!view.wallet_recorded);
                BOOST_CHECK(!view.node_accepted);
                BOOST_CHECK(view.owns_inputs);

                BOOST_CHECK(!m_node.mempool->exists(view.original->GetHash()));

                {
                    LOCK(m_sender->cs_wallet);
                    BOOST_CHECK(!m_sender->mapWallet.contains(view.original->GetHash()));
                    CheckOwnedInputs(id, *view.original);
                }

                if (offset < std::chrono::milliseconds::zero()) {
                    BOOST_CHECK(!view.issue);
                    BOOST_CHECK(view.transport_accepted);
                    BOOST_CHECK(view.possibly_exposed);
                    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
                    BOOST_CHECK(m_transport->m_pending.front().timeout == std::chrono::milliseconds{1});
                    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts + (retry ? 2 : 1));

                    auto pending = std::move(m_transport->m_pending.front());
                    m_transport->m_pending.pop_front();
                    pending.complete({Delivery::NotSent, {}, "deadline boundary cleanup"});
                    Flush();
                } else {
                    BOOST_CHECK(view.issue == PaymentIssue::Deadline);
                    BOOST_CHECK_EQUAL(view.diagnostic, "payment deadline reached");
                    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts + (retry ? 1 : 0));
                    BOOST_CHECK(!view.transport_accepted);
                    BOOST_CHECK(!view.possibly_exposed);
                    BOOST_CHECK(!ReadStoredPayment(id).exposed);
                    BOOST_CHECK(m_transport->m_pending.empty());
                }

                m_service->Cancel(id);
                Flush();

                BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_registration_failure_forbids_dispatch)
{
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Owner, FaultDatabase::WriteFailure::AfterWrite);
    const auto id = m_service->Start(Intent());
    Flush();

    m_database->CheckWriteFailed();
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Storage);
    BOOST_CHECK(!m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK(!m_service->Snapshot(id)->original_saved);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_registration_begin_failure_preserves_database_and_foreign_reservation)
{
    const auto foreign = ReserveForeignCoin(*this);
    const auto records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
    const auto locks = WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins);

    std::map<std::string, size_t> writes;
    ScopedHook write_hook{m_database->m_on_write};
    m_database->m_on_write = [&](const std::string& type) { ++writes[type]; };

    m_database->SetTransactionFailure(FaultDatabase::Transaction::Begin);
    const auto id = m_service->Start(Intent());
    Flush();
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Begin);
    m_database->SetTransactionFailure(FaultDatabase::Transaction::Begin, false);
    write_hook.Reset();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK_EQUAL(view.diagnostic, "registration transaction failed");
    BOOST_CHECK(!view.original_saved);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(!view.storage_uncertain);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(m_transport->m_pending.empty());
    CheckNoPublication(*this, view);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins == locks));
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
    for (const auto& type : std::vector<std::string>{PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) {
        BOOST_TEST_CONTEXT(type) { BOOST_CHECK_EQUAL(WriteCount(writes, type), 0); }
    }
}

BOOST_AUTO_TEST_CASE(sender_registration_commit_failure_rolls_back_written_records)
{
    const auto foreign = ReserveForeignCoin(*this);
    const auto records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
    const auto locks = WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins);

    bool commit_observed{false}, rollback_confirmed{false};
    const auto id = m_service->Start(Intent());
    ScopedHook write_hook{m_database->m_on_write};
    m_database->m_on_write = [&](const std::string& type) {
        if (type == PAYMENT_RECORD) m_database->SetTransactionFailure(FaultDatabase::Transaction::Commit);
    };
    ScopedHook transaction_hook{m_database->m_on_transaction};
    m_database->m_on_transaction = [&](FaultDatabase::Transaction operation, bool success) {
        if (operation == FaultDatabase::Transaction::Abort && commit_observed) rollback_confirmed = success;
        if (operation != FaultDatabase::Transaction::Commit || !HasStoredPayment(id)) return;

        BOOST_REQUIRE(!success);

        const auto stored = ReadStoredPayment(id);
        BOOST_CHECK(stored.selected.empty());
        BOOST_CHECK(!stored.exposed);
        BOOST_CHECK(!stored.released);
        const auto journal = Journal(id);
        BOOST_CHECK(journal.first.empty());
        BOOST_CHECK(!journal.second);
        DataStream bytes{stored.original};
        CMutableTransaction original;
        bytes >> TX_WITH_WITNESS(original);
        BOOST_REQUIRE(bytes.empty());
        BOOST_REQUIRE(!original.vin.empty());
        for (const auto& input : original.vin) {
            BOOST_CHECK(ReadOwner(input.prevout) == id);
            BOOST_CHECK(!LockedMarker(input.prevout));
            BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
        }
        commit_observed = true;
    };

    Flush();
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Commit);
    m_database->SetTransactionFailure(FaultDatabase::Transaction::Commit, false);
    transaction_hook.Reset();
    write_hook.Reset();
    BOOST_REQUIRE(commit_observed);
    BOOST_REQUIRE(rollback_confirmed);

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK_EQUAL(view.diagnostic, "registration failed");
    BOOST_CHECK(!view.original_saved);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(!view.storage_uncertain);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(m_transport->m_pending.empty());
    CheckNoPublication(*this, view);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins == locks));
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(sender_registration_lost_commit_acknowledgement_preserves_durable_records)
{
    const auto foreign = ReserveForeignCoin(*this);
    const auto locks = WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins);
    ScopedHook write_hook{m_database->m_on_write};
    m_database->m_on_write = [&](const std::string& type) {
        if (type == PAYMENT_RECORD) m_database->LoseNextCommitAcknowledgement();
    };
    bool abort_observed{false};
    ScopedHook transaction_hook{m_database->m_on_transaction};
    m_database->m_on_transaction = [&](FaultDatabase::Transaction operation, bool success) {
        if (operation != FaultDatabase::Transaction::Abort) return;

        abort_observed = true;
        BOOST_CHECK(!success);
    };
    const auto id = m_service->Start(Intent());
    Flush();
    write_hook.Reset();
    transaction_hook.Reset();

    m_database->CheckCommitAcknowledgementLost();
    BOOST_REQUIRE(!m_database->HasActiveTxn());
    BOOST_REQUIRE(abort_observed);
    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK_EQUAL(view.diagnostic, "registration failed");
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(!view.original_saved);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    CheckNoPublication(*this, view);

    const auto stored = ReadStoredPayment(id);
    DataStream bytes{stored.original};
    CTransactionRef original;
    bytes >> TX_WITH_WITNESS(original);
    BOOST_REQUIRE(bytes.empty());
    BOOST_REQUIRE(original->Equals(*view.original));
    BOOST_CHECK(stored.selected.empty());
    BOOST_CHECK(!stored.exposed);
    BOOST_CHECK(!stored.released);
    BOOST_CHECK(Journal(id).first.empty());
    BOOST_CHECK(!Journal(id).second);
    for (const auto& input : original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
        BOOST_CHECK(!LockedMarker(input.prevout));
        BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
    }
    const auto records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});

    auto cancelled = m_service->Execute(id, SenderCommand::Cancel);
    Flush();
    const auto cancellation = cancelled.get();
    BOOST_REQUIRE_EQUAL(cancellation.payments.size(), 1);
    BOOST_CHECK(cancellation.payments.front().payment.storage_uncertain);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);

    m_service->Stop();
    BOOST_CHECK(m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins == locks));
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
    CheckNoPublication(*this, *m_service->Snapshot(id));
}

BOOST_AUTO_TEST_CASE(sender_partial_lock_failure_forbids_dispatch)
{
    m_database->FailNextWrite(FaultDatabase::WriteTarget::LockedCoin, FaultDatabase::WriteFailure::AfterWrite);
    const auto id = m_service->Start(Intent());
    Flush();
    m_database->CheckWriteFailed();
    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK(view.original_saved);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(m_transport->m_pending.empty());
}

void CheckUnregisteredForeignSpend(SenderFixture& fixture, bool collision, bool uncertain = false)
{
    fixture.m_database->SetOwnerCollision(collision);
    if (!collision) {
        fixture.m_database->FailNextWrite(FaultDatabase::WriteTarget::Owner, FaultDatabase::WriteFailure::AfterWrite);
        fixture.m_database->SetTransactionFailure(FaultDatabase::Transaction::Abort, uncertain);
    }

    const auto id = fixture.m_service->Start(fixture.Intent());
    fixture.Flush();

    const auto before = *fixture.m_service->Snapshot(id);
    BOOST_REQUIRE(before.original);
    BOOST_REQUIRE(!before.original_saved);
    BOOST_REQUIRE(!before.owns_inputs);
    BOOST_REQUIRE_EQUAL(before.storage_uncertain, uncertain);
    BOOST_REQUIRE(before.issue);
    BOOST_REQUIRE(!before.diagnostic.empty());
    BOOST_CHECK(before.issue == (collision ? PaymentIssue::Reservation : PaymentIssue::Storage));
    BOOST_CHECK(fixture.m_transport->m_pending.empty());

    fixture.m_database->SetOwnerCollision(false);
    if (collision) {
        fixture.m_database->CheckOwnerCollision();
    } else {
        fixture.m_database->CheckWriteFailed();
        if (uncertain) fixture.m_database->CheckTransactionFailed(FaultDatabase::Transaction::Abort);
    }
    fixture.m_database->SetTransactionFailure(FaultDatabase::Transaction::Abort, false);

    CMutableTransaction other{*before.original};
    for (auto& input : other.vin) {
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }
    other.vout[0].nValue -= 1000;
    PartiallySignedTransaction psbt{other, 0};
    bool complete{false};
    {
        LOCK(fixture.m_sender->cs_wallet);
        BOOST_REQUIRE(!fixture.m_sender->FillPSBT(psbt, {}, complete));
    }
    BOOST_REQUIRE(complete);
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, other));
    const auto conflict = MakeTransactionRef(std::move(other));
    BOOST_REQUIRE(conflict->GetHash() != before.original->GetHash());
    fixture.Confirm(conflict);

    const uint256 foreign_owner{uint256::ONE};
    for (const auto& input : before.original->vin) {
        BOOST_REQUIRE(!fixture.HasOwner(input.prevout));
        fixture.WriteOwner(input.prevout, foreign_owner);
        LOCK(fixture.m_sender->cs_wallet);
        BOOST_REQUIRE(fixture.m_sender->LockCoin(input.prevout, true));
    }

    for (int i = 0; i < 2; ++i) {
        fixture.m_service->Refresh(id);
        fixture.Flush();

        const auto view = *fixture.m_service->Snapshot(id);
        BOOST_REQUIRE(view.observed_spend);
        BOOST_CHECK(view.observed_spend->kind == SpendKind::Other);
        BOOST_CHECK(view.observed_spend->presence == TransactionPresence::Confirmed);
        BOOST_CHECK(view.phase == before.phase);
        BOOST_CHECK(!view.settlement);
        BOOST_CHECK(view.issue == before.issue);
        BOOST_CHECK_EQUAL(view.diagnostic, before.diagnostic);
        BOOST_CHECK_EQUAL(view.storage_uncertain, uncertain);
        BOOST_CHECK(!view.original_saved);
        BOOST_CHECK(!view.owns_inputs);
        BOOST_CHECK(!fixture.HasStoredPayment(id));
        for (const auto& input : before.original->vin) {
            auto owner = fixture.ReadOwner(input.prevout);
            BOOST_CHECK(owner == foreign_owner);
            BOOST_CHECK(fixture.LockedMarker(input.prevout));
            BOOST_CHECK(WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsLockedCoin(input.prevout)));
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_unregistered_collision_preserves_error_after_confirmed_foreign_spend)
{
    CheckUnregisteredForeignSpend(*this, true);
}

BOOST_AUTO_TEST_CASE(sender_rolled_back_registration_preserves_error_after_confirmed_foreign_spend)
{
    CheckUnregisteredForeignSpend(*this, false);
}

BOOST_AUTO_TEST_CASE(sender_uncertain_registration_preserves_error_after_confirmed_foreign_spend)
{
    CheckUnregisteredForeignSpend(*this, false, true);
}

BOOST_AUTO_TEST_CASE(sender_observation_uses_spending_index_before_original_is_recorded)
{
    m_transport->m_acceptance = SubmitResult::Busy;
    auto intent = Intent();
    intent.amount = 99 * COIN;
    intent.uri.replace(intent.uri.find("amount=1"), 8, "amount=99");
    const auto id = m_service->Start(intent);
    Flush();
    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    BOOST_REQUIRE_EQUAL(original->vin.size(), 2);

    const auto sign = [&](CMutableTransaction tx) {
        for (auto& input : tx.vin) {
            input.scriptSig.clear();
            input.scriptWitness.SetNull();
        }
        PartiallySignedTransaction psbt{tx, 0};
        bool complete{false};
        {
            LOCK(m_sender->cs_wallet);
            BOOST_REQUIRE(!m_sender->FillPSBT(psbt, {}, complete));
        }
        BOOST_REQUIRE(complete);
        BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, tx));
        return MakeTransactionRef(std::move(tx));
    };

    CMutableTransaction alternative{*original};
    alternative.vout[0].nValue -= 1000;
    const auto inactive = sign(std::move(alternative));
    std::vector<CTransactionRef> confirmed;
    for (const auto& input : original->vin) {
        CMutableTransaction spend;
        spend.vin.emplace_back(input.prevout);
        const auto value = WITH_LOCK(m_sender->cs_wallet, return m_sender->GetWalletTx(input.prevout.hash)->GetTx()->vout.at(input.prevout.n).nValue);
        spend.vout.emplace_back(value - 1000, m_receiver_coin->vout[0].scriptPubKey);
        confirmed.push_back(sign(std::move(spend)));
    }
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->AddToWallet(inactive, TxStateInactive{}));
    }
    for (const auto& spend : confirmed) {
        Confirm(spend);
    }

    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(!m_sender->GetWalletTx(original->GetHash()));
        BOOST_CHECK(m_sender->GetSpendingTxids(COutPoint{m_receiver_coin->GetHash(), 0}).empty());
        for (size_t i = 0; i < original->vin.size(); ++i) {
            const std::set<Txid> spenders{inactive->GetHash(), confirmed[i]->GetHash()};
            BOOST_CHECK(m_sender->GetSpendingTxids(original->vin[i].prevout) == spenders);
        }
    }
    m_service->Refresh(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_REQUIRE(view.observed_spend);
    BOOST_CHECK(view.observed_spend->kind == SpendKind::Other);
    BOOST_CHECK(view.observed_spend->presence == TransactionPresence::Confirmed);
    BOOST_CHECK(view.observed_spend->transaction->GetHash() == std::min(confirmed[0]->GetHash(), confirmed[1]->GetHash()));
    BOOST_REQUIRE(view.settlement);
    BOOST_CHECK(view.settlement->transaction == view.observed_spend->transaction);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).released);
}

BOOST_AUTO_TEST_CASE(sender_initial_dispatch_trusts_persistent_memory_lock)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    COutPoint input;
    uint256 owner;

    m_queue->insert([&] {
        const auto prepared = *m_service->Snapshot(id);
        BOOST_REQUIRE(prepared.locks_verified);
        BOOST_REQUIRE(prepared.original);
        input = prepared.original->vin[0].prevout;
        BOOST_REQUIRE(LockedMarker(input));

        {
            LOCK(m_sender->cs_wallet);
            BOOST_REQUIRE(WalletBatch{m_sender->GetDatabase()}.EraseLockedUTXO(input));
            BOOST_REQUIRE(m_sender->m_locked_coins.at(input));
        }
        BOOST_REQUIRE(!LockedMarker(input));
        owner = ReadOwner(input);
        BOOST_REQUIRE(owner == id);
    });

    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(!view.issue);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(view.locks_verified);
    BOOST_CHECK(view.possibly_exposed);
    BOOST_CHECK(view.transport_accepted);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);
    BOOST_CHECK_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_CHECK(!LockedMarker(input));
    owner = ReadOwner(input);
    BOOST_CHECK(owner == id);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins.at(input)));
}

BOOST_AUTO_TEST_CASE(sender_initial_dispatch_rechecks_manual_unlock)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();

    m_queue->insert([&] {
        const auto prepared = *m_service->Snapshot(id);
        BOOST_REQUIRE(prepared.locks_verified);
        BOOST_REQUIRE(prepared.original);

        const auto input = prepared.original->vin[0].prevout;
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->UnlockCoin(input));
        BOOST_REQUIRE(!m_sender->IsLockedCoin(input));
    });

    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Reservation);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.locks_verified);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_persistent_marker_without_memory_flag_forbids_dispatch)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    COutPoint input;

    m_queue->insert([&] {
        const auto prepared = *m_service->Snapshot(id);
        BOOST_REQUIRE(prepared.original);
        BOOST_REQUIRE(prepared.locks_verified);

        input = prepared.original->vin[0].prevout;
        {
            LOCK(m_sender->cs_wallet);
            BOOST_REQUIRE(m_sender->UnlockCoin(input));
            BOOST_REQUIRE(m_sender->LockCoin(input, false));
            BOOST_REQUIRE(WalletBatch{m_sender->GetDatabase()}.WriteLockedUTXO(input));
            BOOST_REQUIRE(m_sender->IsLockedCoin(input));
            BOOST_REQUIRE(!m_sender->m_locked_coins.at(input));
        }
        BOOST_REQUIRE(LockedMarker(input));
    });

    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Reservation);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.locks_verified);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(LockedMarker(input));
    BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins.at(input)));
}

BOOST_AUTO_TEST_CASE(sender_owner_read_failure_before_dispatch_preserves_reservations)
{
    const auto foreign = ReserveForeignCoin(*this);
    std::map<std::string, std::string> records;
    const auto locks = WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins);
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_queue->insert([&] {
        const auto prepared = *m_service->Snapshot(id);
        BOOST_REQUIRE(prepared.original);
        BOOST_REQUIRE(prepared.locks_verified);
        records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
        m_database->FailNextRead(std::pair{std::string{OWNER_RECORD}, prepared.original->vin.front().prevout});
    });
    Flush();
    m_database->CheckReadFailed();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Reservation);
    BOOST_CHECK_EQUAL(view.diagnostic, "payment inputs changed; reconciliation required");
    BOOST_CHECK(!view.storage_uncertain);
    BOOST_CHECK(!view.locks_verified);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(m_transport->m_pending.empty());
    CheckNoPublication(*this, view);
    CheckRetainedReservations(*this, view);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
    BOOST_CHECK(LockedMarker(foreign));
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins.at(foreign) == locks.at(foreign)));
}

BOOST_AUTO_TEST_CASE(sender_release_owner_read_failure_precedes_every_unlock)
{
    auto intent = Intent();
    intent.amount = 99 * COIN;
    intent.uri.replace(intent.uri.find("amount=1"), 8, "amount=99");
    const COutPoint foreign{m_receiver_coin->GetHash(), 0};
    WriteOwner(foreign, uint256::ONE);
    BOOST_REQUIRE(WITH_LOCK(m_sender->cs_wallet, return m_sender->LockCoin(foreign, true)));
    std::map<std::string, std::string> records;
    std::map<COutPoint, bool> locks;

    const auto id = m_service->Start(intent);
    m_node.chain->waitForNotifications();
    m_queue->insert([&] {
        const auto prepared = *m_service->Snapshot(id);
        BOOST_REQUIRE(prepared.original);
        BOOST_REQUIRE_EQUAL(prepared.original->vin.size(), 2);
        records = ReadRecords(*m_database, {PAYMENT_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
        locks = WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins);

        m_database->FailNextRead(std::pair{std::string{OWNER_RECORD}, prepared.original->vin.back().prevout});
    });
    m_service->Cancel(id);
    Flush();
    m_database->CheckReadFailed();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Reservation);
    BOOST_CHECK_EQUAL(view.diagnostic, "cannot release another payment's inputs");
    BOOST_CHECK(!view.storage_uncertain);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(m_transport->m_pending.empty());
    CheckNoPublication(*this, view);

    CheckRetainedReservations(*this, view);
    BOOST_CHECK(Journal(id).second);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->m_locked_coins == locks));
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(sender_wallet_journal_load_read_failure_forbids_dispatch)
{
    const auto foreign = ReserveForeignCoin(*this);
    const auto id = m_service->Start(Intent());
    m_database->FailNextRead(std::pair{std::string{JOURNAL_RECORD}, id});
    Flush();
    m_database->CheckReadFailed();

    CheckJournalCreationFailure(*this, id, "Payjoin event log load failed: journal load failed");
    const auto journal = Journal(id);
    BOOST_CHECK(journal.first.empty());
    BOOST_CHECK(!journal.second);
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
    BOOST_CHECK(LockedMarker(foreign));
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(foreign)));
}

BOOST_AUTO_TEST_CASE(sender_wallet_journal_save_read_failure_forbids_dispatch)
{
    const auto foreign = ReserveForeignCoin(*this);
    const auto id = m_service->Start(Intent());
    m_database->FailNextRead(std::pair{std::string{JOURNAL_RECORD}, id}, 1);
    Flush();
    m_database->CheckReadFailed();

    CheckJournalCreationFailure(*this, id, "Payjoin event log save failed: journal unavailable");
    const auto journal = Journal(id);
    BOOST_CHECK(journal.first.empty());
    BOOST_CHECK(!journal.second);
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
    BOOST_CHECK(LockedMarker(foreign));
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(foreign)));
}

BOOST_AUTO_TEST_CASE(sender_wallet_journal_missing_at_create_forbids_dispatch)
{
    const auto id = m_service->Start(Intent());
    bool removed{false};
    ScopedHook transaction_hook{m_database->m_on_transaction};
    m_database->m_on_transaction = [&](FaultDatabase::Transaction operation, bool success) {
        if (operation != FaultDatabase::Transaction::Commit || !HasStoredPayment(id)) return;
        BOOST_REQUIRE(success);
        removed = m_database->MakeBatch()->Erase(std::pair{std::string{JOURNAL_RECORD}, id});
    };
    Flush();
    transaction_hook.Reset();
    BOOST_REQUIRE(removed);

    CheckJournalCreationFailure(*this, id, "Payjoin event log load failed: journal load failed");
    BOOST_CHECK(!m_database->MakeBatch()->Exists(std::pair{std::string{JOURNAL_RECORD}, id}));
}

BOOST_AUTO_TEST_CASE(sender_wallet_journal_closed_at_create_forbids_dispatch)
{
    const auto id = m_service->Start(Intent());
    bool closed{false};
    ScopedHook transaction_hook{m_database->m_on_transaction};
    m_database->m_on_transaction = [&](FaultDatabase::Transaction operation, bool success) {
        if (operation != FaultDatabase::Transaction::Commit || !HasStoredPayment(id)) return;
        BOOST_REQUIRE(success);
        closed = m_database->MakeBatch()->Write(std::pair{std::string{JOURNAL_RECORD}, id},
                                                std::pair{std::vector<std::string>{}, true});
    };
    Flush();
    transaction_hook.Reset();
    BOOST_REQUIRE(closed);

    CheckJournalCreationFailure(*this, id, "Payjoin event log save failed: journal unavailable");
    const auto journal = Journal(id);
    BOOST_CHECK(journal.first.empty());
    BOOST_CHECK(journal.second);
}

BOOST_AUTO_TEST_CASE(sender_wallet_journal_close_read_failure_retains_reservations)
{
    const auto foreign = ReserveForeignCoin(*this);
    std::pair<std::vector<std::string>, bool> journal_before;
    std::map<std::string, std::string> records;
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_queue->insert([&] {
        journal_before = Journal(id);
        BOOST_REQUIRE(!journal_before.second);
        records = ReadRecords(*m_database, {PAYMENT_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
        m_database->FailNextRead(std::pair{std::string{JOURNAL_RECORD}, id}, 2);
    });
    m_service->Cancel(id);
    Flush();
    m_database->CheckReadFailed();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK_EQUAL(view.diagnostic, "Payjoin event log close failed: journal load failed");
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(!view.transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);
    BOOST_CHECK(m_transport->m_pending.empty());
    CheckNoPublication(*this, view);
    CheckRetainedReservations(*this, view);
    const auto journal = Journal(id);
    BOOST_REQUIRE_EQUAL(journal.first.size(), journal_before.first.size() + 2);
    BOOST_CHECK(std::equal(journal_before.first.begin(), journal_before.first.end(), journal.first.begin()));
    BOOST_CHECK(!journal.second);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    BOOST_CHECK(ReadOwner(foreign) == uint256::ONE);
    BOOST_CHECK(LockedMarker(foreign));
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(foreign)));

    auto fallback_future = m_service->Execute(id, SenderCommand::Fallback);
    Flush();

    const auto fallback_result = fallback_future.get();
    BOOST_CHECK(fallback_result.refusal == CommandRefusal::StorageUncertain);
    CheckNoPublication(*this, *m_service->Snapshot(id));
    BOOST_CHECK(Journal(id) == journal);
}

BOOST_AUTO_TEST_CASE(sender_created_journal_failure_forbids_dispatch)
{
    m_database->FailNextWrite(FaultDatabase::WriteTarget::JournalEvent, FaultDatabase::WriteFailure::AfterWrite);
    const auto id = m_service->Start(Intent());
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(view.original_saved);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(m_transport->m_pending.empty());
    m_database->CheckWriteFailed();
}

BOOST_AUTO_TEST_CASE(sender_disclosure_write_failure_forbids_dispatch)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_queue->insert([&] { m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment, FaultDatabase::WriteFailure::AfterWrite); });
    Flush();
    m_database->CheckWriteFailed();
    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(view.possibly_exposed);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_invalid_intent_has_no_reservation)
{
    auto intent = Intent();
    intent.amount += 1;
    const auto mismatch = m_service->Start(intent);
    intent.amount = -1;
    const auto negative = m_service->Start(intent);
    Flush();
    for (const auto& id : {mismatch, negative}) {
        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.issue == PaymentIssue::InvalidIntent);
        BOOST_CHECK(!view.original);
        BOOST_CHECK(!view.owns_inputs);
        BOOST_CHECK(!view.original_saved);
    }

    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_intent_policy_boundaries)
{
    struct Boundary {
        const char* name;
        std::function<void(PaymentIntent&)> set;
        std::optional<PaymentIssue> issue;
        const char* diagnostic;
    };

    const std::string policy_error{"invalid amount, fee policy or timeout"};

    const auto amount_uri = m_uri.substr(0, m_uri.find('?')) + "?" + m_uri.substr(m_uri.find("&pjos") + 1);
    const std::vector<Boundary> boundaries{
        {"amount zero", [](auto& i) { i.amount = 0; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"amount one satoshi", [](auto& i) { i.amount = 1; }, PaymentIssue::Preparation, "Transaction amount too small"},
        {"amount above MAX_MONEY", [](auto& i) { i.amount = MAX_MONEY + 1; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"amount MAX_MONEY", [](auto& i) { i.amount = MAX_MONEY; }, PaymentIssue::Preparation, "Insufficient funds"},
        {"negative max_fee", [](auto& i) { i.max_fee = -1; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"zero max_fee", [](auto& i) { i.max_fee = 0; }, PaymentIssue::InvalidIntent, "original fee exceeds policy"},
        {"max_fee above MAX_MONEY", [](auto& i) { i.max_fee = MAX_MONEY + 1; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"max_fee MAX_MONEY", [](auto& i) { i.max_fee = MAX_MONEY; }, std::nullopt, ""},
        {"zero fee_rate", [](auto& i) { i.fee_rate = CFeeRate{0}; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"fee_rate one satoshi per kB", [](auto& i) { i.fee_rate = CFeeRate{1}; }, PaymentIssue::Preparation, "Fee rate ("},
        {"zero timeout", [](auto& i) { i.timeout = std::chrono::milliseconds{0}; i.poll_interval = std::chrono::milliseconds{1}; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"one millisecond timeout", [](auto& i) { i.timeout = i.poll_interval = std::chrono::milliseconds{1}; }, std::nullopt, ""},
        {"timeout above 24 hours", [](auto& i) { i.timeout = std::chrono::hours{24} + std::chrono::milliseconds{1}; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"timeout 24 hours", [](auto& i) { i.timeout = std::chrono::hours{24}; }, std::nullopt, ""},
        {"zero poll_interval", [](auto& i) { i.poll_interval = std::chrono::milliseconds{0}; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"one millisecond poll_interval", [](auto& i) { i.poll_interval = std::chrono::milliseconds{1}; }, std::nullopt, ""},
        {"poll_interval above timeout", [](auto& i) { i.poll_interval = i.timeout + std::chrono::milliseconds{1}; }, PaymentIssue::InvalidIntent, policy_error.c_str()},
        {"poll_interval equal to timeout", [](auto& i) { i.poll_interval = i.timeout; }, std::nullopt, ""},
        {"wrong network", [](auto& i) { i.uri.replace(8, i.uri.find('?') - 8, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"); }, PaymentIssue::InvalidIntent, "destination network or amount mismatch"},
        {"regtest network", [](auto&) {}, std::nullopt, ""},
    };

    for (const auto& boundary : boundaries) {
        BOOST_TEST_CONTEXT(boundary.name)
        {
            auto intent = Intent();
            intent.uri = amount_uri;
            boundary.set(intent);

            std::map<std::string, size_t> writes;
            ScopedHook write_hook{m_database->m_on_write};
            m_database->m_on_write = [&](const std::string& type) { ++writes[type]; };
            const auto attempts = m_transport->m_attempts;

            const auto id = m_service->Start(intent);
            Flush();
            write_hook.Reset();

            const auto view = *m_service->Snapshot(id);
            BOOST_CHECK(view.issue == boundary.issue);
            {
                LOCK(m_sender->cs_wallet);
                if (boundary.issue) {
                    BOOST_CHECK_MESSAGE(view.diagnostic.starts_with(boundary.diagnostic), view.diagnostic);
                    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);
                    BOOST_CHECK(!view.transport_accepted);
                    BOOST_CHECK(!view.original);
                    BOOST_CHECK(!view.original_saved);
                    BOOST_CHECK(!view.owns_inputs);

                    BOOST_CHECK(!HasStoredPayment(id));
                    BOOST_CHECK(!m_database->MakeBatch()->Exists(std::pair{std::string{JOURNAL_RECORD}, id}));
                    for (const auto& type : std::vector<std::string>{PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) {
                        BOOST_CHECK_EQUAL(WriteCount(writes, type), 0);
                    }
                } else {
                    BOOST_REQUIRE_MESSAGE(view.transport_accepted, view.diagnostic);
                    BOOST_REQUIRE(view.original);
                    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts + 1);
                    BOOST_CHECK(view.original_saved);
                    BOOST_CHECK(view.owns_inputs);

                    BOOST_CHECK(HasStoredPayment(id));
                    BOOST_CHECK(WriteCount(writes, PAYMENT_RECORD) > 0);
                    BOOST_CHECK(WriteCount(writes, JOURNAL_RECORD) > 0);

                    CheckOwnedInputs(id, *view.original);
                }
            }

            if (!boundary.issue) {
                auto pending = std::move(m_transport->m_pending.front());
                m_transport->m_pending.pop_front();
                pending.complete({Delivery::NotSent, {}, "boundary test cleanup"});
                Flush();

                m_service->Cancel(id);
                Flush();
            }

            LOCK(m_sender->cs_wallet);
            std::vector<COutPoint> locked;
            m_sender->ListLockedCoins(locked);
            BOOST_CHECK(locked.empty());
            for (const auto& [txid, wtx] : m_sender->mapWallet) {
                for (uint32_t n = 0; n < wtx.GetTx()->vout.size(); ++n) {
                    const COutPoint out{txid, n};
                    BOOST_CHECK(!HasOwner(out));
                    BOOST_CHECK(!LockedMarker(out));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_original_fee_budget_boundary)
{
    const auto probe = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(probe)->original;
    BOOST_REQUIRE(original);
    CAmount input_value{0};
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& input : original->vin) {
            const auto* parent = m_sender->GetWalletTx(input.prevout.hash);
            BOOST_REQUIRE(parent);
            input_value += parent->GetTx()->vout.at(input.prevout.n).nValue;
        }
    }
    const auto fee = input_value - original->GetValueOut();
    BOOST_REQUIRE(fee > 0);

    auto pending = std::move(m_transport->m_pending.front());
    m_transport->m_pending.pop_front();
    pending.complete({Delivery::NotSent, {}, "fee probe cleanup"});
    Flush();

    m_service->Cancel(probe);
    Flush();

    for (const auto budget : {fee - 1, fee}) {
        BOOST_TEST_CONTEXT("original fee budget=" << budget)
        {
            auto intent = Intent();
            intent.max_fee = budget;

            std::map<std::string, size_t> writes;
            ScopedHook write_hook{m_database->m_on_write};
            m_database->m_on_write = [&](const std::string& type) { ++writes[type]; };

            const auto attempts = m_transport->m_attempts;
            const auto id = m_service->Start(intent);
            Flush();
            write_hook.Reset();

            const auto view = *m_service->Snapshot(id);
            LOCK(m_sender->cs_wallet);
            if (budget < fee) {
                BOOST_CHECK(view.issue == PaymentIssue::InvalidIntent);
                BOOST_CHECK_EQUAL(view.diagnostic, "original fee exceeds policy");
                BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);
                BOOST_CHECK(!view.original);
                BOOST_CHECK(!view.owns_inputs);
                BOOST_CHECK(!HasStoredPayment(id));
                BOOST_CHECK(!m_database->MakeBatch()->Exists(std::pair{std::string{JOURNAL_RECORD}, id}));
                for (const auto& type : std::vector<std::string>{PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) {
                    BOOST_CHECK_EQUAL(WriteCount(writes, type), 0);
                }

                std::vector<COutPoint> locked;
                m_sender->ListLockedCoins(locked);
                BOOST_CHECK(locked.empty());
                for (const auto& input : original->vin) {
                    BOOST_CHECK(!HasOwner(input.prevout));
                    BOOST_CHECK(!LockedMarker(input.prevout));
                }
            } else {
                BOOST_REQUIRE_MESSAGE(view.transport_accepted, view.diagnostic);
                BOOST_REQUIRE(view.original);
                CAmount total{0};
                for (const auto& input : view.original->vin) {
                    total += m_sender->GetWalletTx(input.prevout.hash)->GetTx()->vout.at(input.prevout.n).nValue;
                    BOOST_CHECK(ReadOwner(input.prevout) == id);
                    BOOST_CHECK(m_sender->IsLockedCoin(input.prevout));
                    BOOST_CHECK(LockedMarker(input.prevout));
                }
                BOOST_CHECK_EQUAL(total - view.original->GetValueOut(), fee);
                BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts + 1);
                BOOST_CHECK(view.owns_inputs);
                BOOST_CHECK(HasStoredPayment(id));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_confirmed_conflict_releases_exposed_inputs)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;

    CMutableTransaction conflict{*original};
    for (auto& input : conflict.vin) {
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }

    conflict.vout[0].nValue -= 1000;
    PartiallySignedTransaction psbt{conflict, 0};
    bool complete{false};
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(!m_sender->FillPSBT(psbt, {}, complete));
    }

    BOOST_REQUIRE(complete);
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, conflict));
    const auto conflicting = MakeTransactionRef(conflict);

    const auto block = Confirm(conflicting);
    m_service->Refresh(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.phase == PaymentPhase::Conflicted);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(!view.selected);

    m_service->PublishFallback(id);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->selected);

    const auto journal = Journal(id);
    Disconnect(block);
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        BOOST_CHECK(!m_service->Snapshot(id)->settlement);
        BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Attention);
        BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
        BOOST_CHECK(!m_service->Snapshot(id)->fallback_available);
    }

    Confirm(conflicting);
    m_service->Refresh(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->settlement);
    BOOST_CHECK(m_service->Snapshot(id)->settlement->kind == SpendKind::Other);

    m_service->Cancel(id);
    Flush();
    m_service->Stop();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Conflicted);

    BOOST_CHECK(Journal(id) == journal);
}

BOOST_AUTO_TEST_CASE(sender_confirmed_original_survives_cancel_and_stop)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;

    Confirm(original);
    m_service->Refresh(id);
    Flush();

    const auto journal = Journal(id);
    m_service->Cancel(id);
    Flush();
    m_service->Stop();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.phase == PaymentPhase::Confirmed);
    BOOST_REQUIRE(view.settlement);
    BOOST_CHECK(view.settlement->kind == SpendKind::Original);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(!view.selected);

    BOOST_CHECK(Journal(id) == journal);
}

BOOST_AUTO_TEST_CASE(sender_stop_clears_actions_for_selected_unconfirmed_payment)
{
    const auto id = m_service->Start(Intent());
    Flush();

    {
        LOCK(m_sender->cs_wallet);
        m_sender->SetBroadcastTransactions(false);
    }
    m_service->PublishFallback(id);
    Flush();

    const auto prepared = m_service->Snapshot(id);
    BOOST_REQUIRE(prepared);
    const auto before = *prepared;
    BOOST_REQUIRE(before.phase == PaymentPhase::Attention);
    BOOST_REQUIRE(before.issue == PaymentIssue::BroadcastDisabled);
    BOOST_REQUIRE(before.original);
    BOOST_REQUIRE(before.selected);
    BOOST_REQUIRE(before.selection_saved);
    BOOST_REQUIRE(before.wallet_recorded);
    BOOST_REQUIRE(before.owns_inputs);
    BOOST_REQUIRE(!before.node_accepted);
    BOOST_REQUIRE(!before.settlement);
    BOOST_REQUIRE(before.publication_retry_available);

    const auto writes = m_database->WriteCount();
    const auto attempts = m_transport->m_attempts;
    std::map<COutPoint, std::pair<bool, bool>> locks;
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& input : before.original->vin) {
            BOOST_REQUIRE(ReadOwner(input.prevout) == id);
            locks.emplace(input.prevout, std::pair{m_sender->IsLockedCoin(input.prevout), LockedMarker(input.prevout)});
        }
    }

    m_service->Stop();

    const auto check_stopped = [&](const PaymentSnapshot& view, const char* source) {
        BOOST_TEST_CONTEXT("source=" << source)
        {
            BOOST_CHECK(view.id == id);
            BOOST_CHECK(view.phase == before.phase);
            BOOST_REQUIRE(view.original);
            BOOST_REQUIRE(view.selected);
            BOOST_CHECK(view.original->Equals(*before.original));
            BOOST_CHECK(view.selected->Equals(*before.selected));
            BOOST_CHECK(view.selection_saved);
            BOOST_CHECK(view.wallet_recorded);
            BOOST_CHECK(view.owns_inputs);
            BOOST_CHECK(!view.node_accepted);
            BOOST_CHECK(!view.settlement);
            BOOST_CHECK(view.possibly_exposed == before.possibly_exposed);
            BOOST_CHECK(view.storage_uncertain == before.storage_uncertain);
            BOOST_CHECK(view.issue == before.issue);
            BOOST_CHECK_EQUAL(view.diagnostic, before.diagnostic);

            BOOST_CHECK(!view.cancel_available);
            BOOST_CHECK(!view.fallback_available);
            BOOST_CHECK(!view.signing_available);
            BOOST_CHECK(!view.publication_retry_available);
        }
    };

    const auto stopped = m_service->Snapshot(id);
    BOOST_REQUIRE(stopped);
    check_stopped(*stopped, "Snapshot");

    const auto archive = m_service->Archive();
    BOOST_REQUIRE(archive);
    BOOST_REQUIRE_EQUAL(archive->size(), 1);
    check_stopped(archive->front().payment, "Archive");

    auto read = m_service->Read(id);
    BOOST_REQUIRE(read.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    const auto result = read.get();
    BOOST_CHECK(result.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
    check_stopped(result.payments.front().payment, "Read");

    auto retry = m_service->Execute(id, SenderCommand::RetryPublication);
    BOOST_REQUIRE(retry.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
    const auto retried = retry.get();
    BOOST_CHECK(retried.status == CommandStatus::Stopped);
    BOOST_REQUIRE_EQUAL(retried.payments.size(), 1);
    check_stopped(retried.payments.front().payment, "RetryPublication");
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);

    LOCK(m_sender->cs_wallet);
    for (const auto& [outpoint, lock_state] : locks) {
        BOOST_CHECK(ReadOwner(outpoint) == id);
        BOOST_CHECK_EQUAL(m_sender->IsLockedCoin(outpoint), lock_state.first);
        BOOST_CHECK_EQUAL(LockedMarker(outpoint), lock_state.second);
    }
}

BOOST_AUTO_TEST_CASE(sender_broadcast_disabled_and_current_observation)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_sender->SetBroadcastTransactions(false);
    m_service->PublishFallback(id);
    Flush();

    const auto before = *m_service->Snapshot(id);
    BOOST_CHECK(before.issue == PaymentIssue::BroadcastDisabled);
    BOOST_REQUIRE(before.selected);
    BOOST_REQUIRE(before.wallet_recorded);
    BOOST_REQUIRE(before.selection_saved);

    m_service->RetryPublication(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::BroadcastDisabled);
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->AbandonTransaction(before.selected->GetHash()));
    }

    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->selected_presence == TransactionPresence::Abandoned);
    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);

    m_service->RetryPublication(id);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->node_accepted);
}

BOOST_AUTO_TEST_CASE(sender_unknown_rollback_and_invalid_fallback)
{
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Owner, FaultDatabase::WriteFailure::AfterWrite);
    m_database->SetTransactionFailure(FaultDatabase::Transaction::Abort, true);
    const auto id = m_service->Start(Intent());
    Flush();
    m_database->CheckWriteFailed();
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Abort);

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(!view.original_saved);

    auto fallback_future = m_service->Execute(id, SenderCommand::Fallback);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == view.phase);
    const auto fallback_result = fallback_future.get();
    BOOST_CHECK(fallback_result.refusal == CommandRefusal::StorageUncertain);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_observes_receiver_original_in_mempool)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    m_service->Refresh(id);
    Flush();

    auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.original_presence == TransactionPresence::Mempool);
    BOOST_REQUIRE(view.observed_spend);
    BOOST_CHECK(view.observed_spend->kind == SpendKind::Original);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.settlement);
    BOOST_REQUIRE(!m_transport->m_pending.empty());

    const auto request_id = m_transport->m_pending.front().id;
    m_service->PublishFallback(id);
    Flush();

    view = *m_service->Snapshot(id);
    BOOST_REQUIRE(view.selected);
    BOOST_CHECK(view.selected->GetWitnessHash() == original->GetWitnessHash());
    BOOST_CHECK(view.phase == PaymentPhase::Published);
    BOOST_CHECK(view.node_accepted);
    BOOST_CHECK(view.selection_saved);
    BOOST_CHECK(view.wallet_recorded);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.issue);
    BOOST_CHECK(!view.fallback_available);
    BOOST_REQUIRE_EQUAL(m_transport->m_cancelled.size(), 1);
    BOOST_CHECK_EQUAL(m_transport->m_cancelled.front(), request_id);
    const auto journal = Journal(id);
    BOOST_CHECK(journal.second);

    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*original, MemPoolRemovalReason::EXPIRY);
    }
    m_sender->transactionRemovedFromMempool(original, MemPoolRemovalReason::EXPIRY);
    BOOST_REQUIRE(!m_node.mempool->exists(original->GetHash()));
    m_service->RetryPublication(id);
    Flush();

    view = *m_service->Snapshot(id);
    BOOST_REQUIRE(view.selected);
    BOOST_CHECK(view.selected->GetWitnessHash() == original->GetWitnessHash());
    BOOST_CHECK(view.node_accepted);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(view.phase == PaymentPhase::Published);
    BOOST_CHECK(!view.issue);

    BOOST_CHECK(m_node.mempool->exists(original->GetHash()));

    BOOST_CHECK(Journal(id) == journal);
}

BOOST_AUTO_TEST_CASE(sender_mempool_fallback_reports_publication_failures)
{
    for (const bool fail_save : {false, true}) {
        BOOST_TEST_CONTEXT("selection save failure " << fail_save)
        {
            const auto id = m_service->Start(Intent());
            Flush();

            const auto original = m_service->Snapshot(id)->original;
            {
                LOCK(m_sender->cs_wallet);
                auto* wtx = m_sender->AddToWallet(original, TxStateInactive{});
                BOOST_REQUIRE(wtx);
                std::string error;
                BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
            }

            if (fail_save) {
                m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment);
            } else {
                m_sender->SetBroadcastTransactions(false);
            }

            m_service->PublishFallback(id);
            Flush();

            const auto view = *m_service->Snapshot(id);
            BOOST_REQUIRE(view.selected);
            BOOST_CHECK(view.selected->GetWitnessHash() == original->GetWitnessHash());
            BOOST_CHECK(view.phase != PaymentPhase::Published);
            BOOST_CHECK(!view.node_accepted);
            BOOST_CHECK(view.owns_inputs);
            BOOST_CHECK(view.storage_uncertain == fail_save);
            BOOST_CHECK(view.selection_saved == !fail_save);
            BOOST_CHECK(view.issue == (fail_save ? PaymentIssue::Storage : PaymentIssue::BroadcastDisabled));
            BOOST_CHECK(!view.diagnostic.empty());

            if (fail_save) m_database->CheckWriteFailed();
            m_sender->SetBroadcastTransactions(true);
            auto publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
            Flush();

            const auto retried = *m_service->Snapshot(id);
            if (fail_save) {
                const auto publication_result = publication_future.get();
                BOOST_CHECK(publication_result.refusal == CommandRefusal::StorageUncertain);
                BOOST_CHECK(!retried.node_accepted);
            } else {
                BOOST_CHECK(retried.phase == PaymentPhase::Published);
                BOOST_CHECK(retried.node_accepted);
                BOOST_CHECK(!retried.issue);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_witness_identity_is_checked_before_selection)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    BOOST_REQUIRE(!original->vin.empty());

    CMutableTransaction mismatched{*original};
    BOOST_REQUIRE(!mismatched.vin[0].scriptWitness.stack.empty());
    mismatched.vin[0].scriptWitness.stack[0].push_back(0);
    const auto wallet_transaction = MakeTransactionRef(std::move(mismatched));
    BOOST_REQUIRE(wallet_transaction->GetHash() == original->GetHash());
    BOOST_REQUIRE(wallet_transaction->GetWitnessHash() != original->GetWitnessHash());
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->AddToWallet(wallet_transaction, TxStateInactive{}));
    }
    const auto journal = Journal(id);

    m_service->PublishFallback(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Publication);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK(!view.selection_saved);
    BOOST_CHECK(!view.wallet_recorded);

    BOOST_CHECK(Journal(id) == journal);

    LOCK(m_sender->cs_wallet);
    const auto* known = m_sender->GetWalletTx(original->GetHash());
    BOOST_REQUIRE(known);
    BOOST_CHECK(known->GetWitnessHash() == wallet_transaction->GetWitnessHash());
}

BOOST_AUTO_TEST_CASE(sender_publication_retry_rejects_changed_wallet_witness)
{
    m_sender->SetBroadcastTransactions(false);
    const auto id = m_service->Start(Intent());
    Flush();

    m_service->PublishFallback(id);
    Flush();

    const auto selected = *m_service->Snapshot(id);
    BOOST_REQUIRE(selected.selected);
    BOOST_REQUIRE(selected.selection_saved);
    BOOST_REQUIRE(selected.wallet_recorded);
    BOOST_REQUIRE(selected.issue == PaymentIssue::BroadcastDisabled);

    DataStream selected_bytes;
    selected_bytes << TX_WITH_WITNESS(selected.selected);
    const auto stored = ReadStoredPayment(id);
    BOOST_CHECK_EQUAL_COLLECTIONS(stored.selected.begin(), stored.selected.end(),
                                  UCharCast(selected_bytes.data()), UCharCast(selected_bytes.data()) + selected_bytes.size());
    const auto journal = Journal(id);

    CMutableTransaction changed{*selected.selected};
    BOOST_REQUIRE(!changed.vin.empty());
    BOOST_REQUIRE(!changed.vin[0].scriptWitness.stack.empty());
    BOOST_REQUIRE(changed.vin[0].scriptWitness.stack[0].size() > 1);
    changed.vin[0].scriptWitness.stack[0].pop_back();
    const auto wallet_transaction = MakeTransactionRef(std::move(changed));
    BOOST_REQUIRE(wallet_transaction->GetHash() == selected.selected->GetHash());
    BOOST_REQUIRE(wallet_transaction->GetWitnessHash() != selected.selected->GetWitnessHash());
    {
        LOCK(m_sender->cs_wallet);
        const auto* known = m_sender->AddToWallet(wallet_transaction, TxStateInactive{});
        BOOST_REQUIRE(known);
        BOOST_REQUIRE(known->GetWitnessHash() == wallet_transaction->GetWitnessHash());
    }

    m_sender->SetBroadcastTransactions(true);
    m_service->RetryPublication(id);
    Flush();

    const auto retried = *m_service->Snapshot(id);
    BOOST_CHECK(retried.issue == PaymentIssue::Publication);
    BOOST_CHECK_EQUAL(retried.diagnostic, "selected transaction requires reconciliation");
    BOOST_CHECK(!retried.node_accepted);

    BOOST_CHECK(!m_node.mempool->exists(wallet_transaction->GetHash()));
    BOOST_REQUIRE(retried.selected);
    DataStream retried_bytes;
    retried_bytes << TX_WITH_WITNESS(retried.selected);
    BOOST_CHECK_EQUAL_COLLECTIONS(UCharCast(selected_bytes.data()), UCharCast(selected_bytes.data()) + selected_bytes.size(),
                                  UCharCast(retried_bytes.data()), UCharCast(retried_bytes.data()) + retried_bytes.size());
    const auto after = ReadStoredPayment(id);
    BOOST_CHECK_EQUAL_COLLECTIONS(stored.selected.begin(), stored.selected.end(), after.selected.begin(), after.selected.end());

    BOOST_CHECK(Journal(id) == journal);
    for (const auto& input : selected.original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
    }
    LOCK(m_sender->cs_wallet);
    const auto* known = m_sender->GetWalletTx(wallet_transaction->GetHash());
    BOOST_REQUIRE(known);
    BOOST_CHECK(known->GetWitnessHash() == wallet_transaction->GetWitnessHash());
}

BOOST_AUTO_TEST_CASE(sender_release_failure_preserves_ownership)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    m_queue->insert([&] {
        BOOST_REQUIRE(m_service->Snapshot(id)->locks_verified);
        m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment, FaultDatabase::WriteFailure::AfterWrite);
    });
    m_service->Cancel(id);
    Flush();
    m_database->CheckWriteFailed();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.locks_verified);
    BOOST_CHECK(view.phase == PaymentPhase::Attention);
    BOOST_CHECK(!view.possibly_exposed);
    BOOST_CHECK(m_transport->m_pending.empty());
    auto owner = ReadOwner(view.original->vin[0].prevout);
    BOOST_CHECK(owner == id);
}

BOOST_AUTO_TEST_CASE(sender_wallet_lock_covers_check_and_publication)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto coin = m_service->Snapshot(id)->original->vin[0].prevout;
    std::atomic<bool> competitor_acquired{false};
    std::promise<void> attempted;
    auto attempt = attempted.get_future();
    std::jthread competitor;
    bool publication_checked{false};

    ScopedHook read_hook{m_database->m_on_read};
    ScopedHook write_hook{m_database->m_on_write};
    m_database->m_on_read = [&](const std::string& type) {
        if (type != OWNER_RECORD || competitor.joinable()) return;
        competitor = std::jthread{[&] {
            {
                TRY_LOCK(m_sender->cs_wallet, lock);
                if (lock) competitor_acquired = true;
            }
            attempted.set_value();
            LOCK(m_sender->cs_wallet);
            competitor_acquired = true;
            m_sender->UnlockCoin(coin);
        }};
        attempt.wait();
    };
    m_database->m_on_write = [&](const std::string& type) {
        if (type == PAYMENT_RECORD) {
            publication_checked = true;
            BOOST_CHECK(!competitor_acquired);
        }
    };

    m_service->PublishFallback(id);
    Flush();
    if (competitor.joinable()) competitor.join();
    read_hook.Reset();
    write_hook.Reset();

    BOOST_CHECK(publication_checked);
    BOOST_CHECK(m_service->Snapshot(id)->node_accepted);
}

BOOST_AUTO_TEST_CASE(sender_default_intent_is_rejected)
{
    const auto id = m_service->Start(PaymentIntent{});
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::InvalidIntent);
    BOOST_CHECK(!m_service->Snapshot(id)->original_saved);
}

BOOST_AUTO_TEST_CASE(sender_owner_collision_is_known_registration_failure)
{
    m_database->SetOwnerCollision(true);
    const auto id = m_service->Start(Intent());
    Flush();
    m_database->CheckOwnerCollision();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.issue == PaymentIssue::Reservation);
    BOOST_CHECK(!view.storage_uncertain);
    BOOST_CHECK(!view.original_saved);
    BOOST_CHECK(!view.owns_inputs);
    BOOST_CHECK(m_transport->m_pending.empty());
    BOOST_CHECK(!HasStoredPayment(id));

    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(view.original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    m_service->Refresh(id);
    m_service->PublishFallback(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->original_presence == TransactionPresence::Mempool);
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Reservation);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);
}

BOOST_AUTO_TEST_CASE(sender_unusable_fallback_does_not_mutate_protocol)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_database->FailNextWrite(FaultDatabase::WriteTarget::Journal);
    m_service->Cancel(id);
    Flush();

    const auto before = *m_service->Snapshot(id);
    BOOST_REQUIRE(before.issue == PaymentIssue::Storage);
    BOOST_REQUIRE(before.storage_uncertain);
    const auto journal = Journal(id);
    m_database->CheckWriteFailed();

    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(before.original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->original_presence == TransactionPresence::Mempool);

    auto fallback_future = m_service->Execute(id, SenderCommand::Fallback);
    Flush();

    const auto after = *m_service->Snapshot(id);
    BOOST_CHECK(after.phase == before.phase);
    BOOST_CHECK(after.issue == before.issue);
    const auto fallback_result = fallback_future.get();
    BOOST_CHECK(fallback_result.refusal == CommandRefusal::StorageUncertain);
    BOOST_CHECK(!after.selected);
    BOOST_CHECK(!after.fallback_available);

    BOOST_CHECK(Journal(id) == journal);
}

BOOST_AUTO_TEST_CASE(sender_busy_rechecks_cleared_spend_observation)
{
    m_transport->m_acceptance = SubmitResult::Busy;
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    BOOST_REQUIRE_EQUAL(m_transport->m_attempts, 1);
    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    m_service->Refresh(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->observed_spend);
    BOOST_CHECK(!m_service->Snapshot(id)->settlement);

    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*original, MemPoolRemovalReason::EXPIRY);
    }
    m_sender->transactionRemovedFromMempool(original, MemPoolRemovalReason::EXPIRY);
    BOOST_REQUIRE(m_sender->AbandonTransaction(original->GetHash()));
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& input : original->vin) {
            BOOST_REQUIRE(!m_sender->IsSpent(input.prevout));
            BOOST_REQUIRE(m_sender->LockCoin(input.prevout, true));
        }
    }

    m_transport->m_acceptance = SubmitResult::Accepted;
    Tick();

    const auto after = *m_service->Snapshot(id);
    BOOST_CHECK(!after.observed_spend);
    BOOST_CHECK(after.phase == PaymentPhase::Negotiating);
    BOOST_CHECK(after.issue != PaymentIssue::ObservedSpend);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 2);
}

BOOST_AUTO_TEST_CASE(sender_refresh_separates_submission_from_mempool_presence)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_service->PublishFallback(id);
    Flush();

    const auto selected = m_service->Snapshot(id)->selected;
    BOOST_REQUIRE(selected);
    BOOST_REQUIRE(m_service->Snapshot(id)->node_accepted);
    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*selected, MemPoolRemovalReason::EXPIRY);
    }

    m_sender->transactionRemovedFromMempool(selected, MemPoolRemovalReason::EXPIRY);
    m_service->Refresh(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.node_accepted);
    BOOST_CHECK(view.selected_presence == TransactionPresence::Inactive);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.settlement);
}

BOOST_AUTO_TEST_CASE(sender_confirmed_release_failure_survives_refresh)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;

    Confirm(original);
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& input : original->vin) {
            BOOST_REQUIRE(m_sender->LockCoin(input.prevout, true));
        }
    }

    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment, FaultDatabase::WriteFailure::AfterWrite);
    auto failed_refresh = m_service->Execute(id, SenderCommand::Refresh);
    Flush();

    const auto failed = *m_service->Snapshot(id);
    BOOST_REQUIRE(failed.settlement);
    BOOST_CHECK(failed.phase == PaymentPhase::Confirmed);
    BOOST_CHECK(failed.issue == PaymentIssue::Storage);
    BOOST_CHECK(failed.storage_uncertain);
    BOOST_CHECK(failed.owns_inputs);
    BOOST_CHECK(!failed.locks_verified);
    BOOST_CHECK(!failed.diagnostic.empty());
    const auto failed_result = failed_refresh.get();
    BOOST_CHECK(failed_result.status == CommandStatus::Failed);
    BOOST_CHECK_EQUAL(failed_result.diagnostic, failed.diagnostic);
    BOOST_CHECK(!ReadStoredPayment(id).released);
    for (const auto& input : original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
    }

    const auto writes = m_database->WriteCount();
    m_database->CheckWriteFailed();
    auto refresh_future = m_service->Execute(id, SenderCommand::Refresh);
    Flush();

    const auto repeated = *m_service->Snapshot(id);
    BOOST_CHECK(repeated.phase == failed.phase);
    BOOST_CHECK(repeated.issue == failed.issue);
    BOOST_CHECK_EQUAL(repeated.diagnostic, failed.diagnostic);
    BOOST_CHECK(repeated.storage_uncertain);
    BOOST_CHECK(repeated.owns_inputs);
    BOOST_CHECK(!repeated.locks_verified);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    const auto refresh_result = refresh_future.get();
    BOOST_CHECK(refresh_result.status == CommandStatus::Completed);
    BOOST_CHECK(refresh_result.diagnostic.empty());
    BOOST_CHECK(!refresh_result.refusal);

    auto publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto publication_result = publication_future.get();
    BOOST_CHECK(publication_result.refusal == CommandRefusal::StorageUncertain);

    auto final_refresh_future = m_service->Execute(id, SenderCommand::Refresh);
    Flush();
    m_service->Stop();

    const auto final_refresh_result = final_refresh_future.get();
    BOOST_CHECK(!final_refresh_result.refusal);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Confirmed);
}

BOOST_AUTO_TEST_CASE(sender_observation_exception_reports_failure_per_invocation)
{
    for (const bool read : {false, true}) {
        const auto id = m_service->Start(Intent());
        Flush();
        const auto original = m_service->Snapshot(id)->original;
        BOOST_REQUIRE(original);
        Confirm(original);
        const auto records = ReadRecords(*m_database, {PAYMENT_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
        bool triggered{false};
        ScopedHook hook{m_database->m_on_read};
        m_database->m_on_read = [&](const std::string& type) {
            if (type != OWNER_RECORD) return;

            triggered = true;
            throw std::runtime_error{"ownership read failed"};
        };
        auto pending = read ? m_service->Read(id) : m_service->Execute(id, SenderCommand::Refresh);
        Flush();
        hook.Reset();
        BOOST_REQUIRE(triggered);
        const auto result = pending.get();
        BOOST_CHECK(result.status == CommandStatus::Failed);
        BOOST_REQUIRE_EQUAL(result.payments.size(), 1);
        const auto& payment = result.payments.front().payment;
        BOOST_CHECK(payment.issue == PaymentIssue::Storage);
        BOOST_CHECK(payment.storage_uncertain);
        BOOST_CHECK(payment.owns_inputs);
        BOOST_CHECK(!result.diagnostic.empty());
        BOOST_CHECK_EQUAL(result.diagnostic, payment.diagnostic);
        BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);

        const auto writes = m_database->WriteCount();
        auto repeated = read ? m_service->Read(id) : m_service->Execute(id, SenderCommand::Refresh);
        Flush();
        const auto repeated_result = repeated.get();
        BOOST_CHECK(repeated_result.status == CommandStatus::Completed);
        BOOST_CHECK(repeated_result.diagnostic.empty());
        BOOST_CHECK_EQUAL(repeated_result.payments.front().payment.diagnostic, payment.diagnostic);
        BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    }
}

BOOST_AUTO_TEST_CASE(sender_read_failure_still_updates_other_payments)
{
    const auto first = m_service->Start(Intent());
    Flush();
    const auto second = m_service->Start(Intent());
    Flush();
    const auto failed_id = std::min(first, second);
    const auto settled_id = std::max(first, second);
    const auto original = m_service->Snapshot(failed_id)->original;
    const auto other = m_service->Snapshot(settled_id)->original;
    BOOST_REQUIRE(original);
    BOOST_REQUIRE(other);
    Confirm(original);
    Confirm(other);
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment, FaultDatabase::WriteFailure::AfterWrite);

    auto pending = m_service->Read();
    Flush();
    const auto result = pending.get();
    BOOST_CHECK(result.status == CommandStatus::Failed);
    BOOST_REQUIRE_EQUAL(result.payments.size(), 2);
    const auto& failed = result.payments.front().payment;
    BOOST_CHECK(failed.id == failed_id);
    BOOST_CHECK(failed.storage_uncertain);
    BOOST_CHECK(failed.owns_inputs);
    BOOST_CHECK(failed.issue == PaymentIssue::Storage);
    BOOST_CHECK(!result.diagnostic.empty());
    BOOST_CHECK_EQUAL(result.diagnostic, failed.diagnostic);
    BOOST_CHECK(!ReadStoredPayment(failed_id).released);
    for (const auto& input : original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == failed_id);
    }
    BOOST_CHECK(result.payments.back().payment.id == settled_id);
    CheckReleased(settled_id);
    m_database->CheckWriteFailed();

    const auto writes = m_database->WriteCount();
    auto repeated = m_service->Read();
    Flush();
    const auto repeated_result = repeated.get();
    BOOST_CHECK(repeated_result.status == CommandStatus::Completed);
    BOOST_CHECK(repeated_result.diagnostic.empty());
    BOOST_CHECK_EQUAL(repeated_result.payments.front().payment.diagnostic, failed.diagnostic);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
}

BOOST_AUTO_TEST_CASE(sender_notification_release_failure_preserves_uncertainty)
{
    PaymentRequest request;
    request.uri = m_uri;
    request.relay = m_relay;
    request.fee_rate = CFeeRate{1000};
    auto pending = m_service->Send(std::move(request));
    Flush();
    const auto accepted = pending.get();
    BOOST_REQUIRE(accepted.status == CommandStatus::Completed);
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    Confirm(original);
    {
        LOCK(m_sender->cs_wallet);
        for (const auto& input : original->vin) {
            BOOST_REQUIRE(m_sender->LockCoin(input.prevout, true));
        }
    }
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment, FaultDatabase::WriteFailure::AfterWrite);
    Flush();

    const auto failed = *m_service->Snapshot(id);
    BOOST_REQUIRE(failed.settlement);
    BOOST_CHECK(failed.phase == PaymentPhase::Confirmed);
    BOOST_CHECK(failed.issue == PaymentIssue::Storage);
    BOOST_CHECK(failed.storage_uncertain);
    BOOST_CHECK(failed.owns_inputs);
    BOOST_CHECK(!failed.locks_verified);
    BOOST_CHECK(!failed.diagnostic.empty());
    BOOST_CHECK(!ReadStoredPayment(id).released);
    for (const auto& input : original->vin) {
        BOOST_CHECK(ReadOwner(input.prevout) == id);
    }
    m_database->CheckWriteFailed();

    const auto writes = m_database->WriteCount();
    m_node.validation_signals->TransactionRemovedFromMempool(original, MemPoolRemovalReason::BLOCK, 0);
    Flush();
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK(m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK_EQUAL(m_service->Snapshot(id)->diagnostic, failed.diagnostic);
}

BOOST_AUTO_TEST_CASE(sender_queued_notification_does_not_settle_during_stop)
{
    m_service->Stop();
    std::promise<void> unblock;
    auto transport = std::make_unique<BlockingStopTransport>(unblock.get_future().share());
    auto entered = transport->m_entered.get_future();
    m_transport = transport.get();
    m_service = MakeService(std::move(transport));
    std::promise<void> finished;
    auto stopped = finished.get_future();
    SchedulerTestCleanup cleanup{m_scheduler, m_service, &unblock};
    PaymentRequest request;
    request.uri = m_uri;
    request.relay = m_relay;
    request.fee_rate = CFeeRate{1000};
    auto pending = m_service->Send(std::move(request));
    Flush();
    const auto accepted = pending.get();
    BOOST_REQUIRE_EQUAL(accepted.payments.size(), 1);
    const auto id = accepted.payments.front().payment.id;
    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    auto dispatch = std::move(m_transport->m_pending.front());
    m_transport->m_pending.pop_front();
    dispatch.complete({Delivery::Uncertain, {}, "delivery uncertain"});
    Flush();
    Confirm(original);
    m_node.chain->waitForNotifications();
    BOOST_REQUIRE(!m_service->Snapshot(id)->settlement);
    BOOST_REQUIRE(m_service->Snapshot(id)->owns_inputs);

    cleanup.m_stopper = std::thread{[&] {
        m_service->Stop();
        finished.set_value();
    }};
    BOOST_REQUIRE(entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    const auto records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
    const auto writes = m_database->WriteCount();
    m_queue->flush();
    BOOST_CHECK(!m_service->Snapshot(id)->settlement);
    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Delivery);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);

    cleanup.Release();
    BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    cleanup.m_stopper.join();
    const auto stopped_records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});
    const auto stopped_writes = m_database->WriteCount();
    Flush();
    const auto final = *m_service->Snapshot(id);
    BOOST_CHECK(final.phase == PaymentPhase::Stopped);
    BOOST_CHECK(!final.selected);
    BOOST_CHECK(!final.node_accepted);
    BOOST_CHECK(!final.settlement);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);
    BOOST_CHECK_EQUAL(m_database->WriteCount(), stopped_writes);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == stopped_records);
}

BOOST_AUTO_TEST_CASE(sender_busy_waits_without_repeating_accepted_initial_post)
{
    m_transport->m_acceptance = SubmitResult::Busy;
    const auto id = m_service->Start(Intent());
    Flush();

    const auto busy = *m_service->Snapshot(id);
    BOOST_CHECK(busy.phase == PaymentPhase::Ready);
    BOOST_CHECK(!busy.issue);
    BOOST_CHECK(!busy.transport_accepted);
    BOOST_CHECK(!busy.possibly_exposed);
    BOOST_CHECK(!busy.disclosure_saved);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);
    BOOST_CHECK(m_transport->m_pending.empty());
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);

    m_transport->m_acceptance = SubmitResult::Accepted;
    Tick();
    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 2);

    m_transport->m_pending.front().complete({Delivery::NotSent, {}, "dispatch deadline elapsed", false});
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Delivery);
    BOOST_CHECK_EQUAL(m_service->Snapshot(id)->diagnostic, "dispatch deadline elapsed");

    while (!m_timers.empty()) {
        Tick();
    }

    BOOST_CHECK_EQUAL(m_transport->m_attempts, 2);
    BOOST_CHECK(!m_service->Snapshot(id)->possibly_exposed);
    BOOST_CHECK(!m_service->Snapshot(id)->disclosure_saved);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);
}

BOOST_AUTO_TEST_CASE(sender_busy_wait_is_cancelled_or_expires)
{
    m_transport->m_acceptance = SubmitResult::Busy;
    const auto cancelled = m_service->Start(Intent());
    const auto expired = m_service->Start(Intent());
    Flush();

    m_service->Cancel(cancelled);
    Flush();

    const auto attempts = m_transport->m_attempts;
    m_now += std::chrono::hours{1};
    while (!m_timers.empty()) {
        auto fn = std::move(m_timers.begin()->second);
        m_timers.erase(m_timers.begin());
        fn();
        Flush();
    }

    BOOST_CHECK_EQUAL(m_transport->m_attempts, attempts);
    BOOST_CHECK(m_service->Snapshot(cancelled)->phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!m_service->Snapshot(cancelled)->owns_inputs);
    BOOST_CHECK(m_service->Snapshot(expired)->issue == PaymentIssue::Deadline);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_dispatch_deadline_after_disclosure)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    ScopedHook write_hook{m_database->m_on_write};
    m_queue->insert([&] {
        m_database->m_on_write = [&](const std::string& type) {
            if (type == PAYMENT_RECORD) m_now += std::chrono::hours{1};
        };
    });

    Flush();
    write_hook.Reset();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Deadline);
    BOOST_CHECK(!m_service->Snapshot(id)->possibly_exposed);
    BOOST_CHECK(!m_service->Snapshot(id)->disclosure_saved);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);
    BOOST_CHECK(!m_service->Snapshot(id)->transport_accepted);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 0);

    m_service->Cancel(id);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
}

BOOST_AUTO_TEST_CASE(sender_rejected_initial_submit_releases_on_cancel)
{
    for (const auto rejection : {SubmitResult::Stopped, SubmitResult::InvalidRequest}) {
        BOOST_TEST_CONTEXT("submit result " << static_cast<int>(rejection))
        {
            m_transport->m_acceptance = rejection;
            const auto id = m_service->Start(Intent());
            Flush();

            const auto failed = *m_service->Snapshot(id);
            BOOST_CHECK(failed.issue == PaymentIssue::Delivery);
            BOOST_CHECK(failed.original_saved);
            BOOST_CHECK(failed.owns_inputs);
            BOOST_CHECK(!failed.possibly_exposed);
            BOOST_CHECK(!failed.disclosure_saved);
            BOOST_CHECK(!failed.transport_accepted);
            BOOST_CHECK(!ReadStoredPayment(id).exposed);
            BOOST_CHECK(m_transport->m_pending.empty());

            m_service->Cancel(id);
            Flush();

            const auto cancelled = *m_service->Snapshot(id);
            BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
            BOOST_CHECK(!cancelled.owns_inputs);
            BOOST_CHECK(!cancelled.selected);
            BOOST_CHECK(!cancelled.node_accepted);
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_disclosure_rollback_failure_is_conservative)
{
    m_transport->m_acceptance = SubmitResult::Busy;
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();

    m_queue->insert([&] {
        m_database->FailNextWrite(FaultDatabase::WriteTarget::PaymentUnexposed, FaultDatabase::WriteFailure::AfterWrite);
    });
    Flush();
    m_database->CheckWriteFailed();

    const auto failed = *m_service->Snapshot(id);
    BOOST_CHECK(failed.issue == PaymentIssue::Storage);
    BOOST_CHECK(failed.storage_uncertain);
    BOOST_CHECK(failed.possibly_exposed);
    BOOST_CHECK(failed.disclosure_saved);
    BOOST_CHECK(failed.owns_inputs);
    BOOST_CHECK(!failed.transport_accepted);
    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_not_sent_initial_completion_releases_on_cancel)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);
    BOOST_REQUIRE(ReadStoredPayment(id).exposed);
    auto complete = m_transport->m_pending.front().complete;

    complete({Delivery::NotSent, {}, "local URL rejected", false});
    Flush();

    const auto failed = *m_service->Snapshot(id);
    BOOST_CHECK(failed.issue == PaymentIssue::Delivery);
    BOOST_CHECK(!failed.possibly_exposed);
    BOOST_CHECK(!failed.disclosure_saved);
    BOOST_CHECK(failed.transport_accepted);
    BOOST_CHECK(!failed.storage_uncertain);
    BOOST_CHECK(!ReadStoredPayment(id).exposed);

    m_service->Cancel(id);
    Flush();

    const auto cancelled = *m_service->Snapshot(id);
    BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!cancelled.owns_inputs);
    BOOST_CHECK(!cancelled.selected);
    BOOST_CHECK(!cancelled.node_accepted);
    BOOST_REQUIRE(cancelled.original);

    BOOST_CHECK(!m_node.mempool->exists(cancelled.original->GetHash()));

    const auto writes = m_database->WriteCount();
    complete({Delivery::NotSent, {}, "duplicate late completion", false});
    Flush();

    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
}

BOOST_AUTO_TEST_CASE(sender_retired_not_sent_after_cancel_releases)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    auto complete = std::move(m_transport->m_pending.front().complete);
    m_transport->m_pending.pop_front();

    m_service->Cancel(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);
    BOOST_REQUIRE(m_service->Snapshot(id)->owns_inputs);

    complete({Delivery::NotSent, {}, "cancelled request was not sent"});
    Flush();

    const auto cancelled = *m_service->Snapshot(id);
    BOOST_CHECK(cancelled.phase == PaymentPhase::Cancelled);
    BOOST_CHECK(!cancelled.possibly_exposed);
    BOOST_CHECK(!cancelled.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).released);

    const auto writes = m_database->WriteCount();
    complete({Delivery::NotSent, {}, "duplicate completion"});
    Flush();

    BOOST_CHECK_EQUAL(m_database->WriteCount(), writes);
}

BOOST_AUTO_TEST_CASE(sender_retired_not_sent_after_deadline_waits_for_cancel)
{
    for (const bool cancel_first : {false, true}) {
        BOOST_TEST_CONTEXT("cancel before completion " << cancel_first)
        {
            const auto id = m_service->Start(Intent());
            Flush();

            BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
            auto complete = std::move(m_transport->m_pending.front().complete);
            m_transport->m_pending.pop_front();

            Tick();
            BOOST_REQUIRE(m_service->Snapshot(id)->issue == PaymentIssue::Deadline);
            BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);

            if (cancel_first) {
                m_service->Cancel(id);
                Flush();

                BOOST_REQUIRE(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);
                BOOST_REQUIRE(m_service->Snapshot(id)->owns_inputs);
            }

            complete({Delivery::NotSent, {}, "expired request was not sent"});
            Flush();

            const auto after_completion = *m_service->Snapshot(id);
            BOOST_CHECK(!after_completion.possibly_exposed);
            BOOST_CHECK(!ReadStoredPayment(id).exposed);
            if (!cancel_first) {
                BOOST_CHECK(after_completion.phase == PaymentPhase::Attention);
                BOOST_CHECK(after_completion.issue == PaymentIssue::Deadline);
                BOOST_CHECK_EQUAL(after_completion.diagnostic, "payment deadline reached");
                BOOST_CHECK(after_completion.owns_inputs);
                BOOST_CHECK(!ReadStoredPayment(id).released);

                m_service->Cancel(id);
                Flush();
            }

            BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Cancelled);
            BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
            BOOST_CHECK(ReadStoredPayment(id).released);
        }
    }
}

BOOST_AUTO_TEST_CASE(sender_retired_not_sent_save_failure_keeps_reservation)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    auto complete = std::move(m_transport->m_pending.front().complete);
    m_transport->m_pending.pop_front();

    m_service->Cancel(id);
    Flush();

    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment);
    complete({Delivery::NotSent, {}, "cancelled request was not sent"});
    Flush();
    m_database->CheckWriteFailed();

    const auto failed = *m_service->Snapshot(id);
    BOOST_CHECK(failed.issue == PaymentIssue::Storage);
    BOOST_CHECK(failed.storage_uncertain);
    BOOST_CHECK(failed.possibly_exposed);
    BOOST_CHECK(failed.owns_inputs);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
}

BOOST_AUTO_TEST_CASE(sender_not_sent_disclosure_rollback_failure_preserves_reservation)
{
    const auto id = m_service->Start(Intent());
    Flush();

    BOOST_REQUIRE_EQUAL(m_transport->m_pending.size(), 1);
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment);

    m_transport->m_pending.front().complete({Delivery::NotSent, {}, "local URL rejected", false});
    Flush();
    m_database->CheckWriteFailed();

    const auto failed = *m_service->Snapshot(id);
    BOOST_CHECK(failed.issue == PaymentIssue::Storage);
    BOOST_CHECK(failed.storage_uncertain);
    BOOST_CHECK(failed.possibly_exposed);
    BOOST_CHECK(failed.disclosure_saved);
    BOOST_CHECK(ReadStoredPayment(id).exposed);
    BOOST_CHECK(failed.owns_inputs);

    m_service->Cancel(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);
    BOOST_CHECK(!m_service->Snapshot(id)->selected);
    BOOST_CHECK(!m_service->Snapshot(id)->node_accepted);
}

BOOST_AUTO_TEST_CASE(sender_wallet_lock_covers_final_check_and_dispatch)
{
    const auto id = m_service->Start(Intent());
    m_node.chain->waitForNotifications();
    COutPoint coin;
    std::atomic<bool> acquired{false};
    std::promise<void> attempted;
    auto attempt = attempted.get_future();
    std::jthread competitor;
    ScopedHook read_hook{m_database->m_on_read};
    ScopedHook dispatch_hook{m_transport->m_on_dispatch};

    m_queue->insert([&] {
        BOOST_REQUIRE(m_service->Snapshot(id)->original);
        coin = m_service->Snapshot(id)->original->vin[0].prevout;
        m_database->m_on_read = [&](const std::string& type) {
            if (type != OWNER_RECORD || competitor.joinable()) return;
            competitor = std::jthread{[&] {
                {
                    TRY_LOCK(m_sender->cs_wallet, lock);
                    if (lock) acquired = true;
                }
                attempted.set_value();
                LOCK(m_sender->cs_wallet);
                acquired = true;
                m_sender->UnlockCoin(coin);
            }};
            attempt.wait();
        };
    });

    bool dispatched{false};
    m_transport->m_on_dispatch = [&] {
        dispatched = true;
        BOOST_CHECK(!acquired);
    };

    Flush();
    if (competitor.joinable()) competitor.join();
    read_hook.Reset();
    dispatch_hook.Reset();

    BOOST_CHECK(dispatched);
    BOOST_CHECK(acquired);
    BOOST_CHECK(m_service->Snapshot(id)->transport_accepted);
}

BOOST_AUTO_TEST_CASE(sender_fallback_has_no_cancelled_snapshot_even_when_close_fails)
{
    for (const bool fail_close : {false, true}) {
        BOOST_TEST_CONTEXT("close failure " << fail_close)
        {
            const auto id = m_service->Start(Intent());
            m_node.chain->waitForNotifications();
            CTransactionRef original;
            ScopedHook write_hook{m_database->m_on_write};
            m_queue->insert([&] {
                original = m_service->Snapshot(id)->original;
                BOOST_REQUIRE(original);
                m_database->m_on_write = [&](const std::string&) {
                    BOOST_CHECK(m_service->Snapshot(id)->phase != PaymentPhase::Cancelled);
                };
                if (fail_close) m_database->FailNextWrite(FaultDatabase::WriteTarget::JournalClose);
            });

            auto fallback_future = m_service->Execute(id, SenderCommand::Fallback);
            Flush();
            write_hook.Reset();
            if (fail_close) m_database->CheckWriteFailed();

            const auto view = *m_service->Snapshot(id);
            BOOST_REQUIRE(view.selected);
            BOOST_CHECK(view.selected->GetWitnessHash() == original->GetWitnessHash());
            BOOST_CHECK(view.node_accepted);
            const auto fallback_result = fallback_future.get();
            BOOST_CHECK(!fallback_result.refusal);
            BOOST_CHECK(view.storage_uncertain == fail_close);
            if (fail_close) BOOST_CHECK(view.issue == PaymentIssue::Storage);
            BOOST_CHECK(view.phase != PaymentPhase::Cancelled);
        }
    }

    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_owner_cursor_failure_prevents_selection)
{
    for (const auto& [name, fault] : {
             std::pair{"open", FaultDatabase::CursorFault::Open},
             std::pair{"read", FaultDatabase::CursorFault::Read},
             std::pair{"decode", FaultDatabase::CursorFault::Decode}}) {
        BOOST_TEST_CONTEXT("owner cursor " << name)
        {
            m_database->SetOwnerCursorFault(fault);
            const auto id = m_service->Start(Intent());
            Flush();

            m_database->CheckOwnerCursorFailed();
            BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Storage);
            BOOST_CHECK(!m_service->Snapshot(id)->original);
            BOOST_CHECK(!m_service->Snapshot(id)->original_saved);
            BOOST_CHECK(!m_service->Snapshot(id)->storage_uncertain);
            BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
        }
    }

    BOOST_CHECK(m_transport->m_pending.empty());
}

BOOST_AUTO_TEST_CASE(sender_invalid_uri_and_relay_can_be_cancelled)
{
    for (const auto& uri_value : {std::string{"not a uri"}, std::string{"bitcoin:"} + EncodeDestination(WitnessV0KeyHash{m_receiver_key.GetPubKey()}), m_uri + "&amount=2"}) {
        auto intent = Intent();
        intent.uri = uri_value;
        const auto id = m_service->Start(intent);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.issue == PaymentIssue::InvalidIntent);
        BOOST_CHECK(!view.diagnostic.empty());
        BOOST_CHECK(view.diagnostic != "std::exception");
        BOOST_CHECK(!view.original_saved);
        BOOST_CHECK(!view.owns_inputs);
        BOOST_CHECK(!view.storage_uncertain);
    }

    m_transport->m_acceptance = SubmitResult::InvalidRequest;
    for (const auto* relay_value : {"", "ftp://relay.example", "https://", "https:///missing-host", "https://user:secret@relay.example"}) {
        auto intent = Intent();
        intent.relay = relay_value;
        const auto id = m_service->Start(intent);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.issue == PaymentIssue::Protocol || view.issue == PaymentIssue::Delivery);
        BOOST_CHECK(view.original_saved);
        BOOST_CHECK(view.owns_inputs);
        BOOST_CHECK(!view.possibly_exposed);
        BOOST_CHECK(!view.disclosure_saved);
        BOOST_CHECK(!view.transport_accepted);
        BOOST_CHECK(!view.storage_uncertain);
        BOOST_CHECK(!ReadStoredPayment(id).exposed);

        m_service->Cancel(id);
        Flush();

        BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
        BOOST_CHECK(!m_service->Snapshot(id)->selected);
        BOOST_CHECK(!m_service->Snapshot(id)->node_accepted);
    }

    BOOST_CHECK(m_transport->m_pending.empty());

    auto without_amount = m_uri;
    without_amount.erase(without_amount.find("amount=1&"), std::string{"amount=1&"}.size());
    const auto parsed = ParsePayjoinUri(without_amount);
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(!parsed->amount_sats);

    const auto with_amount = ParsePayjoinUri(m_uri);
    BOOST_REQUIRE(with_amount);
    BOOST_CHECK(with_amount->amount_sats == COIN);
}

BOOST_AUTO_TEST_CASE(sender_mempool_refresh_preserves_delivery_diagnostic_until_fallback)
{
    const auto id = m_service->Start(Intent());
    Flush();

    auto pending = std::move(m_transport->m_pending.front());
    m_transport->m_pending.pop_front();
    pending.complete({Delivery::Uncertain, {}, "initial response lost"});
    Flush();

    const auto lost = *m_service->Snapshot(id);
    BOOST_CHECK(lost.possibly_exposed);
    BOOST_CHECK(lost.disclosure_saved);
    BOOST_CHECK(ReadStoredPayment(id).exposed);

    const auto original = lost.original;
    {
        LOCK(m_sender->cs_wallet);
        auto* wtx = m_sender->AddToWallet(original, TxStateInactive{});
        BOOST_REQUIRE(wtx);
        std::string error;
        BOOST_REQUIRE(m_sender->SubmitTxMemoryPoolAndRelay(*wtx, error, node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL));
    }

    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.phase == PaymentPhase::Attention);
        BOOST_CHECK(view.issue == PaymentIssue::Delivery);
        BOOST_CHECK_EQUAL(view.diagnostic, "initial response lost");
        BOOST_CHECK(view.original_presence == TransactionPresence::Mempool);
        BOOST_CHECK(view.fallback_available);
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

    BOOST_CHECK(Journal(id).second);
    BOOST_CHECK_EQUAL(m_transport->m_attempts, 1);

    Confirm(original);
    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Confirmed);
    BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
}

BOOST_AUTO_TEST_CASE(sender_reorg_original_does_not_restore_released_ownership)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    const auto block = Confirm(original);
    m_service->Refresh(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->settlement);
    BOOST_REQUIRE(!m_service->Snapshot(id)->owns_inputs);

    Disconnect(block);
    for (int i = 0; i < 2; ++i) {
        auto refreshed = m_service->Execute(id, SenderCommand::Refresh);
        Flush();
        const auto result = refreshed.get();
        BOOST_CHECK(result.status == CommandStatus::Completed);
        BOOST_CHECK(result.diagnostic.empty());

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(!view.settlement);
        BOOST_CHECK(view.phase == PaymentPhase::Attention);
        BOOST_CHECK(view.issue == PaymentIssue::ObservedSpend);
        BOOST_CHECK(!view.owns_inputs);
        BOOST_CHECK(!view.fallback_available);
    }

    m_service->PublishFallback(id);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->selected);

    BOOST_REQUIRE(m_node.mempool->exists(original->GetHash()));
    m_sender->transactionAddedToMempool(original);
    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->original_presence == TransactionPresence::Mempool);
    BOOST_CHECK(!m_service->Snapshot(id)->settlement);

    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*original, MemPoolRemovalReason::EXPIRY);
    }
    m_sender->transactionRemovedFromMempool(original, MemPoolRemovalReason::EXPIRY);
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(m_sender->AbandonTransaction(original->GetHash()));
    }

    auto next_intent = Intent();
    next_intent.amount = 99 * COIN;
    next_intent.uri.replace(next_intent.uri.find("amount=1"), 8, "amount=99");
    const auto next = m_service->Start(next_intent);
    Flush();

    BOOST_REQUIRE_MESSAGE(m_service->Snapshot(next)->owns_inputs, m_service->Snapshot(next)->diagnostic);

    const auto input = original->vin[0].prevout;
    m_service->Cancel(id);
    Flush();
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();
        LOCK(m_sender->cs_wallet);
        auto owner = ReadOwner(input);
        BOOST_CHECK(owner == next);
        BOOST_CHECK(m_sender->IsLockedCoin(input));
        BOOST_CHECK(!m_service->Snapshot(id)->owns_inputs);
    }

    Confirm(original);
    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Confirmed);
    BOOST_CHECK(m_service->Snapshot(id)->settlement);

    LOCK(m_sender->cs_wallet);
    auto owner = ReadOwner(input);
    BOOST_CHECK(owner == next);
}

BOOST_AUTO_TEST_CASE(sender_reorg_selected_preserves_uncertain_release)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_service->PublishFallback(id);
    Flush();

    const auto selected = m_service->Snapshot(id)->selected;
    BOOST_REQUIRE(selected);

    const auto block = Confirm(selected);
    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment);
    m_service->Refresh(id);
    Flush();
    m_database->CheckWriteFailed();
    BOOST_REQUIRE(m_service->Snapshot(id)->storage_uncertain);

    Disconnect(block);
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(!view.settlement);
        BOOST_CHECK(view.phase == PaymentPhase::Attention);
        BOOST_CHECK(view.issue == PaymentIssue::Storage);
        BOOST_CHECK(view.storage_uncertain);
        BOOST_CHECK(view.owns_inputs);
        BOOST_CHECK(!view.fallback_available);
    }

    auto publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto publication_result = publication_future.get();
    BOOST_CHECK(publication_result.refusal == CommandRefusal::StorageUncertain);
}

BOOST_AUTO_TEST_CASE(sender_unlock_failure_keeps_release_uncertain)
{
    auto intent = Intent();
    intent.amount = 99 * COIN;
    intent.uri.replace(intent.uri.find("amount=1"), 8, "amount=99");

    const auto id = m_service->Start(intent);
    m_node.chain->waitForNotifications();
    CTransactionRef original;
    m_queue->insert([&] {
        original = m_service->Snapshot(id)->original;
        BOOST_REQUIRE(original);
        BOOST_REQUIRE_EQUAL(original->vin.size(), 2);
        m_database->SetEraseFailure("lockedutxo");
    });
    m_service->Cancel(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);

    const auto input = original->vin[0].prevout;
    {
        LOCK(m_sender->cs_wallet);
        BOOST_CHECK(!m_sender->IsLockedCoin(input));
    }
    BOOST_CHECK(LockedMarker(input));

    m_database->CheckEraseFailed();
    m_database->ClearEraseFailure();
    m_service->Cancel(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);

    const auto stored = ReadStoredPayment(id);
    BOOST_CHECK(!stored.released);
    for (size_t i = 0; i < original->vin.size(); ++i) {
        const auto out = original->vin[i].prevout;
        auto owner = ReadOwner(out);
        BOOST_CHECK(owner == id);
        BOOST_CHECK(LockedMarker(out));
        BOOST_CHECK_EQUAL(WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(out)), i != 0);
    }
}

void CheckStaleFallbackMarker(SenderFixture& fixture, bool persistent_failure)
{
    const auto id = fixture.m_service->Start(fixture.Intent());
    fixture.Flush();

    const auto original = fixture.m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);

    fixture.m_database->SetEraseFailure(DBKeys::LOCKED_UTXO);
    fixture.m_service->PublishFallback(id);
    fixture.Flush();
    fixture.m_database->CheckEraseFailed();
    BOOST_REQUIRE(fixture.m_service->Snapshot(id)->node_accepted);
    for (const auto& input : original->vin) {
        BOOST_REQUIRE(fixture.LockedMarker(input.prevout));
        BOOST_REQUIRE(!WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsLockedCoin(input.prevout)));
    }

    if (!persistent_failure) fixture.m_database->ClearEraseFailure();
    fixture.Confirm(original);
    for (const auto& input : original->vin) {
        BOOST_REQUIRE(fixture.LockedMarker(input.prevout));
    }

    std::string diagnostic;
    for (int i = 0; i < 3; ++i) {
        if (i == 2) fixture.m_database->ClearEraseFailure();
        fixture.m_service->Refresh(id);
        fixture.Flush();

        if (!persistent_failure) {
            fixture.CheckReleased(id);
            continue;
        }
        const auto view = *fixture.m_service->Snapshot(id);
        BOOST_REQUIRE(view.settlement);
        BOOST_CHECK(view.settlement->kind == SpendKind::Original);
        BOOST_CHECK(view.storage_uncertain);
        BOOST_CHECK(view.owns_inputs);
        BOOST_CHECK(!view.locks_verified);
        BOOST_CHECK(view.issue == PaymentIssue::Storage);
        BOOST_CHECK(!view.diagnostic.empty());
        if (i == 0) diagnostic = view.diagnostic;
        BOOST_CHECK_EQUAL(view.diagnostic, diagnostic);

        const auto stored = fixture.ReadStoredPayment(id);
        BOOST_CHECK(!stored.released);
        for (const auto& input : original->vin) {
            auto owner = fixture.ReadOwner(input.prevout);
            BOOST_CHECK(owner == id);
            BOOST_CHECK(fixture.LockedMarker(input.prevout));
            BOOST_CHECK(!WITH_LOCK(fixture.m_sender->cs_wallet, return fixture.m_sender->IsLockedCoin(input.prevout)));
        }
    }

    if (persistent_failure) {
        auto publication_future = fixture.m_service->Execute(id, SenderCommand::RetryPublication);
        fixture.Flush();

        const auto publication_result = publication_future.get();
        BOOST_CHECK(publication_result.refusal == CommandRefusal::StorageUncertain);
    }
}

BOOST_AUTO_TEST_CASE(sender_fallback_settlement_erases_stale_persistent_marker)
{
    CheckStaleFallbackMarker(*this, false);
}

BOOST_AUTO_TEST_CASE(sender_fallback_marker_erase_failure_preserves_owner_and_uncertainty)
{
    CheckStaleFallbackMarker(*this, true);
}

BOOST_AUTO_TEST_CASE(sender_release_checks_all_owners_before_any_unlock)
{
    auto intent = Intent();
    intent.amount = 99 * COIN;
    intent.uri.replace(intent.uri.find("amount=1"), 8, "amount=99");

    const auto id = m_service->Start(intent);
    m_node.chain->waitForNotifications();
    const uint256 foreign_owner{uint256::ONE};
    CTransactionRef original;
    COutPoint foreign_input;
    m_queue->insert([&] {
        original = m_service->Snapshot(id)->original;
        BOOST_REQUIRE(original);
        BOOST_REQUIRE_EQUAL(original->vin.size(), 2);
        foreign_input = original->vin.back().prevout;
        WriteOwner(foreign_input, foreign_owner);
    });

    m_service->Cancel(id);
    Flush();

    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.issue == PaymentIssue::Reservation);
        BOOST_CHECK(view.owns_inputs);
        BOOST_CHECK(!view.storage_uncertain);

        const auto stored = ReadStoredPayment(id);
        BOOST_CHECK(!stored.released);
        for (const auto& input : original->vin) {
            auto owner = ReadOwner(input.prevout);
            BOOST_CHECK(owner == (input.prevout == foreign_input ? foreign_owner : id));
            BOOST_CHECK(LockedMarker(input.prevout));
            BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
        }
    }
}

struct ReleaseFailureFixture : SenderFixture {
    const uint256 m_id{m_service->Start(Intent())};

    ReleaseFailureFixture() { m_node.chain->waitForNotifications(); }

    ~ReleaseFailureFixture()
    {
        m_database->SetTransactionFailure(FaultDatabase::Transaction::Begin, false);
        m_database->SetTransactionFailure(FaultDatabase::Transaction::Commit, false);
        m_database->SetTransactionFailure(FaultDatabase::Transaction::Abort, false);
        m_database->ClearEraseFailure();
    }

    void CheckUnreleased()
    {
        const auto view = *m_service->Snapshot(m_id);
        BOOST_CHECK(view.storage_uncertain);
        BOOST_CHECK(view.owns_inputs);
        BOOST_CHECK(!view.locks_verified);
        BOOST_REQUIRE(view.original);
        auto owner = ReadOwner(view.original->vin[0].prevout);
        BOOST_CHECK(owner == m_id);
    }
};

BOOST_FIXTURE_TEST_CASE(sender_release_begin_failure_does_not_claim_success, ReleaseFailureFixture)
{
    m_queue->insert([&] { m_database->SetTransactionFailure(FaultDatabase::Transaction::Begin, true); });
    m_service->Cancel(m_id);
    Flush();

    CheckUnreleased();
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Begin);
}

BOOST_FIXTURE_TEST_CASE(sender_release_commit_failure_does_not_claim_success, ReleaseFailureFixture)
{
    m_queue->insert([&] { m_database->SetTransactionFailure(FaultDatabase::Transaction::Commit, true); });
    m_service->Cancel(m_id);
    Flush();

    CheckUnreleased();
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Commit);
}

BOOST_AUTO_TEST_CASE(sender_release_lost_commit_acknowledgement_preserves_uncertainty)
{
    m_transport->m_acceptance = SubmitResult::Busy;
    const auto id = m_service->Start(Intent());
    Flush();
    const auto prepared = *m_service->Snapshot(id);
    BOOST_REQUIRE(!prepared.possibly_exposed);
    BOOST_REQUIRE(prepared.owns_inputs);
    {
        LOCK(m_sender->cs_wallet);
        CheckOwnedInputs(id, *prepared.original);
    }

    m_database->LoseNextCommitAcknowledgement();
    auto cancelled = m_service->Execute(id, SenderCommand::Cancel);
    Flush();
    BOOST_CHECK(cancelled.get().status == CommandStatus::Failed);
    m_database->CheckCommitAcknowledgementLost();
    BOOST_REQUIRE(!m_database->HasActiveTxn());
    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(view.storage_uncertain);
    BOOST_CHECK(view.owns_inputs);
    BOOST_CHECK(!view.locks_verified);
    BOOST_CHECK(view.issue == PaymentIssue::Storage);
    BOOST_CHECK_EQUAL(view.diagnostic, "ownership release rollback failed");

    BOOST_CHECK(ReadStoredPayment(id).released);
    BOOST_CHECK(Journal(id).second);
    for (const auto& input : view.original->vin) {
        BOOST_CHECK(!HasOwner(input.prevout));
        BOOST_CHECK(!LockedMarker(input.prevout));
        BOOST_CHECK(!WITH_LOCK(m_sender->cs_wallet, return m_sender->IsLockedCoin(input.prevout)));
    }
    const auto records = ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO});

    m_service->Cancel(id);
    Flush();
    BOOST_CHECK(m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);

    m_service->Stop();
    BOOST_CHECK(m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK(ReadRecords(*m_database, {PAYMENT_RECORD, JOURNAL_RECORD, OWNER_RECORD, DBKeys::LOCKED_UTXO}) == records);
    CheckNoPublication(*this, *m_service->Snapshot(id));
}

BOOST_FIXTURE_TEST_CASE(sender_release_owner_erase_failure_does_not_claim_success, ReleaseFailureFixture)
{
    m_queue->insert([&] { m_database->SetEraseFailure(OWNER_RECORD); });
    m_service->Cancel(m_id);
    Flush();

    CheckUnreleased();
    m_database->CheckEraseFailed();

    m_database->ClearEraseFailure();
    m_service->Refresh(m_id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(m_id)->storage_uncertain);
    BOOST_CHECK(m_service->Snapshot(m_id)->owns_inputs);
}

BOOST_FIXTURE_TEST_CASE(sender_release_abort_failure_remains_uncertain, ReleaseFailureFixture)
{
    m_queue->insert([&] {
        m_database->SetTransactionFailure(FaultDatabase::Transaction::Commit, true);
        m_database->SetTransactionFailure(FaultDatabase::Transaction::Abort, true);
    });
    m_service->Cancel(m_id);
    Flush();

    CheckUnreleased();
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Commit);
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Abort);
    BOOST_CHECK(m_service->Snapshot(m_id)->issue == PaymentIssue::Storage);

    m_database->SetTransactionFailure(FaultDatabase::Transaction::Commit, false);
    m_database->SetTransactionFailure(FaultDatabase::Transaction::Abort, false);
    m_service->Refresh(m_id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(m_id)->storage_uncertain);
}

BOOST_AUTO_TEST_CASE(sender_cancel_after_reorg_observes_reconfirmation)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(m_service->Snapshot(id)->possibly_exposed);

    const auto block = Confirm(original);
    m_service->Refresh(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->settlement);
    BOOST_REQUIRE(!m_service->Snapshot(id)->owns_inputs);

    Disconnect(block);
    m_service->Refresh(id);
    Flush();

    BOOST_REQUIRE(!m_service->Snapshot(id)->settlement);

    m_service->Cancel(id);
    Flush();

    Confirm(original);
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_CHECK(view.original_presence == TransactionPresence::Confirmed);
        BOOST_CHECK(view.phase == PaymentPhase::Confirmed);
        BOOST_CHECK(view.settlement.has_value());
        BOOST_CHECK(!view.owns_inputs);
    }
}

BOOST_AUTO_TEST_CASE(sender_cancel_after_original_reorg_observes_conflict)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;

    CMutableTransaction other{*original};
    for (auto& input : other.vin) {
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }

    other.vout[0].nValue -= 1000;
    PartiallySignedTransaction psbt{other, 0};
    bool complete{false};
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(!m_sender->FillPSBT(psbt, {}, complete));
    }
    BOOST_REQUIRE(complete);
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, other));

    const auto block = Confirm(original);
    m_service->Refresh(id);
    Flush();

    Disconnect(block);
    m_service->Refresh(id);
    m_service->Cancel(id);
    Flush();

    Confirm(MakeTransactionRef(std::move(other)));
    for (int i = 0; i < 2; ++i) {
        m_service->Refresh(id);
        Flush();

        const auto view = *m_service->Snapshot(id);
        BOOST_REQUIRE(view.settlement);
        BOOST_CHECK(view.settlement->kind == SpendKind::Other);
        BOOST_CHECK(view.phase == PaymentPhase::Conflicted);
        BOOST_CHECK(!view.owns_inputs);
    }
}

BOOST_AUTO_TEST_CASE(sender_delayed_disconnect_requires_wallet_synchronization)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    const auto block = Confirm(original);

    auto* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip->GetBlockHash() == block.GetHash());
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*original, MemPoolRemovalReason::EXPIRY);
    }

    m_service->PublishFallback(id);
    Flush();

    const auto view = *m_service->Snapshot(id);
    BOOST_CHECK(!view.node_accepted);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK(!view.selection_saved);
    BOOST_CHECK(view.issue == PaymentIssue::Publication);
    BOOST_CHECK(view.diagnostic.find("synchronization") != std::string::npos);
    BOOST_CHECK(view.phase != PaymentPhase::Published);

    BOOST_CHECK(!m_node.mempool->exists(original->GetHash()));

    m_sender->blockDisconnected(kernel::MakeBlockInfo(tip, &block));
    m_sender->transactionRemovedFromMempool(original, MemPoolRemovalReason::EXPIRY);

    m_service->PublishFallback(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->node_accepted);
    BOOST_CHECK(m_service->Snapshot(id)->phase == PaymentPhase::Published);

    BOOST_CHECK(m_node.mempool->exists(original->GetHash()));
}

BOOST_AUTO_TEST_CASE(sender_publication_notifies_spent_wallet_parents)
{
    CMutableTransaction funding;
    {
        LOCK(m_sender->cs_wallet);
        const auto& coin = m_sender->mapWallet.begin()->second.GetTx();
        funding.vin.emplace_back(COutPoint{coin->GetHash(), 0});
    }
    const auto script = GetScriptForDestination(WitnessV0KeyHash{m_sender_key.GetPubKey()});
    funding.vout.emplace_back(25 * COIN, script);
    funding.vout.emplace_back(25 * COIN - 1000, script);
    PartiallySignedTransaction psbt{funding, 0};
    bool complete{false};
    {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(!m_sender->FillPSBT(psbt, {}, complete));
    }
    BOOST_REQUIRE(complete);
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, funding));
    Confirm(MakeTransactionRef(std::move(funding)));

    auto intent = Intent();
    intent.amount = 99 * COIN;
    intent.uri.replace(intent.uri.find("amount=1"), 8, "amount=99");
    const auto id = m_service->Start(intent);
    Flush();

    const auto original = m_service->Snapshot(id)->original;
    BOOST_REQUIRE(original);
    BOOST_REQUIRE_EQUAL(original->vin.size(), 3);

    struct RestoreLoadFactor {
        CWallet& m_wallet;
        const float m_load_factor;

        ~RestoreLoadFactor()
        {
            LOCK(m_wallet.cs_wallet);
            m_wallet.mapWallet.max_load_factor(m_load_factor);
        }
    } restore_load_factor{*m_sender, WITH_LOCK(m_sender->cs_wallet, return m_sender->mapWallet.max_load_factor())};

    const auto buckets_before = [&] {
        LOCK(m_sender->cs_wallet);
        BOOST_REQUIRE(!m_sender->mapWallet.contains(original->GetHash()));
        BOOST_REQUIRE(!m_sender->mapWallet.empty());
        m_sender->mapWallet.max_load_factor(m_sender->mapWallet.load_factor() / 2);
        return m_sender->mapWallet.bucket_count();
    }();

    std::map<Txid, size_t> updated;
    btcsignals::scoped_connection connection{m_sender->NotifyTransactionChanged.connect([&](const Txid& txid, ChangeType status) {
        if (status == CT_UPDATED) ++updated[txid];
    })};

    m_service->PublishFallback(id);
    Flush();
    connection.disconnect();

    BOOST_REQUIRE(m_service->Snapshot(id)->node_accepted);
    BOOST_CHECK(WITH_LOCK(m_sender->cs_wallet, return m_sender->mapWallet.bucket_count()) != buckets_before);
    for (const auto& input : original->vin) {
        const auto notification = updated.find(input.prevout.hash);
        BOOST_REQUIRE(notification != updated.end());
        BOOST_CHECK_EQUAL(notification->second, 1);
    }

    updated.clear();
    btcsignals::scoped_connection retry_connection{m_sender->NotifyTransactionChanged.connect([&](const Txid& txid, ChangeType status) {
        if (status == CT_UPDATED) ++updated[txid];
    })};
    m_service->RetryPublication(id);
    Flush();
    retry_connection.disconnect();
    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == original->GetWitnessHash());
    for (const auto& input : original->vin) {
        BOOST_CHECK(!updated.contains(input.prevout.hash));
    }
}

BOOST_AUTO_TEST_CASE(sender_wallet_parent_notifications_survive_submission_failure)
{
    for (const bool broadcast : {false, true}) {
        BOOST_TEST_CONTEXT("broadcast=" << broadcast)
        {
            const auto id = m_service->Start(Intent());
            Flush();

            const auto original = m_service->Snapshot(id)->original;
            BOOST_REQUIRE(original);

            const auto max_fee = m_sender->m_max_tx_fee;
            m_sender->SetBroadcastTransactions(broadcast);
            m_sender->m_max_tx_fee = 1;
            std::set<Txid> updated;
            btcsignals::scoped_connection connection{m_sender->NotifyTransactionChanged.connect([&](const Txid& txid, ChangeType status) {
                if (status == CT_UPDATED) updated.insert(txid);
            })};

            m_service->PublishFallback(id);
            Flush();
            connection.disconnect();
            m_sender->m_max_tx_fee = max_fee;
            m_sender->SetBroadcastTransactions(true);

            const auto view = *m_service->Snapshot(id);
            BOOST_CHECK(view.wallet_recorded);
            BOOST_CHECK(!view.node_accepted);
            BOOST_CHECK(view.issue == (broadcast ? PaymentIssue::Publication : PaymentIssue::BroadcastDisabled));
            for (const auto& input : original->vin) {
                BOOST_CHECK(updated.contains(input.prevout.hash));
            }
        }
    }
}

namespace {
void CheckKnownOriginalState(SenderFixture& fixture, TransactionPresence presence)
{
    const auto id = fixture.m_service->Start(fixture.Intent());
    fixture.Flush();

    const auto original = fixture.m_service->Snapshot(id)->original;
    const auto tip = WITH_LOCK(cs_main, return fixture.m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    const auto height = WITH_LOCK(cs_main, return fixture.m_node.chainman->ActiveChain().Height());
    {
        LOCK(fixture.m_sender->cs_wallet);
        const TxState state = presence == TransactionPresence::BlockConflicted ? TxState{TxStateBlockConflicted{tip, height}} : TxState{TxStateInactive{presence == TransactionPresence::Abandoned}};
        auto* known = fixture.m_sender->AddToWallet(original, state);
        BOOST_REQUIRE(known);
        if (presence == TransactionPresence::MempoolConflicted) known->mempool_conflicts.insert(fixture.m_receiver_coin->GetHash());
        for (const auto& input : original->vin) {
            BOOST_CHECK(!fixture.m_sender->IsLockedCoin(input.prevout));
        }
    }

    fixture.m_service->PublishFallback(id);
    fixture.Flush();

    const auto view = *fixture.m_service->Snapshot(id);
    BOOST_CHECK(view.original_presence == presence);
    BOOST_CHECK(view.issue == PaymentIssue::Publication);
    BOOST_CHECK(view.diagnostic.find("reconciliation") != std::string::npos);
    BOOST_CHECK(!view.selected);
    BOOST_CHECK(!view.node_accepted);

    {
        LOCK(fixture.m_sender->cs_wallet);
        fixture.WriteOwner(original->vin[0].prevout, uint256{});
    }

    fixture.m_service->PublishFallback(id);
    fixture.Flush();

    BOOST_CHECK(fixture.m_service->Snapshot(id)->issue == PaymentIssue::Reservation);
}
} // namespace

BOOST_AUTO_TEST_CASE(sender_abandoned_original_requires_reconciliation)
{
    CheckKnownOriginalState(*this, TransactionPresence::Abandoned);
}

BOOST_AUTO_TEST_CASE(sender_mempool_conflicted_original_requires_reconciliation)
{
    CheckKnownOriginalState(*this, TransactionPresence::MempoolConflicted);
}

BOOST_AUTO_TEST_CASE(sender_block_conflicted_original_requires_reconciliation)
{
    CheckKnownOriginalState(*this, TransactionPresence::BlockConflicted);
}

BOOST_AUTO_TEST_CASE(sender_publication_retry_refusal_priority)
{
    const auto id = m_service->Start(Intent());
    Flush();

    auto unselected_publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto unselected_publication_result = unselected_publication_future.get();
    BOOST_CHECK(unselected_publication_result.refusal == CommandRefusal::InvalidState);

    const auto original = m_service->Snapshot(id)->original;
    const auto block = Confirm(original);

    auto confirmed_publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto confirmed_publication_result = confirmed_publication_future.get();
    BOOST_CHECK(confirmed_publication_result.refusal == CommandRefusal::Settled);
    BOOST_CHECK(!m_service->Snapshot(id)->node_accepted);

    Disconnect(block);

    auto reorg_publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->settlement);
    const auto reorg_publication_result = reorg_publication_future.get();
    BOOST_CHECK(reorg_publication_result.refusal == CommandRefusal::Settled);

    auto refresh_future = m_service->Execute(id, SenderCommand::Refresh);
    Flush();

    const auto refresh_result = refresh_future.get();
    BOOST_CHECK(!refresh_result.refusal);
}

BOOST_AUTO_TEST_CASE(sender_publication_retry_waits_for_wallet_disconnect)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_sender->SetBroadcastTransactions(false);
    m_service->PublishFallback(id);
    Flush();

    const auto selected = m_service->Snapshot(id)->selected;
    BOOST_REQUIRE(selected);

    const auto block = Confirm(selected);
    auto* tip = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip));
    {
        LOCK(m_node.mempool->cs);
        m_node.mempool->removeRecursive(*selected, MemPoolRemovalReason::EXPIRY);
    }

    m_sender->SetBroadcastTransactions(true);
    m_service->RetryPublication(id);
    Flush();

    BOOST_CHECK(!m_service->Snapshot(id)->node_accepted);
    BOOST_CHECK(m_service->Snapshot(id)->diagnostic.find("synchronization") != std::string::npos);
    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == selected->GetWitnessHash());

    m_sender->blockDisconnected(kernel::MakeBlockInfo(tip, &block));
    m_sender->transactionRemovedFromMempool(selected, MemPoolRemovalReason::EXPIRY);
    m_service->RetryPublication(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->node_accepted);

    BOOST_CHECK(m_node.mempool->exists(selected->GetHash()));
    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == selected->GetWitnessHash());
}

BOOST_AUTO_TEST_CASE(sender_cancel_after_reorg_preserves_uncertain_release)
{
    const auto id = m_service->Start(Intent());
    Flush();

    const auto block = Confirm(m_service->Snapshot(id)->original);
    m_database->SetTransactionFailure(FaultDatabase::Transaction::Begin, true);
    m_service->Refresh(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->storage_uncertain);
    m_database->CheckTransactionFailed(FaultDatabase::Transaction::Begin);
    m_database->SetTransactionFailure(FaultDatabase::Transaction::Begin, false);

    Disconnect(block);
    m_service->Refresh(id);
    m_service->Cancel(id);
    m_service->Refresh(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->storage_uncertain);
    BOOST_CHECK(m_service->Snapshot(id)->owns_inputs);
    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Storage);
}

BOOST_AUTO_TEST_CASE(sender_publication_retry_requires_saved_selection)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_database->FailNextWrite(FaultDatabase::WriteTarget::Payment);
    m_service->PublishFallback(id);
    Flush();

    BOOST_REQUIRE(m_service->Snapshot(id)->selected);
    BOOST_CHECK(!m_service->Snapshot(id)->selection_saved);
    BOOST_CHECK(!m_service->Snapshot(id)->wallet_recorded);
    m_database->CheckWriteFailed();

    auto publication_future = m_service->Execute(id, SenderCommand::RetryPublication);
    Flush();

    const auto publication_result = publication_future.get();
    BOOST_CHECK(publication_result.refusal == CommandRefusal::StorageUncertain);
}

BOOST_AUTO_TEST_CASE(sender_publication_retry_does_not_reinsert_missing_wallet_record)
{
    const auto id = m_service->Start(Intent());
    Flush();

    m_sender->SetBroadcastTransactions(false);
    m_service->PublishFallback(id);
    Flush();

    const auto selected = m_service->Snapshot(id)->selected;
    BOOST_REQUIRE(selected);
    {
        LOCK(m_sender->cs_wallet);
        std::vector<Txid> removed{selected->GetHash()};
        BOOST_REQUIRE(m_sender->RemoveTxs(removed));
    }

    m_service->RetryPublication(id);
    Flush();

    BOOST_CHECK(m_service->Snapshot(id)->issue == PaymentIssue::Publication);
    BOOST_CHECK(m_service->Snapshot(id)->selected->GetWitnessHash() == selected->GetWitnessHash());

    LOCK(m_sender->cs_wallet);
    BOOST_CHECK(!m_sender->GetWalletTx(selected->GetHash()));
}

BOOST_FIXTURE_TEST_CASE(controlled_transport_stop_retires_held_requests, BasicTestingSetup)
{
    ControlledTransport transport;
    int callbacks{0};
    const auto completion = [&](const TransportResult& result) {
        ++callbacks;
        BOOST_CHECK(result.delivery == Delivery::NotSent);
    };
    BOOST_REQUIRE(transport.Submit(1, {"http://not-used.invalid", "text/plain", {}},
                                   std::chrono::seconds{1}, completion) == SubmitResult::Accepted);
    BOOST_REQUIRE(transport.Submit(2, {"http://not-used.invalid", "text/plain", {}},
                                   std::chrono::seconds{1}, completion) == SubmitResult::Accepted);

    transport.Stop();
    BOOST_CHECK_EQUAL(callbacks, 2);
    BOOST_CHECK(transport.m_pending.empty());
    BOOST_CHECK(transport.Submit(3, {}, std::chrono::seconds{1}, completion) == SubmitResult::Stopped);
}
BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet::payjoin
