// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <compat/compat.h>
#include <curl/curl.h>
#include <netbase.h>
#include <netinet/in.h>
#include <payjoin/client.h>
#include <payjoin/http_transport.h>
#include <payjoin/transport.h>
#include <sync.h>
#include <sys/socket.h>
#include <tinyformat.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef __linux__
struct MultiFailureProbe;
static std::atomic<MultiFailureProbe*> g_multi_probe{nullptr};

struct MultiFailureProbe {
    std::atomic<bool> m_hold_active_poll{false};
    std::atomic<bool> m_fail_idle_poll{false};
    std::atomic<bool> m_fail_active_poll{false};
    std::atomic<bool> m_fail_perform{false};
    std::promise<void> m_poll_entered;
    std::promise<void> m_poll_release;
    std::promise<void> m_perform_entered;
    std::promise<void> m_perform_release;
    std::atomic<bool> m_poll_released{false};
    std::atomic<bool> m_perform_released{false};
    MultiFailureProbe* const m_previous{g_multi_probe.exchange(this)};

    MultiFailureProbe() = default;

    MultiFailureProbe(const MultiFailureProbe&) = delete;

    MultiFailureProbe& operator=(const MultiFailureProbe&) = delete;

    ~MultiFailureProbe() { g_multi_probe.store(m_previous); }

    void ReleasePoll()
    {
        if (!m_poll_released.exchange(true)) m_poll_release.set_value();
    }

    void ReleasePerform()
    {
        if (!m_perform_released.exchange(true)) m_perform_release.set_value();
    }
};

extern "C" CURLMcode __real_curl_multi_poll(CURLM*, curl_waitfd*, unsigned int, int, int*);
extern "C" CURLMcode __real_curl_multi_perform(CURLM*, int*);

extern "C" CURLMcode __wrap_curl_multi_poll(CURLM* multi, curl_waitfd* extra, unsigned int count, int timeout, int* running)
{
    auto* probe = g_multi_probe.load();
    if (probe) {
        if (timeout == 60000 && probe->m_fail_idle_poll.exchange(false)) {
            probe->m_poll_entered.set_value();
            probe->m_poll_release.get_future().wait();
            return CURLM_BAD_HANDLE;
        }
        if (timeout == 1000 && probe->m_hold_active_poll.exchange(false)) {
            probe->m_poll_entered.set_value();
            probe->m_poll_release.get_future().wait();
            if (probe->m_fail_active_poll.exchange(false)) return CURLM_BAD_HANDLE;
        }
    }

    return __real_curl_multi_poll(multi, extra, count, timeout, running);
}

extern "C" CURLMcode __wrap_curl_multi_perform(CURLM* multi, int* running)
{
    auto* probe = g_multi_probe.load();
    if (probe && probe->m_fail_perform.exchange(false)) {
        probe->m_perform_entered.set_value();
        probe->m_perform_release.get_future().wait();
        return CURLM_BAD_HANDLE;
    }

    return __real_curl_multi_perform(multi, running);
}
#endif

namespace wallet::payjoin {
namespace {
constexpr size_t TEST_REQUEST_BODY_SIZE{512};

#ifdef __linux__
class MultiProbeCleanup
{
    MultiFailureProbe& m_probe;
    HttpSenderTransport& m_http;
    std::promise<void>* m_callback_release;

public:
    explicit MultiProbeCleanup(MultiFailureProbe& probe, HttpSenderTransport& http, std::promise<void>* callback_release = nullptr)
        : m_probe{probe}, m_http{http}, m_callback_release{callback_release} {}

    void ReleaseCallback()
    {
        if (auto* release = std::exchange(m_callback_release, nullptr)) release->set_value();
    }

    ~MultiProbeCleanup()
    {
        m_probe.ReleasePoll();
        m_probe.ReleasePerform();
        ReleaseCallback();
        m_http.Stop();
    }
};
#endif

class HttpTestCleanup
{
    HttpSenderTransport& m_http;
    std::promise<void>* m_barrier;
    std::thread* m_first;
    std::thread* m_second;

public:
    explicit HttpTestCleanup(HttpSenderTransport& http, std::promise<void>* barrier = nullptr,
                             std::thread* first = nullptr, std::thread* second = nullptr)
        : m_http{http}, m_barrier{barrier}, m_first{first}, m_second{second} {}

    HttpTestCleanup(const HttpTestCleanup&) = delete;

    HttpTestCleanup& operator=(const HttpTestCleanup&) = delete;

    void Release()
    {
        if (auto* barrier = std::exchange(m_barrier, nullptr)) barrier->set_value();
    }

    ~HttpTestCleanup()
    {
        Release();
        if (m_first && m_first->joinable()) m_first->join();
        if (m_second && m_second->joinable()) m_second->join();
        m_http.Stop();
    }
};

class ScopedEnvironment
{
    std::string m_name;
    std::optional<std::string> m_previous;

public:
    explicit ScopedEnvironment(std::string name, const char* value) : m_name{std::move(name)}
    {
        if (const char* previous = std::getenv(m_name.c_str())) m_previous = previous;
        if ((value ? setenv(m_name.c_str(), value, 1) : unsetenv(m_name.c_str())) != 0) {
            throw std::runtime_error{"environment setup failed"};
        }
    }

    ~ScopedEnvironment()
    {
        if (m_previous) {
            setenv(m_name.c_str(), m_previous->c_str(), 1);
        } else {
            unsetenv(m_name.c_str());
        }
    }
};

class ReservedTcpPort
{
    std::unique_ptr<Sock> m_socket{CreateSockOS(AF_INET, SOCK_STREAM, 0)};
    uint16_t m_port{0};

public:
    ReservedTcpPort()
    {
        BOOST_REQUIRE(m_socket);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE_EQUAL(m_socket->Bind(reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);

        socklen_t length = sizeof(address);
        BOOST_REQUIRE_EQUAL(m_socket->GetSockName(reinterpret_cast<sockaddr*>(&address), &length), 0);
        m_port = ntohs(address.sin_port);
        BOOST_REQUIRE(m_port != 0);
    }

    uint16_t Port() const { return m_port; }
};

class HttpWireObserver
{
    std::unique_ptr<Sock> m_socket{CreateSockOS(AF_INET, SOCK_STREAM, 0)};
    CThreadInterrupt m_interrupt;
    std::thread m_worker;
    std::exception_ptr m_error;
    Mutex m_mutex;
    std::vector<std::string> m_requests GUARDED_BY(m_mutex);
    std::atomic<int> m_connections{0};
    std::promise<void> m_request_received;

    void Run(size_t expected_body_size, bool respond, bool chunked, bool partial, bool allow_disconnect, const std::optional<std::string>& reply) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        while (!m_interrupt) {
            Sock::Event ready{};
            if (!m_socket->Wait(std::chrono::milliseconds{100}, Sock::RecvEvent, &ready)) {
                if (!IOErrorIsPermanent(WSAGetLastError())) continue;
                throw std::runtime_error{"listener wait failed"};
            }
            if (!ready) continue;

            auto client = m_socket->Accept(nullptr, nullptr);
            if (!client) {
                if (!IOErrorIsPermanent(WSAGetLastError())) continue;
                throw std::runtime_error{"accept failed"};
            }
            ++m_connections;
            if (!client->IsSelectable()) throw std::runtime_error{"non-selectable client socket"};
            if (!client->SetNonBlocking()) throw std::runtime_error{"nonblocking client setup failed"};

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
            std::string request;
            std::array<char, 4096> buffer;
            bool complete{false};
            bool disconnected{false};
            while (!m_interrupt && request.size() < 16384) {
                if (std::chrono::steady_clock::now() >= deadline) throw std::runtime_error{"request receive timeout"};
                ready = 0;
                if (!client->Wait(std::chrono::milliseconds{100}, Sock::RecvEvent, &ready)) {
                    if (!IOErrorIsPermanent(WSAGetLastError())) continue;
                    throw std::runtime_error{"client wait failed"};
                }
                if (!ready) continue;

                const auto count = client->Recv(buffer.data(), buffer.size(), 0);
                if (count < 0) {
                    const auto error = WSAGetLastError();
                    if (!IOErrorIsPermanent(error)) continue;
                    if (allow_disconnect && error == ECONNRESET) {
                        disconnected = true;
                        break;
                    }
                    throw std::runtime_error{"request receive failed"};
                }
                if (count == 0) {
                    disconnected = true;
                    break;
                }

                request.append(buffer.data(), count);
                const auto end = request.find("\r\n\r\n");
                if (end != std::string::npos && request.size() >= end + 4 + expected_body_size) {
                    complete = true;
                    break;
                }
            }

            if (m_interrupt) return;
            if (!complete && !(allow_disconnect && disconnected)) throw std::runtime_error{"incomplete request"};

            {
                LOCK(m_mutex);
                m_requests.push_back(std::move(request));
                if (m_requests.size() == 1) m_request_received.set_value();
            }

            if (respond && complete) {
                std::string response;
                if (reply) {
                    response = *reply;
                } else if (partial) {
                    response = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort";
                } else if (chunked) {
                    response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\n12345678\r\n0\r\n\r\n";
                } else {
                    response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                }

                try {
                    client->SendComplete(response, std::chrono::seconds{2}, m_interrupt);
                } catch (const std::runtime_error&) {
                    std::string error;
                    if (!allow_disconnect || client->IsConnected(error)) throw;
                }
            }
        }
    }

    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        m_interrupt();
        if (m_worker.joinable()) m_worker.join();
    }

public:
    std::string m_url;

    explicit HttpWireObserver(size_t expected_body_size, bool respond, bool chunked = false, bool partial = false, bool allow_disconnect = false,
                              std::optional<std::string> reply = std::nullopt)
    {
        BOOST_REQUIRE(m_socket);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        BOOST_REQUIRE_EQUAL(m_socket->Bind(reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
        BOOST_REQUIRE_EQUAL(m_socket->Listen(8), 0);

        socklen_t length = sizeof(address);
        BOOST_REQUIRE_EQUAL(m_socket->GetSockName(reinterpret_cast<sockaddr*>(&address), &length), 0);
        m_url = strprintf("http://127.0.0.1:%u/payjoin", ntohs(address.sin_port));

        m_worker = std::thread{[this, expected_body_size, respond, chunked, partial, allow_disconnect, reply = std::move(reply)] {
            try {
                Run(expected_body_size, respond, chunked, partial, allow_disconnect, reply);
            } catch (...) {
                m_error = std::current_exception();
            }
        }};
    }

    explicit HttpWireObserver(size_t expected_body_size, std::string reply, bool allow_disconnect = false)
        : HttpWireObserver{expected_body_size, true, false, false, allow_disconnect, std::move(reply)} {}

    ~HttpWireObserver()
    {
        Stop();
    }

    void Check() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        Stop();
        if (m_error) std::rethrow_exception(m_error);
    }

    auto Requests() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_requests;
    }

    auto RequestReceived() { return m_request_received.get_future(); }

    int Connections() const { return m_connections; }
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
} // namespace

BOOST_AUTO_TEST_SUITE(payjoin_transport_tests)

BOOST_AUTO_TEST_CASE(http_transport_response_size_boundaries)
{
    constexpr size_t limit{1U << 20};
    BOOST_REQUIRE_EQUAL(HttpTransportOptions{}.max_response_bytes, limit);
    for (const bool chunked : {false, true}) {
        for (const size_t size : {limit - 1, limit, limit + 1}) {
            BOOST_TEST_CONTEXT("chunked=" << chunked << ", response bytes=" << size)
            {
                std::vector<unsigned char> payload(size);
                for (size_t i = 0; i < size; ++i) {
                    payload[i] = i % 251;
                }

                std::string response{"HTTP/1.1 200 OK\r\nConnection: close\r\n"};
                if (chunked) {
                    response += "Transfer-Encoding: chunked\r\n\r\n";
                    for (size_t offset = 0; offset < size;) {
                        const size_t count = std::min(size_t{65536}, size - offset);
                        response += strprintf("%x\r\n", count);
                        response.append(reinterpret_cast<const char*>(payload.data() + offset), count);
                        response += "\r\n";
                        offset += count;
                    }
                    response += "0\r\n\r\n";
                } else {
                    response += strprintf("Content-Length: %u\r\n\r\n", size);
                    response.append(reinterpret_cast<const char*>(payload.data()), size);
                }

                HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, std::move(response), size > limit};
                HttpSenderTransport http;
                HttpTestCleanup cleanup{http};

                const auto result = Post(http, {observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')});
                if (size <= limit) {
                    BOOST_REQUIRE_MESSAGE(result.delivery == Delivery::Response, result.diagnostic);
                    BOOST_CHECK(result.body == payload);
                } else {
                    BOOST_CHECK(result.delivery == Delivery::Uncertain);
                    BOOST_CHECK(!result.retryable);
                    BOOST_CHECK(result.body.size() <= limit);
                    BOOST_CHECK(result.diagnostic.starts_with("HTTP transfer failed"));
                }

                http.Stop();
                observer.Check();
                BOOST_CHECK_EQUAL(observer.Requests().size(), 1);
                BOOST_CHECK_EQUAL(observer.Connections(), 1);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(http_transport_does_not_follow_post_redirects)
{
    for (const int status : {307, 308}) {
        BOOST_TEST_CONTEXT("redirect status=" << status)
        {
            HttpWireObserver destination{TEST_REQUEST_BODY_SIZE, true};
            HttpWireObserver origin{TEST_REQUEST_BODY_SIZE, strprintf("HTTP/1.1 %d Redirect\r\nLocation: %s\r\nContent-Length: 8\r\nConnection: close\r\n\r\nredirect",
                                                                      status, destination.m_url)};
            HttpSenderTransport http;
            HttpTestCleanup cleanup{http};

            const auto result = Post(http, {origin.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')});
            BOOST_CHECK(result.delivery == Delivery::Uncertain);
            BOOST_CHECK(!result.retryable);
            BOOST_CHECK(result.diagnostic.find(strprintf("status %d", status)) != std::string::npos);

            http.Stop();
            origin.Check();
            destination.Check();
            const auto requests = origin.Requests();
            BOOST_REQUIRE_EQUAL(requests.size(), 1);
            BOOST_CHECK(requests.front().starts_with("POST /payjoin HTTP/1.1\r\n"));
            BOOST_CHECK(requests.front().ends_with(std::string(TEST_REQUEST_BODY_SIZE, 'X')));
            BOOST_CHECK_EQUAL(origin.Connections(), 1);
            BOOST_CHECK(destination.Requests().empty());
            BOOST_CHECK_EQUAL(destination.Connections(), 0);
        }
    }
}

BOOST_AUTO_TEST_CASE(http_transport_one_submit_one_http11_body)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, false};
    SenderRequest request{observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    std::promise<TransportResult> completion;
    auto result = completion.get_future();
    std::atomic<int> callbacks{0};
    HttpSenderTransport http;
    HttpTestCleanup cleanup{http};

    BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult response) {
        if (++callbacks == 1) completion.set_value(std::move(response));
    }) == SubmitResult::Accepted);
    BOOST_REQUIRE(result.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_CHECK(result.get().delivery == Delivery::Uncertain);

    http.Stop();
    BOOST_CHECK_EQUAL(callbacks, 1);

    observer.Check();
    const auto requests = observer.Requests();
    BOOST_REQUIRE_EQUAL(requests.size(), 1);
    BOOST_CHECK(requests[0].starts_with("POST /payjoin HTTP/1.1\r\n"));
    BOOST_CHECK(requests[0].ends_with(std::string(TEST_REQUEST_BODY_SIZE, 'X')));
}

BOOST_AUTO_TEST_CASE(http_transport_request_body_size_boundaries)
{
    for (const size_t size : {0, 1, 512, 513}) {
        BOOST_TEST_CONTEXT("request bytes=" << size)
        {
            std::vector<unsigned char> payload(size);
            for (size_t i = 0; i < size; ++i) {
                payload[i] = i % 251;
            }

            HttpWireObserver observer{size, true};
            auto received = observer.RequestReceived();
            std::promise<TransportResult> completion;
            auto result = completion.get_future();
            std::atomic<int> callbacks{0};
            HttpSenderTransport http;
            HttpTestCleanup cleanup{http};

            BOOST_REQUIRE(http.Submit(1, {observer.m_url, "application/octet-stream", payload}, std::chrono::seconds{3}, [&](TransportResult response) {
                if (++callbacks == 1) completion.set_value(std::move(response));
            }) == SubmitResult::Accepted);
            const auto status = received.wait_for(std::chrono::seconds{5});
            if (status != std::future_status::ready) observer.Check();
            BOOST_REQUIRE(status == std::future_status::ready);
            BOOST_REQUIRE(result.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
            const auto response = result.get();
            BOOST_REQUIRE_MESSAGE(response.delivery == Delivery::Response, response.diagnostic);

            http.Stop();
            BOOST_CHECK_EQUAL(callbacks, 1);

            observer.Check();
            const auto requests = observer.Requests();
            BOOST_REQUIRE_EQUAL(requests.size(), 1);
            BOOST_CHECK_EQUAL(observer.Connections(), 1);
            BOOST_CHECK(requests.front().starts_with("POST /payjoin HTTP/1.1\r\n"));
            const auto end = requests.front().find("\r\n\r\n");
            BOOST_REQUIRE(end != std::string::npos);
            const std::vector<unsigned char> body{requests.front().begin() + end + 4, requests.front().end()};
            BOOST_CHECK_EQUAL(body.size(), size);
            BOOST_CHECK_EQUAL_COLLECTIONS(body.begin(), body.end(), payload.begin(), payload.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(http_transport_reused_id_and_before_dispatch_cancellation)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, true};
    HttpTransportOptions options;
    options.max_requests = 2;
    SenderRequest request{observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    std::promise<void> first_callback, finish_callback;
    auto first = first_callback.get_future();
    auto finish = finish_callback.get_future();
    std::atomic<int> callbacks{0};
    std::promise<TransportResult> cancelled_callback, second_callback;
    auto cancelled = cancelled_callback.get_future();
    auto second = second_callback.get_future();
    HttpSenderTransport http{options};
    HttpTestCleanup cleanup{http, &finish_callback};

    BOOST_REQUIRE(http.Submit(7, request, std::chrono::seconds{3}, [&](TransportResult response) {
        ++callbacks;
        first_callback.set_value();
        finish.wait();
    }) == SubmitResult::Accepted);
    BOOST_REQUIRE(first.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

    http.Cancel(7);
    BOOST_REQUIRE(http.Submit(8, request, std::chrono::seconds{3}, [&](TransportResult response) {
        ++callbacks;
        cancelled_callback.set_value(std::move(response));
    }) == SubmitResult::Accepted);
    http.Cancel(8);

    BOOST_REQUIRE(http.Submit(7, request, std::chrono::seconds{3}, [&](TransportResult response) {
        ++callbacks;
        second_callback.set_value(std::move(response));
    }) == SubmitResult::Accepted);
    BOOST_CHECK(http.Submit(9, request, std::chrono::seconds{3}, [&](auto) { ++callbacks; }) == SubmitResult::Busy);
    BOOST_CHECK(http.Submit(7, request, std::chrono::seconds{3}, [&](auto) { ++callbacks; }) == SubmitResult::InvalidRequest);

    cleanup.Release();
    BOOST_REQUIRE(cancelled.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_REQUIRE(second.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_CHECK(cancelled.get().delivery == Delivery::NotSent);
    BOOST_CHECK(second.get().delivery == Delivery::Response);

    http.Stop();
    BOOST_CHECK(http.Submit(9, request, std::chrono::seconds{3}, [&](auto) { ++callbacks; }) == SubmitResult::Stopped);
    BOOST_CHECK_EQUAL(callbacks, 3);

    observer.Check();
    BOOST_CHECK_EQUAL(observer.Requests().size(), 2);
}

BOOST_AUTO_TEST_CASE(http_transport_chunked_limit_and_plain_http_proxy)
{
    HttpWireObserver chunked{TEST_REQUEST_BODY_SIZE, /*respond=*/true, /*chunked=*/true, /*partial=*/false, /*allow_disconnect=*/true};
    HttpTransportOptions options;
    options.max_response_bytes = 4;
    HttpSenderTransport bounded{options};

    const auto limited = Post(bounded, {chunked.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')});
    BOOST_CHECK(limited.delivery == Delivery::Uncertain);
    BOOST_CHECK(!limited.retryable);
    BOOST_CHECK(limited.body.size() <= 4);

    bounded.Stop();
    chunked.Check();

    HttpWireObserver proxy{TEST_REQUEST_BODY_SIZE, true};
    options.max_response_bytes = 1024;
    options.proxy = proxy.m_url;
    HttpSenderTransport proxied{options};

    const auto response = Post(proxied, {"http://origin.invalid/payjoin", "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')});
    BOOST_CHECK(response.delivery == Delivery::Response);

    proxied.Stop();
    proxy.Check();
    const auto requests = proxy.Requests();
    BOOST_REQUIRE_EQUAL(requests.size(), 1);
    BOOST_CHECK(requests[0].starts_with("POST http://origin.invalid/payjoin HTTP/1.1\r\n"));
}

BOOST_AUTO_TEST_CASE(http_transport_defers_url_rejection)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, true};
    HttpSenderTransport http;
    HttpTestCleanup cleanup{http};
    std::atomic<int> callbacks{0};
    const auto rejected = [&](const std::string& url, const std::string& content_type) {
        return http.Submit(1, {url, content_type, {}}, std::chrono::seconds{1}, [&](auto) { ++callbacks; });
    };

    const SenderRequest valid{observer.m_url, "text/plain", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    BOOST_CHECK(Post(http, valid).delivery == Delivery::Response);

    uint64_t id{10};
    const auto locally_rejected = [&](const std::string& url) {
        auto promise = std::make_shared<std::promise<TransportResult>>();
        auto result = promise->get_future();
        BOOST_REQUIRE(http.Submit(++id, {url, "text/plain", {}}, std::chrono::seconds{3}, [&, promise](TransportResult response) {
            ++callbacks;
            promise->set_value(std::move(response));
        }) == SubmitResult::Accepted);
        BOOST_REQUIRE(result.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
        return result.get();
    };

    std::string invalid_port = observer.m_url;
    invalid_port.insert(invalid_port.find("/payjoin"), ":invalid");
    for (const std::string& url : std::array<std::string, 3>{"file:///etc/passwd", "https://", invalid_port}) {
        const auto result = locally_rejected(url);
        BOOST_CHECK(result.delivery == Delivery::NotSent);
        BOOST_CHECK(!result.retryable);
    }

    std::string credentials = observer.m_url;
    credentials.insert(credentials.find("127.0.0.1"), "user:secret@");
    const auto denied = locally_rejected(credentials);
    BOOST_CHECK(denied.delivery == Delivery::Uncertain);
    BOOST_CHECK(!denied.retryable);

    BOOST_CHECK(rejected(std::string{"http://example.com\0/hidden", 26}, "text/plain") == SubmitResult::InvalidRequest);
    for (const std::string& content_type : std::array<std::string, 3>{"text/plain\rX", "text/plain\nX", std::string{"text/plain\0X", 12}}) {
        BOOST_CHECK(rejected("http://example.com", content_type) == SubmitResult::InvalidRequest);
    }

    http.Stop();
    observer.Check();
    BOOST_CHECK_EQUAL(callbacks, 4);
    BOOST_CHECK_EQUAL(observer.Connections(), 1);
    BOOST_CHECK_EQUAL(observer.Requests().size(), 1);
}

BOOST_AUTO_TEST_CASE(http_transport_rejects_invalid_options_with_distinct_errors)
{
    const auto error_message = [](HttpTransportOptions options) {
        try {
            HttpSenderTransport transport{std::move(options)};
        } catch (const std::invalid_argument& error) {
            return std::string{error.what()};
        }
        return std::string{};
    };

    HttpTransportOptions options;
    options.max_requests = 0;
    BOOST_CHECK_EQUAL(error_message(options), "invalid HTTP transport limits");

    options = {};
    options.max_response_bytes = 0;
    BOOST_CHECK_EQUAL(error_message(options), "invalid HTTP transport limits");

    options = {};
    options.proxy = std::string{"http://proxy.example\0/hidden", 28};
    BOOST_CHECK_EQUAL(error_message(options), "HTTP proxy contains an embedded NUL");

    options = {};
    options.ca_file = std::string{"ca.pem\0hidden", 13};
    BOOST_CHECK_EQUAL(error_message(options), "CA file path contains an embedded NUL");
}

BOOST_AUTO_TEST_CASE(http_transport_connection_failure_is_retryable_not_sent)
{
    ReservedTcpPort port;
    HttpSenderTransport http;
    const auto failed = Post(http, {strprintf("http://127.0.0.1:%u/payjoin", port.Port()), "text/plain", {}});
    BOOST_CHECK(failed.delivery == Delivery::NotSent);
    BOOST_CHECK(failed.retryable);
    http.Stop();
}

BOOST_AUTO_TEST_CASE(http_transport_proxy_configuration_and_environment)
{
    HttpWireObserver target{TEST_REQUEST_BODY_SIZE, true};
    HttpWireObserver proxy{TEST_REQUEST_BODY_SIZE, true};
    const SenderRequest request{target.m_url, "text/plain", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    ScopedEnvironment http_proxy{"http_proxy", proxy.m_url.c_str()};
    ScopedEnvironment upper_http_proxy{"HTTP_PROXY", proxy.m_url.c_str()};
    ScopedEnvironment https_proxy{"https_proxy", proxy.m_url.c_str()};
    ScopedEnvironment upper_https_proxy{"HTTPS_PROXY", proxy.m_url.c_str()};
    ScopedEnvironment all_proxy{"all_proxy", proxy.m_url.c_str()};
    ScopedEnvironment upper_all_proxy{"ALL_PROXY", proxy.m_url.c_str()};
    ScopedEnvironment no_proxy{"no_proxy", nullptr};
    ScopedEnvironment upper_no_proxy{"NO_PROXY", nullptr};

    HttpSenderTransport direct;
    BOOST_CHECK(Post(direct, request).delivery == Delivery::Response);
    direct.Stop();
    BOOST_CHECK_EQUAL(target.Connections(), 1);
    BOOST_REQUIRE_EQUAL(target.Requests().size(), 1);
    BOOST_CHECK(target.Requests().front().starts_with("POST /payjoin HTTP/1.1\r\n"));
    BOOST_CHECK_EQUAL(proxy.Connections(), 0);
    BOOST_CHECK(proxy.Requests().empty());

    HttpTransportOptions options;
    options.proxy = proxy.m_url;
    {
        ScopedEnvironment bypass{"no_proxy", "127.0.0.1"};
        ScopedEnvironment upper_bypass{"NO_PROXY", "127.0.0.1"};
        HttpSenderTransport proxied{options};
        BOOST_CHECK(Post(proxied, request).delivery == Delivery::Response);
        proxied.Stop();
    }
    BOOST_CHECK_EQUAL(proxy.Connections(), 1);
    BOOST_REQUIRE_EQUAL(proxy.Requests().size(), 1);
    BOOST_CHECK(proxy.Requests().front().starts_with("POST " + target.m_url + " HTTP/1.1\r\n"));
    BOOST_CHECK_EQUAL(target.Connections(), 1);
    BOOST_CHECK_EQUAL(target.Requests().size(), 1);

    ReservedTcpPort unavailable_port;
    options.proxy = strprintf("http://user:private-password@127.0.0.1:%u", unavailable_port.Port());
    HttpSenderTransport unavailable{options};
    std::promise<TransportResult> completion;
    auto result = completion.get_future();
    std::atomic<int> callbacks{0};
    HttpTestCleanup unavailable_cleanup{unavailable};

    BOOST_REQUIRE(unavailable.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult response) {
        ++callbacks;
        completion.set_value(std::move(response));
    }) == SubmitResult::Accepted);
    BOOST_REQUIRE(result.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

    const auto failed = result.get();
    BOOST_CHECK(failed.delivery == Delivery::NotSent);
    BOOST_CHECK(failed.retryable);
    BOOST_CHECK(failed.diagnostic.find("user") == std::string::npos);
    BOOST_CHECK(failed.diagnostic.find("private-password") == std::string::npos);

    unavailable.Stop();
    BOOST_CHECK_EQUAL(callbacks, 1);
    BOOST_CHECK_EQUAL(target.Connections(), 1);

    options.proxy = "socks5h://127.0.0.1:1";
    HttpSenderTransport configured{options};
    configured.Stop();

    target.Check();
    proxy.Check();
    BOOST_CHECK_EQUAL(target.Requests().size(), 1);
    BOOST_CHECK_EQUAL(proxy.Requests().size(), 1);
}

BOOST_AUTO_TEST_CASE(http_transport_queued_deadline_diagnostic)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, true};
    const SenderRequest request{observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    std::promise<void> first_callback, finish_callback;
    auto first = first_callback.get_future();
    auto finish = finish_callback.get_future();
    std::promise<TransportResult> expired_callback;
    auto expired = expired_callback.get_future();
    HttpSenderTransport http;
    HttpTestCleanup cleanup{http, &finish_callback};

    BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult) {
        first_callback.set_value();
        finish.wait();
    }) == SubmitResult::Accepted);
    BOOST_REQUIRE(first.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

    BOOST_REQUIRE(http.Submit(2, request, std::chrono::milliseconds{1}, [&](TransportResult response) {
        expired_callback.set_value(std::move(response));
    }) == SubmitResult::Accepted);

    BOOST_REQUIRE(expired.wait_for(std::chrono::milliseconds{20}) == std::future_status::timeout);

    cleanup.Release();
    BOOST_REQUIRE(expired.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    const auto response = expired.get();
    BOOST_CHECK(response.delivery == Delivery::NotSent);
    BOOST_CHECK(!response.retryable);
    BOOST_CHECK(response.body.empty());
    BOOST_CHECK_EQUAL(response.diagnostic, "dispatch deadline elapsed");
    http.Stop();
    observer.Check();
    BOOST_CHECK_EQUAL(observer.Requests().size(), 1);
}

BOOST_AUTO_TEST_CASE(http_transport_cleanup_on_early_exit)
{
    for (int stage = 0; stage < 3; ++stage) {
        HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, /*respond=*/true, /*chunked=*/false, /*partial=*/false, /*allow_disconnect=*/true};
        const SenderRequest request{observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
        std::promise<void> first_callback, finish_callback;
        auto first = first_callback.get_future();
        auto finish = finish_callback.get_future();
        std::atomic<int> callbacks{0};
        HttpSenderTransport http;

        const auto unwind = [&] {
            HttpTestCleanup cleanup{http, &finish_callback};
            BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult) {
                ++callbacks;
                first_callback.set_value();
                finish.wait();
            }) == SubmitResult::Accepted);
            BOOST_REQUIRE(first.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

            if (stage > 0) {
                BOOST_REQUIRE(http.Submit(2, request, std::chrono::seconds{3}, [&](TransportResult) {
                    ++callbacks;
                }) == SubmitResult::Accepted);
            }

            if (stage == 2) cleanup.Release();
            throw std::runtime_error{"test early exit"};
        };

        BOOST_CHECK_THROW(unwind(), std::runtime_error);
        BOOST_CHECK_EQUAL(callbacks, stage == 0 ? 1 : 2);

        http.Stop();
        observer.Check();
    }
}

BOOST_AUTO_TEST_CASE(http_transport_partial_response_is_retryable)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, true, false, true};
    HttpSenderTransport http;

    const auto response = Post(http, {observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')});
    BOOST_CHECK(response.delivery == Delivery::Uncertain);
    BOOST_CHECK(response.retryable);
    BOOST_CHECK(response.diagnostic.starts_with("HTTP transfer failed ("));
    BOOST_CHECK(response.diagnostic.ends_with(", status 200)"));

    http.Stop();
    observer.Check();
    BOOST_CHECK_EQUAL(observer.Requests().size(), 1);
}

BOOST_AUTO_TEST_CASE(http_transport_stop_waits_for_entered_completion)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, /*respond=*/true, /*chunked=*/false, /*partial=*/false, /*allow_disconnect=*/true};
    const SenderRequest request{observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    std::atomic<int> callbacks{0}, queued_callbacks{0};
    std::promise<void> callback_entered, callback_release, first_stopped, second_stopped;
    auto entered = callback_entered.get_future();
    auto release = callback_release.get_future();
    auto first_done = first_stopped.get_future();
    auto second_done = second_stopped.get_future();
    std::thread first, second;
    HttpSenderTransport http;
    HttpTestCleanup cleanup{http, &callback_release, &first, &second};

    BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult) {
        if (++callbacks == 1) callback_entered.set_value();
        release.wait();
    }) == SubmitResult::Accepted);
    BOOST_REQUIRE(entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_REQUIRE(http.Submit(2, request, std::chrono::seconds{3}, [&](TransportResult) { ++queued_callbacks; }) == SubmitResult::Accepted);

    first = std::thread{[&] {
        http.Stop();
        first_stopped.set_value();
    }};

    auto admission = SubmitResult::InvalidRequest;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    do {
        admission = http.Submit(2, request, std::chrono::seconds{3}, [&](TransportResult) { ++queued_callbacks; });
        if (admission != SubmitResult::InvalidRequest) break;
        std::this_thread::yield();
    } while (std::chrono::steady_clock::now() < deadline);
    BOOST_REQUIRE(admission == SubmitResult::Stopped);

    second = std::thread{[&] {
        http.Stop();
        second_stopped.set_value();
    }};

    BOOST_CHECK_MESSAGE(first_done.wait_for(std::chrono::milliseconds{0}) == std::future_status::timeout,
                        "Stop returned before the completion callback was released");
    BOOST_CHECK(second_done.wait_for(std::chrono::milliseconds{0}) == std::future_status::timeout);

    cleanup.Release();
    BOOST_REQUIRE(first_done.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_REQUIRE(second_done.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    first.join();
    second.join();

    http.Stop();
    BOOST_CHECK_EQUAL(callbacks, 1);
    BOOST_CHECK_EQUAL(queued_callbacks, 1);
    BOOST_CHECK(http.Submit(3, request, std::chrono::seconds{3}, [&](TransportResult) { ++callbacks; }) == SubmitResult::Stopped);
    BOOST_CHECK_EQUAL(callbacks, 1);
    observer.Check();
}

BOOST_AUTO_TEST_CASE(http_transport_completion_exception_is_not_replayed)
{
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, true};
    std::atomic<int> callbacks{0};
    std::promise<void> invoked;
    auto ready = invoked.get_future();
    const SenderRequest request{observer.m_url, "application/octet-stream", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    HttpSenderTransport http;
    HttpTestCleanup cleanup{http};

    BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult) {
        ++callbacks;
        invoked.set_value();
        throw std::runtime_error{"test enqueue failure"};
    }) == SubmitResult::Accepted);
    BOOST_REQUIRE(ready.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

    BOOST_CHECK(Post(http, request).delivery == Delivery::Response);

    http.Stop();
    BOOST_CHECK_EQUAL(callbacks, 1);
    observer.Check();
}

#ifdef __linux__
BOOST_AUTO_TEST_CASE(http_transport_idle_poll_failure_stops_worker)
{
    MultiFailureProbe probe;
    probe.m_fail_idle_poll = true;
    auto entered = probe.m_poll_entered.get_future();
    HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, true};
    const SenderRequest request{observer.m_url, "text/plain", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
    std::promise<TransportResult> completion;
    auto result = completion.get_future();
    std::atomic<int> callbacks{0}, unexpected_callbacks{0};
    HttpSenderTransport http;
    MultiProbeCleanup cleanup{probe, http};
    BOOST_REQUIRE(entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{3}, [&](TransportResult response) {
        if (++callbacks == 1) completion.set_value(std::move(response));
    }) == SubmitResult::Accepted);

    probe.ReleasePoll();

    BOOST_REQUIRE(result.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
    const auto failed = result.get();
    BOOST_CHECK_MESSAGE(failed.delivery == Delivery::NotSent, "idle poll failure did not complete the queued request as NotSent");
    BOOST_CHECK(!failed.retryable);
    BOOST_CHECK_EQUAL(callbacks, 1);
    BOOST_CHECK_MESSAGE(http.Submit(2, request, std::chrono::seconds{3}, [&](TransportResult) { ++unexpected_callbacks; }) == SubmitResult::Stopped,
                        "idle poll failure did not stop admission before explicit Stop");

    http.Stop();
    BOOST_CHECK_EQUAL(callbacks, 1);
    BOOST_CHECK_EQUAL(unexpected_callbacks, 0);
    observer.Check();
    BOOST_CHECK_EQUAL(observer.Connections(), 0);
    BOOST_CHECK(observer.Requests().empty());
}

BOOST_AUTO_TEST_CASE(http_transport_active_multi_failures_complete_once)
{
    for (const bool fail_perform : {false, true}) {
        BOOST_TEST_CONTEXT("operation " << (fail_perform ? "perform" : "poll"))
        {
            MultiFailureProbe probe;
            probe.m_hold_active_poll = true;
            probe.m_fail_active_poll = !fail_perform;
            auto poll_entered = probe.m_poll_entered.get_future();
            auto perform_entered = probe.m_perform_entered.get_future();
            HttpWireObserver observer{TEST_REQUEST_BODY_SIZE, /*respond=*/false, /*chunked=*/false, /*partial=*/false, /*allow_disconnect=*/true};
            HttpSenderTransport http;

            const SenderRequest request{observer.m_url, "text/plain", std::vector<unsigned char>(TEST_REQUEST_BODY_SIZE, 'X')};
            std::promise<TransportResult> first_result, second_result;
            auto first = first_result.get_future();
            auto second = second_result.get_future();
            std::promise<void> callback_release;
            auto callback_finish = callback_release.get_future();
            std::atomic<int> first_calls{0}, second_calls{0};

            MultiProbeCleanup cleanup{probe, http, &callback_release};

            BOOST_REQUIRE(http.Submit(1, request, std::chrono::seconds{10}, [&](TransportResult result) {
                if (++first_calls == 1) first_result.set_value(std::move(result));
                callback_finish.wait();
            }) == SubmitResult::Accepted);
            BOOST_REQUIRE(poll_entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
            if (fail_perform) {
                probe.m_fail_perform = true;

                probe.ReleasePoll();
                BOOST_REQUIRE(perform_entered.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
            }

            BOOST_REQUIRE(http.Submit(2, request, std::chrono::seconds{10}, [&](TransportResult result) {
                if (++second_calls == 1) second_result.set_value(std::move(result));
            }) == SubmitResult::Accepted);

            probe.ReleasePoll();
            probe.ReleasePerform();
            BOOST_REQUIRE(first.wait_for(std::chrono::seconds{5}) == std::future_status::ready);
            BOOST_CHECK(http.Submit(3, request, std::chrono::seconds{1}, [](auto) {}) == SubmitResult::Stopped);
            cleanup.ReleaseCallback();
            BOOST_REQUIRE(second.wait_for(std::chrono::seconds{5}) == std::future_status::ready);

            const auto active = first.get();
            const auto pending = second.get();
            BOOST_CHECK(active.delivery == Delivery::Uncertain);
            BOOST_CHECK(pending.delivery == Delivery::NotSent);
            BOOST_CHECK(!active.retryable);
            BOOST_CHECK(!pending.retryable);

            http.Stop();
            BOOST_CHECK_EQUAL(first_calls, 1);
            BOOST_CHECK_EQUAL(second_calls, 1);
            BOOST_CHECK(http.Submit(3, request, std::chrono::seconds{1}, [](auto) {}) == SubmitResult::Stopped);
            http.Stop();
            observer.Check();
        }
    }
}
#endif

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet::payjoin
