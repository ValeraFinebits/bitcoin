// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <payjoin/http_transport.h>

#include <curl/curl.h>
#include <logging.h>
#include <payjoin/client.h>
#include <payjoin/transport.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/thread.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace wallet::payjoin {
namespace {
template <auto Cleanup>
struct CurlDeleter {
    template <typename T>
    void operator()(T* resource) const noexcept
    {
        Cleanup(resource);
    }
};

using CurlEasy = std::unique_ptr<CURL, CurlDeleter<curl_easy_cleanup>>;
using CurlMulti = std::unique_ptr<CURLM, CurlDeleter<curl_multi_cleanup>>;
using CurlHeaders = std::unique_ptr<curl_slist, CurlDeleter<curl_slist_free_all>>;

class SetupError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};
constexpr int IDLE_POLL_TIMEOUT_MS{60000};
constexpr int ACTIVE_POLL_TIMEOUT_MS{1000};

template <typename T>
concept CurlArgument = std::is_same_v<T, long> || std::is_same_v<T, curl_off_t> || std::is_pointer_v<T>;
static_assert(!CurlArgument<int>);
static_assert(CurlArgument<long> && CurlArgument<const char*> && CurlArgument<curl_write_callback>);
} // namespace

struct HttpSenderTransport::Impl {
    struct Transfer {
        Transfer() = default;

        Transfer(const Transfer&) = delete;

        Transfer& operator=(const Transfer&) = delete;

        std::atomic<bool> m_cancelled{false};
        uint64_t m_id{0};
        SenderRequest m_request;
        Completion m_completion;
        std::chrono::steady_clock::time_point m_deadline;
        size_t m_limit{0};
        std::vector<unsigned char> m_response;

        CurlHeaders m_headers;
        CurlEasy m_easy;

        static size_t Write(char* data, size_t size, size_t count, void* context) noexcept
        {
            auto& self = *static_cast<Transfer*>(context);
            if (size && count > SIZE_MAX / size) return 0;
            const size_t bytes = size * count;
            if (bytes > self.m_limit - self.m_response.size()) return 0;

            try {
                self.m_response.insert(self.m_response.end(), data, data + bytes);
            } catch (...) {
                return 0;
            }
            return bytes;
        }

        template <CurlArgument T>
        void Set(CURLoption option, T value)
        {
            const auto code = curl_easy_setopt(m_easy.get(), option, value);
            if (code != CURLE_OK) {
                throw SetupError{strprintf("curl option %d rejected (curl %d: %s)", option, code, curl_easy_strerror(code))};
            }
        }

        void Configure(const HttpTransportOptions& options)
        {
            m_easy.reset(curl_easy_init());
            if (!m_easy) throw SetupError{"curl allocation failed"};

            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(m_deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0 || remaining > LONG_MAX) throw SetupError{"dispatch deadline elapsed"};

            Set(CURLOPT_URL, m_request.url.c_str());
            Set(CURLOPT_PROTOCOLS_STR, "http,https");
            Set(CURLOPT_DISALLOW_USERNAME_IN_URL, 1L);
            Set(CURLOPT_FOLLOWLOCATION, 0L);

            Set(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
            Set(CURLOPT_PATH_AS_IS, 1L);
            Set(CURLOPT_PROXY, options.proxy.c_str());
            Set(CURLOPT_NOPROXY, "");
            Set(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));

            Set(CURLOPT_SSL_VERIFYPEER, 1L);
            Set(CURLOPT_SSL_VERIFYHOST, 2L);
            Set(CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
            if (!options.ca_file.empty()) Set(CURLOPT_CAINFO, options.ca_file.c_str());

            Set(CURLOPT_NOSIGNAL, 1L);
            Set(CURLOPT_TIMEOUT_MS, static_cast<long>(remaining));
            Set(CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(remaining));

            Set(CURLOPT_POST, 1L);
            Set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(m_request.body.size()));
            Set(CURLOPT_POSTFIELDS, m_request.body.empty() ? "" : reinterpret_cast<const char*>(m_request.body.data()));

            m_headers.reset(curl_slist_append(nullptr, ("Content-Type: " + m_request.content_type).c_str()));
            if (!m_headers) throw SetupError{"curl header allocation failed"};
            auto* appended = curl_slist_append(m_headers.get(), "Expect:");
            if (!appended) throw SetupError{"curl header allocation failed"};

            (void)m_headers.release();
            m_headers.reset(appended);
            Set(CURLOPT_HTTPHEADER, m_headers.get());

            Set(CURLOPT_WRITEFUNCTION, static_cast<curl_write_callback>(&Transfer::Write));
            Set(CURLOPT_WRITEDATA, this);

            Set(CURLOPT_FRESH_CONNECT, 1L);
            Set(CURLOPT_FORBID_REUSE, 1L);
        }
    };

    HttpTransportOptions m_options;
    CurlMulti m_multi;
    Mutex m_mutex;
    Mutex m_stop_mutex;
    bool m_stopping GUARDED_BY(m_mutex){false};
    std::deque<std::unique_ptr<Transfer>> m_pending GUARDED_BY(m_mutex);
    std::map<uint64_t, Transfer*> m_ids GUARDED_BY(m_mutex);
    std::thread m_worker;

    explicit Impl(HttpTransportOptions options) : m_options{std::move(options)}
    {
        static const auto initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (initialized != CURLE_OK) {
            throw std::runtime_error{strprintf("curl global initialization failed: %s", curl_easy_strerror(initialized))};
        }
        const auto* version = curl_version_info(CURLVERSION_NOW);
        if (!(version->features & CURL_VERSION_ASYNCHDNS)) {
            throw std::runtime_error{strprintf("Payjoin requires libcurl with asynchronous DNS support (loaded %s)", version->version)};
        }

        if (!m_options.max_requests || !m_options.max_response_bytes) {
            throw std::invalid_argument{"invalid HTTP transport limits"};
        }
        if (m_options.proxy.find('\0') != std::string::npos) {
            throw std::invalid_argument{"HTTP proxy contains an embedded NUL"};
        }
        if (m_options.ca_file.find('\0') != std::string::npos) {
            throw std::invalid_argument{"CA file path contains an embedded NUL"};
        }

        m_multi.reset(curl_multi_init());
        if (!m_multi) throw std::runtime_error{"curl multi allocation failed"};

        m_worker = std::thread{util::TraceThread, "payjoin-http", [this] { Run(); }};
    }

    ~Impl()
    {
        Stop();
    }

    void Stop() EXCLUSIVE_LOCKS_REQUIRED(!m_stop_mutex, !m_mutex)
    {
        LOCK(m_stop_mutex);
        {
            LOCK(m_mutex);
            m_stopping = true;
        }

        curl_multi_wakeup(m_multi.get());
        if (m_worker.joinable()) m_worker.join();
    }

    void Complete(std::unique_ptr<Transfer> transfer, Delivery delivery, std::string diagnostic, bool retryable = false) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        {
            LOCK(m_mutex);
            m_ids.erase(transfer->m_id);
        }

        auto callback = std::move(transfer->m_completion);
        auto response = std::move(transfer->m_response);
        transfer.reset();

        try {
            callback({delivery, std::move(response), std::move(diagnostic), retryable});
        } catch (const std::bad_alloc&) {
            throw;
        } catch (...) {
            LogDebug(BCLog::NET, "Payjoin transport completion failed\n");
        }
    }

    void Run() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        struct ActiveTransfers {
            CurlMulti& m_multi;
            std::map<CURL*, std::unique_ptr<Transfer>> m_transfers;

            ~ActiveTransfers()
            {
                for (const auto& [easy, transfer] : m_transfers) {
                    if (transfer) curl_multi_remove_handle(m_multi.get(), easy);
                }
            }
        } active_transfers{m_multi, {}};
        auto& active = active_transfers.m_transfers;

        const auto stop_for_multi_error = [&](const char* operation, CURLMcode code) {
            LogError("Payjoin %s failed (curl %d: %s)", operation, code, curl_multi_strerror(code));

            std::deque<std::unique_ptr<Transfer>> pending;
            {
                LOCK(m_mutex);
                m_stopping = true;
                pending.swap(m_pending);
            }

            for (const auto& [easy, transfer] : active) {
                curl_multi_remove_handle(m_multi.get(), easy);
            }
            for (auto& [easy, transfer] : active) {
                Complete(std::move(transfer), Delivery::Uncertain, "curl multi failed");
            }
            active.clear();
            for (auto& transfer : pending) {
                Complete(std::move(transfer), Delivery::NotSent, "curl multi failed");
            }
        };

        for (;;) {
            std::deque<std::unique_ptr<Transfer>> incoming;
            bool stop;
            {
                LOCK(m_mutex);
                incoming.swap(m_pending);
                stop = m_stopping;
            }

            for (auto& transfer : incoming) {
                if (stop || transfer->m_cancelled) {
                    Complete(std::move(transfer), Delivery::NotSent, "request cancelled before dispatch");
                    continue;
                }

                try {
                    transfer->Configure(m_options);
                    CURL* easy = transfer->m_easy.get();

                    auto [it, inserted] = active.emplace(easy, std::move(transfer));
                    if (curl_multi_add_handle(m_multi.get(), easy) != CURLM_OK) {
                        auto failed = std::move(it->second);
                        active.erase(it);
                        Complete(std::move(failed), Delivery::NotSent, "curl dispatch failed");
                    }
                } catch (const std::bad_alloc&) {
                    throw;
                } catch (const SetupError& error) {
                    if (transfer) Complete(std::move(transfer), Delivery::NotSent, error.what());
                } catch (const std::exception&) {
                    if (transfer) Complete(std::move(transfer), Delivery::NotSent, "HTTP request setup failed");
                }
            }

            for (auto it = active.begin(); it != active.end();) {
                if (stop || it->second->m_cancelled) {
                    curl_multi_remove_handle(m_multi.get(), it->first);
                    auto removed = std::move(it->second);
                    it = active.erase(it);
                    Complete(std::move(removed), Delivery::Cancelled, "request cancelled; delivery unknown");
                } else {
                    ++it;
                }
            }

            if (stop) return;

            int running{0};
            const auto performed = curl_multi_perform(m_multi.get(), &running);
            if (performed != CURLM_OK) {
                stop_for_multi_error("curl_multi_perform", performed);
                return;
            }

            int queued{0};
            while (auto* message = curl_multi_info_read(m_multi.get(), &queued)) {
                if (message->msg != CURLMSG_DONE) continue;

                auto it = active.find(message->easy_handle);
                if (it == active.end()) continue;

                long status{0};
                curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &status);
                const auto code = message->data.result;

                curl_multi_remove_handle(m_multi.get(), message->easy_handle);
                auto done = std::move(it->second);
                active.erase(it);

                const bool success = code == CURLE_OK && status >= 200 && status < 300;
                const bool retryable = code == CURLE_OPERATION_TIMEDOUT || code == CURLE_COULDNT_CONNECT ||
                                       code == CURLE_COULDNT_RESOLVE_HOST || code == CURLE_COULDNT_RESOLVE_PROXY ||
                                       code == CURLE_RECV_ERROR || code == CURLE_SEND_ERROR || code == CURLE_GOT_NOTHING || code == CURLE_PARTIAL_FILE ||
                                       (code == CURLE_OK && (status == 429 || status >= 500));

                const bool invalid_url = code == CURLE_URL_MALFORMAT || code == CURLE_UNSUPPORTED_PROTOCOL;
                Delivery delivery{Delivery::Uncertain};
                if (success) {
                    delivery = Delivery::Response;
                } else if (invalid_url) {
                    delivery = Delivery::NotSent;
                }

                Complete(std::move(done), delivery,
                         success ? "" : strprintf("HTTP transfer failed (curl %d: %s, status %d)", code, curl_easy_strerror(code), status), retryable);
            }

            const auto polled = curl_multi_poll(m_multi.get(), nullptr, 0, active.empty() ? IDLE_POLL_TIMEOUT_MS : ACTIVE_POLL_TIMEOUT_MS, nullptr);
            if (polled != CURLM_OK) {
                stop_for_multi_error("curl_multi_poll", polled);
                return;
            }
        }
    }
};

HttpSenderTransport::HttpSenderTransport(HttpTransportOptions options) : m_impl{std::make_unique<Impl>(std::move(options))} {}

HttpSenderTransport::~HttpSenderTransport() = default;

SubmitResult HttpSenderTransport::Submit(uint64_t id, SenderRequest request, std::chrono::milliseconds timeout, Completion completion)
{
    if (!completion || timeout.count() <= 0 || timeout > std::chrono::hours{24} || timeout.count() > LONG_MAX || request.url.find('\0') != std::string::npos ||
        request.content_type.find_first_of("\r\n") != std::string::npos || request.content_type.find('\0') != std::string::npos) {
        return SubmitResult::InvalidRequest;
    }

    auto transfer = std::make_unique<Impl::Transfer>();
    transfer->m_id = id;
    transfer->m_request = std::move(request);
    transfer->m_completion = std::move(completion);
    transfer->m_deadline = std::chrono::steady_clock::now() + timeout;
    transfer->m_limit = m_impl->m_options.max_response_bytes;

    {
        LOCK(m_impl->m_mutex);
        if (m_impl->m_stopping) return SubmitResult::Stopped;
        if (m_impl->m_ids.contains(id)) return SubmitResult::InvalidRequest;
        if (m_impl->m_ids.size() >= m_impl->m_options.max_requests) return SubmitResult::Busy;

        m_impl->m_ids.emplace(id, transfer.get());
        try {
            m_impl->m_pending.push_back(std::move(transfer));
        } catch (...) {
            m_impl->m_ids.erase(id);
            throw;
        }
    }

    curl_multi_wakeup(m_impl->m_multi.get());
    return SubmitResult::Accepted;
}

void HttpSenderTransport::Cancel(uint64_t id)
{
    {
        LOCK(m_impl->m_mutex);
        const auto it = m_impl->m_ids.find(id);
        if (it != m_impl->m_ids.end()) it->second->m_cancelled = true;
    }

    curl_multi_wakeup(m_impl->m_multi.get());
}

void HttpSenderTransport::Stop() { m_impl->Stop(); }
} // namespace wallet::payjoin
