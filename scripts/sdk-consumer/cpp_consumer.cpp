// SPDX-License-Identifier: GPL-3.0-or-later
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <type_traits>

#include "reality.h"

struct EventQueue {
    static constexpr std::size_t max_events = 1024;

    std::mutex mutex;
    std::queue<std::string> events;
    std::atomic<std::uint64_t> dropped_events{0};
};

// A C++ host callback should be noexcept and contain every exception locally.
// Keep the bounded queue's critical section short; the application should
// drain it on its own event-loop thread and must not call the same RcCore here.
extern "C" void event_callback(const char *json, void *user) noexcept {
    if (json == nullptr || user == nullptr) {
        return;
    }

    auto *queue = static_cast<EventQueue *>(user);
    try {
        std::lock_guard<std::mutex> lock(queue->mutex);
        if (queue->events.size() >= EventQueue::max_events) {
            queue->dropped_events.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        queue->events.emplace(json);
    } catch (...) {
        queue->dropped_events.fetch_add(1, std::memory_order_relaxed);
    }
}

static_assert(std::is_convertible<decltype(&event_callback), rc_callback>::value,
              "noexcept adapter must match the SDK callback type");

int main() {
    constexpr char config[] =
        R"({"inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":0}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}})";
    const char *version = rc_version();
    if (version == nullptr || rc_validate(config, nullptr) != 1) {
        return 1;
    }

    // Exercise the noexcept adapter in the extracted-SDK consumer check.
    EventQueue event_queue;
    event_callback("{\"type\":\"demo\"}", &event_queue);
    {
        std::lock_guard<std::mutex> lock(event_queue.mutex);
        if (event_queue.events.size() != 1 ||
            event_queue.dropped_events.load(std::memory_order_relaxed) != 0) {
            return 2;
        }
    }
    if (rc_set_event_callback(nullptr, event_callback, &event_queue) != -1) {
        return 3;
    }

    std::cout << "vpn-core C++ SDK consumer " << version << '\n';
    return 0;
}
