#pragma once

#include "msys/mipc_broker.hpp"
#include "msys/native_catalog.hpp"
#include "msys/reactor.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace msys::native::lite {

struct RouterCallbacks {
    std::function<bool(std::size_t)> activate_component;
    std::function<bool(std::size_t)> stop_component;
    std::function<std::string(std::size_t)> component_state;
    std::function<std::uint64_t(std::size_t)> component_generation;
    std::function<bool(std::size_t)> component_ready;
    std::function<std::optional<std::size_t>(pid_t)> component_for_pid;
    std::function<bool(const msys::native::mipc::PeerIdentity&)> operator_peer;
    std::function<void(std::size_t, int)> provider_busy_delta;
    std::function<void(std::size_t)> component_activity;
    std::function<std::vector<std::size_t>()> foreground_components;
};

class NativeRouter final {
public:
    NativeRouter(
        Reactor& reactor,
        const RuntimePlan& plan,
        const NativeCatalog& catalog,
        msys::native::mipc::Broker& broker,
        RouterCallbacks callbacks);
    ~NativeRouter();

    NativeRouter(const NativeRouter&) = delete;
    NativeRouter& operator=(const NativeRouter&) = delete;

    [[nodiscard]] bool authorize_call(
        const msys::native::mipc::AccessRequest& request) const;
    void on_message(const msys::native::mipc::RoutedMessage& routed);
    void component_ready(std::size_t component, std::uint64_t generation);
    void component_unavailable(std::size_t component, std::uint64_t generation);
    void session_closed(
        std::uint64_t session_id,
        const msys::native::mipc::PeerIdentity& peer);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace msys::native::lite
