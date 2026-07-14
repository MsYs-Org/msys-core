#pragma once

#include "msys/native_lite.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace msys::native::lite {

struct CatalogProvider {
    std::size_t component_index{0U};
    std::uint32_t priority{0U};
    bool exclusive{false};
    bool profile_preferred{false};
    std::uint32_t profile_rank{0U};
};

struct CatalogRole {
    std::string name;
    std::vector<CatalogProvider> candidates;
};

class NativeCatalog final {
public:
    explicit NativeCatalog(const RuntimePlan& plan);

    [[nodiscard]] const ComponentPlan* component(std::string_view id) const noexcept;
    [[nodiscard]] std::optional<std::size_t> component_index(
        std::string_view id) const noexcept;
    [[nodiscard]] const std::vector<CatalogRole>& roles() const noexcept;
    [[nodiscard]] const CatalogRole* role(std::string_view name) const noexcept;
    [[nodiscard]] const std::vector<CatalogProvider>* interface_providers(
        std::string_view name) const noexcept;
    [[nodiscard]] std::optional<std::size_t> preferred_role_provider(
        std::string_view name) const noexcept;
    [[nodiscard]] std::optional<std::size_t> preferred_interface_provider(
        std::string_view name) const noexcept;
    [[nodiscard]] std::vector<std::size_t> launchable_apps() const;

    [[nodiscard]] bool allows_call(
        std::size_t source,
        std::string_view target,
        std::string_view method) const;
    [[nodiscard]] bool allows_subscribe(
        std::size_t source,
        std::string_view topic) const noexcept;
    [[nodiscard]] bool allows_publish(
        std::size_t source,
        std::string_view topic) const noexcept;

private:
    [[nodiscard]] bool has_permission(
        std::size_t source,
        std::string_view broad,
        std::string_view exact) const noexcept;

    const RuntimePlan& plan_;
    std::unordered_map<std::string, std::size_t> components_;
    std::vector<CatalogRole> roles_;
    std::unordered_map<std::string, std::size_t> role_indices_;
    std::unordered_map<std::string, std::vector<CatalogProvider>> interfaces_;
};

}  // namespace msys::native::lite
