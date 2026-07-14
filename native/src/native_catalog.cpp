#include "msys/native_catalog.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>

namespace msys::native::lite {
namespace {

bool provider_less(const CatalogProvider& left, const CatalogProvider& right) {
    if (left.profile_preferred != right.profile_preferred) {
        return left.profile_preferred;
    }
    if (left.profile_preferred && left.profile_rank != right.profile_rank) {
        return left.profile_rank < right.profile_rank;
    }
    if (left.priority != right.priority) {
        return left.priority > right.priority;
    }
    return left.component_index < right.component_index;
}

bool topic_match(std::string_view rule, std::string_view topic) noexcept {
    if (rule == "*") {
        return true;
    }
    if (rule.size() >= 2U && rule.ends_with(".*")) {
        const std::string_view prefix = rule.substr(0U, rule.size() - 1U);
        return topic.starts_with(prefix);
    }
    return rule == topic;
}

}  // namespace

NativeCatalog::NativeCatalog(const RuntimePlan& plan) : plan_(plan) {
    components_.reserve(plan_.components.size());
    for (std::size_t index = 0U; index < plan_.components.size(); ++index) {
        if (!components_.emplace(plan_.components[index].id, index).second) {
            throw std::invalid_argument("native catalog has a duplicate component id");
        }
    }

    std::unordered_map<std::string, std::vector<std::string>> preferred;
    for (const auto& role : plan_.role_preferences) {
        if (!preferred.emplace(role.role, role.providers).second) {
            throw std::invalid_argument("native catalog has duplicate profile role preferences");
        }
    }

    for (std::size_t index = 0U; index < plan_.components.size(); ++index) {
        const auto& component_plan = plan_.components[index];
        std::unordered_set<std::string> unique;
        for (const auto& provided : component_plan.provides) {
            const std::string unique_key = std::to_string(static_cast<int>(provided.kind))
                + ":" + provided.name;
            if (!unique.insert(unique_key).second) {
                throw std::invalid_argument(
                    "native catalog component repeats a provided service");
            }
            CatalogProvider candidate{index, provided.priority, provided.exclusive, false, 0U};
            if (provided.kind == ProvideKind::role) {
                auto role_iterator = role_indices_.find(provided.name);
                if (role_iterator == role_indices_.end()) {
                    const std::size_t role_index = roles_.size();
                    roles_.push_back(CatalogRole{provided.name, {}});
                    role_indices_.emplace(provided.name, role_index);
                    role_iterator = role_indices_.find(provided.name);
                }
                const auto preference = preferred.find(provided.name);
                if (preference != preferred.end()) {
                    const auto position = std::find(
                        preference->second.begin(),
                        preference->second.end(),
                        component_plan.id);
                    if (position != preference->second.end()) {
                        const auto distance = std::distance(preference->second.begin(), position);
                        const auto rank = static_cast<std::uint32_t>(distance);
                        candidate.profile_preferred = true;
                        candidate.profile_rank = rank;
                    }
                }
                roles_[role_iterator->second].candidates.push_back(candidate);
            } else if (provided.kind == ProvideKind::interface) {
                interfaces_[provided.name].push_back(candidate);
            }
        }
    }

    std::sort(roles_.begin(), roles_.end(), [](const CatalogRole& left, const CatalogRole& right) {
        return left.name < right.name;
    });
    role_indices_.clear();
    for (std::size_t index = 0U; index < roles_.size(); ++index) {
        auto& candidates = roles_[index].candidates;
        std::sort(candidates.begin(), candidates.end(), provider_less);
        role_indices_.emplace(roles_[index].name, index);
    }
    for (auto& entry : interfaces_) {
        std::sort(entry.second.begin(), entry.second.end(), provider_less);
    }
    for (const auto& preference : plan_.role_preferences) {
        const CatalogRole* declared_role = role(preference.role);
        if (declared_role == nullptr) {
            throw std::invalid_argument("profile prefers an undeclared native role");
        }
        for (const auto& provider_id : preference.providers) {
            const auto provider_index = component_index(provider_id);
            const bool declared = provider_index.has_value()
                && std::any_of(
                    declared_role->candidates.begin(),
                    declared_role->candidates.end(),
                    [provider_index](const CatalogProvider& candidate) {
                        return candidate.component_index == *provider_index;
                    });
            if (!declared) {
                throw std::invalid_argument(
                    "profile role preference names a component that does not provide it");
            }
        }
    }
}

const ComponentPlan* NativeCatalog::component(std::string_view id) const noexcept {
    const auto found = component_index(id);
    return found.has_value() ? &plan_.components[*found] : nullptr;
}

std::optional<std::size_t> NativeCatalog::component_index(std::string_view id) const noexcept {
    for (std::size_t index = 0U; index < plan_.components.size(); ++index) {
        if (plan_.components[index].id == id) {
            return index;
        }
    }
    return std::nullopt;
}

const std::vector<CatalogRole>& NativeCatalog::roles() const noexcept {
    return roles_;
}

const CatalogRole* NativeCatalog::role(std::string_view name) const noexcept {
    const auto iterator = std::find_if(
        roles_.begin(), roles_.end(),
        [name](const CatalogRole& candidate) { return candidate.name == name; });
    return iterator == roles_.end() ? nullptr : &*iterator;
}

const std::vector<CatalogProvider>* NativeCatalog::interface_providers(
    std::string_view name) const noexcept {
    const auto iterator = std::find_if(
        interfaces_.begin(), interfaces_.end(),
        [name](const auto& entry) { return entry.first == name; });
    return iterator == interfaces_.end() ? nullptr : &iterator->second;
}

std::optional<std::size_t> NativeCatalog::preferred_role_provider(
    std::string_view name) const noexcept {
    const CatalogRole* found = role(name);
    if (found == nullptr || found->candidates.empty()) {
        return std::nullopt;
    }
    return found->candidates.front().component_index;
}

std::optional<std::size_t> NativeCatalog::preferred_interface_provider(
    std::string_view name) const noexcept {
    const auto* found = interface_providers(name);
    if (found == nullptr || found->empty()) {
        return std::nullopt;
    }
    return found->front().component_index;
}

std::vector<std::size_t> NativeCatalog::launchable_apps() const {
    std::vector<std::size_t> result;
    for (std::size_t index = 0U; index < plan_.components.size(); ++index) {
        if (plan_.components[index].launchable) {
            result.push_back(index);
        }
    }
    std::sort(result.begin(), result.end(), [this](std::size_t left, std::size_t right) {
        const auto& left_component = plan_.components[left];
        const auto& right_component = plan_.components[right];
        if (left_component.name != right_component.name) {
            return left_component.name < right_component.name;
        }
        return left_component.id < right_component.id;
    });
    return result;
}

bool NativeCatalog::has_permission(
    std::size_t source,
    std::string_view broad,
    std::string_view exact) const noexcept {
    if (source >= plan_.components.size()) {
        return false;
    }
    const auto& permissions = plan_.components[source].permissions;
    return std::any_of(permissions.begin(), permissions.end(), [&](const std::string& value) {
        return value == broad || value == exact;
    });
}

bool NativeCatalog::allows_call(
    std::size_t source,
    std::string_view target,
    std::string_view method) const {
    const std::string_view permission_target = target.starts_with("interface:")
        ? target.substr(10U) : target;
    const std::string broad = "mipc.call:" + std::string{permission_target};
    const std::string exact = broad + "." + std::string{method};
    return has_permission(source, broad, exact);
}

bool NativeCatalog::allows_subscribe(
    std::size_t source,
    std::string_view topic) const noexcept {
    if (source >= plan_.components.size()) {
        return false;
    }
    constexpr std::string_view prefix = "mipc.event:subscribe:";
    for (const auto& permission : plan_.components[source].permissions) {
        if (permission.starts_with(prefix)
            && topic_match(std::string_view{permission}.substr(prefix.size()), topic)) {
            return true;
        }
    }
    return false;
}

bool NativeCatalog::allows_publish(
    std::size_t source,
    std::string_view topic) const noexcept {
    if (source >= plan_.components.size()) {
        return false;
    }
    constexpr std::string_view prefix = "mipc.event:publish:";
    for (const auto& permission : plan_.components[source].permissions) {
        if (permission.starts_with(prefix)
            && topic_match(std::string_view{permission}.substr(prefix.size()), topic)) {
            return true;
        }
    }
    return false;
}

}  // namespace msys::native::lite
