#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace OpenWifi::UserAccess {

// This contract is shared by service adapters. Scope lineage MUST come from
// canonical server ownership, never a request's entity/venue parameters.
struct Scope {
    std::string type;
    std::string id;
    bool operator==(const Scope &other) const { return type == other.type && id == other.id; }
};

struct Grant {
    Scope scope;
    bool descendants = false;
    std::vector<std::string> capabilities;
};

struct Policy {
    unsigned version = 1;
    std::vector<Grant> grants;
};

struct Resource {
    Scope scope;
    std::vector<Scope> ancestors;
    bool ownershipResolved = false;
};

// Canonical provisioning root is a sentinel, not a tenant grant or wildcard.
inline const Scope PlatformRoot{"entity", "0000-0000-0000"};

inline const std::vector<std::string> &Capabilities() {
    static const std::vector<std::string> values{
        "devices.read", "clients.read", "configuration.read", "configuration.write",
        "configuration.push", "devices.reboot", "firmware.read", "firmware.upgrade",
        "diagnostics.read", "diagnostics.run", "devices.console", "enrollment.manage",
        "resources.write", "resources.delete", "resources.move", "users.manage",
        "secrets.read", "rrm.read", "rrm.manage", "firmware.publish", "controller.manage"};
    return values;
}

inline bool KnownCapability(std::string_view value) {
    return std::find(Capabilities().begin(), Capabilities().end(), value) != Capabilities().end();
}

inline bool GlobalOnly(std::string_view value) {
    return value == "firmware.publish" || value == "controller.manage";
}

inline bool ValidScope(const Scope &scope) {
    if (scope.type != "entity" && scope.type != "venue") return false;
    if (scope.id.size() != 36) return false;
    for (std::size_t i = 0; i < scope.id.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (scope.id[i] != '-') return false;
        } else if (!((scope.id[i] >= '0' && scope.id[i] <= '9') ||
                     (scope.id[i] >= 'a' && scope.id[i] <= 'f'))) return false;
    }
    return true;
}

inline bool Valid(const Policy &policy) {
    if (policy.version != 1 || policy.grants.size() > 256) return false;
    for (const auto &grant : policy.grants) {
        if (!ValidScope(grant.scope) || grant.capabilities.empty() ||
            grant.capabilities.size() > Capabilities().size()) return false;
        std::vector<std::string> seen;
        for (const auto &capability : grant.capabilities) {
            if (!KnownCapability(capability) || GlobalOnly(capability) ||
                std::find(seen.begin(), seen.end(), capability) != seen.end()) return false;
            seen.push_back(capability);
        }
    }
    return true;
}

inline bool ValidResource(const Resource &resource) {
    if (!resource.ownershipResolved || !ValidScope(resource.scope) ||
        resource.ancestors.size() > 128) return false;
    std::vector<Scope> seen{resource.scope};
    for (const auto &ancestor : resource.ancestors) {
        if (!ValidScope(ancestor) || std::find(seen.begin(), seen.end(), ancestor) != seen.end())
            return false; // Cycles and duplicate lineage fail closed.
        seen.push_back(ancestor);
    }
    return true;
}

using ParentLookup = std::function<bool(const Scope &, Scope &)>;
inline Resource Resolve(const Scope &scope, const ParentLookup &lookup) {
    Resource result{scope, {}, false};
    if (!ValidScope(scope)) return result;
    Scope current = scope;
    std::vector<Scope> seen;
    for (unsigned depth = 0; depth < 128; ++depth) {
        if ((!ValidScope(current) && !(current == PlatformRoot)) ||
            std::find(seen.begin(), seen.end(), current) != seen.end()) return result;
        seen.push_back(current);
        Scope parent;
        if (!lookup(current, parent)) return result;
        if (parent.type.empty() && parent.id.empty()) {
            // Only the real platform root can terminate a canonical tree.
            result.ownershipResolved = current == PlatformRoot;
            return result;
        }
        if (current.type == "entity" && parent.type != "entity") return result;
        if (!(parent == PlatformRoot)) result.ancestors.push_back(parent);
        current = parent;
    }
    return result;
}

inline bool Allows(const Policy &policy, const Resource &resource,
                   std::string_view capability, bool platformAdministrator = false,
                   bool suspended = false) {
    if (suspended || !KnownCapability(capability)) return false;
    if (platformAdministrator) return true;
    if (!Valid(policy) || !ValidResource(resource)) return false;
    for (const auto &grant : policy.grants) {
        // Check scope and capability in the SAME grant. Never union the actions
        // of one site with the scope of another site.
        if (std::find(grant.capabilities.begin(), grant.capabilities.end(), capability) ==
            grant.capabilities.end()) continue;
        if (grant.scope == resource.scope) return true;
        if (grant.descendants && std::find(resource.ancestors.begin(), resource.ancestors.end(),
                                          grant.scope) != resource.ancestors.end()) return true;
    }
    return false;
}

inline std::vector<std::string> Preset(std::string_view name) {
    const std::vector<std::string> viewer{"devices.read", "clients.read", "configuration.read",
                                         "firmware.read", "diagnostics.read", "rrm.read"};
    if (name == "viewer") return viewer;
    if (name != "editor" && name != "operator") return {};
    auto result = viewer;
    result.insert(result.end(), {"configuration.write"});
    if (name == "operator") result.insert(result.end(), {"configuration.push", "devices.reboot"});
    // Firmware upgrade, shell, secrets, enrollment, deletion and user management
    // are explicit opt-ins, never implied by the operator preset.
    return result;
}

inline bool CanAssign(bool platformAdministrator, bool suspended,
                      const std::string &actor, const std::string &target) {
    // Scoped delegation will have its own subset/containment checks. It is not
    // silently treated as global administration in this first implementation.
    return platformAdministrator && !suspended && !actor.empty() && !target.empty() && actor != target;
}

inline bool CachedIdentityUsable(std::uint64_t expiresOn, std::uint64_t now, bool suspended) {
    return !suspended && expiresOn > now;
}

} // namespace OpenWifi::UserAccess
