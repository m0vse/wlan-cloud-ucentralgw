#pragma once
#include "framework/UserAccessPolicy.h"
#include <map>
#include <sstream>

namespace OpenWifi::UserAccess {
struct RequestRule {
    bool known = false;
    bool collection = false;
    bool catalog = false;
    std::string kind, id;
    std::vector<std::string> capabilities;
};
using Query = std::map<std::string, std::string>;

inline RequestRule Classify(const std::string &service, const std::string &method,
                            const std::string &path, const Query &query) {
    RequestRule rule;
    std::vector<std::string> parts;
    std::istringstream stream(path);
    std::string part;
    while (std::getline(stream, part, '/')) if (!part.empty()) parts.push_back(part);
    if (parts.size() < 3 || parts[0] != "api" || parts[1] != "v1") return rule;
    auto flag = [&](const std::string &key) {
        auto found = query.find(key); return found != query.end() && found->second == "true";
    };
    auto value = [&](const std::string &key) {
        auto found = query.find(key); return found == query.end() ? std::string{} : found->second;
    };
    const auto &name = parts[2];
    if (service == "owprov") {
        const std::map<std::string, std::string> kinds{{"entity", "entity"}, {"venue", "venue"},
            {"inventory", "inventory"}, {"configuration", "configuration"}, {"variable", "variable"},
            {"contact", "contact"}, {"location", "location"}, {"map", "map"}};
        const auto found = kinds.find(name);
        if (found == kinds.end() || parts.size() > 4) return rule;
        rule.kind = found->second;
        rule.id = parts.size() == 4 ? parts[3] : "";
        rule.collection = parts.size() == 3;
        if (method == "GET") {
            rule.capabilities = {name == "configuration" ? "configuration.read" : "devices.read"};
            if (flag("applyConfiguration")) rule.capabilities = {"configuration.push"};
            if (flag("config") || flag("resolveConfig") || flag("explain"))
                rule.capabilities.push_back("configuration.read");
            if (flag("rrmSettings")) rule.capabilities.push_back("rrm.read");
            if (flag("firmwareOptions")) rule.capabilities.push_back("firmware.read");
            // Schema/order metadata contains no site records.
            if (flag("orderSpec") && flag("applyConfiguration")) return RequestRule{};
            if (flag("orderSpec") && rule.collection) {
                if (query.size() != 1 || name != "inventory") return RequestRule{};
                rule.catalog = true; rule.collection = false;
            }
        } else if (method == "POST" || method == "PUT") {
            rule.capabilities = {name == "configuration" ? "configuration.write" : "resources.write"};
            if (flag("updateAllDevices")) rule.capabilities = {"configuration.push"};
            if (flag("upgradeAllDevices")) rule.capabilities = {"firmware.upgrade"};
            if (flag("rebootAllDevices")) rule.capabilities = {"devices.reboot"};
            // A combined request needs ALL requested actions, not just the last flag.
            if (flag("updateAllDevices")) rule.capabilities.push_back("configuration.push");
            if (flag("upgradeAllDevices")) rule.capabilities.push_back("firmware.upgrade");
            if (flag("rebootAllDevices")) rule.capabilities.push_back("devices.reboot");
            if (flag("setTree")) return RequestRule{}; // Platform-wide tree import is admin-only.
        } else if (method == "DELETE") rule.capabilities = {"resources.delete"};
        else return RequestRule{};
        rule.known = true;
        return rule;
    }
    if (service == "owgw") {
        if (name == "device" && parts.size() >= 4 && parts.size() <= 5) {
            rule.kind = "inventory"; rule.id = parts[3];
            if (parts.size() == 4) {
                if (method == "GET") rule.capabilities = {"devices.read"};
                else if (method == "POST" || method == "PUT") rule.capabilities = {"configuration.push"};
                else return rule;
            } else {
                const auto &command = parts[4];
                if (method == "GET") {
                    if (command == "capabilities" || command == "status" || command == "statistics")
                        rule.capabilities = {"devices.read"};
                    else if (command == "logs" || command == "checks" || command == "healthchecks")
                        rule.capabilities = {"diagnostics.read"};
                    else if (command == "rtty") rule.capabilities = {"devices.console"};
                    else return rule;
                } else if (method == "POST") {
                    if (command == "configure") rule.capabilities = {"configuration.push"};
                    else if (command == "upgrade") rule.capabilities = {"firmware.upgrade"};
                    else if (command == "reboot") rule.capabilities = {"devices.reboot"};
                    else if (command == "rtty") rule.capabilities = {"devices.console"};
                    else if (command == "wifiscan" || command == "ping" || command == "trace")
                        rule.capabilities = {"diagnostics.run"};
                    else return rule; // Factory reset, scripts, packages etc. stay admin-only.
                } else return rule;
            }
            rule.known = true; return rule;
        }
        if (name == "devices" && parts.size() == 3 && method == "GET") {
            if (flag("connectionStatistics")) return rule; // Global aggregates are not scoped reads.
            rule = {true, true, false, "inventory", "", {"devices.read"}};
            if (flag("orderSpec")) {
                if (query.size() != 1) return RequestRule{};
                rule.catalog = true; rule.collection = false;
            }
            return rule;
        }
        if (name == "commands" && parts.size() == 3 && method == "GET" && !value("serialNumber").empty())
            return {true, false, false, "inventory", value("serialNumber"), {"diagnostics.read"}};
        if ((name == "regulatory" || name == "ouis") && method == "GET")
            return {true, false, true, "", "", {"devices.read"}};
    }
    if (service == "owfms" && (name == "firmware" || name == "firmwares") && method == "GET")
        return {true, false, true, "", "", {"firmware.read"}};
    return rule; // No new endpoint inherits permission just because its HTTP method is GET.
}

inline bool AnyGrantAllows(const Policy &policy, const std::string &capability) {
    if (!Valid(policy)) return false;
    return std::any_of(policy.grants.begin(), policy.grants.end(), [&](const Grant &grant) {
        return std::find(grant.capabilities.begin(), grant.capabilities.end(), capability) != grant.capabilities.end();
    });
}
} // namespace OpenWifi::UserAccess
