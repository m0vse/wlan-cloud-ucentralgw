#pragma once

#include "framework/UserAccessPolicy.h"
#include "Poco/JSON/Parser.h"
#include <sstream>

namespace OpenWifi::UserAccess {

// Reuse the existing persisted/security-service-transported securityPolicy
// field. No credentials, user-type extensions or device configuration policy
// are repurposed. Only this explicitly versioned document is accepted.
inline bool Parse(const std::string &text, Policy &output) {
    output = Policy{};
    output.version = 0;
    if (text.empty() || text.size() > 65536) return false;
    try {
        Poco::JSON::Parser parser;
        std::istringstream stream(text);
        const auto object = parser.parse(stream).extract<Poco::JSON::Object::Ptr>();
        stream >> std::ws;
        if (stream.peek() != std::char_traits<char>::eof()) return false;
        if (!object || object->size() != 2 || !object->has("version") || !object->has("grants"))
            return false;
        const auto version = object->get("version");
        if (version.type() == typeid(bool) || !version.isInteger() || version.convert<unsigned>() != 1)
            return false;
        auto grants = object->getArray("grants");
        if (!grants || grants->size() > 256) return false;
        Policy policy;
        for (std::size_t i = 0; i < grants->size(); ++i) {
            auto item = grants->getObject(i);
            if (!item || item->size() != 4 || !item->has("scopeType") || !item->has("scopeId") ||
                !item->has("includeDescendants") || !item->has("capabilities")) return false;
            if (!item->get("scopeType").isString() || !item->get("scopeId").isString() ||
                item->get("includeDescendants").type() != typeid(bool)) return false;
            Grant grant{{item->getValue<std::string>("scopeType"),
                         item->getValue<std::string>("scopeId")},
                        item->getValue<bool>("includeDescendants"), {}};
            const auto capabilities = item->getArray("capabilities");
            if (!capabilities || capabilities->size() > Capabilities().size()) return false;
            for (std::size_t j = 0; j < capabilities->size(); ++j) {
                const auto capability = capabilities->get(j);
                if (!capability.isString()) return false;
                grant.capabilities.push_back(capability.convert<std::string>());
            }
            policy.grants.push_back(std::move(grant));
        }
        if (!Valid(policy)) return false;
        output = std::move(policy);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace OpenWifi::UserAccess
