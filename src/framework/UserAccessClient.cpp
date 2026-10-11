#include "framework/UserAccessClient.h"
#include "framework/UserAccessPolicyJSON.h"
#include "framework/OpenAPIRequests.h"
#include "framework/MicroServiceNames.h"
#include "Poco/JSON/Array.h"
#include <cctype>

namespace OpenWifi::UserAccess {
Decision Check(const SecurityObjects::UserInfo &user, const std::string &kind,
               const std::string &id, const std::string &capability) {
    if (user.id.empty() || user.suspended || user.blackListed) return {};
    if (user.userRole == SecurityObjects::ROOT) return {true, true};
    Poco::JSON::Object body;
    body.set("userId", user.id); body.set("capability", capability);
    body.set("objectType", kind); body.set("objectId", id);
    OpenAPIRequestPost request(uSERVICE_PROVISIONING, "/api/v1/access/check", {}, body, 3000);
    Poco::JSON::Object::Ptr response;
    if (request.Do(response) != Poco::Net::HTTPServerResponse::HTTP_OK || !response ||
        !response->has("allowed") || response->get("allowed").type() != typeid(bool) ||
        !response->has("secretsAllowed") || response->get("secretsAllowed").type() != typeid(bool)) return {};
    return {response->getValue<bool>("allowed"), response->optValue<bool>("secretsAllowed", false)};
}

Decision Authorize(const SecurityObjects::UserInfo &user, const std::string &service,
                   const std::string &method, const std::string &path, const Query &query,
                   bool scopedCollectionSupported) {
    if (user.id.empty() || user.suspended || user.blackListed) return {};
    if (user.userRole == SecurityObjects::ROOT) return {true, true};
    if (service == "owsec") {
        // Profile/preferences/MFA operate only on the authenticated identity;
        // the existing per-user handlers still perform their ownership checks.
        if (path == "/api/v1/oauth2" || path == "/api/v1/preferences" ||
            path == "/api/v1/totp" || path == "/api/v1/systemEndpoints") return {true, false};
        if (path == "/api/v1/user/" + user.id || path == "/api/v1/avatar/" + user.id)
            return {true, false};
        auto version = query.find("accessPolicyVersion");
        if ((path == "/api/v1/validateToken" || path == "/api/v1/validateApiKey") &&
            version != query.end() && version->second == "1") return {true, false};
        return {}; // Global user, role and controller administration stay root-only.
    }
    Policy policy;
    if (!Parse(user.securityPolicy, policy)) return {};
    if (method != "GET" && !(service == "owprov" && method == "PUT" &&
            path.compare(0, 22, "/api/v1/configuration/") == 0) &&
        !(service == "owgw" && method == "POST" &&
            path.compare(0, 15, "/api/v1/device/") == 0)) return {};
    if (service == "owprov") {
        for (const auto &key : {"withExtendedInfo", "additionalInfo", "expandInUse", "computedAffected", "getDevices",
                               "getChildren", "explain", "resolveConfig"}) {
            auto found = query.find(key);
            if (found != query.end() && found->second == "true") return {};
        }
    }
    const auto rule = Classify(service, method, path, query);
    if (!rule.known || (rule.collection && !scopedCollectionSupported)) return {};
    if (rule.catalog && !rule.id.empty()) return {};
    if (rule.catalog) for (const auto &capability : rule.capabilities)
        if (capability == "configuration.push" || capability == "devices.reboot" ||
            capability == "firmware.upgrade") return {};
    if (service == "owgw" && method == "POST" &&
        std::count(path.begin(), path.end(), '/') != 5) return {};
    for (const auto &capability : rule.capabilities) {
        if (capability == "devices.console" || capability == "diagnostics.run") return {};
        if (method != "GET" && service == "owgw" && capability != "configuration.push" &&
            capability != "devices.reboot" && capability != "firmware.upgrade") return {};
    }
    bool secrets = true;
    for (const auto &capability : rule.capabilities) {
        if (rule.catalog || rule.collection) {
            if (!AnyGrantAllows(policy, capability)) return {};
            // Scoped adapters redact each record using that record's grant.
            // Catalog responses have no record ownership or secret access.
            if (rule.catalog) secrets = false;
        } else {
            const auto decision = Check(user, rule.kind, rule.id, capability);
            if (!decision.allowed) return {};
            secrets = secrets && decision.secretsAllowed;
        }
    }
    return {true, secrets};
}

void FilterConfigurationReferences(const SecurityObjects::UserInfo &user, Poco::JSON::Object &object) {
    for (const auto &key : {"configurations", "deviceConfiguration"}) {
        if (!object.has(key)) continue;
        auto value = object.get(key);
        if (value.type() == typeid(Poco::JSON::Array::Ptr)) {
            auto array = value.extract<Poco::JSON::Array::Ptr>();
            auto allowed = Poco::makeShared<Poco::JSON::Array>();
            if (array) for (std::size_t i = 0; i < array->size(); ++i) {
                auto id = array->get(i);
                if (id.isString() && Check(user, "configuration", id.convert<std::string>(), "configuration.read").allowed)
                    allowed->add(id);
            }
            object.set(key, allowed);
        } else if (!value.isString() || !Check(user, "configuration", value.convert<std::string>(), "configuration.read").allowed)
            object.set(key, "");
    }
}

static bool Sensitive(std::string key) {
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
    key.erase(std::remove_if(key.begin(), key.end(), [](char c) { return c == '-' || c == '_'; }), key.end());
    static const std::vector<std::string> fields{"key", "password", "currentpassword", "lastpasswords",
        "secret", "passphrase", "psk", "privatekey", "clientkey", "token", "accesstoken",
        "refreshtoken", "apikey", "authenticatorsecret", "accesspin", "enrollmentkey",
        "hostapdbssraw", "hostapdradioraw", "raw", "sharedsecret", "sharedkey",
        "privatekeypassword", "passwordhistory", "radiussecret", "credential", "credentials",
        "accesskey", "secretkey", "signingkey", "sslkey", "wifikey",
        "log", "logs", "crashlog", "errortext", "message"};
    return std::find(fields.begin(), fields.end(), key) != fields.end();
}

static void RedactArray(Poco::JSON::Array &array) {
    for (std::size_t i = 0; i < array.size(); ++i) {
        auto entry = array.get(i);
        if (entry.type() == typeid(Poco::JSON::Object::Ptr)) {
            auto child = entry.extract<Poco::JSON::Object::Ptr>();
            if (child) RedactSecrets(*child);
        } else if (entry.type() == typeid(Poco::JSON::Array::Ptr)) {
            auto child = entry.extract<Poco::JSON::Array::Ptr>();
            if (child) RedactArray(*child);
        }
    }
}

void RedactSecrets(Poco::JSON::Object &object) {
    for (auto iterator = object.begin(); iterator != object.end(); ++iterator) {
        const auto &key = iterator->first;
        auto value = iterator->second;
        if (Sensitive(key)) { object.set(key, "__REDACTED__"); continue; }
        if (value.type() == typeid(Poco::JSON::Object::Ptr)) {
            auto child = value.extract<Poco::JSON::Object::Ptr>();
            if (child) RedactSecrets(*child);
        } else if (value.type() == typeid(Poco::JSON::Array::Ptr)) {
            auto array = value.extract<Poco::JSON::Array::Ptr>();
            if (!array) continue;
            RedactArray(*array);
        } else if (value.isString() && (key == "configuration" || key == "config" || key == "pendingConfiguration" ||
                                       key == "appliedConfiguration" ||
                                       key == "details" || key == "request" || key == "response" ||
                                       key == "results" || key == "log" || key == "logs" || key == "data" ||
                                       key == "crashlog")) {
            try {
                Poco::JSON::Parser parser;
                auto child = parser.parse(value.convert<std::string>()).extract<Poco::JSON::Object::Ptr>();
                if (!child) { object.set(key, "__REDACTED__"); continue; }
                RedactSecrets(*child);
                std::ostringstream output; child->stringify(output); object.set(key, output.str());
            } catch (...) { object.set(key, "__REDACTED__"); }
        }
    }
}
}
