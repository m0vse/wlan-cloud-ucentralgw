#pragma once
#include "RESTObjects/RESTAPI_SecurityObjects.h"
#include "framework/UserAccessRequest.h"
#include "Poco/JSON/Object.h"

namespace OpenWifi::UserAccess {
struct Decision { bool allowed = false; bool secretsAllowed = false; };
Decision Check(const SecurityObjects::UserInfo &user, const std::string &kind,
               const std::string &id, const std::string &capability);
Decision Authorize(const SecurityObjects::UserInfo &user, const std::string &service,
                   const std::string &method, const std::string &path, const Query &query,
                   bool scopedCollectionSupported = false);
void RedactSecrets(Poco::JSON::Object &object);
void FilterConfigurationReferences(const SecurityObjects::UserInfo &user, Poco::JSON::Object &object);
}
