#pragma once
#include "Poco/JSON/Object.h"
#include "Poco/JSON/Array.h"
#include "Poco/JSON/Parser.h"
#include <sstream>

namespace OpenWifi::UserAccess {
// A redacted value is a preservation instruction, never a device credential.
inline bool PreserveRedacted(Poco::Dynamic::Var &incoming, const Poco::Dynamic::Var &stored) {
    if (incoming.isString() && incoming.convert<std::string>() == "__REDACTED__") {
        if (stored.isEmpty()) return false;
        incoming = stored; return true;
    }
    if (incoming.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto object = incoming.extract<Poco::JSON::Object::Ptr>();
        auto original = stored.type() == typeid(Poco::JSON::Object::Ptr)
            ? stored.extract<Poco::JSON::Object::Ptr>() : Poco::JSON::Object::Ptr{};
        for (auto it = object->begin(); it != object->end(); ++it) {
            auto value = it->second;
            if (!PreserveRedacted(value, original && original->has(it->first)
                    ? original->get(it->first) : Poco::Dynamic::Var{})) return false;
            object->set(it->first, value);
        }
    } else if (incoming.type() == typeid(Poco::JSON::Array::Ptr)) {
        auto array = incoming.extract<Poco::JSON::Array::Ptr>();
        auto original = stored.type() == typeid(Poco::JSON::Array::Ptr)
            ? stored.extract<Poco::JSON::Array::Ptr>() : Poco::JSON::Array::Ptr{};
        for (std::size_t i = 0; i < array->size(); ++i) {
            auto value = array->get(i);
            if (!PreserveRedacted(value, original && i < original->size()
                    ? original->get(i) : Poco::Dynamic::Var{})) return false;
            array->set(i, value);
        }
    } else if (incoming.isString() && incoming.convert<std::string>().find("__REDACTED__") != std::string::npos) {
        try {
            Poco::JSON::Parser parser;
            auto value = parser.parse(incoming.convert<std::string>());
            auto old = stored.isString() ? parser.parse(stored.convert<std::string>()) : Poco::Dynamic::Var{};
            if (!PreserveRedacted(value, old)) return false;
            std::ostringstream output; Poco::JSON::Stringifier::stringify(value, output);
            incoming = output.str();
        } catch (...) { return false; }
    }
    return true;
}
inline bool PreserveRedacted(Poco::JSON::Object::Ptr incoming, const Poco::JSON::Object &stored) {
    Poco::Dynamic::Var value(incoming);
    Poco::Dynamic::Var original(Poco::makeShared<Poco::JSON::Object>(stored));
    return incoming && PreserveRedacted(value, original);
}
}
