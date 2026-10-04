#include "PrivatePKIPolicy.h"
#include <openssl/pem.h>
#include <fstream>
#include <iostream>
#include <stdexcept>

using OpenWifi::PrivatePKIPolicy;
using nlohmann::json;

static void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const std::string directory = argv[1], serial = "001122334455";
    const auto path = directory + "/policy.json";
    auto load = [&](const std::string &name) {
        FILE *file = fopen((directory + "/" + name + ".pem").c_str(), "rb");
        require(file != nullptr, "fixture missing");
        X509 *cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
        fclose(file);
        require(cert != nullptr, "invalid fixture");
        return std::unique_ptr<X509, decltype(&X509_free)>(cert, X509_free);
    };
    auto good = load("good"), other = load("other");
    const auto pin = PrivatePKIPolicy::Fingerprint(good.get());
    json policy = {{"schemaVersion", 1}, {"version", 1u}, {"expires", std::time(nullptr) + 60},
                   {"inventory", {{serial, {{"enabled", true}, {"fingerprints", json::array({pin})}}}}},
                   {"revoked", json::array()}};
    auto write = [&]() { std::ofstream(path) << policy.dump(); chmod(path.c_str(), 0600); };
    write();
    PrivatePKIPolicy gate;
    gate.Configure(path);
    std::string observed;
    require(gate.Admit(good.get(), serial, observed) && observed == pin, "valid identity refused");
    require(!gate.Admit(good.get(), "001122334456", observed), "mismatched serial admitted");
    require(!gate.Admit(other.get(), serial, observed), "replacement key not pinned admitted");
    for (const auto &name : {"expired", "server", "ca", "noeku"}) {
        auto cert = load(name);
        policy["inventory"][serial]["fingerprints"].push_back(PrivatePKIPolicy::Fingerprint(cert.get()));
        policy["version"] = policy["version"].get<unsigned>() + 1;
        write();
        require(!gate.Admit(cert.get(), serial, observed), "invalid pinned leaf admitted");
    }
    // Current sessions use the same Allowed policy as initial admission.
    policy["version"] = 10u;
    policy["revoked"] = json::array({pin}); write();
    require(!gate.Allowed(serial, pin), "revoked current session admitted");
    policy["version"] = 11u;
    policy["revoked"] = json::array(); write();
    require(gate.Allowed(serial, pin), "restored policy refused");
    policy["version"] = 10u; write();
    require(!gate.Allowed(serial, pin), "policy rollback admitted");
    policy["version"] = 12u;
    policy["inventory"][serial]["enabled"] = false; write();
    require(!gate.Allowed(serial, pin), "disabled inventory admitted");
    policy["version"] = 13u;
    policy["inventory"][serial]["enabled"] = true; write();
    require(gate.Allowed(serial, pin), "new policy refused");
    policy["revoked"] = json::array({pin}); write();
    require(!gate.Allowed(serial, pin), "same-version replacement admitted");
    policy["version"] = 14u;
    policy["revoked"] = json::array();
    policy["expires"] = std::time(nullptr) - 1; write();
    require(!gate.Allowed(serial, pin), "expired policy admitted");
    policy["version"] = 15u;
    policy["expires"] = std::time(nullptr) + 301; write();
    require(!gate.Allowed(serial, pin), "excessive policy TTL admitted");
    policy["version"] = 16u;
    policy["expires"] = std::time(nullptr) + 60; write();
    chmod(path.c_str(), 0666);
    require(!gate.Allowed(serial, pin), "unsafe permissions admitted");
    chmod(path.c_str(), 0600);
    require(gate.Allowed(serial, pin), "safe policy refused");
    rename(path.c_str(), (path + ".real").c_str());
    symlink((path + ".real").c_str(), path.c_str());
    require(!gate.Allowed(serial, pin), "symlink policy admitted");
    std::cout << "PASS: native admission, exact CN/DER pins, key substitution, validity/EKU/CA, current-session revocation, disabled inventory, version/TTL/file safety\n";
}
