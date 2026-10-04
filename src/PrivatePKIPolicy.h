#pragma once

// Optional private-deployment admission overlay. Inputs are operator-published
// local policy, never AP-supplied fingerprints or TLS proxy headers.
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctime>
#include <mutex>
#include <memory>
#include <regex>
#include <string>

namespace OpenWifi {
class PrivatePKIPolicy {
  public:
    void Configure(std::string path, uid_t owner = geteuid()) { path_ = std::move(path); owner_ = owner; }
    bool Enabled() const { return !path_.empty(); }
    std::uint64_t Version() { std::lock_guard guard(mutex_); return version_; }

    static std::string Fingerprint(const X509 *certificate) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        if (!certificate || X509_digest(certificate, EVP_sha256(), digest, &length) != 1 || length != 32)
            return {};
        const char *hex = "0123456789abcdef";
        std::string result;
        for (unsigned int i = 0; i < length; ++i) {
            result += hex[digest[i] >> 4];
            result += hex[digest[i] & 15];
        }
        return result;
    }

    // Certificate cryptographic chain validation remains mandatory in OWGW.
    // Exact approved DER pins add inventory/revocation policy to that validation.
    bool Admit(const X509 *peer, const std::string &serial, std::string &fingerprint) {
        if (!Enabled()) return true;
        std::unique_ptr<X509, decltype(&X509_free)> copy(peer ? X509_dup(peer) : nullptr, X509_free);
        auto *certificate = copy.get();
        if (!certificate || X509_cmp_current_time(X509_get0_notBefore(certificate)) >= 0 ||
            X509_cmp_current_time(X509_get0_notAfter(certificate)) <= 0 ||
            X509_check_ca(certificate) != 0 || X509_check_purpose(certificate, X509_PURPOSE_SSL_CLIENT, 0) != 1)
            return false;
        auto *purpose = static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(certificate, NID_ext_key_usage, nullptr, nullptr));
        bool clientAuth = false;
        if (purpose) {
            for (int i = 0; i < sk_ASN1_OBJECT_num(purpose); ++i)
                if (OBJ_obj2nid(sk_ASN1_OBJECT_value(purpose, i)) == NID_client_auth) clientAuth = true;
            EXTENDED_KEY_USAGE_free(purpose);
        }
        if (!clientAuth) return false;
        X509_NAME *subject = X509_get_subject_name(certificate);
        int index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (index < 0 || X509_NAME_get_index_by_NID(subject, NID_commonName, index) >= 0) return false;
        ASN1_STRING *cn = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, index));
        unsigned char *value = nullptr;
        int size = ASN1_STRING_to_UTF8(&value, cn);
        if (size < 0) return false;
        std::string actual(reinterpret_cast<char *>(value), static_cast<std::size_t>(size));
        OPENSSL_free(value);
        if (actual != serial) return false;
        fingerprint = Fingerprint(certificate);
        return Allowed(serial, fingerprint);
    }

    bool Allowed(const std::string &serial, const std::string &fingerprint) {
        if (!Enabled()) return true;
        if (!std::regex_match(serial, std::regex("[0-9a-f]{12}")) ||
            !std::regex_match(fingerprint, std::regex("[0-9a-f]{64}"))) return false;
        std::lock_guard guard(mutex_);
        try {
            const auto text = Read();
            auto policy = nlohmann::json::parse(text);
            auto stamp = std::time(nullptr);
            if (policy.at("schemaVersion") != 1 || !policy.at("version").is_number_unsigned() ||
                !policy.at("expires").is_number_unsigned()) return false;
            auto version = policy.at("version").get<std::uint64_t>();
            auto expires = policy.at("expires").get<std::uint64_t>();
            if (!version || version < version_ || expires <= static_cast<std::uint64_t>(stamp) ||
                expires > static_cast<std::uint64_t>(stamp) + 300 ||
                (version == version_ && !last_.empty() && text != last_)) return false;
            version_ = version;
            last_ = text;
            const auto &revoked = policy.at("revoked");
            if (!revoked.is_array()) return false;
            for (const auto &item : revoked) if (item == fingerprint) return false;
            const auto &device = policy.at("inventory").at(serial);
            if (!device.at("enabled").is_boolean() || !device.at("enabled").get<bool>()) return false;
            const auto &pins = device.at("fingerprints");
            if (!pins.is_array()) return false;
            for (const auto &pin : pins) if (pin.is_string() && pin == fingerprint) return true;
        } catch (...) { }
        return false;
    }

  private:
    std::string Read() const {
        int fd = open(path_.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) throw std::runtime_error("policy unavailable");
        struct Close { int fd; ~Close() { close(fd); } } cleanup{fd};
        struct stat info{};
        if (fstat(fd, &info) || !S_ISREG(info.st_mode) || (info.st_uid != 0 && info.st_uid != owner_) ||
            (info.st_mode & 0022) || info.st_size < 1 || info.st_size > 1024 * 1024)
            throw std::runtime_error("unsafe policy");
        std::string text(static_cast<std::size_t>(info.st_size), '\0');
        std::size_t offset = 0;
        while (offset < text.size()) {
            auto count = read(fd, text.data() + offset, text.size() - offset);
            if (count <= 0) throw std::runtime_error("incomplete policy");
            offset += static_cast<std::size_t>(count);
        }
        return text;
    }
    std::string path_, last_;
    uid_t owner_ = geteuid();
    std::uint64_t version_ = 0;
    std::mutex mutex_;
};
}
