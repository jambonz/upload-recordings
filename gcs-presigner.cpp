#include "gcs-presigner.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

#include <ctime>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace {

const char* GCS_HOST = "storage.googleapis.com";
const char* GCS_ALGORITHM = "GOOG4-RSA-SHA256";

std::string toHex(const unsigned char* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

} // namespace

std::string gcsUriEncode(const std::string& in, bool preserveSlash) {
    static const char* digits = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved || (preserveSlash && c == '/')) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(digits[c >> 4]);
            out.push_back(digits[c & 0x0f]);
        }
    }
    return out;
}

std::string gcsSha256Hex(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return toHex(digest, SHA256_DIGEST_LENGTH);
}

std::string gcsRsaSha256Hex(const std::string& privateKeyPem, const std::string& data) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(privateKeyPem.data(), static_cast<int>(privateKeyPem.size())), BIO_free);
    if (!bio) throw std::runtime_error("gcs presign: BIO_new_mem_buf failed");

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!pkey) throw std::runtime_error("gcs presign: failed to parse service-account private key");

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("gcs presign: EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) {
        throw std::runtime_error("gcs presign: EVP_DigestSignInit failed");
    }
    size_t sigLen = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &sigLen,
                       reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
        throw std::runtime_error("gcs presign: EVP_DigestSign (size) failed");
    }
    std::string sig(sigLen, '\0');
    if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(&sig[0]), &sigLen,
                       reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
        throw std::runtime_error("gcs presign: EVP_DigestSign failed");
    }
    sig.resize(sigLen);
    return toHex(reinterpret_cast<const unsigned char*>(sig.data()), sig.size());
}

std::string gcsCanonicalQuery(const std::string& clientEmail, const std::string& credentialScope,
                               const std::string& goog4Timestamp, long long expiresSecs) {
    // Parameters must appear sorted by name; these five are already alphabetical.
    std::ostringstream q;
    q << "X-Goog-Algorithm=" << GCS_ALGORITHM
      << "&X-Goog-Credential=" << gcsUriEncode(clientEmail + "/" + credentialScope, false)
      << "&X-Goog-Date=" << goog4Timestamp
      << "&X-Goog-Expires=" << expiresSecs
      << "&X-Goog-SignedHeaders=host";
    return q.str();
}

std::string gcsCanonicalRequest(const std::string& bucket, const std::string& objectKey,
                                 const std::string& canonicalQuery) {
    std::ostringstream cr;
    cr << "GET\n"
       << "/" << gcsUriEncode(bucket, true) << "/" << gcsUriEncode(objectKey, true) << "\n"
       << canonicalQuery << "\n"
       << "host:" << GCS_HOST << "\n"
       << "\n"
       << "host\n"
       << "UNSIGNED-PAYLOAD";
    return cr.str();
}

std::string generateGcsV4SignedUrl(const std::string& bucket, const std::string& objectKey,
                                    const std::string& clientEmail, const std::string& privateKeyPem,
                                    long long expiresSecs,
                                    std::chrono::system_clock::time_point signingTime) {
    std::time_t secs = std::chrono::system_clock::to_time_t(signingTime);
    std::tm tm{};
    gmtime_r(&secs, &tm);
    char dateBuf[16];
    char tsBuf[24];
    std::strftime(dateBuf, sizeof(dateBuf), "%Y%m%d", &tm);
    std::strftime(tsBuf, sizeof(tsBuf), "%Y%m%dT%H%M%SZ", &tm);

    const std::string credentialScope = std::string(dateBuf) + "/auto/storage/goog4_request";
    const std::string canonicalQuery = gcsCanonicalQuery(clientEmail, credentialScope, tsBuf, expiresSecs);
    const std::string canonicalRequest = gcsCanonicalRequest(bucket, objectKey, canonicalQuery);

    std::ostringstream sts;
    sts << GCS_ALGORITHM << "\n"
        << tsBuf << "\n"
        << credentialScope << "\n"
        << gcsSha256Hex(canonicalRequest);

    const std::string signature = gcsRsaSha256Hex(privateKeyPem, sts.str());

    std::ostringstream url;
    url << "https://" << GCS_HOST << "/" << gcsUriEncode(bucket, true) << "/"
        << gcsUriEncode(objectKey, true) << "?" << canonicalQuery
        << "&X-Goog-Signature=" << signature;
    return url.str();
}
