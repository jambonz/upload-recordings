#ifndef GCS_PRESIGNER_H
#define GCS_PRESIGNER_H

#include <chrono>
#include <string>

// V4 signed GET URLs for Google Cloud Storage, so the eval-notify hook can hand a vendor
// a fetchable recording URL for google-bucket accounts (mirrors what GeneratePresignedUrl
// does for aws_s3/s3_compatible). Spec: https://cloud.google.com/storage/docs/access-control/signed-urls
//
// Everything below is a pure function of its inputs (the signing time is a parameter, not
// a clock read) so the standalone test binary can verify the canonical request byte-for-byte
// and check the RSA signature with the matching public key -- no network, no live bucket.

// RFC-3986 percent-encoding as GCS requires it: unreserved characters pass through; for a
// path, '/' separators are preserved.
std::string gcsUriEncode(const std::string& in, bool preserveSlash);

// Lowercase-hex SHA-256 of `data`.
std::string gcsSha256Hex(const std::string& data);

// Lowercase-hex RSA-SHA256 signature of `data` using a PEM private key (the GCS service
// account key). Throws std::runtime_error on any OpenSSL failure.
std::string gcsRsaSha256Hex(const std::string& privateKeyPem, const std::string& data);

// The V4 canonical request for a GET of /<bucket>/<objectKey> on storage.googleapis.com
// with SignedHeaders=host and UNSIGNED-PAYLOAD. Exposed for the test binary.
std::string gcsCanonicalRequest(const std::string& bucket, const std::string& objectKey,
                                 const std::string& canonicalQuery);

// The sorted canonical query string for the signed URL (everything except X-Goog-Signature).
std::string gcsCanonicalQuery(const std::string& clientEmail, const std::string& credentialScope,
                               const std::string& goog4Timestamp, long long expiresSecs);

// Builds the complete signed URL. `signingTime` is truncated to whole seconds (UTC).
std::string generateGcsV4SignedUrl(const std::string& bucket, const std::string& objectKey,
                                    const std::string& clientEmail, const std::string& privateKeyPem,
                                    long long expiresSecs,
                                    std::chrono::system_clock::time_point signingTime);

#endif // GCS_PRESIGNER_H
