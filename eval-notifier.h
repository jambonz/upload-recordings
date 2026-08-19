#ifndef EVAL_NOTIFIER_H
#define EVAL_NOTIFIER_H

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>

#include <spdlog/spdlog.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/client/ClientConfiguration.h>

#include "storage-uploader.h" // for Metadata_t
#include "yyjson.h"

// A vendor credential decrypted+parsed by Session ({"vendor":"roark","api_key":"..."}).
struct EvalCredential {
    std::string vendor;
    std::string apiKey;
};

// Everything needed to build a GET-presigned recording URL. `presignable` is false for
// google/azure buckets (v1 logs and skips them) and is only ever set true by
// Session::createStorageUploader() for aws_s3/s3_compatible.
struct PresignInfo {
    bool presignable = false;
    Aws::Auth::AWSCredentials credentials;
    std::string region;
    std::string bucket;
    std::string customEndpoint; // empty for plain aws_s3
};

// Everything the vendor adapter needs, gathered by StorageUploader::postUploadHook().
struct EvalNotifyContext {
    EvalCredential credential;
    PresignInfo presign;
    std::string recordingKey; // audio object key, e.g. "2026/08/19/CAxxx.wav"
    Metadata_t metadata;      // call_sid/account_sid/direction/from/to/application_sid
    std::chrono::system_clock::time_point audioStartTime;
    bool audioStartTimeSet = false;
    // Empty when session.json did not land (audio-only send is still valid).
    std::string stampedSessionSummaryJson;
};

// ---------------------------------------------------------------------------------------
// Pure/free helpers -- no MySQL and no live AWS/network calls, so a future standalone
// test binary (see the design doc's deferred §5.6) can exercise them without pulling in
// MySQLHelper, S3Client, or curl.
// ---------------------------------------------------------------------------------------

// jambonz termination_reason -> Roark endedStatus (best-effort; empty when unmapped).
std::string mapEndedStatus(const std::string& terminationReason);

// Normalize a phone number to E.164; returns empty string when it cannot be normalized.
std::string toE164(const std::string& number);

// One flattened, recording-relative transcript turn.
struct RoarkTranscriptEntry {
    std::string role; // "CUSTOMER" | "AGENT"
    std::string text;
    int64_t startOffsetMs = 0;
    int64_t endOffsetMs = 0;
};

// Maps a parsed session-summary document's turns into Roark transcript entries, offsets
// shifted by recordingStartedAtMs and end times approximated monotonically (mirrors the
// deleted examples/roark-bridge/lib.js mapTranscript).
//
// Orientation note: for calls the platform RECEIVED, session.json's per-turn `transcript`
// field is what the human caller said and `response` is what the voice agent said -- so
// `transcript` maps to role CUSTOMER and `response` maps to role AGENT. This is backwards
// from what the field names suggest; getting it wrong silently inverts every score Roark
// computes, so don't "fix" this mapping without re-checking session.json's actual field
// semantics.
std::vector<RoarkTranscriptEntry> mapTranscript(yyjson_val* sessionSummaryRoot, int64_t recordingStartedAtMs);

// Builds the S3 (non-CRT) client configuration used to presign a GET url, mirroring
// S3ClientManager::createConfig's region/endpointOverride/path-style logic. The plain
// Aws::S3::S3Client (not the S3Crt client used for uploads) is the only one exposing
// GeneratePresignedUrl, hence a separate, lighter-weight config builder here.
Aws::Client::ClientConfiguration buildPresignClientConfig(const std::string& region,
                                                           const std::string& customEndpoint,
                                                           bool& useVirtualAddressing);

// Inputs to the Roark CallCreate payload, already flattened out of Metadata_t/session.json
// so the mapping function itself has no MySQL/AWS-network dependency.
struct RoarkCallInputs {
    std::string recordingUrl;
    std::string startedAt;     // ISO-8601; omitted from the payload when empty
    std::string callDirection; // "INBOUND" | "OUTBOUND"
    std::string externalId;    // call_sid
    std::string endedStatus;   // may be empty -> omitted
    std::string customerE164;  // may be empty -> omitted
    std::string applicationSid;
    std::string accountSid;
    std::string callSid;
    bool hasTranscript = false;
    std::vector<RoarkTranscriptEntry> transcript;
};

// Builds the Roark CallCreate JSON body (compact) using Aws::Utils::Json::JsonValue --
// the JSON-building pattern already used by stampAndSerializeSessionSummary.
std::string buildRoarkCall(const RoarkCallInputs& in);

// ---------------------------------------------------------------------------------------
// The vendor adapter interface. v1 implements Roark only; a second vendor (Coval, ...) is
// a new subclass plus a new case in create() -- StorageUploader never needs to know about
// vendor internals.
// ---------------------------------------------------------------------------------------
class EvalNotifier {
public:
    virtual ~EvalNotifier() = default;

    // Never throws: any vendor/network failure is logged (via `log`) and swallowed so it
    // can never affect the recording upload or call processing.
    virtual void notify(std::shared_ptr<spdlog::logger> log, const EvalNotifyContext& ctx) = 0;

    // Returns nullptr for an unrecognized vendor string.
    static std::unique_ptr<EvalNotifier> create(const std::string& vendor);
};

#endif // EVAL_NOTIFIER_H
