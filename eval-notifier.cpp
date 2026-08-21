#include "eval-notifier.h"
#include "connection-manager.h"
#include "s3-client-manager.h"
#include "gcs-presigner.h"
#include "coval-mapper.h"
#include "influx-alert.h"

#include <aws/core/Aws.h>
#include <aws/s3/S3Client.h>
#include <aws/core/utils/json/JsonSerializer.h>
#include <aws/core/utils/Array.h>

#include <curl/curl.h>

#include <regex>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cctype>
#include <algorithm>
#include <unordered_map>

namespace {

constexpr long EVAL_POST_CONNECT_TIMEOUT_SECS = 3;
constexpr long EVAL_POST_TOTAL_TIMEOUT_SECS = 10;
constexpr long long PRESIGN_EXPIRATION_SECS = 3600;
constexpr const char* ROARK_CALL_URL = "https://api.roark.ai/v1/call";
constexpr const char* COVAL_SUBMIT_URL = "https://api.coval.dev/v1/conversations:submit";
constexpr size_t ERROR_BODY_TRUNCATE_LEN = 500;
constexpr size_t COVAL_MAX_BODY_BYTES = 250 * 1024;  // vendor rejects >256 KB; keep headroom
constexpr int64_t COVAL_MIN_AUDIO_SECS = 5;          // vendor rejects shorter recordings
constexpr const char* EVAL_ALERT_TYPE = "eval-post-failure";

size_t collectResponseBody(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

// Formats a system_clock time_point as the ISO-8601 form session.json's call_start uses
// ("2026-04-16T18:24:43.955Z"), for the audio-only fallback (see notify() below).
std::string isoFromSystemClock(std::chrono::system_clock::time_point tp) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
    std::time_t secs = static_cast<std::time_t>(ms / 1000);
    int millis = static_cast<int>(ms % 1000);
    std::tm tm{};
    gmtime_r(&secs, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    std::ostringstream oss;
    oss << buf << "." << std::setfill('0') << std::setw(3) << millis << "Z";
    return oss.str();
}

// Fresh curl_easy_init() handle per request; one attempt, no retry machinery (matches
// this repo's uniform log-and-continue error style for vendor calls). Each vendor supplies
// its own auth header (Roark: Authorization Bearer; Coval: X-API-Key).
bool postJson(const char* url, const std::vector<std::string>& extraHeaders,
              const std::string& body, long& httpCodeOut, std::string& errorOut) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        errorOut = "curl_easy_init failed";
        return false;
    }

    struct curl_slist* headers = nullptr;
    for (const auto& h : extraHeaders) {
        headers = curl_slist_append(headers, h.c_str());
    }
    headers = curl_slist_append(headers, "Content-Type: application/json");

    std::string responseBody;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collectResponseBody);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, EVAL_POST_CONNECT_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, EVAL_POST_TOTAL_TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    CURLcode res = curl_easy_perform(curl);
    bool success = false;
    if (res != CURLE_OK) {
        errorOut = curl_easy_strerror(res);
    } else {
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        httpCodeOut = httpCode;
        success = httpCode >= 200 && httpCode < 300;
        if (!success) {
            errorOut = responseBody.substr(0, ERROR_BODY_TRUNCATE_LEN);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

std::string presignRecordingUrl(const EvalNotifyContext& ctx,
                                 const std::shared_ptr<spdlog::logger>& log) {
    const std::string& key = ctx.recordingKey;

    if (ctx.presign.presignable) {
        const PresignInfo& info = ctx.presign;
        try {
            bool useVirtualAddressing = true;
            auto config = buildPresignClientConfig(info.region, info.customEndpoint, useVirtualAddressing);

            Aws::S3::S3Client client(
                Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("EvalNotifier", info.credentials),
                config,
                Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never,
                useVirtualAddressing
            );

            return client.GeneratePresignedUrl(info.bucket, key, Aws::Http::HttpMethod::HTTP_GET,
                                                PRESIGN_EXPIRATION_SECS);
        } catch (const std::exception& e) {
            log->error("eval-notify: failed to presign recording URL for key '{}': {}", key, e.what());
            return {};
        }
    }

    if (ctx.gcsPresign.presignable) {
        try {
            return generateGcsV4SignedUrl(ctx.gcsPresign.bucket, key, ctx.gcsPresign.clientEmail,
                                           ctx.gcsPresign.privateKeyPem, PRESIGN_EXPIRATION_SECS,
                                           std::chrono::system_clock::now());
        } catch (const std::exception& e) {
            log->error("eval-notify: failed to build GCS signed URL for key '{}': {}", key, e.what());
            return {};
        }
    }

    log->info("eval-notify: bucket type does not support presigning (azure) -- skipping vendor POST");
    return {};
}

// Every vendor POST failure becomes a portal alert (EVAL-INTEGRATION-DESIGN.md §5.5): the
// account owner configured this integration and has no shell access, so the alert carries
// enough to troubleshoot -- vendor, http status or curl error, response excerpt, call sid,
// recording key.
void writeEvalFailureAlert(const std::shared_ptr<spdlog::logger>& log, const std::string& vendor,
                            const EvalNotifyContext& ctx, long httpCode, const std::string& errorDetail) {
    std::ostringstream detail;
    detail << "call_sid=" << ctx.metadata.call_sid
           << " recording_key=" << ctx.recordingKey
           << " http=" << httpCode
           << " error=" << errorDetail;
    const int64_t tsNanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    sendInfluxAlert(log, buildAlertLine(ctx.metadata.account_sid, EVAL_ALERT_TYPE, vendor,
        "Failed posting call data to " + vendor + " for evaluation", detail.str(), tsNanos));
}

void bumpEvalCounter(bool success) {
    if (auto* statsd = ConnectionManager::getStatsdClient()) {
        statsd->increment(success ? "recording.eval_notify.success" : "recording.eval_notify.failure");
    }
}

class RoarkNotifier : public EvalNotifier {
public:
    void notify(std::shared_ptr<spdlog::logger> log, const EvalNotifyContext& ctx) override {
        try {
            std::string recordingUrl = presignRecordingUrl(ctx, log);
            if (recordingUrl.empty()) {
                // Already logged (unsupported bucket type or presign failure): there is
                // nothing fetchable to send Roark, so don't POST a broken URL.
                bumpCounter(false);
                return;
            }

            bool inbound = ctx.metadata.direction == "inbound";

            RoarkCallInputs in;
            in.recordingUrl = recordingUrl;
            in.callDirection = inbound ? "INBOUND" : "OUTBOUND";
            in.externalId = ctx.metadata.call_sid;
            in.applicationSid = ctx.metadata.application_sid;
            in.accountSid = ctx.metadata.account_sid;
            in.callSid = ctx.metadata.call_sid;
            in.customerE164 = toE164(inbound ? ctx.metadata.from : ctx.metadata.to);

            yyjson_doc* summaryDoc = nullptr;
            if (!ctx.stampedSessionSummaryJson.empty()) {
                summaryDoc = yyjson_read(ctx.stampedSessionSummaryJson.c_str(),
                                          ctx.stampedSessionSummaryJson.size(), 0);
            }

            if (summaryDoc) {
                yyjson_val* root = yyjson_doc_get_root(summaryDoc);

                yyjson_val* callStart = yyjson_obj_get(root, "call_start");
                if (callStart && yyjson_is_str(callStart)) {
                    in.startedAt = yyjson_get_str(callStart);
                }

                yyjson_val* terminationReason = yyjson_obj_get(root, "termination_reason");
                if (terminationReason && yyjson_is_str(terminationReason)) {
                    in.endedStatus = mapEndedStatus(yyjson_get_str(terminationReason));
                }

                int64_t recordingStartedAtMs = 0;
                yyjson_val* recStartedAt = yyjson_obj_get(root, "recording_started_at_ms");
                if (recStartedAt && yyjson_is_num(recStartedAt)) {
                    recordingStartedAtMs = yyjson_get_sint(recStartedAt);
                }

                in.transcript = mapTranscript(root, recordingStartedAtMs);
                in.hasTranscript = !in.transcript.empty();

                yyjson_doc_free(summaryDoc);
            }

            if (in.startedAt.empty() && ctx.audioStartTimeSet) {
                // No session.json (audio-only) or it had no call_start: fall back to the
                // recording's own start time rather than omit startedAt entirely.
                in.startedAt = isoFromSystemClock(ctx.audioStartTime);
            }

            std::string body = buildRoarkCall(in);

            long httpCode = 0;
            std::string errorDetail;
            bool ok = postJson(ROARK_CALL_URL,
                {"Authorization: Bearer " + ctx.credential.apiKey}, body, httpCode, errorDetail);

            if (ok) {
                log->info("eval-notify: posted call {} to roark ({} bytes, transcript: {})",
                    ctx.metadata.call_sid, body.size(), in.hasTranscript ? "yes" : "no");
            } else {
                log->error("eval-notify: roark POST failed for call {} (vendor: roark, http: {}): {}",
                    ctx.metadata.call_sid, httpCode, errorDetail);
                writeEvalFailureAlert(log, "roark", ctx, httpCode, errorDetail);
            }
            bumpCounter(ok);
        } catch (const std::exception& e) {
            log->error("eval-notify: unexpected exception notifying roark for call {}: {}",
                ctx.metadata.call_sid, e.what());
            bumpCounter(false);
        }
    }

private:
    static void bumpCounter(bool success) { bumpEvalCounter(success); }
};

class CovalNotifier : public EvalNotifier {
public:
    void notify(std::shared_ptr<spdlog::logger> log, const EvalNotifyContext& ctx) override {
        yyjson_doc* summaryDoc = nullptr;
        try {
            std::string recordingUrl = presignRecordingUrl(ctx, log);
            if (recordingUrl.empty()) {
                // v1 always sends audio (transcript-only submissions were deliberately
                // deferred); nothing presignable means nothing to send.
                bumpEvalCounter(false);
                return;
            }

            using Aws::Utils::Json::JsonValue;

            CovalCallInputs in;
            in.audioUrl = recordingUrl;
            in.externalConversationId = ctx.metadata.call_sid;

            // Identity metadata: stable, documented key names -- customers build Coval
            // conditional metric rules on these. 'call_id' and 'trace_id' are reserved by
            // Coval, hence sip_call_id / jambonz_trace_id.
            JsonValue meta;
            meta.WithString("call_sid", ctx.metadata.call_sid);
            meta.WithString("account_sid", ctx.metadata.account_sid);
            if (!ctx.metadata.application_sid.empty()) {
                meta.WithString("application_sid", ctx.metadata.application_sid);
            }
            if (!ctx.metadata.direction.empty()) meta.WithString("direction", ctx.metadata.direction);
            if (!ctx.metadata.from.empty()) meta.WithString("from", ctx.metadata.from);
            if (!ctx.metadata.to.empty()) meta.WithString("to", ctx.metadata.to);
            if (!ctx.metadata.caller_name.empty()) meta.WithString("caller_name", ctx.metadata.caller_name);
            if (!ctx.metadata.trace_id.empty()) meta.WithString("jambonz_trace_id", ctx.metadata.trace_id);
            std::string sipCallId = ctx.metadata.sip_call_id;

            if (!ctx.stampedSessionSummaryJson.empty()) {
                summaryDoc = yyjson_read(ctx.stampedSessionSummaryJson.c_str(),
                                          ctx.stampedSessionSummaryJson.size(), 0);
            }

            if (summaryDoc) {
                yyjson_val* root = yyjson_doc_get_root(summaryDoc);

                yyjson_val* duration = yyjson_obj_get(root, "duration_sec");
                if (duration && yyjson_is_num(duration) &&
                    yyjson_get_sint(duration) < COVAL_MIN_AUDIO_SECS) {
                    log->info("eval-notify: call {} is shorter than coval's {}s minimum -- skipping",
                        ctx.metadata.call_sid, COVAL_MIN_AUDIO_SECS);
                    yyjson_doc_free(summaryDoc);
                    bumpEvalCounter(false);
                    return;
                }
                if (duration && yyjson_is_num(duration)) {
                    meta.WithInt64("duration_sec", yyjson_get_sint(duration));
                }

                yyjson_val* callStart = yyjson_obj_get(root, "call_start");
                if (callStart && yyjson_is_str(callStart)) in.occurredAt = yyjson_get_str(callStart);

                if (sipCallId.empty()) {
                    yyjson_val* sipCid = yyjson_obj_get(root, "sip_call_id");
                    if (sipCid && yyjson_is_str(sipCid)) sipCallId = yyjson_get_str(sipCid);
                }

                yyjson_val* term = yyjson_obj_get(root, "termination_reason");
                if (term && yyjson_is_str(term)) meta.WithString("termination_reason", yyjson_get_str(term));

                addAgentMetadata(root, meta);
                addOutcomeMetadata(root, meta);

                int64_t recordingStartedAtMs = 0;
                yyjson_val* recStartedAt = yyjson_obj_get(root, "recording_started_at_ms");
                if (recStartedAt && yyjson_is_num(recStartedAt)) {
                    recordingStartedAtMs = yyjson_get_sint(recStartedAt);
                }
                in.transcript = mapTranscript(root, recordingStartedAtMs);

                yyjson_doc_free(summaryDoc);
                summaryDoc = nullptr;
            }

            if (!sipCallId.empty()) meta.WithString("sip_call_id", sipCallId);
            if (in.occurredAt.empty() && ctx.audioStartTimeSet) {
                in.occurredAt = isoFromSystemClock(ctx.audioStartTime);
            }
            addCustomerData(ctx.metadata.customer_data_json, meta, log);

            in.metadata = std::move(meta);
            std::string body = buildCovalConversation(in, COVAL_MAX_BODY_BYTES);

            long httpCode = 0;
            std::string errorDetail;
            bool ok = postJson(COVAL_SUBMIT_URL,
                {"X-API-Key: " + ctx.credential.apiKey}, body, httpCode, errorDetail);

            if (ok) {
                log->info("eval-notify: posted call {} to coval ({} bytes, transcript: {} messages)",
                    ctx.metadata.call_sid, body.size(), in.transcript.size());
            } else {
                log->error("eval-notify: coval POST failed for call {} (vendor: coval, http: {}): {}",
                    ctx.metadata.call_sid, httpCode, errorDetail);
                writeEvalFailureAlert(log, "coval", ctx, httpCode, errorDetail);
            }
            bumpEvalCounter(ok);
        } catch (const std::exception& e) {
            if (summaryDoc) yyjson_doc_free(summaryDoc);
            log->error("eval-notify: unexpected exception notifying coval for call {}: {}",
                ctx.metadata.call_sid, e.what());
            bumpEvalCounter(false);
        }
    }

private:
    // AI configuration from the first agent[] entry: which STT/TTS/LLM served this call --
    // the keys customers segment their Coval scores by.
    static void addAgentMetadata(yyjson_val* root, Aws::Utils::Json::JsonValue& meta) {
        yyjson_val* agentArr = yyjson_obj_get(root, "agent");
        if (!agentArr || !yyjson_is_arr(agentArr) || yyjson_arr_size(agentArr) == 0) return;
        yyjson_val* first = yyjson_arr_get(agentArr, 0);

        yyjson_val* config = yyjson_obj_get(first, "config");
        if (config && yyjson_is_obj(config)) {
            static const std::pair<const char*, const char*> kConfigKeys[] = {
                {"stt_vendor", "stt_vendor"}, {"stt_model", "stt_model"},
                {"tts_vendor", "tts_vendor"}, {"tts_voice", "tts_voice"},
                {"llm_vendor", "llm_vendor"}, {"llm_model", "llm_model"},
                {"turn_detection", "turn_detection"}
            };
            for (const auto& [src, dst] : kConfigKeys) {
                yyjson_val* v = yyjson_obj_get(config, src);
                if (v && yyjson_is_str(v)) meta.WithString(dst, yyjson_get_str(v));
            }
        }

        yyjson_val* latency = yyjson_obj_get(first, "latency_avg");
        if (latency && yyjson_is_obj(latency)) {
            static const std::pair<const char*, const char*> kLatencyKeys[] = {
                {"stt_ms", "avg_stt_ms"}, {"llm_ms", "avg_llm_ms"}, {"tts_ms", "avg_tts_ms"}
            };
            for (const auto& [src, dst] : kLatencyKeys) {
                yyjson_val* v = yyjson_obj_get(latency, src);
                if (v && yyjson_is_num(v)) meta.WithInt64(dst, yyjson_get_sint(v));
            }
        }
    }

    // Outcome/quality across all agent[] entries + the verb_events timeline.
    static void addOutcomeMetadata(yyjson_val* root, Aws::Utils::Json::JsonValue& meta) {
        int64_t bargeIns = 0;
        int64_t errors = 0;
        bool transferred = false;

        yyjson_val* agentArr = yyjson_obj_get(root, "agent");
        if (agentArr && yyjson_is_arr(agentArr)) {
            yyjson_val* item;
            yyjson_arr_iter iter = yyjson_arr_iter_with(agentArr);
            while ((item = yyjson_arr_iter_next(&iter))) {
                yyjson_val* bi = yyjson_obj_get(item, "barge_in");
                if (bi && yyjson_is_obj(bi)) {
                    yyjson_val* confirmed = yyjson_obj_get(bi, "confirmed");
                    if (confirmed && yyjson_is_num(confirmed)) bargeIns += yyjson_get_sint(confirmed);
                }
                yyjson_val* errArr = yyjson_obj_get(item, "errors");
                if (errArr && yyjson_is_arr(errArr)) errors += yyjson_arr_size(errArr);
                yyjson_val* result = yyjson_obj_get(item, "result");
                if (result && yyjson_is_str(result) &&
                    std::string(yyjson_get_str(result)) == "handoff") {
                    transferred = true;
                }
            }
        }

        yyjson_val* events = yyjson_obj_get(root, "verb_events");
        if (events && yyjson_is_arr(events)) {
            yyjson_val* evt;
            yyjson_arr_iter iter = yyjson_arr_iter_with(events);
            while ((evt = yyjson_arr_iter_next(&iter))) {
                yyjson_val* type = yyjson_obj_get(evt, "type");
                if (type && yyjson_is_str(type)) {
                    std::string t = yyjson_get_str(type);
                    if (t == "sip:refer" || t == "transfer") transferred = true;
                }
            }
        }

        meta.WithInt64("barge_ins_confirmed", bargeIns);
        meta.WithInt64("error_count", errors);
        meta.WithBool("transferred", transferred);
    }

    // Top-level primitives from the createCall tag (customerData) become metadata keys,
    // skipping names Coval reserves.
    static void addCustomerData(const std::string& customerDataJson,
                                 Aws::Utils::Json::JsonValue& meta,
                                 const std::shared_ptr<spdlog::logger>& log) {
        if (customerDataJson.empty()) return;
        yyjson_doc* doc = yyjson_read(customerDataJson.c_str(), customerDataJson.size(), 0);
        if (!doc) {
            log->debug("eval-notify: customerData is not parseable JSON -- ignoring");
            return;
        }
        yyjson_val* root = yyjson_doc_get_root(doc);
        if (root && yyjson_is_obj(root)) {
            static const char* kReserved[] = {
                "conversation_id", "external_conversation_id", "call_id", "trace_id",
                "langfuse_trace_id", "observation_id", "langfuse_observation_id",
                "project_id", "environment", "occurred_at"
            };
            yyjson_obj_iter iter = yyjson_obj_iter_with(root);
            yyjson_val* key;
            while ((key = yyjson_obj_iter_next(&iter))) {
                yyjson_val* val = yyjson_obj_iter_get_val(key);
                std::string k = yyjson_get_str(key);
                bool reserved = false;
                for (const char* r : kReserved) {
                    if (k == r) { reserved = true; break; }
                }
                if (reserved) continue;
                if (yyjson_is_str(val)) meta.WithString(k, yyjson_get_str(val));
                else if (yyjson_is_bool(val)) meta.WithBool(k, yyjson_get_bool(val));
                else if (yyjson_is_num(val)) meta.WithDouble(k, yyjson_get_num(val));
            }
        }
        yyjson_doc_free(doc);
    }
};

} // namespace

bool shouldSampleCall(const std::string& callSid, int samplingPercent) {
    if (samplingPercent >= 100) return true;
    if (samplingPercent <= 0) return false;
    if (callSid.empty()) return true; // cannot decide deterministically -- fail open

    uint64_t hash = 14695981039346656037ULL; // FNV-1a 64-bit offset basis
    for (unsigned char c : callSid) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL; // FNV prime
    }
    return static_cast<int>(hash % 100) < samplingPercent;
}

std::string mapEndedStatus(const std::string& terminationReason) {
    static const std::unordered_map<std::string, std::string> kMap = {
        {"caller-hangup", "CUSTOMER_ENDED_CALL"},
        {"callee-hangup", "AGENT_ENDED_CALL"},
        {"normal", "AGENT_ENDED_CALL"},
        {"media-timeout", "PHONE_CALL_PROVIDER_CONNECTION_ERROR"}
    };
    auto it = kMap.find(terminationReason);
    return it != kMap.end() ? it->second : std::string();
}

std::string toE164(const std::string& number) {
    if (number.empty()) return {};

    std::string digits;
    digits.reserve(number.size());
    for (char c : number) {
        if (std::isdigit(static_cast<unsigned char>(c)) || c == '+') digits.push_back(c);
    }

    static const std::regex reE164(R"(^\+\d{7,15}$)");
    static const std::regex reUs(R"(^1\d{10}$)");
    static const std::regex reBare(R"(^\d{7,15}$)");

    if (std::regex_match(digits, reE164)) return digits;
    if (std::regex_match(digits, reUs)) return "+" + digits;
    if (std::regex_match(digits, reBare)) return "+" + digits;
    return {};
}

std::vector<RoarkTranscriptEntry> mapTranscript(yyjson_val* sessionSummaryRoot, int64_t recordingStartedAtMs) {
    std::vector<RoarkTranscriptEntry> entries;
    if (!sessionSummaryRoot) return entries;

    // Iterate every entry of the session's agent[] array regardless of which verb
    // produced it (this includes Dialogflow CES turns -- same array and fields).
    yyjson_val* agentArr = yyjson_obj_get(sessionSummaryRoot, "agent");
    if (!agentArr || !yyjson_is_arr(agentArr)) return entries;

    yyjson_val* agentItem;
    yyjson_arr_iter agentIter = yyjson_arr_iter_with(agentArr);
    while ((agentItem = yyjson_arr_iter_next(&agentIter))) {
        yyjson_val* turns = yyjson_obj_get(agentItem, "turns");
        if (!turns || !yyjson_is_arr(turns)) continue;

        yyjson_val* turn;
        yyjson_arr_iter turnIter = yyjson_arr_iter_with(turns);
        while ((turn = yyjson_arr_iter_next(&turnIter))) {
            yyjson_val* turnNum = yyjson_obj_get(turn, "turn");
            if (!turnNum || !yyjson_is_num(turnNum)) continue;

            int64_t startMs = 0;
            yyjson_val* startVal = yyjson_obj_get(turn, "start_ms");
            if (startVal && yyjson_is_num(startVal)) startMs = yyjson_get_sint(startVal);
            int64_t start = std::max<int64_t>(0, startMs - recordingStartedAtMs);

            // Orientation: `transcript` is the human caller (role CUSTOMER), `response`
            // is the voice agent (role AGENT) -- see the header comment above
            // mapTranscript for why this looks backwards from the field names.
            yyjson_val* transcriptVal = yyjson_obj_get(turn, "transcript");
            if (transcriptVal && yyjson_is_str(transcriptVal) && yyjson_get_len(transcriptVal) > 0) {
                RoarkTranscriptEntry entry;
                entry.role = "CUSTOMER";
                entry.text = yyjson_get_str(transcriptVal);
                entry.startOffsetMs = start;
                entry.endOffsetMs = start; // fixed up below
                entries.push_back(std::move(entry));
            }

            yyjson_val* responseVal = yyjson_obj_get(turn, "response");
            if (responseVal && yyjson_is_str(responseVal) && yyjson_get_len(responseVal) > 0) {
                RoarkTranscriptEntry entry;
                entry.role = "AGENT";
                entry.text = yyjson_get_str(responseVal);
                entry.startOffsetMs = start;
                entry.endOffsetMs = start; // fixed up below
                entries.push_back(std::move(entry));
            }
        }
    }

    // Monotonic approximate end boundaries (mirrors the deleted JS bridge): each entry's
    // end is the next entry's start (or +1s for the last), and a later start is never
    // allowed to precede an earlier one.
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i + 1 < entries.size()) {
            if (entries[i + 1].startOffsetMs < entries[i].startOffsetMs) {
                entries[i + 1].startOffsetMs = entries[i].startOffsetMs;
            }
            entries[i].endOffsetMs = std::max(entries[i + 1].startOffsetMs, entries[i].startOffsetMs);
        } else {
            entries[i].endOffsetMs = entries[i].startOffsetMs + 1000;
        }
    }

    return entries;
}

Aws::Client::ClientConfiguration buildPresignClientConfig(const std::string& region,
                                                           const std::string& customEndpoint,
                                                           bool& useVirtualAddressing) {
    // Default to virtual-hosted addressing (matches AWS S3 behaviour); only flipped to
    // path-style below for localhost or configured S3-compatible endpoints, exactly as
    // S3ClientManager::createConfig does for uploads. The caller passes this to the
    // S3Client constructor -- setting it on the config alone is not sufficient (same
    // aws-sdk-cpp quirk noted in s3-client-manager.cpp).
    useVirtualAddressing = true;

    Aws::Client::ClientConfiguration config;
    config.region = region;
    config.connectTimeoutMs = 3000;
    config.requestTimeoutMs = 10000;
    config.scheme = Aws::Http::Scheme::HTTPS;
    config.verifySSL = true;

    if (!customEndpoint.empty()) {
        std::string endpoint = customEndpoint;

        if (!endpoint.empty() && endpoint.back() == '/') {
            endpoint.pop_back();
        }
        if (endpoint.rfind("https://", 0) == 0) {
            endpoint = endpoint.substr(8);
        } else if (endpoint.rfind("http://", 0) == 0) {
            endpoint = endpoint.substr(7);
        }
        config.endpointOverride = endpoint;

        if (endpoint.find("localhost") != std::string::npos ||
            endpoint.find("127.0.0.1") != std::string::npos) {
            useVirtualAddressing = false;
        }

        if (useVirtualAddressing) {
            for (const auto& service : S3ClientManager::getPathStyleServices()) {
                if (endpoint.find(service) != std::string::npos) {
                    useVirtualAddressing = false;
                    break;
                }
            }
        }
    }

    return config;
}

std::string buildRoarkCall(const RoarkCallInputs& in) {
    using Aws::Utils::Json::JsonValue;

    JsonValue root;
    root.WithString("recordingUrl", in.recordingUrl);
    if (!in.startedAt.empty()) {
        root.WithString("startedAt", in.startedAt);
    }
    root.WithString("interfaceType", "PHONE");
    root.WithString("callDirection", in.callDirection);
    root.WithString("externalId", in.externalId);
    if (!in.endedStatus.empty()) {
        root.WithString("endedStatus", in.endedStatus);
    }
    if (!in.customerE164.empty()) {
        root.WithObject("customer", JsonValue().WithString("phoneNumberE164", in.customerE164));
    }
    root.WithObject("agent", JsonValue()
        .WithString("customId", in.applicationSid.empty() ? "jambonz-app" : in.applicationSid)
        .WithString("name", "jambonz voice agent"));
    root.WithObject("properties", JsonValue()
        .WithString("jambonz_call_sid", in.callSid)
        .WithString("jambonz_account_sid", in.accountSid));

    if (in.hasTranscript) {
        Aws::Utils::Array<JsonValue> transcriptArr(in.transcript.size());
        for (size_t i = 0; i < in.transcript.size(); ++i) {
            JsonValue entry;
            entry.WithString("role", in.transcript[i].role);
            entry.WithString("text", in.transcript[i].text);
            entry.WithInt64("startOffsetMs", in.transcript[i].startOffsetMs);
            entry.WithInt64("endOffsetMs", in.transcript[i].endOffsetMs);
            transcriptArr[i] = std::move(entry);
        }
        root.WithArray("transcript", transcriptArr);
    }

    return root.View().WriteCompact();
}

std::unique_ptr<EvalNotifier> EvalNotifier::create(const std::string& vendor) {
    if (vendor == "roark") {
        return std::make_unique<RoarkNotifier>();
    }
    if (vendor == "coval") {
        return std::make_unique<CovalNotifier>();
    }
    return nullptr;
}
