// Standalone unit tests for the pure eval-notify helpers: no MySQL, no network, no live
// cloud calls. Run via `make check`. Plain asserts -- a failure aborts with the line number.

#include "eval-notifier.h"
#include "gcs-presigner.h"
#include "coval-mapper.h"
#include "influx-alert.h"
#include "yyjson.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

namespace {

// A representative caller-leg/production session summary: two agent[] entries (an agent
// verb and a dialogflow-style one -- the mapper must not care which verb produced them).
const char* kSessionJson = R"({
  "schema_version": "1.2",
  "call_sid": "call-1",
  "sip_call_id": "abc123@host",
  "call_start": "2026-08-19T14:00:00.000Z",
  "duration_sec": 42,
  "termination_reason": "caller-hangup",
  "recording_started_at_ms": 500,
  "agent": [
    {
      "task_id": "t1",
      "verb": "agent",
      "config": {"stt_vendor": "deepgram", "stt_model": "nova-3", "tts_vendor": "elevenlabs",
                  "tts_voice": "Rachel", "llm_vendor": "openai", "llm_model": "gpt-4o",
                  "turn_detection": "stt"},
      "latency_avg": {"stt_ms": 480, "llm_ms": 900, "tts_ms": 200},
      "barge_in": {"attempts": 2, "confirmed": 1, "reverted": 1},
      "errors": [],
      "result": "normal",
      "turns": [
        {"turn": 1, "start_ms": 1500, "transcript": "", "response": "Hello, how can I help?"},
        {"turn": 2, "start_ms": 6000, "transcript": "What are your hours?",
         "response": "We are open nine to five."}
      ]
    },
    {
      "task_id": "t2",
      "verb": "dialogflow",
      "turns": [
        {"turn": 1, "start_ms": 20000, "transcript": "Thanks, goodbye.", "response": "Goodbye!"}
      ]
    }
  ],
  "verb_events": [
    {"type": "agent", "task_id": "t1", "started_at_ms": 1},
    {"type": "sip:refer", "started_at_ms": 30000}
  ]
})";

yyjson_doc* parseSession() {
    return yyjson_read(kSessionJson, std::strlen(kSessionJson), 0);
}

std::string makeTestRsaKeyPem(EVP_PKEY** outKey) {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return {};
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);
    BIO_free(bio);
    *outKey = pkey;
    return pem;
}

bool verifyRsaSha256Hex(EVP_PKEY* pkey, const std::string& data, const std::string& sigHex) {
    std::string sig;
    sig.reserve(sigHex.size() / 2);
    for (size_t i = 0; i + 1 < sigHex.size(); i += 2) {
        sig.push_back(static_cast<char>(std::stoi(sigHex.substr(i, 2), nullptr, 16)));
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
              EVP_DigestVerify(ctx,
                  reinterpret_cast<const unsigned char*>(sig.data()), sig.size(),
                  reinterpret_cast<const unsigned char*>(data.data()), data.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace

int main() {
    // ---- shouldSampleCall: deterministic and boundary-correct
    CHECK(shouldSampleCall("any-sid", 100));
    CHECK(!shouldSampleCall("any-sid", 0));
    CHECK(shouldSampleCall("", 50)); // fails open
    const bool first = shouldSampleCall("d880590d-4906-41c9-a56d-5c69927e24f2", 50);
    for (int i = 0; i < 5; ++i) {
        CHECK(shouldSampleCall("d880590d-4906-41c9-a56d-5c69927e24f2", 50) == first);
    }

    // ---- toE164
    CHECK(toE164("+14155551234") == "+14155551234");
    CHECK(toE164("14155551234") == "+14155551234");
    CHECK(toE164("(508) 206-9511") == "+5082069511");
    CHECK(toE164("anonymous").empty());

    // ---- mapEndedStatus
    CHECK(mapEndedStatus("caller-hangup") == "CUSTOMER_ENDED_CALL");
    CHECK(mapEndedStatus("normal") == "AGENT_ENDED_CALL");
    CHECK(mapEndedStatus("something-else").empty());

    // ---- mapTranscript: verb-agnostic over agent[], offsets shifted, ends monotonic
    {
        yyjson_doc* doc = parseSession();
        CHECK(doc != nullptr);
        auto entries = mapTranscript(yyjson_doc_get_root(doc), 500);
        // turn1 has no caller text -> AGENT only; turn2 both; dialogflow turn both = 5
        CHECK(entries.size() == 5);
        CHECK(entries[0].role == "AGENT");
        CHECK(entries[0].startOffsetMs == 1000); // 1500 - 500
        CHECK(entries[1].role == "CUSTOMER");
        CHECK(entries[1].text == "What are your hours?");
        CHECK(entries[3].text == "Thanks, goodbye."); // the dialogflow entry made it in
        for (size_t i = 0; i < entries.size(); ++i) {
            CHECK(entries[i].endOffsetMs >= entries[i].startOffsetMs);
            if (i > 0) CHECK(entries[i].startOffsetMs >= entries[i - 1].startOffsetMs);
        }
        yyjson_doc_free(doc);
    }

    // ---- buildCovalConversation: roles, seconds, required fields
    {
        yyjson_doc* doc = parseSession();
        CovalCallInputs in;
        in.audioUrl = "https://signed.example/rec.mp3";
        in.externalConversationId = "call-1";
        in.occurredAt = "2026-08-19T14:00:00.000Z";
        in.metadata.WithString("call_sid", "call-1");
        in.transcript = mapTranscript(yyjson_doc_get_root(doc), 500);
        yyjson_doc_free(doc);

        std::string body = buildCovalConversation(in, 256 * 1024);
        yyjson_doc* out = yyjson_read(body.c_str(), body.size(), 0);
        CHECK(out != nullptr);
        yyjson_val* root = yyjson_doc_get_root(out);
        CHECK(std::string(yyjson_get_str(yyjson_obj_get(root, "audio_url"))) ==
              "https://signed.example/rec.mp3");
        CHECK(std::string(yyjson_get_str(yyjson_obj_get(root, "external_conversation_id"))) == "call-1");
        yyjson_val* transcript = yyjson_obj_get(root, "transcript");
        CHECK(transcript && yyjson_is_arr(transcript) && yyjson_arr_size(transcript) == 5);
        yyjson_val* first0 = yyjson_arr_get(transcript, 0);
        CHECK(std::string(yyjson_get_str(yyjson_obj_get(first0, "role"))) == "assistant");
        CHECK(yyjson_get_num(yyjson_obj_get(first0, "start_time")) == 1.0); // 1000ms -> 1.0s
        yyjson_val* second = yyjson_arr_get(transcript, 1);
        CHECK(std::string(yyjson_get_str(yyjson_obj_get(second, "role"))) == "user");
        yyjson_doc_free(out);
    }

    // ---- buildCovalConversation: truncation drops oldest, marks metadata, keeps audio
    {
        CovalCallInputs in;
        in.audioUrl = "https://signed.example/rec.mp3";
        in.externalConversationId = "call-1";
        for (int i = 0; i < 200; ++i) {
            RoarkTranscriptEntry e;
            e.role = (i % 2) ? "AGENT" : "CUSTOMER";
            e.text = std::string(1024, 'x') + std::to_string(i);
            e.startOffsetMs = i * 1000;
            e.endOffsetMs = i * 1000 + 900;
            in.transcript.push_back(e);
        }
        std::string body = buildCovalConversation(in, 64 * 1024);
        CHECK(body.size() <= 64 * 1024);
        yyjson_doc* out = yyjson_read(body.c_str(), body.size(), 0);
        yyjson_val* root = yyjson_doc_get_root(out);
        yyjson_val* meta = yyjson_obj_get(root, "metadata");
        CHECK(yyjson_get_bool(yyjson_obj_get(meta, "transcript_truncated")));
        CHECK(yyjson_get_sint(yyjson_obj_get(meta, "transcript_dropped_messages")) > 0);
        yyjson_val* transcript = yyjson_obj_get(root, "transcript");
        CHECK(transcript && yyjson_arr_size(transcript) > 0);
        // oldest dropped first: the FIRST remaining message is a late one
        yyjson_val* firstMsg = yyjson_arr_get(transcript, 0);
        CHECK(yyjson_get_num(yyjson_obj_get(firstMsg, "start_time")) > 0.0);
        CHECK(std::string(yyjson_get_str(yyjson_obj_get(root, "audio_url"))).size() > 0);
        yyjson_doc_free(out);
    }

    // ---- GCS V4 signed URL: canonical strings are exact; signature verifies
    {
        const std::string bucket = "my-bucket";
        const std::string key = "2026/08/19/call-1.mp3";
        const std::string email = "svc@project.iam.gserviceaccount.com";
        const auto signingTime = std::chrono::system_clock::from_time_t(1755610200); // fixed

        const std::string ts = "20250819T130000Z"; // whatever 1755610200 formats to, computed below
        (void)ts;

        const std::string scopeDate = [] {
            std::time_t t = 1755610200;
            std::tm tm{};
            gmtime_r(&t, &tm);
            char buf[16];
            std::strftime(buf, sizeof(buf), "%Y%m%d", &tm);
            return std::string(buf);
        }();
        const std::string goog4Ts = [] {
            std::time_t t = 1755610200;
            std::tm tm{};
            gmtime_r(&t, &tm);
            char buf[24];
            std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%SZ", &tm);
            return std::string(buf);
        }();
        const std::string scope = scopeDate + "/auto/storage/goog4_request";

        const std::string cq = gcsCanonicalQuery(email, scope, goog4Ts, 3600);
        CHECK(cq.find("X-Goog-Algorithm=GOOG4-RSA-SHA256") == 0);
        CHECK(cq.find("X-Goog-Credential=svc%40project.iam.gserviceaccount.com%2F" +
                      scopeDate) != std::string::npos);
        CHECK(cq.find("&X-Goog-Expires=3600&X-Goog-SignedHeaders=host") != std::string::npos);

        const std::string cr = gcsCanonicalRequest(bucket, key, cq);
        CHECK(cr.find("GET\n/my-bucket/2026/08/19/call-1.mp3\n") == 0);
        CHECK(cr.find("host:storage.googleapis.com\n\nhost\nUNSIGNED-PAYLOAD") != std::string::npos);

        EVP_PKEY* pkey = nullptr;
        const std::string pem = makeTestRsaKeyPem(&pkey);
        CHECK(!pem.empty() && pkey != nullptr);

        const std::string url = generateGcsV4SignedUrl(bucket, key, email, pem, 3600, signingTime);
        CHECK(url.find("https://storage.googleapis.com/my-bucket/2026/08/19/call-1.mp3?") == 0);

        const std::string sigMarker = "&X-Goog-Signature=";
        const size_t sigPos = url.find(sigMarker);
        CHECK(sigPos != std::string::npos);
        const std::string sigHex = url.substr(sigPos + sigMarker.size());
        CHECK(sigHex.size() == 512); // 2048-bit RSA -> 256 bytes -> 512 hex chars

        const std::string sts = std::string("GOOG4-RSA-SHA256\n") + goog4Ts + "\n" + scope + "\n" +
            gcsSha256Hex(cr);
        CHECK(verifyRsaSha256Hex(pkey, sts, sigHex));
        EVP_PKEY_free(pkey);
    }

    // ---- influx alert line protocol
    {
        CHECK(influxEscapeTag("has space,comma=eq") == "has\\ space\\,comma\\=eq");
        CHECK(influxEscapeFieldString("say \"hi\"\nback\\slash") == "say \\\"hi\\\" back\\\\slash");
        const std::string line = buildAlertLine("acc-1", "eval-post-failure", "coval",
            "Failed posting call data to coval for evaluation",
            "call_sid=c1 http=401 error=unauthorized", 1755610200000000000LL);
        CHECK(line ==
            "alerts,account_sid=acc-1,alert_type=eval-post-failure,vendor=coval "
            "message=\"Failed posting call data to coval for evaluation\","
            "detail=\"call_sid=c1 http=401 error=unauthorized\" 1755610200000000000");
    }

    std::printf("eval-test: all checks passed\n");
    return 0;
}
