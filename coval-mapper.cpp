#include "coval-mapper.h"

#include <aws/core/utils/Array.h>

#include <cmath>
#include <cstdio>

namespace {

// Coval takes seconds; our offsets are milliseconds. Emit with millisecond precision.
double msToSeconds(int64_t ms) {
    return std::round(static_cast<double>(ms)) / 1000.0;
}

std::string covalRole(const std::string& roarkRole) {
    return roarkRole == "AGENT" ? "assistant" : "user";
}

std::string serialize(const CovalCallInputs& in, size_t dropOldest, bool truncated) {
    using Aws::Utils::Json::JsonValue;

    JsonValue root;
    root.WithString("audio_url", in.audioUrl);
    root.WithString("external_conversation_id", in.externalConversationId);
    if (!in.occurredAt.empty()) {
        root.WithString("occurred_at", in.occurredAt);
    }

    JsonValue metadata(in.metadata);
    if (truncated) {
        metadata.WithBool("transcript_truncated", true);
        metadata.WithInt64("transcript_dropped_messages", static_cast<long long>(dropOldest));
    }
    root.WithObject("metadata", metadata);

    if (in.transcript.size() > dropOldest) {
        const size_t count = in.transcript.size() - dropOldest;
        Aws::Utils::Array<JsonValue> messages(count);
        for (size_t i = 0; i < count; ++i) {
            const auto& e = in.transcript[dropOldest + i];
            JsonValue msg;
            msg.WithString("role", covalRole(e.role));
            msg.WithString("content", e.text);
            msg.WithDouble("start_time", msToSeconds(e.startOffsetMs));
            msg.WithDouble("end_time", msToSeconds(e.endOffsetMs));
            messages[i] = std::move(msg);
        }
        root.WithArray("transcript", messages);
    }

    return root.View().WriteCompact();
}

} // namespace

std::string buildCovalConversation(const CovalCallInputs& in, size_t maxBodyBytes) {
    std::string body = serialize(in, 0, false);
    if (body.size() <= maxBodyBytes || in.transcript.empty()) {
        return body;
    }

    // Over the cap: keep the newest messages, halving how many are kept until it fits
    // (the tail of a call is what an evaluation needs most). Few iterations; the
    // keep-nothing fallback is still a valid audio-only submission.
    for (size_t keep = in.transcript.size() / 2; keep > 0; keep /= 2) {
        body = serialize(in, in.transcript.size() - keep, true);
        if (body.size() <= maxBodyBytes) return body;
    }
    return serialize(in, in.transcript.size(), true);
}
