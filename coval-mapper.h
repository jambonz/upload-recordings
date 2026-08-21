#ifndef COVAL_MAPPER_H
#define COVAL_MAPPER_H

#include <string>
#include <vector>

#include <aws/core/utils/json/JsonSerializer.h>

#include "eval-notifier.h" // RoarkTranscriptEntry (the shared flattened turn shape)

// Inputs to Coval's POST /v1/conversations:submit body, flattened so the builder is a pure
// function the standalone test binary can exercise (no MySQL, no network).
struct CovalCallInputs {
    std::string audioUrl;                 // presigned WAV/MP3 GET url; required in v1
    std::string occurredAt;               // ISO-8601; omitted when empty
    std::string externalConversationId;   // call_sid
    Aws::Utils::Json::JsonValue metadata; // free-form key/values (see EVAL-INTEGRATION-DESIGN.md)
    std::vector<RoarkTranscriptEntry> transcript; // empty -> audio-only submission
};

// Builds the Coval conversations:submit JSON body (compact).
//
// Transcript mapping: role CUSTOMER -> "user", AGENT -> "assistant"; offsets converted from
// recording-relative milliseconds to seconds (3 decimals) as Coval requires. Per-message
// start_time/end_time are always included -- Coval mandates them whenever audio accompanies
// the transcript, and v1 always sends audio.
//
// Coval caps the request body at 256 KB (HTTP 413). When the serialized body exceeds
// maxBodyBytes, the OLDEST transcript messages are dropped first (the tail of a call is
// usually what an evaluation needs most) and metadata gains transcript_truncated=true and
// transcript_dropped_messages=<n>.
std::string buildCovalConversation(const CovalCallInputs& in, size_t maxBodyBytes);

#endif // COVAL_MAPPER_H
