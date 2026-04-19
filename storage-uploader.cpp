#include "storage-uploader.h"
#include "connection-manager.h"
#include <aws/core/utils/json/JsonSerializer.h>
#include <iostream>
#include <stdexcept>
#include <cstdio>
#include <filesystem>

namespace fs = std::filesystem;

std::atomic<int> StorageUploader::uniqueCounter{0};

void StorageUploader::createTempFile(const std::string& uploadFolder) {
    try {
        // Determine the directory for the temp file
        fs::path tempDir = uploadFolder.empty() ? fs::temp_directory_path() : fs::path(uploadFolder);

        // Generate a unique file name using the static atomic counter
        int counterValue = uniqueCounter.fetch_add(1, std::memory_order_relaxed);
        std::string uniqueName = "upload-" + std::to_string(counterValue) + ".tmp";
        fs::path tempFilePath = tempDir / uniqueName;

        // Open the temporary file for writing
        tempFile_.open(tempFilePath, std::ios::binary | std::ios::out);
        if (!tempFile_) {
            throw std::runtime_error("Failed to create temporary file: " + tempFilePath.string());
        }

        tempFilePath_ = tempFilePath.string();
        log_->info("Temporary file created:{}", tempFilePath_);
    } catch (const fs::filesystem_error& e) {
        throw std::runtime_error("Filesystem error while creating temporary file: " + std::string(e.what()));
    }
}

void StorageUploader::cleanupTempFile() {
    if (tempFile_.is_open()) {
        tempFile_.close();
    }
    if (!tempFilePath_.empty()) {
      if (std::remove(tempFilePath_.c_str()) == 0) {
        log_->info("Temporary file successfully deleted: {}", tempFilePath_);
      } else {
        log_->warn("Failed to delete temporary file: {} (error: {})", tempFilePath_, strerror(errno));
      }
      tempFilePath_.clear();
    }

    // now the session can be destroyed
    if (auto session = sessionRef_.lock()) {
      log_->debug("StorageUploader::cleanupTempFile - destroying session");
      ConnectionManager::getInstance().destroySession(session.get());
    }
    else {
      log_->warn("StorageUploader::cleanupTempFile - sessionRef is no longer valid");
    }
}

std::string StorageUploader::currentDatePrefix() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);  // thread-safe

    std::ostringstream s;
    s << tm.tm_year + 1900 << "/"
      << std::setfill('0') << std::setw(2) << tm.tm_mon + 1 << "/"
      << std::setfill('0') << std::setw(2) << tm.tm_mday << "/";
    return s.str();
}

std::string StorageUploader::createObjectPath(const std::string& callSid, const std::string& recordFormat) {
    return currentDatePrefix() + callSid + "." + recordFormat;
}

std::string StorageUploader::createSessionJsonPath(const std::string& callSid) {
    return currentDatePrefix() + callSid + "/session.json";
}

std::string StorageUploader::stampAndSerializeSessionSummary(const std::string& recordingKey) {
    Aws::Utils::Json::JsonValue json(sessionSummaryJson_);
    if (!json.WasParseSuccessful()) {
        log_->error("Failed to parse session summary JSON");
        return {};
    }
    json.WithString("recording_key", recordingKey);

    // Calculate and stamp recording_started_at_ms if we have audio start time
    if (audioStartTimeSet_) {
        auto callStartStr = json.View().GetString("call_start");
        if (!callStartStr.empty()) {
            // Parse ISO8601 timestamp: "2026-04-16T18:24:43.955Z"
            std::tm tm = {};
            int millis = 0;
            std::istringstream ss(std::string(callStartStr.c_str()));
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
            if (!ss.fail()) {
                // Parse optional milliseconds
                char c;
                if (ss >> c && c == '.') {
                    ss >> millis;
                    // Handle variable precision (could be .9, .95, .955, etc)
                    std::string remaining;
                    std::getline(ss, remaining, 'Z');
                    // millis now contains the fractional part, normalize to ms
                    int digits = std::to_string(millis).length();
                    while (digits < 3) { millis *= 10; digits++; }
                    while (digits > 3) { millis /= 10; digits--; }
                }

                // Convert to milliseconds since epoch
                auto callStartEpoch = timegm(&tm);
                int64_t callStartMs = static_cast<int64_t>(callStartEpoch) * 1000 + millis;

                // Convert audioStartTime_ to milliseconds since epoch
                auto audioStartMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    audioStartTime_.time_since_epoch()).count();

                // Calculate offset
                int64_t recordingOffset = audioStartMs - callStartMs;
                json.WithInt64("recording_started_at_ms", recordingOffset);
                log_->info("Stamped recording_started_at_ms: {} (audio started {}ms after call_start)",
                    recordingOffset, recordingOffset);
            } else {
                log_->warn("Failed to parse call_start timestamp: {}", callStartStr.c_str());
            }
        }
    }

    return json.View().WriteCompact();
}
