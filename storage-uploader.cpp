#include "storage-uploader.h"
#include "connection-manager.h"
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
    cJSON *json = cJSON_AS4CPP_Parse(sessionSummaryJson_.c_str());
    if (!json) {
        log_->error("Failed to parse session summary JSON");
        return {};
    }
    cJSON_AS4CPP_AddStringToObject(json, "recording_key", recordingKey.c_str());
    char *printed = cJSON_AS4CPP_PrintUnformatted(json);
    cJSON_AS4CPP_Delete(json);
    if (!printed) {
        log_->error("Failed to serialize stamped session summary");
        return {};
    }
    std::string body(printed);
    cJSON_AS4CPP_free(printed);
    return body;
}
