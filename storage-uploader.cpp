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
      log_->info("StorageUploader::cleanupTempFile - destroying session");
      ConnectionManager::getInstance().destroySession(session.get());
    }
    else {
      log_->warn("StorageUploader::cleanupTempFile - sessionRef is no longer valid");
    }
}

std::string StorageUploader::createObjectPath(const std::string& callSid, const std::string& recordFormat) {
    // Get the current date and time
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);

    // Create a string stream to format the path
    std::ostringstream pathStream;

    // Append year, month, and day, formatted as YYYY/MM/DD
    pathStream << tm.tm_year + 1900 << "/"
               << std::setfill('0') << std::setw(2) << tm.tm_mon + 1 << "/"
               << std::setfill('0') << std::setw(2) << tm.tm_mday << "/";

    // Append the callSid and recordFormat to the path
    pathStream << callSid << "." << recordFormat;

    return pathStream.str();
}
