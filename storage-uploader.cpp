#include "storage-uploader.h"
#include <iostream>
#include <stdexcept>
#include <cstdio>
#include <filesystem>

namespace fs = std::filesystem;

void StorageUploader::createTempFile(const std::string& uploadFolder) {
    try {
        // Determine the directory for the temp file
        fs::path tempDir = uploadFolder.empty() ? fs::temp_directory_path() : fs::path(uploadFolder);

        // Seed the random number generator for uniqueness
        std::srand(static_cast<unsigned int>(std::time(nullptr)));

        // Generate a unique file name
        std::string uniqueName = "upload-" + std::to_string(std::rand()) + ".tmp";
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
    // Close and delete the temporary file if it exists
    if (tempFile_.is_open()) {
        tempFile_.close();
    }
    if (!tempFilePath_.empty()) {
        std::remove(tempFilePath_.c_str());
        log_->info("Temporary file cleaned up: {}", tempFilePath_);
        tempFilePath_.clear();
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
