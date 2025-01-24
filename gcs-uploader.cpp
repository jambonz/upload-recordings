#include "gcs-uploader.h"
#include <iostream>
#include <stdexcept>
#include "google/cloud/storage/client_options.h"
#include "google/cloud/storage/oauth2/credentials.h"

GCSUploader::GCSUploader(const std::string& bucketName, const std::string& objectKey, const std::string& jsonKey)
    : bucketName_(bucketName), objectKey_(objectKey), jsonKey_(jsonKey), partNumber_(1) {
    // Set up custom credentials from the JSON key
    auto credentials = std::dynamic_pointer_cast<google::cloud::storage::oauth2::Credentials>(
        google::cloud::MakeServiceAccountCredentials(jsonKey));
    if (!credentials) {
        throw std::runtime_error("Failed to create credentials from JSON key");
    }

    // Create a client with the custom credentials
    auto client_options = gcs::ClientOptions(credentials);
    client_ = gcs::Client(client_options);

    // Initialize the GCS write stream
    writer_ = client_.WriteObject(bucketName_, objectKey_);
    if (!writer_.IsOpen()) {
        throw std::runtime_error("Failed to open GCS write stream");
    }
}

GCSUploader::~GCSUploader() {
    try {
        if (writer_.IsOpen()) {
            writer_.Close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error closing GCS write stream: " << e.what() << std::endl;
    }
}

bool GCSUploader::upload(std::vector<char>& data, bool isFinalChunk) {
    try {
        if (!writer_.IsOpen()) {
            throw std::runtime_error("GCS write stream is not open.");
        }

        // Write data to GCS
        writer_.write(data.data(), data.size());

        // If this is the final chunk, close the stream
        if (isFinalChunk) {
            writer_.Close();
        }

        ++partNumber_;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error uploading to GCS: " << e.what() << std::endl;
        return false;
    }
}