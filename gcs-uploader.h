#ifndef GCS_UPLOADER_H
#define GCS_UPLOADER_H

#include "storage-uploader.h"
#include "google/cloud/storage/client.h"
#include <string>
#include <vector>

namespace gcs = google::cloud::storage;

class GCSUploader : public StorageUploader {
public:
    GCSUploader(const std::string& bucketName, const std::string& objectKey, const std::string& jsonKey);
    ~GCSUploader();

    bool upload(std::vector<char>& data, bool isFinalChunk = false) override;

private:
    std::string bucketName_;
    std::string objectKey_;
    std::string jsonKey_;

    gcs::Client client_;
    gcs::ObjectWriteStream writer_;
    size_t partNumber_;
};

#endif // GCS_UPLOADER_H