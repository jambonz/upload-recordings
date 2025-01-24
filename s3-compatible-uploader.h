#ifndef S3_COMPATIBLE_UPLOADER_H
#define S3_COMPATIBLE_UPLOADER_H

#include "storage-uploader.h"
#include <aws/core/Aws.h>
#include <aws/s3-crt/S3CrtClient.h>
#include <aws/s3-crt/model/PutObjectRequest.h>
#include <fstream>
#include <string>

class S3CompatibleUploader : public StorageUploader {
public:
    S3CompatibleUploader(std::string& uploadFolder, RecordFileType ftype, const Aws::Auth::AWSCredentials& credentials, const Aws::String& region, 
                         const Aws::String& bucketName, const Aws::String& customEndpoint);
    ~S3CompatibleUploader();

    bool upload(std::vector<char>& data, bool isFinalChunk = false) override;

private:
    bool firstWrite_;

    std::string uploadFolder_;
    RecordFileType recordFileType_;
    Aws::String bucketName_;
    Aws::String region_;
    Aws::String customEndpoint_;
    std::shared_ptr<Aws::S3Crt::S3CrtClient> s3CrtClient_;
    std::ofstream tempFile_;
    std::string tempFilePath_;
    Aws::String objectKey_;

    void finalizeUpload();
    void cleanupTempFile();
};

#endif // S3_COMPATIBLE_UPLOADER_H