#ifndef S3_UPLOADER_H
#define S3_UPLOADER_H

#include "storage-uploader.h"
#include <aws/core/Aws.h>
#include <aws/s3-crt/model/CreateMultipartUploadRequest.h>
#include <aws/s3-crt/model/UploadPartRequest.h>
#include <aws/s3-crt/model/CompleteMultipartUploadRequest.h>
#include <aws/s3-crt/model/AbortMultipartUploadRequest.h>
#include <aws/s3-crt/S3CrtClient.h>
#include <string>

class S3Uploader : public StorageUploader {
public:
    S3Uploader(RecordFileType ftype, const Aws::Auth::AWSCredentials& credentials, const Aws::String& region, 
       const Aws::String& bucketname);
    ~S3Uploader();

    bool upload(std::vector<char>& data, bool isFinalChunk = false) override;

private:
    RecordFileType recordFileType_;
    Aws::String bucketName_;
    Aws::String objectKey_;
    Aws::String region_;
    
    std::shared_ptr<Aws::S3Crt::S3CrtClient> s3CrtClient_;
    Aws::S3Crt::Model::CreateMultipartUploadRequest createRequest_;
    Aws::String uploadId_;
    std::vector<Aws::S3Crt::Model::CompletedPart> completedParts_;
    size_t partNumber_;
};

#endif // S3_UPLOADER_H
