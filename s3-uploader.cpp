#include "s3-uploader.h"
#include "wav-header.h"

#include <iostream>

S3Uploader::S3Uploader(RecordFileType ftype, const Aws::Auth::AWSCredentials& credentials, const Aws::String& region, 
      const Aws::String& bucketName)
  : bucketName_(bucketName), region_(region), recordFileType_(ftype) {

  upload_in_progress_ = false;
  upload_failed_ = false;

  Aws::S3Crt::ClientConfiguration config;
  config.region = region;

  std::cout << "Creating S3 uploader for bucket: " << bucketName << ", region: " << region << std::endl;

  s3CrtClient_ = std::make_shared<Aws::S3Crt::S3CrtClient>(
      Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("MemoryStreamAllocator", credentials),
      config
  );
}
S3Uploader::~S3Uploader() {
  std::cout << "Destroying S3Uploader...\n";
  if (upload_in_progress_) {
    Aws::S3Crt::Model::AbortMultipartUploadRequest abortRequest;
    abortRequest.SetBucket(bucketName_);
    abortRequest.SetKey(objectKey_);
    abortRequest.SetUploadId(uploadId_);

    auto abortOutcome = s3CrtClient_->AbortMultipartUpload(abortRequest);
    if (abortOutcome.IsSuccess()) {
      std::cout << "Aborted multipart upload successfully.\n";
    } else {
      std::cerr << "Failed to abort multipart upload: " << abortOutcome.GetError().GetMessage() << "\n";
    }
  }
  s3CrtClient_.reset();
  std::cout << "S3Uploader destroyed.\n";
}

bool S3Uploader::upload(std::vector<char>& data, bool isFinalChunk) {
  const size_t chunkSize = 5 * 1024 * 1024;

  if (upload_failed_) return false;

  else if (!upload_in_progress_) {
    objectKey_ = createObjectPath(metadata_.call_sid, recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");
    createRequest_.SetBucket(bucketName_);
    createRequest_.SetKey(objectKey_);

    Aws::Map<Aws::String, Aws::String> awsMetadata;
    awsMetadata["Account-Sid"] = metadata_.account_sid.c_str();
    awsMetadata["Call-Sid"] = metadata_.call_sid.c_str();
    awsMetadata["Direction"] = metadata_.direction.c_str();
    awsMetadata["From"] = metadata_.from.c_str();
    awsMetadata["To"] = metadata_.to.c_str();
    awsMetadata["Application-Sid"] = metadata_.application_sid.c_str();
    awsMetadata["Originating-Sip-Id"] = metadata_.originating_sip_id.c_str();
    awsMetadata["Originating-Sip-Trunk-Name"] = metadata_.originating_sip_trunk_name.c_str();
    awsMetadata["Sample-Rate"] = std::to_string(metadata_.sample_rate).c_str();

    createRequest_.SetMetadata(awsMetadata);
    createRequest_.SetContentType("binary/octet-stream");

    auto createOutcome = s3CrtClient_->CreateMultipartUpload(createRequest_);
    if (!createOutcome.IsSuccess()) {
        std::cerr << "Failed to initiate multipart upload: " << createOutcome.GetError().GetMessage() << std::endl;
        upload_failed_ = true;
        return false;
    }

    uploadId_ = createOutcome.GetResult().GetUploadId();
    std::cout << "Multipart upload initiated with UploadId: " << uploadId_ << std::endl;

    partNumber_ = 0;
    upload_in_progress_ = true;

    if (recordFileType_ == RecordFileType::WAV) {
      WavHeaderPrepender headerPrepender(8000, 2, 16);
      headerPrepender.prependHeader(data);
    }
  }

  partNumber_++;
  auto partStream = Aws::MakeShared<Aws::StringStream>("UploadPart");
  partStream->write(data.data(), data.size());

  Aws::S3Crt::Model::UploadPartRequest uploadPartRequest;
  uploadPartRequest.SetBucket(bucketName_);
  uploadPartRequest.SetKey(objectKey_);
  uploadPartRequest.SetUploadId(uploadId_);
  uploadPartRequest.SetPartNumber(partNumber_);
  uploadPartRequest.SetBody(partStream);

  auto uploadPartOutcome = s3CrtClient_->UploadPart(uploadPartRequest);
  if (!uploadPartOutcome.IsSuccess()) {
      std::cerr << "Failed to upload part " << partNumber_ << ": " << uploadPartOutcome.GetError().GetMessage() << std::endl;

      Aws::S3Crt::Model::AbortMultipartUploadRequest abortRequest;
      abortRequest.SetBucket(bucketName_);
      abortRequest.SetKey(objectKey_);
      abortRequest.SetUploadId(uploadId_);
      s3CrtClient_->AbortMultipartUpload(abortRequest);
      upload_failed_ = true;
      return false;
  }

  Aws::S3Crt::Model::CompletedPart completedPart;
  completedPart.SetETag(uploadPartOutcome.GetResult().GetETag());
  completedPart.SetPartNumber(partNumber_);
  completedParts_.push_back(completedPart);

  if (isFinalChunk) {
    Aws::S3Crt::Model::CompleteMultipartUploadRequest completeRequest;
    completeRequest.SetBucket(bucketName_);
    completeRequest.SetKey(objectKey_);
    completeRequest.SetUploadId(uploadId_);

    Aws::S3Crt::Model::CompletedMultipartUpload completedMultipartUpload;
    completedMultipartUpload.SetParts(completedParts_);
    completeRequest.SetMultipartUpload(completedMultipartUpload);

    auto completeOutcome = s3CrtClient_->CompleteMultipartUpload(completeRequest);
    if (!completeOutcome.IsSuccess()) {
        std::cerr << "Failed to complete multipart upload: " << completeOutcome.GetError().GetMessage() << std::endl;
        upload_failed_ = true;
        return false;
    }
    upload_in_progress_ = false;

    std::cout << "Multipart upload completed successfully!" << std::endl;
  }
  return true;
}
