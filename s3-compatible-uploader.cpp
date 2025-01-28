#include "s3-compatible-uploader.h"
#include "wav-header.h"
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <cstdio>

S3CompatibleUploader::S3CompatibleUploader(std::shared_ptr<spdlog::logger> log, std::string& uploadFolder, RecordFileType ftype,
                                           const Aws::Auth::AWSCredentials& credentials, const Aws::String& region,
                                           const Aws::String& bucketName, const Aws::String& customEndpoint)
    : bucketName_(bucketName), region_(region), recordFileType_(ftype), firstWrite_(true) {
    Aws::S3Crt::ClientConfiguration config;
    config.region = region;

    setLogger(log);

    if (!customEndpoint.empty()) {
        config.endpointOverride = customEndpoint;
        config.useVirtualAddressing = false;
        log_->info("Creating S3 compatible uploader for bucket:{}, endpoint {} ", bucketName, customEndpoint);
    } else {
        log_->info("Creating S3 uploader for bucket: {} in region {}", bucketName, region);
    }

    s3CrtClient_ = std::make_shared<Aws::S3Crt::S3CrtClient>(
        Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("MemoryStreamAllocator", credentials),
        config
    );

    // Create a temporary file for buffering data
    createTempFile(uploadFolder);
}

S3CompatibleUploader::~S3CompatibleUploader() {
    cleanupTempFile(); // Use the no-argument cleanupTempFile
}

bool S3CompatibleUploader::upload(std::vector<char>& data, bool isFinalChunk) {
    if (!tempFile_.is_open()) {
      log_->error("Temporary file is not open. Upload failed.");
      upload_failed_ = true;
      return false;
    }

    if (firstWrite_) {
      firstWrite_ = false;

      // Write the WAV header if this is the first write
      if (recordFileType_ == RecordFileType::WAV) {
        WavHeaderPrepender headerPrepender(8000, 2, 16);
        headerPrepender.prependHeader(data);
      }
    }

    // Write the data chunk to the temporary file
    tempFile_.write(data.data(), data.size());
    if (!tempFile_) {
        log_->error("Failed to write data to temporary file.");
        upload_failed_ = true;
        return false;
    }
    tempFile_.flush();

    if (isFinalChunk) {
        tempFile_.close(); // Ensure all data is flushed to disk
        finalizeUpload();
    }

    return true;
}

void S3CompatibleUploader::finalizeUpload() {
    objectKey_ = createObjectPath(metadata_.call_sid, recordFileType_ == RecordFileType::WAV ? "wav" : "mp3");

    // Create a PutObjectRequest
    Aws::S3Crt::Model::PutObjectRequest putObjectRequest;
    putObjectRequest.SetBucket(bucketName_);
    putObjectRequest.SetKey(objectKey_);
    putObjectRequest.SetContentType("binary/octet-stream");

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

    putObjectRequest.SetMetadata(awsMetadata);

    // Close the file stream if it is still open
    if (tempFile_.is_open()) {
     tempFile_.close();
    }

    // Attach the file stream to the request body
    auto inputStream = Aws::MakeShared<Aws::FStream>("PutObjectBody", tempFilePath_.c_str(), std::ios::in | std::ios::binary);
    if (!inputStream->good()) {
      // Retrieve specific error details
      std::string errorMessage;

      if ((inputStream->rdstate() & std::ios::failbit) != 0) {
          errorMessage += "Logical error on input/output operation. ";
      }
      if ((inputStream->rdstate() & std::ios::badbit) != 0) {
          errorMessage += "Read/write error on file stream. ";
      }
      if ((inputStream->rdstate() & std::ios::eofbit) != 0) {
          errorMessage += "End-of-File reached prematurely. ";
      }

      // Use errno to get a system-level error message
      errorMessage += std::strerror(errno);

      log_->error("Failed to open temporary file for upload: {}. Error: {}", tempFilePath_, errorMessage);
      upload_failed_ = true;
      return;
    }
  
    putObjectRequest.SetBody(inputStream);

    // Upload the file in one go
    auto putObjectOutcome = s3CrtClient_->PutObject(putObjectRequest);
    if (!putObjectOutcome.IsSuccess()) {
        log_->error("Failed to upload file: {}", putObjectOutcome.GetError().GetMessage());
        upload_failed_ = true;
    } else {
        log_->info("File uploaded successfully: {}", objectKey_);
    }
}