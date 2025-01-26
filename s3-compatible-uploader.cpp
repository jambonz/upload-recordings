#include "s3-compatible-uploader.h"
#include "wav-header.h"
#include <iostream>
#include <stdexcept>
#include <cstdio>

S3CompatibleUploader::S3CompatibleUploader(std::string& uploadFolder, RecordFileType ftype, const Aws::Auth::AWSCredentials& credentials, const Aws::String& region, 
                                           const Aws::String& bucketName, const Aws::String& customEndpoint)
    : bucketName_(bucketName), region_(region), recordFileType_(ftype), firstWrite_(true), uploadFolder_(uploadFolder) {
    Aws::S3Crt::ClientConfiguration config;
    config.region = region;

    if (customEndpoint.empty()) {
      config.endpointOverride = customEndpoint;
      config.useVirtualAddressing = false;
      std::cout << "Creating S3 compatible uploader for bucket: " << bucketName << ", endpoint: " << customEndpoint << std::endl;
    }
    else {
      std::cout << "Creating S3 uploader for bucket: " << bucketName << " in region " << region << std::endl;
    }
  
    s3CrtClient_ = std::make_shared<Aws::S3Crt::S3CrtClient>(
        Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>("MemoryStreamAllocator", credentials),
        config
    );

    // Create a temporary file to buffer data
    tempFilePath_ = uploadFolder + "/" + std::to_string(std::time(nullptr)) + ".tmp";
    tempFile_.open(tempFilePath_, std::ios::binary | std::ios::out);
    if (!tempFile_.is_open()) {
        throw std::runtime_error("Failed to open temporary file for buffering: " + tempFilePath_);
    }
    //std::cout << "Temporary file created: " << tempFilePath_ << std::endl;
}

S3CompatibleUploader::~S3CompatibleUploader() {
    cleanupTempFile();
}

bool S3CompatibleUploader::upload(std::vector<char>& data, bool isFinalChunk) {
    if (!tempFile_.is_open()) {
        std::cerr << "Temporary file is not open. Upload failed." << std::endl;
        upload_failed_ = true;
        return false;
    }
    if (firstWrite_) {
        firstWrite_ = false;
        // Write the WAV header if this is the first write
        WavHeaderPrepender headerPrepender(8000, 2, 16);
        headerPrepender.prependHeader(data);
    }
  
    // Write the data chunk to the temporary file
    tempFile_.write(data.data(), data.size());
    if (!tempFile_) {
        std::cerr << "Failed to write data to temporary file." << std::endl;
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

    // Attach the file stream to the request body
    auto inputStream = Aws::MakeShared<Aws::FStream>("PutObjectBody", tempFilePath_.c_str(), std::ios::in | std::ios::binary);
    putObjectRequest.SetBody(inputStream);

    // Upload the file in one go
    auto putObjectOutcome = s3CrtClient_->PutObject(putObjectRequest);
    if (!putObjectOutcome.IsSuccess()) {
        std::cerr << "Failed to upload file: " << putObjectOutcome.GetError().GetMessage() << std::endl;
        upload_failed_ = true;
    } else {
        std::cout << "File uploaded successfully: " << objectKey_ << std::endl;
    }

    cleanupTempFile();
}

void S3CompatibleUploader::cleanupTempFile() {
    if (tempFile_.is_open()) {
        tempFile_.close();
    }
    std::remove(tempFilePath_.c_str()); // Delete the temporary file
}
