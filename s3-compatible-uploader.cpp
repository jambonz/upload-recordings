#include "s3-compatible-uploader.h"
#include "wav-header.h"
#include <iostream>
#include <stdexcept>
#include <fstream>
#include <cstdio>

S3CompatibleUploader::S3CompatibleUploader(std::shared_ptr<spdlog::logger> log, std::string& uploadFolder, RecordFileType ftype,
                                           const Aws::Auth::AWSCredentials& credentials, const Aws::String& region,
                                           const Aws::String& bucketName, const Aws::String& customEndpoint)
    : bucketName_(bucketName), region_(region), recordFileType_(ftype) {
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

    // Write the data chunk to the temporary file
    tempFile_.write(data.data(), data.size());
    if (!tempFile_.good()) {
      if (tempFile_.fail()) {
          log_->error("Logical error occurred while writing data to temporary file.");
      }
      if (tempFile_.bad()) {
          log_->error("Critical I/O error occurred while writing data to temporary file.");
      }
      upload_failed_ = true;
      return false;
    }
    tempFile_.flush();

    log_->info("S3CompatibleUploader uploaded {} bytes to temporary file {}.", data.size(), tempFilePath_);

    if (isFinalChunk) {
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

    // if this is a WAV file, we need to prepend a wave header
    std::string finalFilePath = tempFilePath_;
    if (recordFileType_ == RecordFileType::WAV) {
        // Use mkstemp to generate a unique temporary file for the WAV file
        char wavTempFilePath[] = "/tmp/uploads/wavfile-XXXXXX"; // Template for unique file
        int wavTempFd = mkstemp(wavTempFilePath); // Creates the file and returns a file descriptor
        if (wavTempFd == -1) {
            log_->error("Failed to create unique WAV temporary file using mkstemp: {}", strerror(errno));
            upload_failed_ = true;
            return;
        }

        // Open the file stream associated with the descriptor
        std::ofstream wavTempFile(wavTempFilePath, std::ios::binary);
        if (!wavTempFile) {
            log_->error("Failed to open WAV temporary file: {}", wavTempFilePath);
            close(wavTempFd); // Close the file descriptor
            upload_failed_ = true;
            return;
        }

        // Calculate the size of the raw audio data
        auto audioDataSize = std::filesystem::file_size(tempFilePath_);

        // Generate the WAV header
        WavHeaderPrepender headerPrepender(8000, 2, 16); // Sample rate, channels, bit depth
        std::vector<char> wavHeader = headerPrepender.createHeader(static_cast<uint32_t>(audioDataSize));

        // Write the WAV header to the new temporary file
        wavTempFile.write(wavHeader.data(), wavHeader.size());
        if (!wavTempFile.good()) {
            log_->error("Failed to write WAV header to temporary file: {}", wavTempFilePath);
            close(wavTempFd); // Close the file descriptor
            upload_failed_ = true;
            return;
        }

        // Append the raw audio data to the new temporary file
        std::ifstream rawAudioFile(tempFilePath_, std::ios::binary);
        if (!rawAudioFile) {
            log_->error("Failed to open raw audio temporary file: {}", tempFilePath_);
            close(wavTempFd); // Close the file descriptor
            upload_failed_ = true;
            return;
        }

        wavTempFile << rawAudioFile.rdbuf(); // Efficiently copy raw audio data
        wavTempFile.close();
        rawAudioFile.close();
        close(wavTempFd); // Close the descriptor after all writes

        log_->info("WAV file created with header at: {}", wavTempFilePath);

        // Update the final file path to point to the new WAV file
        finalFilePath = wavTempFilePath;
    }

    // Attach the file stream to the request body
    auto inputStream = Aws::MakeShared<Aws::FStream>("PutObjectBody", finalFilePath.c_str(), std::ios::in | std::ios::binary);
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
        log_->error("S3CompatibleUploader Failed to upload file: {}: {}", tempFilePath_, putObjectOutcome.GetError().GetMessage());
        upload_failed_ = true;
    } else {
        log_->info("File uploaded successfully: {} to {}", tempFilePath_, objectKey_);
    }
    if (recordFileType_ == RecordFileType::WAV) {
        std::remove(finalFilePath.c_str());
    }
}