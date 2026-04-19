#include <regex>

#include "session.h"
#include "s3-compatible-uploader.h"
#include "azure-uploader.h"
#include "google-uploader.h"
#include "connection-manager.h"
#include "string-utils.h"

// Static member initialization
std::once_flag Session::initFlag_;
std::string Session::uploadFolder_;
CryptoHelper Session::cryptoHelper_ = CryptoHelper();

// Static configuration variables (defaults will be overridden by main)
size_t Session::bufferProcessSize_ = 512 * 1024;     // 512KB default
size_t Session::maxBufferSize_ = 3 * 1024 * 1024;    // 3MB default
int Session::awsMaxConnections_ = 8;                  // Default
int Session::metadataTimeoutSecs_ = 3;                // Default

Session::Session(const std::string& sessionId)
    : json_metadata_doc_(nullptr),
      json_metadata_(nullptr),
      storage_service_(StorageService::UNKNOWN),
      strand_(ThreadPool::getInstance().createStrand()),
      metadataTimer_(ThreadPool::getInstance().getIoContext()),
      session_id_(sessionId) {

    // Create a unique sink for this session
    auto sink = std::make_shared<spdlog::sinks::stdout_sink_mt>();

    // Create a logger with its own sink
    log_ = std::make_shared<spdlog::logger>("session_logger", sink);
    log_->set_pattern(fmt::format("(session: {}) %v", session_id_));

    buffer_.reserve(maxBufferSize_);  // Use configurable max buffer size
    initialize();

    // Capture audio start time at connection establishment.
    // FreeSWITCH buffers ~1 second of audio before sending the first chunk,
    // so we can't rely on when the first binary arrives. Instead, we use
    // the connection time plus 20ms (one RTP packetization period) to
    // approximate when audio capture actually started.
    audioStartTime_ = std::chrono::system_clock::now() + std::chrono::milliseconds(20);
    audioStartTimeSet_ = true;
}

Session::~Session() {
  if (json_metadata_doc_) {
      yyjson_doc_free(json_metadata_doc_);
  }
}

void Session::setContext(const std::string& account_sid, const std::string& call_sid) {
    account_sid_ = account_sid;
    call_sid_ = call_sid;

    log_->set_pattern(fmt::format("(session: {}, account_sid: {}, call_sid: {}) %v", session_id_, account_sid_, call_sid_));
    log_->info("Received metadata");
}

void Session::addData(int isBinary, const char *data, size_t len) {
    bool should_process = false;
    
    {
        std::unique_lock<std::mutex> lock(mutex_);

        // Check for overflow using configurable max buffer size
        if (buffer_.size() + len > maxBufferSize_) {
            log_->error("Buffer overflow: dropping data, buffer size is {}", buffer_.size());
            return;
        }

        if (isBinary) {
            // Note: audioStartTime_ is set in constructor at connection time + 20ms
            // to account for FreeSWITCH's ~1 second audio buffering before first send

            buffer_.insert(buffer_.end(), data, data + len);

            // Process the buffer if it reaches the configurable threshold
            if (buffer_.size() >= bufferProcessSize_) {
                should_process = true;
            }
        } 
        else if (!json_metadata_doc_) {
            tmp_.append(data, len);
            yyjson_doc *doc = yyjson_read(tmp_.c_str(), tmp_.size(), 0);
            if (doc != nullptr) {
                json_metadata_doc_ = doc;
                json_metadata_ = yyjson_doc_get_root(doc);
                metadata_received_ = true;
                metadataTimer_.cancel();
                postProcessMetadataTask();
            }
        }
        else {
            // Buffer text frames and try to parse as session:summary (may be fragmented)
            sessionSummaryBuffer_.append(data, len);
            yyjson_doc *doc = yyjson_read(sessionSummaryBuffer_.c_str(), sessionSummaryBuffer_.size(), 0);
            if (doc) {
                yyjson_val *root = yyjson_doc_get_root(doc);
                yyjson_val *typeField = yyjson_obj_get(root, "type");
                if (typeField && yyjson_is_str(typeField) &&
                    std::string(yyjson_get_str(typeField)) == "session:summary") {
                    yyjson_val *dataField = yyjson_obj_get(root, "data");
                    if (dataField) {
                        char *printed = yyjson_val_write(dataField, 0, NULL);
                        if (printed) {
                            sessionSummaryJson_ = printed;
                            free(printed);
                            log_->info("Received session:summary ({} bytes)", sessionSummaryJson_.size());
                        }
                    }
                } else {
                    log_->info("Unexpected text frame after metadata: {}", sessionSummaryBuffer_);
                }
                yyjson_doc_free(doc);
                sessionSummaryBuffer_.clear();
            }
            // If parse fails, keep buffering - more fragments may arrive
        }
    }
    
    if (should_process) {
        postProcessBufferTask(false);
    }
}

void Session::notifyClose() {
    log_->info("connection closed");
    metadataTimer_.cancel();
    postProcessBufferTask(true);
}

void Session::startMetadataTimer() {
    metadataTimer_.expires_after(std::chrono::seconds(metadataTimeoutSecs_));
    auto self = shared_from_this();
    metadataTimer_.async_wait(boost::asio::bind_executor(strand_,
        [self](const boost::system::error_code& ec) {
            if (ec) return;  // Timer was cancelled (metadata arrived in time)
            if (!self->metadata_received_) {
                self->log_->warn("No metadata received within timeout, destroying session");
                ConnectionManager::getInstance().destroySession(self.get());
            }
        }
    ));
}

void Session::postProcessMetadataTask() {
    auto self = shared_from_this();

    std::string threadId = getThreadIdString();
    log_->info("read metadata in threadId: {}", threadId);
    
    // Post to strand to ensure sequential processing
    boost::asio::post(strand_, [self]() {
        self->processMetadata();
    });
}

void Session::postProcessBufferTask(bool isFinal) {
    auto self = shared_from_this();
    
    // Post to strand to ensure sequential processing
    boost::asio::post(strand_, [self, isFinal]() {
        self->processBuffer(isFinal);
    });
}

void Session::processMetadata() {
    std::string threadId = getThreadIdString();
    log_->info("processing metadata in threadId: {}", threadId);  
    parseMetadata(json_metadata_);
        
    try {
        recordCredentials_ = std::make_unique<RecordCredentials>(
            MySQLHelper::getInstance().fetchRecordCredentials(account_sid_)
        );

        log_->info("Record Format: {}", recordCredentials_->recordFormat);

        // Decrypt the bucket credential
        std::string decryptedBucketCredential = cryptoHelper_.decrypt(recordCredentials_->bucketCredential);

        yyjson_doc* bucketCredentialDoc = yyjson_read(decryptedBucketCredential.c_str(), decryptedBucketCredential.size(), 0);
        if (bucketCredentialDoc) {
            yyjson_val* bucketCredentialJson = yyjson_doc_get_root(bucketCredentialDoc);
            yyjson_val* vendor = yyjson_obj_get(bucketCredentialJson, "vendor");
            if (vendor && yyjson_is_str(vendor)) {
                const char* vendorStr = yyjson_get_str(vendor);
                if (std::string(vendorStr) == "aws_s3") {
                    storage_service_ = StorageService::AWS_S3;
                    log_->info("Using AWS S3 storage service.");
                    parseAwsCredentials(decryptedBucketCredential);
                }
                else if(std::string(vendorStr) == "s3_compatible") {
                    storage_service_ = StorageService::S3_COMPATIBLE;
                    log_->info("Using S3 compatible storage service.");
                    parseAwsCredentials(decryptedBucketCredential);
                }
                else if(std::string(vendorStr) == "azure") {
                    storage_service_ = StorageService::AZURE_CLOUD_STORAGE;
                    log_->info("Using Azure storage service.");
                    parseAzureCredentials(decryptedBucketCredential);
                }
                else if(std::string(vendorStr) == "google") {
                    storage_service_ = StorageService::GOOGLE_CLOUD_STORAGE;
                    log_->info("Using Google storage service.");
                    parseGoogleCredentials(decryptedBucketCredential);
                }
                else {
                    log_->warn("Unsupported storage service: {}", vendorStr);
                }
            }
            yyjson_doc_free(bucketCredentialDoc);

            if (recordCredentials_->recordFormat == "mp3") {
                recordFileType_ = RecordFileType::MP3;
                // MP3 encoder will be created in the storage uploader at the end
                log_->info("Recording format set to MP3 (encoding will happen at end).");
            }
            else {
                recordFileType_ = RecordFileType::WAV;
            }
        }

        // initialization of the storage uploader
        if (!storageUploader_) {
          if ((storageUploader_ = createStorageUploader(recordFileType_))) {
              storageUploader_->setMetadata(metadata_);
          }
        }
    } catch (const std::exception &e) {
        log_->error("Failed to fetch or decrypt record credentials: {}", e.what());
    }
}

void Session::processBuffer(bool isFinal) {
  std::vector<char> localBuffer;
  bool process_buffer = false;

  {
      std::unique_lock<std::mutex> lock(mutex_);

      if (!buffer_.empty()) {
          std::swap(localBuffer, buffer_);

          // Handle misalignment in the swapped buffer
          size_t numSamples = localBuffer.size() / sizeof(short); // Total samples in localBuffer
          size_t remainder = numSamples % 2;    // Do we have the same num samples for both channels?

          if (remainder != 0) {
              log_->info("Misaligned buffer: {} samples", numSamples);

              // Only move leftover samples back to buffer_ if this is NOT the final chunk
              // If it's the final chunk, we need to upload all remaining data
              if (!isFinal) {
                  // Calculate the size of the trailing odd sample (in bytes)
                  size_t leftoverSize = remainder * sizeof(short);

                  // Move the trailing sample(s) back to the now-empty buffer_
                  buffer_.insert(buffer_.end(), localBuffer.end() - leftoverSize, localBuffer.end());

                  // Remove the trailing sample(s) from localBuffer
                  localBuffer.resize(localBuffer.size() - leftoverSize);
              } else {
                  log_->info("Final chunk: including all {} samples in upload", numSamples);
              }
          }

          process_buffer = true;
      }
  }
  
  // Pass session summary to uploader before final upload
  if (isFinal && !sessionSummaryJson_.empty() && storageUploader_) {
      storageUploader_->setSessionSummary(sessionSummaryJson_);
      if (audioStartTimeSet_) {
          storageUploader_->setAudioStartTime(audioStartTime_);
      }
      log_->info("Session summary passed to storage uploader");
  }

  // Process the buffer if we have data
  if (process_buffer) {
      log_->debug("Processing buffer of size: {}", localBuffer.size());

      if (storageUploader_) {
          if (!storageUploader_->upload(localBuffer, isFinal)) {
              log_->error("Upload failed.");
          }
      }
      else if (isFinal) {
          // We have data but no uploader (metadata processing failed) - clean up
          log_->warn("Session::processBuffer connection closed with data but no StorageUploader.");
          auto self = shared_from_this();
          ConnectionManager::getInstance().destroySession(self.get());
      }
  }
  else if (isFinal) {
    if (storageUploader_) {
      std::string threadId = getThreadIdString();
      log_->info("uploading recording in threadId: {}", threadId);

      storageUploader_->upload(localBuffer, isFinal);
    }
    else {
      // Here we have the case where we did not get metadata so we have no uploader
      // We need to orchestrate the destruction of this Session at this point
      log_->warn("Session::processBuffer connection closed but no StorageUploader.");
      auto self = shared_from_this();
      ConnectionManager::getInstance().destroySession(self.get());
    }
  }
}

void Session::parseAwsCredentials(const std::string& credentials) {
  // Parse the credentials JSON
  yyjson_doc* doc = yyjson_read(credentials.c_str(), credentials.size(), 0);
  if (!doc) {
    std::cerr << "Failed to parse AWS credentials JSON.\n";
    return;
  }

  yyjson_val* json = yyjson_doc_get_root(doc);

  yyjson_val* accessKey = yyjson_obj_get(json, "access_key_id");
  if (accessKey && yyjson_is_str(accessKey)) {
    access_key_ = yyjson_get_str(accessKey);
  }

  yyjson_val* secretKey = yyjson_obj_get(json, "secret_access_key");
  if (secretKey && yyjson_is_str(secretKey)) {
    secret_key_ = yyjson_get_str(secretKey);
  }

  yyjson_val* bucketName = yyjson_obj_get(json, "name");
  if (bucketName && yyjson_is_str(bucketName)) {
    bucket_name_ = yyjson_get_str(bucketName);
  }

  yyjson_val* endpoint = yyjson_obj_get(json, "endpoint");
  if (endpoint && yyjson_is_str(endpoint)) {
    custom_endpoint_ = yyjson_get_str(endpoint);
  }

  // First try to get region from the "region" property
  yyjson_val* region = yyjson_obj_get(json, "region");
  if (region && yyjson_is_str(region)) {
    region_ = yyjson_get_str(region);
  }
  // If no region was found but we have an endpoint, try to extract region from endpoint
  else if (!custom_endpoint_.empty()) {
    extractRegionFromEndpoint(custom_endpoint_, region_);
  }

  yyjson_doc_free(doc);
}

void Session::parseAzureCredentials(const std::string& credentials) {
  yyjson_doc* doc = yyjson_read(credentials.c_str(), credentials.size(), 0);
  if (!doc) {
    std::cerr << "Failed to parse Azure credentials JSON.\n";
    return;
  }

  yyjson_val* json = yyjson_doc_get_root(doc);

  yyjson_val* containerName = yyjson_obj_get(json, "name");
  if (containerName && yyjson_is_str(containerName)) {
    container_name_ = yyjson_get_str(containerName);
  }

  yyjson_val* connectionString = yyjson_obj_get(json, "connection_string");
  if (connectionString && yyjson_is_str(connectionString)) {
    connection_string_ = yyjson_get_str(connectionString);
  }

  yyjson_doc_free(doc);
}

void Session::parseGoogleCredentials(const std::string& credentials) {
    yyjson_doc* doc = yyjson_read(credentials.c_str(), credentials.size(), 0);
    if (!doc) {
        std::cerr << "Failed to parse Google credentials JSON.\n";
        return;
    }

    yyjson_val* json = yyjson_doc_get_root(doc);

    // Extract the bucket name
    yyjson_val* bucketName = yyjson_obj_get(json, "name");
    if (bucketName && yyjson_is_str(bucketName)) {
        bucket_name_ = yyjson_get_str(bucketName);
    }

    // Extract the service_key field
    yyjson_val* serviceKey = yyjson_obj_get(json, "service_key");
    if (serviceKey && yyjson_is_str(serviceKey)) {
        const char* serviceKeyStr = yyjson_get_str(serviceKey);
        yyjson_doc* serviceKeyDoc = yyjson_read(serviceKeyStr, strlen(serviceKeyStr), 0);
        if (serviceKeyDoc) {
            yyjson_val* serviceKeyJson = yyjson_doc_get_root(serviceKeyDoc);

            // Extract the private_key
            yyjson_val* privateKey = yyjson_obj_get(serviceKeyJson, "private_key");
            if (privateKey && yyjson_is_str(privateKey)) {
                private_key_ = yyjson_get_str(privateKey);
            }

            // Extract the client_email
            yyjson_val* clientEmail = yyjson_obj_get(serviceKeyJson, "client_email");
            if (clientEmail && yyjson_is_str(clientEmail)) {
                client_email_ = yyjson_get_str(clientEmail);
            }

            // Extract the token_uri
            yyjson_val* tokenUri = yyjson_obj_get(serviceKeyJson, "token_uri");
            if (tokenUri && yyjson_is_str(tokenUri)) {
                token_uri_ = yyjson_get_str(tokenUri);
            }

            yyjson_doc_free(serviceKeyDoc); // Clean up the parsed service key JSON
        } else {
            std::cerr << "Failed to parse service_key JSON.\n";
        }
    }

    log_->info("parseGoogleCredentials: bucket_name = {}", bucket_name_);

    yyjson_doc_free(doc); // Clean up the main JSON object
}

void Session::parseMetadata(yyjson_val* json) {
  if (!json) {
    std::cerr << "Invalid JSON object for metadata parsing.\n";
    return;
  }

  yyjson_val* sampleRate = yyjson_obj_get(json, "sampleRate");
  if (sampleRate && yyjson_is_num(sampleRate)) {
    metadata_.sample_rate = yyjson_get_int(sampleRate);
  }

  yyjson_val* accountSid = yyjson_obj_get(json, "accountSid");
  if (accountSid && yyjson_is_str(accountSid)) {
    account_sid_ = yyjson_get_str(accountSid);
  }

  yyjson_val* callSid = yyjson_obj_get(json, "callSid");
  if (callSid && yyjson_is_str(callSid)) {
    metadata_.call_sid = call_sid_ = yyjson_get_str(callSid);
  }

  yyjson_val* direction = yyjson_obj_get(json, "direction");
  if (direction && yyjson_is_str(direction)) {
    metadata_.direction = yyjson_get_str(direction);
  }

  yyjson_val* from = yyjson_obj_get(json, "from");
  if (from && yyjson_is_str(from)) {
    metadata_.from = yyjson_get_str(from);
  }

  yyjson_val* to = yyjson_obj_get(json, "to");
  if (to && yyjson_is_str(to)) {
    metadata_.to = yyjson_get_str(to);
  }

  yyjson_val* applicationSid = yyjson_obj_get(json, "applicationSid");
  if (applicationSid && yyjson_is_str(applicationSid)) {
    metadata_.application_sid = yyjson_get_str(applicationSid);
  }

  yyjson_val* originatingSipIp = yyjson_obj_get(json, "originatingSipIp");
  if (originatingSipIp && yyjson_is_str(originatingSipIp)) {
    metadata_.originating_sip_id = yyjson_get_str(originatingSipIp);
  }

  yyjson_val* originatingSipTrunkName = yyjson_obj_get(json, "fsSipAddress");
  if (originatingSipTrunkName && yyjson_is_str(originatingSipTrunkName)) {
    metadata_.originating_sip_trunk_name = yyjson_get_str(originatingSipTrunkName);
  }

  setContext(account_sid_, call_sid_);
}

std::unique_ptr<StorageUploader> Session::createStorageUploader(RecordFileType ftype) {
  try {
    switch (storage_service_) {
      case StorageService::AWS_S3:
        return std::make_unique<S3CompatibleUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          Aws::Auth::AWSCredentials(access_key_, secret_key_),
          region_,
          bucket_name_
        );

      case StorageService::S3_COMPATIBLE:
        return std::make_unique<S3CompatibleUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          Aws::Auth::AWSCredentials(access_key_, secret_key_),
          region_,
          bucket_name_,
          custom_endpoint_
        );
      case StorageService::AZURE_CLOUD_STORAGE:
        return std::make_unique<AzureUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          connection_string_,
          container_name_
        );
      case StorageService::GOOGLE_CLOUD_STORAGE:
        return std::make_unique<GoogleUploader>(
          shared_from_this(),
          log_,
          uploadFolder_,
          ftype,
          bucket_name_,
          client_email_,
          private_key_,
          token_uri_
        );
      default:
        std::cerr << "Unknown storage service.\n";
        return nullptr;
    }
  } catch (const std::exception &e) {
    log_->error("Failed to create storage uploader: {}", e.what());
    return nullptr;
  }
}

void Session::extractRegionFromEndpoint(const std::string& endpoint, std::string& regionVar) {
  // This regex looks for:
  // 1. Optional protocol (http:// or https://) or start of string
  // 2. "s3." prefix
  // 3. A region segment containing a hyphen
  // 4. Followed by a period and at least two more domain segments
  std::regex region_pattern(R"((^|://|^)s3\.([^\.]+\-[^\.]+)\.[^\.]+\.[^\.]+)");
  std::smatch matches;
  
  if (std::regex_search(endpoint, matches, region_pattern) && matches.size() > 2) {
    // Only update the region variable if we successfully extracted a region
    regionVar = matches[2].str();
    log_->info("Extracted region from endpoint: {}", regionVar);
  }
  // If no match is found, regionVar remains unchanged
}