#ifndef STREAMING_MP3_ENCODER_H
#define STREAMING_MP3_ENCODER_H

#include <lame/lame.h>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <fstream>
#include <memory>

class StreamingMp3Encoder {
public:
    StreamingMp3Encoder(int sampleRate, int numChannels, int bitrate)
      : sampleRate_(sampleRate), numChannels_(numChannels), bitrate_(bitrate) {
      lame_ = lame_init();
      if (!lame_) {
        throw std::runtime_error("Failed to initialize LAME encoder.");
      }

      lame_set_in_samplerate(lame_, sampleRate_);
      lame_set_num_channels(lame_, numChannels_);
      lame_set_brate(lame_, bitrate_);
      lame_set_mode(lame_, numChannels_ == 1 ? MONO : STEREO);
      lame_set_quality(lame_, 2); // 2 = High quality, slower encoding

      if (lame_init_params(lame_) < 0) {
        throw std::runtime_error("Failed to set LAME encoder parameters.");
      }

      // Pre-allocate MP3 buffer for chunks
      // For streaming, we use a smaller buffer size
      mp3BufferSize_ = 1.25 * chunkSize_ + 7200;
      mp3Buffer_.resize(mp3BufferSize_);
    }

    ~StreamingMp3Encoder() {
      if (lame_) {
        lame_close(lame_);
      }
    }

    // Encode a chunk of PCM data without flushing
    // Returns the encoded MP3 data
    std::vector<unsigned char> encodeChunk(const std::vector<char>& pcmData) {
      if (pcmData.empty()) {
        return std::vector<unsigned char>();
      }

      // Interpret PCM data as short (16-bit samples)
      const short* pcmSamples = reinterpret_cast<const short*>(pcmData.data());
      size_t numSamples = pcmData.size() / sizeof(short);

      if (numSamples % numChannels_ != 0) {
        throw std::runtime_error("PCM data size is not aligned with the number of channels.");
      }

      // Encode PCM data to MP3 (without flush)
      int mp3DataSize = lame_encode_buffer_interleaved(
        lame_,
        const_cast<short*>(pcmSamples),  // LAME API requires non-const
        numSamples / numChannels_,
        mp3Buffer_.data(),
        mp3BufferSize_
      );

      if (mp3DataSize < 0) {
        throw std::runtime_error("Failed to encode MP3 data.");
      }

      // Return only the encoded data
      return std::vector<unsigned char>(mp3Buffer_.begin(), mp3Buffer_.begin() + mp3DataSize);
    }

    // Final flush - call this only once at the end
    std::vector<unsigned char> flush() {
      int flushSize = lame_encode_flush(lame_, mp3Buffer_.data(), mp3BufferSize_);
      if (flushSize < 0) {
        throw std::runtime_error("Failed to finalize MP3 encoding.");
      }

      return std::vector<unsigned char>(mp3Buffer_.begin(), mp3Buffer_.begin() + flushSize);
    }

    // Stream encode from input file to output file
    void encodeFile(const std::string& inputPath, const std::string& outputPath) {
      std::ifstream inputFile(inputPath, std::ios::binary);
      if (!inputFile) {
        throw std::runtime_error("Failed to open input file: " + inputPath);
      }

      std::ofstream outputFile(outputPath, std::ios::binary);
      if (!outputFile) {
        throw std::runtime_error("Failed to open output file: " + outputPath);
      }

      // Process in chunks
      std::vector<char> pcmBuffer(chunkSize_);
      
      while (inputFile.good()) {
        inputFile.read(pcmBuffer.data(), chunkSize_);
        std::streamsize bytesRead = inputFile.gcount();
        
        if (bytesRead > 0) {
          // Resize buffer to actual bytes read
          pcmBuffer.resize(bytesRead);
          
          // Ensure we have complete samples (multiple of sample size * channels)
          size_t sampleSize = sizeof(short) * numChannels_;
          size_t remainder = bytesRead % sampleSize;
          if (remainder != 0) {
            // Read additional bytes to complete the last sample
            std::vector<char> extraBytes(sampleSize - remainder);
            inputFile.read(extraBytes.data(), extraBytes.size());
            size_t extraBytesRead = inputFile.gcount();
            pcmBuffer.insert(pcmBuffer.end(), extraBytes.begin(), extraBytes.begin() + extraBytesRead);
          }
          
          // Encode the chunk
          auto mp3Data = encodeChunk(pcmBuffer);
          
          // Write to output
          if (!mp3Data.empty()) {
            outputFile.write(reinterpret_cast<const char*>(mp3Data.data()), mp3Data.size());
          }
          
          // Resize buffer back to chunk size for next iteration
          pcmBuffer.resize(chunkSize_);
        }
      }

      // Flush any remaining data
      auto flushData = flush();
      if (!flushData.empty()) {
        outputFile.write(reinterpret_cast<const char*>(flushData.data()), flushData.size());
      }

      inputFile.close();
      outputFile.close();
    }

private:
    lame_t lame_;
    int sampleRate_;
    int numChannels_;
    int bitrate_;
    size_t mp3BufferSize_;
    
    // Use 1MB chunks for streaming (must be multiple of sample size)
    static constexpr size_t chunkSize_ = 1024 * 1024;
    
    std::vector<unsigned char> mp3Buffer_; // Reusable MP3 buffer
};

#endif // STREAMING_MP3_ENCODER_H