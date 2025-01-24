#ifndef MP3_ENCODER_H
#define MP3_ENCODER_H

#include <lame/lame.h>
#include <vector>
#include <stdexcept>
#include <cstring>

class Mp3Encoder {
public:
    Mp3Encoder(int sampleRate, int numChannels, int bitrate)
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

      // Pre-compute maximum MP3 buffer size
      maxMp3Size_ = 1.25 * maxPcmSamples_ + 7200;
      mp3Buffer_.resize(maxMp3Size_);
    }

    ~Mp3Encoder() {
      lame_close(lame_);
    }

    void encodeInPlace(std::vector<char>& pcmData) {
      if (pcmData.empty()) {
        return;
      }

      // Interpret PCM data as short (16-bit samples)
      short* pcmSamples = reinterpret_cast<short*>(pcmData.data());
      size_t numSamples = pcmData.size() / sizeof(short);

      if (numSamples % numChannels_ != 0) {
        throw std::runtime_error("PCM data size is not aligned with the number of channels.");
      }

      // Encode PCM data to MP3
      int mp3DataSize = lame_encode_buffer_interleaved(
        lame_,
        pcmSamples,
        numSamples / numChannels_,
        mp3Buffer_.data(),
        maxMp3Size_
      );

      if (mp3DataSize < 0) {
        throw std::runtime_error("Failed to encode MP3 data.");
      }

      // Finalize MP3 encoding
      int flushSize = lame_encode_flush(lame_, mp3Buffer_.data() + mp3DataSize, maxMp3Size_ - mp3DataSize);
      if (flushSize < 0) {
        throw std::runtime_error("Failed to finalize MP3 encoding.");
      }

      mp3DataSize += flushSize;

      // Replace PCM data with MP3 data (in-place)
      pcmData.assign(mp3Buffer_.begin(), mp3Buffer_.begin() + mp3DataSize);
    }

private:
    lame_t lame_;
    int sampleRate_;
    int numChannels_;
    int bitrate_;
    size_t maxMp3Size_;
    static constexpr size_t maxPcmSamples_ = 5 * 1024 * 1024 / sizeof(short); // 5MB PCM chunk
    std::vector<unsigned char> mp3Buffer_; // Reusable MP3 buffer
};

#endif // MP3_ENCODER_H