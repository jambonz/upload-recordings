#ifndef WAV_HEADER_H
#define WAV_HEADER_H

#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

class WavHeaderPrepender {
public:
    // Constructor to initialize WAV parameters
    WavHeaderPrepender(uint32_t sampleRate, uint16_t numChannels, uint16_t bitsPerSample)
        : sampleRate_(sampleRate), numChannels_(numChannels), bitsPerSample_(bitsPerSample) {}

    // Prepend the WAV header to the provided vector (modifies it in place)
    void prependHeader(std::vector<char>& audioData) const {
        uint32_t dataSize = audioData.size();
        std::vector<char> header = createHeader(dataSize);

        // Insert the header at the beginning of the audio data vector
        audioData.insert(audioData.begin(), header.begin(), header.end());
    }

private:
    uint32_t sampleRate_;
    uint16_t numChannels_;
    uint16_t bitsPerSample_;

    // Generate the WAV header for a given data size
    std::vector<char> createHeader(uint32_t dataSize) const {
        std::vector<char> header(44, 0);

        uint32_t byteRate = sampleRate_ * numChannels_ * (bitsPerSample_ / 8);
        uint16_t blockAlign = numChannels_ * (bitsPerSample_ / 8);
        uint32_t chunkSize = 36 + dataSize;

        // RIFF header
        std::memcpy(&header[0], "RIFF", 4); // Chunk ID
        std::memcpy(&header[4], &chunkSize, 4); // Chunk Size
        std::memcpy(&header[8], "WAVE", 4); // Format

        // fmt subchunk
        std::memcpy(&header[12], "fmt ", 4); // Subchunk1 ID
        uint32_t subchunk1Size = 16; // PCM header size
        std::memcpy(&header[16], &subchunk1Size, 4); // Subchunk1 Size
        uint16_t audioFormat = 1; // PCM format
        std::memcpy(&header[20], &audioFormat, 2); // Audio Format
        std::memcpy(&header[22], &numChannels_, 2); // Num Channels
        std::memcpy(&header[24], &sampleRate_, 4); // Sample Rate
        std::memcpy(&header[28], &byteRate, 4); // Byte Rate
        std::memcpy(&header[32], &blockAlign, 2); // Block Align
        std::memcpy(&header[34], &bitsPerSample_, 2); // Bits Per Sample

        // data subchunk
        std::memcpy(&header[36], "data", 4); // Subchunk2 ID
        std::memcpy(&header[40], &dataSize, 4); // Subchunk2 Size

        return header;
    }
};

#endif // WAV_HEADER_H