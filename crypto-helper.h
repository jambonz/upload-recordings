#ifndef CRYPTO_HELPER_H
#define CRYPTO_HELPER_H

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <cstring>

#include <aws/core/external/cjson/cJSON.h>

// Global base64Encode function
static std::string base64Encode(const unsigned char* data, size_t length) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);

    // Disable newlines
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, length);
    BIO_flush(bio);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);

    std::string base64Str(bptr->data, bptr->length);
    BIO_free_all(bio);

    return base64Str;
}

class CryptoHelper {
public:
    CryptoHelper(const std::string &algorithm = "aes-256-cbc")
        : algorithm_(algorithm) {
        // Retrieve the encryption secret from the environment variable
        const char *envSecret = std::getenv("ENCRYPTION_SECRET");
        if (!envSecret) {
            throw std::runtime_error("ENCRYPTION_SECRET environment variable is not set");
        }
        encryptionSecret_ = std::string(envSecret);
    }

    std::string decrypt(const std::string &encryptedData) {
        std::cout << "Decrypting data: " << encryptedData << std::endl;

        std::string ivHex, contentHex;

        // Parse the JSON
        cJSON *json = cJSON_AS4CPP_Parse(encryptedData.c_str());
        if (!json) {
            throw std::runtime_error("Failed to parse encrypted data JSON");
        }

        cJSON* jIvHex = cJSON_AS4CPP_GetObjectItem(json, "iv");
        if (jIvHex && cJSON_AS4CPP_IsString(jIvHex)) {
            ivHex = jIvHex->valuestring;
            std::cout << "Parsed IV (Hex): " << ivHex << std::endl;
        } else {
            throw std::runtime_error("IV not found in encrypted data JSON");
        }

        cJSON* jContentHex = cJSON_AS4CPP_GetObjectItem(json, "content");
        if (jContentHex && cJSON_AS4CPP_IsString(jContentHex)) {
            contentHex = jContentHex->valuestring;
            std::cout << "Parsed Encrypted Content (Hex): " << contentHex << std::endl;
        } else {
            throw std::runtime_error("Content not found in encrypted data JSON");
        }

        cJSON_AS4CPP_Delete(json);

        // Convert IV and content from hex to binary
        std::vector<unsigned char> iv = hexToBytes(ivHex);
        std::vector<unsigned char> content = hexToBytes(contentHex);

        std::cout << "IV Size: " << iv.size() << " bytes, IV (Binary): ";
        for (unsigned char byte : iv) std::cout << std::hex << (int)byte << " ";
        std::cout << std::endl;

        std::cout << "Encrypted Content Size: " << content.size() << " bytes" << std::endl;

        if (iv.size() != AES_BLOCK_SIZE) {
            throw std::runtime_error("Invalid IV size");
        }

        // Derive the key
        unsigned char rawHash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(encryptionSecret_.c_str()), encryptionSecret_.size(), rawHash);

        std::string base64Key = base64Encode(rawHash, SHA256_DIGEST_LENGTH);
        std::cout << "Derived Base64 Key: " << base64Key << std::endl;

        if (base64Key.size() < 32) {
            throw std::runtime_error("Derived key is too short");
        }
        std::string truncatedKey = base64Key.substr(0, 32);
        std::cout << "Truncated Key (First 32 Bytes): " << truncatedKey << std::endl;

        // Prepare OpenSSL decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }

        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                              reinterpret_cast<const unsigned char*>(truncatedKey.data()), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        std::vector<unsigned char> decryptedContent(content.size());
        int decryptedLength = 0;

        // Decrypt the content
        if (EVP_DecryptUpdate(ctx, decryptedContent.data(), &decryptedLength,
                              content.data(), content.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption update failed");
        }

        int finalLength = 0;
        if (EVP_DecryptFinal_ex(ctx, decryptedContent.data() + decryptedLength, &finalLength) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption finalization failed");
        }
        EVP_CIPHER_CTX_free(ctx);

        decryptedContent.resize(decryptedLength + finalLength);

        std::cout << "Decryption successful, Final Size: " << decryptedContent.size() << " bytes" << std::endl;
        std::string result(decryptedContent.begin(), decryptedContent.end());
        std::cout << "Decrypted Text: " << result << std::endl;

        return result;
    }
private:
    std::string algorithm_;
    std::string encryptionSecret_;

    // Convert a hex string to a vector of bytes
    std::vector<unsigned char> hexToBytes(const std::string &hex) {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }
};

#endif // CRYPTO_HELPER_H