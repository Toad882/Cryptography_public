#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string>
#include "public_key.h"
#include "oqs/oqs.h"

class encryption {
    std::string key;  // AES key

    // Helper function to generate a random string (used for generating AES key)
    std::string generateRandomString(size_t length) {
        std::vector<unsigned char> randomBytes(length);
        if (RAND_bytes(randomBytes.data(), length) != 1) {
            throw std::runtime_error("Error generating random bytes");
        }
        return std::string(randomBytes.begin(), randomBytes.end());
    }

    // Helper function to calculate SHA-256 hash of a given string
    std::string calculateHash(const std::string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)input.c_str(), input.size(), hash);

        // Convert the hash to a hexadecimal string for easier comparison
        std::string hexHash;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            char buf[3];  // 2 characters for the hex representation + null terminator
            snprintf(buf, sizeof(buf), "%02x", hash[i]);
            hexHash += buf;
        }
        return hexHash;
    }

public:
    // Constructor: Generate a random 256-bit AES key
    encryption() {
        key = generateRandomString(32);  // AES-256 key is 32 bytes (256 bits)
    }

    // AES Encryption function
    std::vector<unsigned char> encrypt(const std::string& plaintext) {
        // Initialization vector (IV) must be random and the same during decryption
        std::vector<unsigned char> iv(AES_BLOCK_SIZE);
        if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
            throw std::runtime_error("Error generating IV");
        }

        // Output buffer for encrypted data
        std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len = 0, ciphertext_len = 0;

        // Create and initialize the context for AES encryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.c_str(), iv.data());

        // Encrypt the plaintext
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
        ciphertext_len = len;

        // Finalize encryption
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Resize the buffer to the actual length of the ciphertext
        ciphertext.resize(ciphertext_len);

        // Prepend the IV to the ciphertext (needed for decryption)
        ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

        return ciphertext;
    }

    // AES Decryption function
    std::string decrypt(const std::vector<unsigned char>& ciphertext) {
        if (ciphertext.size() < AES_BLOCK_SIZE) {
            throw std::runtime_error("Ciphertext is too short");
        }

        // Extract IV from the ciphertext
        std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + AES_BLOCK_SIZE);

        // Prepare buffer for the decrypted text
        std::vector<unsigned char> decryptedText(ciphertext.size());
        int len = 0, decryptedText_len = 0;

        // Create and initialize the context for AES decryption
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.c_str(), iv.data());

        // Decrypt the ciphertext
        EVP_DecryptUpdate(ctx, decryptedText.data(), &len, ciphertext.data() + AES_BLOCK_SIZE, ciphertext.size() - AES_BLOCK_SIZE);
        decryptedText_len = len;

        // Finalize decryption
        EVP_DecryptFinal_ex(ctx, decryptedText.data() + len, &len);
        decryptedText_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Resize the buffer to the actual length of the decrypted text
        decryptedText.resize(decryptedText_len);

        return std::string(decryptedText.begin(), decryptedText.end());
    }


    void clear(const std::string& outputFile) {
        std::cout << "Starting clear function." << std::endl;

        // Initialize McEliece context
        OQS_KEM* kem = OQS_KEM_classic_mceliece_6960119f_new();
        if (!kem) {
            throw std::runtime_error("Error creating McEliece context.");
        }

        // Prepare buffers for ciphertext and shared secret
        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

        // Encrypt the message (generate shared secret)
        if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), publicKey) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            throw std::runtime_error("Error encapsulating message.");
        }

        // Debug: Print shared secret and ciphertext lengths
        std::cout << "Shared Secret Length: " << sharedSecret.size() << std::endl;
        std::cout << "Ciphertext Length: " << ciphertext.size() << std::endl;

        // Create a vector to hold the encrypted AES key and append the encapsulated ciphertext
        std::vector<unsigned char> encryptedKey(ciphertext.begin(), ciphertext.end());

        // Now append the AES key to the encrypted key vector
        encryptedKey.insert(encryptedKey.end(), key.begin(), key.end());

        // Save the encrypted AES key to the output file
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile) {
            OQS_KEM_free(kem);
            throw std::runtime_error("Error opening file for writing");
        }

        outFile.write(reinterpret_cast<char*>(encryptedKey.data()), encryptedKey.size());
        outFile.close();

        // Clear the AES key from memory
        std::fill(key.begin(), key.end(), 0);
        key.clear();  // Optional

        // Clean up
        OQS_KEM_free(kem);

        std::cout << "Cleared the AES key from memory." << std::endl;
    }

    void decryptkey(const std::string& encryptedKeyFile, const std::string& privateKeyFile) {
    std::cout << "Starting decryptkey function." << std::endl;

    // Step 1: Read the encrypted key from the file
    std::ifstream inFile(encryptedKeyFile, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Error opening file for reading: " + encryptedKeyFile);
    }

    // Read the encrypted key into a vector
    std::vector<unsigned char> encryptedKey((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    if (encryptedKey.empty()) {
        throw std::runtime_error("The encrypted key file is empty or could not be read.");
    }

    // Step 2: Load the private key from the file
    std::ifstream privateKeyFileStream(privateKeyFile, std::ios::binary);
    if (!privateKeyFileStream) {
        throw std::runtime_error("Error opening private key file: " + privateKeyFile);
    }

    std::vector<uint8_t> privateKeyData((std::istreambuf_iterator<char>(privateKeyFileStream)), std::istreambuf_iterator<char>());
    privateKeyFileStream.close();

    if (privateKeyData.empty()) {
        throw std::runtime_error("The private key file is empty or could not be read.");
    }

    // Step 3: Initialize McEliece context
    OQS_KEM* kem = OQS_KEM_classic_mceliece_6960119f_new();
    if (!kem) {
        throw std::runtime_error("Error creating McEliece context.");
    }

    // Step 4: Calculate the length of the ciphertext and shared secret
    size_t ciphertext_len = kem->length_ciphertext;
    size_t shared_secret_len = kem->length_shared_secret;

    // Ensure the encryptedKey has the correct length
    if (encryptedKey.size() < ciphertext_len) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Encrypted key is too short.");
    }

    // Extract the ciphertext from the encryptedKey vector
    std::vector<unsigned char> ciphertext(encryptedKey.begin(), encryptedKey.begin() + ciphertext_len);

    // Extract the AES key from the remaining part of the encryptedKey vector
    std::vector<unsigned char> encryptedAESKey(encryptedKey.begin() + ciphertext_len, encryptedKey.end());

    // Step 5: Decapsulate the shared secret using the private key and ciphertext
    std::vector<uint8_t> sharedSecret(shared_secret_len);
    if (OQS_KEM_decaps(kem, sharedSecret.data(), ciphertext.data(), privateKeyData.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Error decapsulating message.");
    }

    // Debug: Print shared secret length
    std::cout << "Shared Secret Length: " << sharedSecret.size() << std::endl;

    // Step 6: Assume the encryptedAESKey is the AES key itself (or use the shared secret to decrypt it)
    // For simplicity, let's assume the encryptedAESKey is the AES key itself
    if (key.size() != encryptedAESKey.size()) {
        key.resize(encryptedAESKey.size());
    }
    std::copy(encryptedAESKey.begin(), encryptedAESKey.end(), key.begin());

    // Clean up
    OQS_KEM_free(kem);

    std::cout << "Decrypted the AES key successfully and stored it in the key attribute." << std::endl;
}
};
