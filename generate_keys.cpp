#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include "oqs/oqs.h"

// Function to write the public key and private key hash to a C++ header file
void writePublicKeyAndHashToHeaderFile(const uint8_t* publicKey, size_t pubKeyLen, const std::string& headerFilename, const std::string& privateKeyHash) {
    // Open the header file to write
    std::ofstream headerFile(headerFilename);
    if (!headerFile.is_open()) {
        std::cerr << "Error opening header file to write public key." << std::endl;
        return;
    }

    // Write the C++ header guard
    headerFile << "#ifndef PUBLIC_KEY_H\n";
    headerFile << "#define PUBLIC_KEY_H\n\n";

    // Write the public key as a C++ array of unsigned char
    headerFile << "const unsigned char publicKey[] = {\n";
    for (size_t i = 0; i < pubKeyLen; ++i) {
        if (i % 16 == 0) {
            headerFile << "    ";
        }
        headerFile << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(publicKey[i]) << ",";
        if ((i + 1) % 16 == 0 || i + 1 == pubKeyLen) {
            headerFile << "\n";
        }
    }
    headerFile << "};\n\n";

    // Write the private key hash
    headerFile << "const char* privateKeyHash = \"" << privateKeyHash << "\";\n\n";

    // End the header guard
    headerFile << "#endif // PUBLIC_KEY_H\n";

    headerFile.close();
    std::cout << "Public key and private key hash written to " << headerFilename << " successfully." << std::endl;
}

// Function to compute the SHA-256 hash of a file using the EVP interface (OpenSSL 3.0+)
std::string computeFileHash(const std::string& filename) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Error creating EVP_MD_CTX." << std::endl;
        return "";
    }

    const EVP_MD* md = EVP_sha256();  // Using SHA-256
    if (!EVP_DigestInit_ex(mdctx, md, nullptr)) {
        std::cerr << "Error initializing digest context: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    // Open the file to read
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        std::cerr << "Error opening file for hashing: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    const int bufSize = 32768;
    std::vector<unsigned char> buffer(bufSize);
    size_t bytesRead = 0;

    // Update the digest with the file contents
    while ((bytesRead = fread(buffer.data(), 1, bufSize, file)) > 0) {
        if (!EVP_DigestUpdate(mdctx, buffer.data(), bytesRead)) {
            std::cerr << "Error updating digest: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            fclose(file);
            EVP_MD_CTX_free(mdctx);
            return "";
        }
    }

    fclose(file);

    // Finalize the digest
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (!EVP_DigestFinal_ex(mdctx, hash, &hashLen)) {
        std::cerr << "Error finalizing digest: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_MD_CTX_free(mdctx);
        return "";
    }

    EVP_MD_CTX_free(mdctx);

    // Convert the hash to a hexadecimal string
    std::ostringstream hashString;
    for (unsigned int i = 0; i < hashLen; ++i) {
        hashString << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return hashString.str();
}

void generate_McEliece_keypair(const std::string& privFilename, const std::string& pubHeaderFilename) {
    OQS_KEM* kem = nullptr;
    uint8_t* publicKey = nullptr;
    size_t pubKeyLen = 0;
    uint8_t* privateKey = nullptr;
    size_t privKeyLen = 0;

    // Allocate memory for the keys
    kem = OQS_KEM_classic_mceliece_6960119f_new();
    if (!kem) {
        std::cerr << "Error creating McEliece context." << std::endl;
        return;
    }

    publicKey = static_cast<uint8_t*>(malloc(kem->length_public_key));
    privateKey = static_cast<uint8_t*>(malloc(kem->length_secret_key));

    // Generate the key pair
    if (OQS_KEM_keypair(kem, publicKey, privateKey) != OQS_SUCCESS) {
        std::cerr << "Error generating McEliece key pair." << std::endl;
        free(publicKey);
        free(privateKey);
        OQS_KEM_free(kem);
        return;
    }

    // Save private key to a file
    FILE* privFile = fopen(privFilename.c_str(), "wb");
    if (!privFile) {
        std::cerr << "Error opening file to write private key." << std::endl;
        free(publicKey);
        free(privateKey);
        OQS_KEM_free(kem);
        return;
    }

    size_t written = fwrite(privateKey, 1, kem->length_secret_key, privFile);
    fclose(privFile);

    if (written != kem->length_secret_key) {
        std::cerr << "Error writing private key to file." << std::endl;
        free(publicKey);
        free(privateKey);
        OQS_KEM_free(kem);
        return;
    }

    // Compute the hash of the private key file
    std::string privateKeyHash = computeFileHash(privFilename);
    if (privateKeyHash.empty()) {
        std::cerr << "Error computing hash of private key." << std::endl;
        free(publicKey);
        free(privateKey);
        OQS_KEM_free(kem);
        return;
    }

    // Save public key and private key hash to a C++ header file
    writePublicKeyAndHashToHeaderFile(publicKey, kem->length_public_key, pubHeaderFilename, privateKeyHash);

    // Clean up
    free(publicKey);
    free(privateKey);
    OQS_KEM_free(kem);

    std::cout << "McEliece key pair generated and private key hash saved successfully!" << std::endl;
}

int main() {
    // Specify file names
    std::string privateKeyFile = "private_key.bin";
    std::string publicKeyHeaderFile = "public_key.h";

    // Generate the McEliece key pair and save them to files
    generate_McEliece_keypair(privateKeyFile, publicKeyHeaderFile);

    return 0;
}