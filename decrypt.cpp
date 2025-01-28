#include <iostream>
#include <filesystem>
#include <fstream>
#include "VirtualHardDrive.h"

namespace fs = std::filesystem;

bool checkFileExists(const std::string& fileName) {
    std::ifstream file(fileName);
    return file.good();
}

void decryptAndSave(const fs::path& destPath, VirtualHardDrive& vhd, encryption& enc) {
    std::vector<std::pair<std::string, std::size_t>> files = vhd.getAllFiles();

    for (const auto& [virtualPath, size] : files) {
        std::string decryptedData = vhd.readData(virtualPath, size);
        fs::path outputPath = destPath / virtualPath;
        fs::create_directories(outputPath.parent_path());

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            std::cerr << "Failed to open file for writing: " << outputPath << std::endl;
            continue;
        }
        outFile.write(decryptedData.data(), decryptedData.size());
        outFile.close();
    }
}

int main() {
    std::cout << "Decrypting virtual hard drive..." << std::endl;
    encryption enc;

    // Check if key files exist
    std::string aesKeyFile = "aeskey.dat";
    std::string privateKeyFile = "private_key.bin";

    if (!checkFileExists(aesKeyFile)) {
        std::cerr << "Error: AES key file '" << aesKeyFile << "' not found!" << std::endl;
        return 1; // Exit with an error code
    }

    if (!checkFileExists(privateKeyFile)) {
        std::cerr << "Error: Private key file '" << privateKeyFile << "' not found!" << std::endl;
        return 1; // Exit with an error code
    }

    // Try to decrypt the key with proper error handling
    try {
        enc.decryptkey(aesKeyFile, privateKeyFile); // Decrypt using the provided keys
    } catch (const std::exception& e) {
        std::cerr << "Failed to decrypt key: " << e.what() << std::endl;
        return 1; // Exit if key decryption fails
    }

    try {
        std::string fileName = "virtual_hard_drive.vhd";
        VirtualHardDrive vhd(fileName, enc); // Read from the existing virtual hard drive

        fs::path destDirectory = "./decrypted";
        decryptAndSave(destDirectory, vhd, enc);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1; // Exit with an error code
    }

    std::cout << "Decryption complete." << std::endl;
    return 0;
}
