#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <unordered_map>
#include <cstring>
#ifdef __linux__
#include <fcntl.h>   // For open and fallocate
#include <unistd.h>  // For close
#endif
#include "encryption.h"

// Structure to store file offset and size
struct FileInfo {
    std::size_t offset;
    std::size_t size;
};

class VirtualHardDrive {
public:
    VirtualHardDrive(const std::string& fileName, encryption& enc, bool createNew = false)
            : fileName(fileName), enc(enc), size(determineSize()) { // Initialize size here
        if (createNew) {
            create(); // Create a new file only if specified
        } else {
            loadFileOffsets();
        }
    }

    std::string readData(const std::string& filePath, std::size_t length) {
        std::ifstream inFile(fileName, std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Error opening file for reading: " + fileName);
        }
        std::size_t offset = findOffset(filePath);
        inFile.seekg(offset);
        std::vector<unsigned char> encryptedData(length);
        inFile.read(reinterpret_cast<char*>(encryptedData.data()), length);
        inFile.close();
        return enc.decrypt(encryptedData);
    }

    void writeData(const std::vector<unsigned char>& data, const std::string& filePath) {
        std::ofstream outFile(fileName, std::ios::binary | std::ios::in | std::ios::out);
        if (!outFile) {
            throw std::runtime_error("Error opening file for writing: " + fileName);
        }

        std::size_t offset = findOffset(filePath); // Find or calculate the file's offset
        outFile.seekp(offset);
        outFile.write(reinterpret_cast<const char*>(data.data()), data.size());

        // Ensure to update the file offset and size
        fileOffsets[filePath] = {offset, data.size()};
        saveFileOffsets();
        outFile.close();
    }


    // Retrieve all files and their sizes from the virtual hard drive
    std::vector<std::pair<std::string, std::size_t>> getAllFiles() {
        std::vector<std::pair<std::string, std::size_t>> fileList;
        for (const auto& [filePath, fileInfo] : fileOffsets) {
            fileList.push_back({filePath, fileInfo.size});
        }
        return fileList;
    }

private:
    std::string fileName;
    std::size_t size; // Ensure this is properly initialized
    encryption& enc;
    std::unordered_map<std::string, FileInfo> fileOffsets;

    std::size_t determineSize() {
        return 1024 * 1024; // For example, set to 1 MB
    }

    void create() {
        std::ofstream outFile(fileName, std::ios::binary | std::ios::trunc);
        if (!outFile) {
            throw std::runtime_error("Error creating file: " + fileName);
        }

        // Use fallocate (Linux only) for sparse file creation if available
#ifdef __linux__
        int fd = open(fileName.c_str(), O_RDWR | O_CREAT, 0666); // Ensure the file is created
            if (fd < 0) {
                throw std::runtime_error("Error opening file descriptor for fallocate.");
            }

            // Ensure 'size' is initialized before use
            if (fallocate(fd, 0, 0, size) != 0) {
                close(fd);
                throw std::runtime_error("fallocate failed to create sparse file.");
            }

            close(fd);
#else
        std::vector<char> emptyData(size, 0);
        outFile.write(emptyData.data(), size); // Write 'size' bytes of zeros.
#endif

        outFile.close();
    }

    std::size_t findOffset(const std::string& filePath) {
        // Check if the file already has an assigned offset
        if (fileOffsets.find(filePath) != fileOffsets.end()) {
            return fileOffsets[filePath].offset;
        }

        // Otherwise, calculate a new offset (append at the end of the file)
        std::ifstream inFile(fileName, std::ios::binary | std::ios::ate);
        if (!inFile) {
            throw std::runtime_error("Error opening virtual hard drive file: " + fileName);
        }
        std::size_t offset = inFile.tellg();  // Get current end of file
        inFile.close();

        return offset;
    }

    // Load the file offsets and sizes from the virtual hard drive
    void loadFileOffsets() {
        std::ifstream inFile(fileName, std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("Error opening file for reading offsets: " + fileName);
        }

        inFile.seekg(-static_cast<std::streamoff>(sizeof(std::size_t)), std::ios::end);
        std::size_t offsetTableSize;
        inFile.read(reinterpret_cast<char*>(&offsetTableSize), sizeof(offsetTableSize));

        if (offsetTableSize > size) {
            throw std::runtime_error("Corrupted offset table size.");
        }

        inFile.seekg(-static_cast<std::streamoff>(sizeof(std::size_t) + offsetTableSize), std::ios::end);
        for (std::size_t i = 0; i < offsetTableSize / (sizeof(std::size_t) * 2 + 256); ++i) {
            char filePath[256];
            std::size_t offset, fileSize;
            inFile.read(filePath, 256);
            inFile.read(reinterpret_cast<char*>(&offset), sizeof(offset));
            inFile.read(reinterpret_cast<char*>(&fileSize), sizeof(fileSize));
            fileOffsets[filePath] = {offset, fileSize};
        }
        inFile.close();
    }

    // Save the file offsets and sizes to the virtual hard drive
    void saveFileOffsets() {
        std::ofstream outFile(fileName, std::ios::binary | std::ios::in | std::ios::out);
        if (!outFile) {
            throw std::runtime_error("Error opening file for writing offsets: " + fileName);
        }

        outFile.seekp(0, std::ios::end);

        std::size_t offsetTableSize = fileOffsets.size() * (sizeof(std::size_t) * 2 + 256);

        for (const auto& [filePath, fileInfo] : fileOffsets) {
            char paddedFilePath[256] = {0};
            std::strncpy(paddedFilePath, filePath.c_str(), sizeof(paddedFilePath) - 1);
            outFile.write(paddedFilePath, 256);
            outFile.write(reinterpret_cast<const char*>(&fileInfo.offset), sizeof(fileInfo.offset));
            outFile.write(reinterpret_cast<const char*>(&fileInfo.size), sizeof(fileInfo.size));
        }

        outFile.write(reinterpret_cast<const char*>(&offsetTableSize), sizeof(offsetTableSize));

        outFile.close();
    }
};
