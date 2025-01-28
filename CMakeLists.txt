cmake_minimum_required(VERSION 3.25)
project(PearOS)

set(CMAKE_CXX_STANDARD 20)
set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3.4/include")
# Find OpenSSL
find_package(OpenSSL REQUIRED)

if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h)
find_library(OQS_LIBRARY NAMES oqs)

if(NOT OQS_INCLUDE_DIR OR NOT OQS_LIBRARY)
    message(FATAL_ERROR "OQS library not found")
endif()

include_directories(${OQS_INCLUDE_DIR})

# Add the binary directory to the include paths
include_directories(${CMAKE_BINARY_DIR})

# Add executable for generating keys
add_executable(generate_keys generate_keys.cpp)
target_link_libraries(generate_keys ${OPENSSL_LIBRARIES} ${OQS_LIBRARY})

# Add a custom command to generate keys
add_custom_command(
        OUTPUT generated_keys.h
        COMMAND generate_keys
        DEPENDS generate_keys
        COMMENT "Generating keys..."
)

# Create executable target for PearOS
add_executable(PearOS encrypt.cpp)
target_link_libraries(PearOS OpenSSL::SSL OpenSSL::Crypto ${OQS_LIBRARY})
add_executable(decrypt decrypt.cpp)
target_link_libraries(decrypt OpenSSL::SSL OpenSSL::Crypto ${OQS_LIBRARY})
# Add a custom target that depends on the generated keys
add_custom_target(generate_keys_target DEPENDS generated_keys.h)

# Ensure the main target depends on the custom target
add_dependencies(PearOS generate_keys_target)