cmake_minimum_required(VERSION 3.10)
project(UndeniableSignature)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Crypto++ library
# On macOS with Homebrew: brew install cryptopp
find_path(CRYPTOPP_INCLUDE_DIR cryptopp/cryptlib.h
    HINTS
    /usr/local/include
    /opt/homebrew/include
    /usr/include
)

find_library(CRYPTOPP_LIBRARY
    NAMES cryptopp crypto++
    HINTS
    /usr/local/lib
    /opt/homebrew/lib
    /usr/lib
)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ library not found. Install with: brew install cryptopp")
endif()

message(STATUS "Found Crypto++ include: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Found Crypto++ library: ${CRYPTOPP_LIBRARY}")

include_directories(${CRYPTOPP_INCLUDE_DIR})

# Build library
add_library(undeniable_sig
    undeniable_sig.cpp
)

target_link_libraries(undeniable_sig ${CRYPTOPP_LIBRARY})

# Build test executable
add_executable(test_undeniable
    test.cpp
)

target_link_libraries(test_undeniable undeniable_sig ${CRYPTOPP_LIBRARY})

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(undeniable_sig PRIVATE -Wall -Wextra)
    target_compile_options(test_undeniable PRIVATE -Wall -Wextra)
endif()

# Installation (optional)
install(TARGETS undeniable_sig DESTINATION lib)
install(FILES undeniable_sig.h DESTINATION include)
