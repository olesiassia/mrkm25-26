# Makefile for Undeniable Signature Implementation
# Lab 3 - Cryptographic Mechanisms

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

# Detect OS and set paths accordingly
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS (Homebrew paths)
    CRYPTOPP_INC = -I/opt/homebrew/include -I/usr/local/include
    CRYPTOPP_LIB = -L/opt/homebrew/lib -L/usr/local/lib -lcryptopp
else
    # Linux
    CRYPTOPP_INC = -I/usr/include
    CRYPTOPP_LIB = -lcryptopp
endif

INCLUDES = $(CRYPTOPP_INC)
LIBS = $(CRYPTOPP_LIB)

# Source files
LIB_SRC = undeniable_sig.cpp
LIB_OBJ = $(LIB_SRC:.cpp=.o)

TEST_SRC = test.cpp
TEST_OBJ = $(TEST_SRC:.cpp=.o)

# Targets
TARGET = test_undeniable

.PHONY: all clean run help

all: $(TARGET)

$(TARGET): $(LIB_OBJ) $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "Build complete! Run with: ./$(TARGET)"

%.o: %.cpp undeniable_sig.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(LIB_OBJ) $(TEST_OBJ) $(TARGET)
	rm -f public_key.txt private_key.txt signature.txt
	@echo "Clean complete"

help:
	@echo "Undeniable Signature - Lab 3"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build the test program"
	@echo "  make run      - Build and run tests"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - Crypto++ library"
	@echo "  - C++17 compiler"
	@echo ""
	@echo "Install Crypto++ on macOS: brew install cryptopp"
	@echo "Install Crypto++ on Linux: sudo apt-get install libcrypto++-dev"
