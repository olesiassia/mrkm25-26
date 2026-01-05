# Лабораторна робота №2 - Crypto++ demo
# macOS з Homebrew

CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -lcryptopp

TARGET = crypto_demo
SOURCES = crypto_demo.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean
