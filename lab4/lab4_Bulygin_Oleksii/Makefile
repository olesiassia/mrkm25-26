CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2 -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -lcryptopp

TARGET = security_tests
SRCS = security_tests.cpp undeniable_sig.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean run
