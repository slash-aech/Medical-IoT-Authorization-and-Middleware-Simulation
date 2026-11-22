CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pthread
LDLIBS ?= -lcrypto
TARGET := tps

.PHONY: all clean run
all: $(TARGET)

$(TARGET): tps.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
