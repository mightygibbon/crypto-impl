# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O3 -std=c11 -MMD -MP -I include

# Targets and directories
TARGET = chacha20.elf
SRCS_DIR = src
BUILD_DIR = build

# Sources and dependencies
SRCS = main.c chacha20.c
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)
-include $(DEPS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Object compilation
$(BUILD_DIR)/%.o: $(SRCS_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
 
test: $(TARGET)
	./$(TARGET)

.PHONY: all clean test