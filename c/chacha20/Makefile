# Compiler and flags
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O3 -std=c11 -MMD -MP -I include -I ../utils

# Targets and directories
TARGET = chacha20.elf
SRCS_DIR = src
BUILD_DIR = build

# Sources and dependencies
SRCS = main.c chacha20.c poly1305.c bigint.c
OBJS = $(addprefix $(BUILD_DIR)/, $(SRCS:.c=.o))
DEPS = $(OBJS:.o=.d)

VPATH = $(SRCS_DIR) ../utils

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Object compilation
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
 
test: $(TARGET)
	./$(TARGET)

-include $(DEPS)

.PHONY: all clean test