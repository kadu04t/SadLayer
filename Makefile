CC ?= cc
BUILD_DIR ?= build
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -O2
LDFLAGS ?=

LIB_SOURCES := src/error.c src/pe.c src/loader.c src/win32.c
CLI_SOURCES := src/main.c
TEST_SOURCES := tests/test_pe.c
LIB_OBJECTS := $(LIB_SOURCES:%.c=$(BUILD_DIR)/%.o)
CLI_OBJECTS := $(CLI_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_OBJECTS := $(TEST_SOURCES:%.c=$(BUILD_DIR)/%.o)
DEPFILES := $(LIB_OBJECTS:.o=.d) $(CLI_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

.PHONY: all clean test check sanitize sanitize-no-leaks

all: $(BUILD_DIR)/sadlayer

$(BUILD_DIR)/sadlayer: $(LIB_OBJECTS) $(CLI_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/test_pe: $(LIB_OBJECTS) $(TEST_OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

test: $(BUILD_DIR)/test_pe
	./$(BUILD_DIR)/test_pe

check: all test

sanitize:
	$(MAKE) clean
	$(MAKE) check CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"

sanitize-no-leaks:
	$(MAKE) sanitize ASAN_OPTIONS=detect_leaks=0

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPFILES)
