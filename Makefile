CC ?= cc
BUILD_DIR ?= build
CPPFLAGS ?= -Iinclude
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -O2
LDFLAGS ?=
THREAD_FLAGS ?= -pthread

LIB_SOURCES := src/error.c src/pe.c src/loader.c src/module.c src/unicode.c \
	src/process.c src/context.c src/win32.c src/kernel32.c
CLI_SOURCES := src/main.c
TEST_PE_SOURCES := tests/test_pe.c
TEST_KERNEL32_SOURCES := tests/test_kernel32.c
TEST_UNICODE_SOURCES := tests/test_unicode.c
LIB_OBJECTS := $(LIB_SOURCES:%.c=$(BUILD_DIR)/%.o)
KERNEL32_OBJECT := $(BUILD_DIR)/src/kernel32.o
TEST_KERNEL32_LIB_OBJECT := $(BUILD_DIR)/src/kernel32-test.o
TEST_LIB_OBJECTS := $(filter-out $(KERNEL32_OBJECT),$(LIB_OBJECTS)) \
	$(TEST_KERNEL32_LIB_OBJECT)
CLI_OBJECTS := $(CLI_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_PE_OBJECTS := $(TEST_PE_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_KERNEL32_OBJECTS := $(TEST_KERNEL32_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_UNICODE_OBJECTS := $(TEST_UNICODE_SOURCES:%.c=$(BUILD_DIR)/%.o)
TEST_OBJECTS := $(TEST_PE_OBJECTS) $(TEST_KERNEL32_OBJECTS) \
	$(TEST_UNICODE_OBJECTS)
DEPFILES := $(LIB_OBJECTS:.o=.d) $(TEST_KERNEL32_LIB_OBJECT:.o=.d) \
	$(CLI_OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

.PHONY: all clean test check sanitize sanitize-no-leaks

all: $(BUILD_DIR)/sadlayer

$(BUILD_DIR)/sadlayer: $(LIB_OBJECTS) $(CLI_OBJECTS)
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) $^ -o $@

$(BUILD_DIR)/test_pe: $(TEST_LIB_OBJECTS) $(TEST_PE_OBJECTS)
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) $^ -o $@

$(BUILD_DIR)/test_kernel32: $(TEST_LIB_OBJECTS) $(TEST_KERNEL32_OBJECTS)
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) $^ -o $@

$(BUILD_DIR)/test_unicode: $(TEST_LIB_OBJECTS) $(TEST_UNICODE_OBJECTS)
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) $^ -o $@

$(TEST_KERNEL32_LIB_OBJECT) $(TEST_KERNEL32_OBJECTS): CPPFLAGS += \
	-DSADLAYER_TESTING

$(TEST_KERNEL32_LIB_OBJECT): src/kernel32.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(THREAD_FLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(THREAD_FLAGS) -MMD -MP -c $< -o $@

test: $(BUILD_DIR)/test_pe $(BUILD_DIR)/test_kernel32 $(BUILD_DIR)/test_unicode
	./$(BUILD_DIR)/test_pe
	./$(BUILD_DIR)/test_kernel32
	./$(BUILD_DIR)/test_unicode

check: all test

sanitize:
	$(MAKE) check BUILD_DIR="$(BUILD_DIR)/sanitize" CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"

sanitize-no-leaks:
	$(MAKE) sanitize ASAN_OPTIONS=detect_leaks=0

clean:
	rm -rf $(BUILD_DIR)

-include $(DEPFILES)
