.DELETE_ON_ERROR:

ifneq ($(shell uname -s),Linux)
$(error Linux build required)
endif

CC = $(shell command -v musl-gcc 2>/dev/null || command -v gcc)
BUILD = build
TARGET = $(BUILD)/cwg

SODIUM = ext/libsodium
SODIUM_BUILD = $(BUILD)/vendor/libsodium
SODIUM_PREFIX = $(abspath $(BUILD)/vendor/prefix)
SODIUM_LIB = $(SODIUM_PREFIX)/lib/libsodium.a
SODIUM_INC = $(SODIUM_PREFIX)/include

SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,$(BUILD)/src/%.o,$(SRC))
OBJ += $(BUILD)/src/blake2s-ref.o
DEP = $(OBJ:.o=.d)

CFLAGS = -std=gnu11 -O3 -flto -Wall -Wextra -Wpedantic \
	-ffunction-sections -fdata-sections -fomit-frame-pointer \
	-D_GNU_SOURCE \
	-Isrc -Iext/uthash/src -Iext/blake2/ref -I$(SODIUM_INC)
LDFLAGS = -static -pthread -flto -s -Wl,--gc-sections

all: $(TARGET)

$(TARGET): $(OBJ) $(SODIUM_LIB)
	$(CC) $(OBJ) $(SODIUM_LIB) -o $@ $(LDFLAGS)

$(BUILD)/src/%.o: src/%.c $(SODIUM_LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/src/blake2s-ref.o: ext/blake2/ref/blake2s-ref.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(SODIUM_LIB): $(SODIUM)/configure
	@mkdir -p $(SODIUM_BUILD)
	cd $(SODIUM_BUILD) && CC=$(CC) $(abspath $(SODIUM))/configure \
		--prefix=$(SODIUM_PREFIX) --disable-shared --enable-static \
		--disable-dependency-tracking
	$(MAKE) -C $(SODIUM_BUILD)
	$(MAKE) -C $(SODIUM_BUILD) install

clean:
	rm -rf $(BUILD)

.PHONY: all clean
-include $(DEP)
