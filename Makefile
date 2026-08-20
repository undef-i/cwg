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

SRC = $(wildcard src/*.c) src/aead/aead.c
OBJ = $(patsubst src/%.c,$(BUILD)/src/%.o,$(SRC))
OBJ += $(BUILD)/src/blake2s-ref.o
DEP = $(OBJ:.o=.d)

BSSL = ext/boringssl
BSSL_INC = $(BSSL)/include
BSSL_ASM = $(BSSL)/crypto/cipher/asm

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
CP1305_PL = $(BSSL_ASM)/chacha20_poly1305_x86_64.pl
CP1305_FLAVOUR = elf
CP1305_S = $(BUILD)/src/aead/chacha20_poly1305_x86_64.S
else ifeq ($(UNAME_M),aarch64)
CP1305_PL = $(BSSL_ASM)/chacha20_poly1305_armv8.pl
CP1305_FLAVOUR = linux64
CP1305_S = $(BUILD)/src/aead/chacha20_poly1305_armv8.S
else ifeq ($(UNAME_M),arm64)
CP1305_PL = $(BSSL_ASM)/chacha20_poly1305_armv8.pl
CP1305_FLAVOUR = linux64
CP1305_S = $(BUILD)/src/aead/chacha20_poly1305_armv8.S
endif

ifdef CP1305_S
OBJ += $(CP1305_S:.S=.o)
endif

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

ifdef CP1305_S
$(CP1305_S): $(CP1305_PL)
	@mkdir -p $(dir $@)
	cd $(BSSL_ASM) && perl $(notdir $(CP1305_PL)) $(CP1305_FLAVOUR) $(abspath $@)

$(CP1305_S:.S=.o): $(CP1305_S)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(BSSL_INC) -Wa,--noexecstack -x assembler-with-cpp -c $< -o $@
endif

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
