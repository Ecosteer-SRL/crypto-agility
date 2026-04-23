# auth:  graz
# ver:   1.4
# date:  30/03/2026
#
# Makefile for cipher providers and runtime-loading test infrastructure.
# Location:

#   ~/crypto-agility/c
CC ?= g++
CFG ?= release

COMMON_SRC_DIR := ./src/ciphers
PADDING_SRC_DIR := ./src/padding
TOOLS_SRC_DIR := ./src/tools
COMMON_INC_DIR := ./include
COMMON_INC_CIPHERS_DIR := ./include/ciphers

BUILD_ROOT := build
OBJDIR := $(BUILD_ROOT)/$(CFG)/obj
BINDIR := $(BUILD_ROOT)/$(CFG)/bin
LIBDIR := $(BUILD_ROOT)/$(CFG)/lib

IFLAGS := -I$(COMMON_INC_DIR) -I$(COMMON_INC_CIPHERS_DIR) -I. -I..
CFLAGS_COMMON := -Wall -fPIC -MMD -MP $(IFLAGS)

CFLAGS_debug     := -O0 -g3 -DDEBUG
CFLAGS_release   := -O3 -DNDEBUG
CFLAGS_callgrind := -O0 -g3 -fno-omit-frame-pointer -fno-inline -DDEBUG
CFLAGS_CFG := $(CFLAGS_$(CFG))

LDLIBS_AES_CBC_SO               := -lcrypto
LDLIBS_AES_CTR_SO               := -lcrypto
LDLIBS_CHACHA20_POLY1305_SO     := -lcrypto
LDLIBS_BLOWFISH_ECB_SO          := -lcrypto
LDLIBS_RL_TEST                  := -ldl

APPS := test_cipher_provider
LIBS := libaes_cbc_provider.so libaes_ctr_provider.so libchacha20_poly1305_provider.so libblowfish_ecb_provider.so

OBJS_test_cipher_provider := \
	$(OBJDIR)/test_cipher_provider.o \
	$(OBJDIR)/cipher_provider.o \
	$(OBJDIR)/dvco_padding.o

OBJS_libaes_cbc_provider := \
	$(OBJDIR)/aes_cbc_provider.o

OBJS_libaes_ctr_provider := \
	$(OBJDIR)/aes_ctr_provider.o

OBJS_libchacha20_poly1305_provider := \
	$(OBJDIR)/chacha20_poly1305_provider.o

OBJS_libblowfish_ecb_provider := \
	$(OBJDIR)/blowfish_ecb_provider.o

ALL_OBJS := \
	$(OBJS_test_cipher_provider) \
	$(OBJS_libaes_cbc_provider) \
	$(OBJS_libaes_ctr_provider) \
	$(OBJS_libchacha20_poly1305_provider) \
	$(OBJS_libblowfish_ecb_provider)

ALL_DEPS := $(ALL_OBJS:.o=.d)

BIN_test_cipher_provider := $(BINDIR)/test_cipher_provider

SO_libaes_cbc_provider := $(LIBDIR)/libaes_cbc_provider.so
SO_libaes_ctr_provider := $(LIBDIR)/libaes_ctr_provider.so
SO_libchacha20_poly1305_provider := $(LIBDIR)/libchacha20_poly1305_provider.so
SO_libblowfish_ecb_provider := $(LIBDIR)/libblowfish_ecb_provider.so

ALL_BINS := \
	$(BIN_test_cipher_provider)

ALL_LIBS := \
	$(SO_libaes_cbc_provider) \
	$(SO_libaes_ctr_provider) \
	$(SO_libchacha20_poly1305_provider) \
	$(SO_libblowfish_ecb_provider)

.PHONY: all build_cfg debug release callgrind clean clean_debug clean_release clean_callgrind

all: release

build_cfg: $(ALL_LIBS) $(ALL_BINS)

debug:
	$(MAKE) CFG=debug build_cfg

release:
	$(MAKE) CFG=release build_cfg

callgrind:
	$(MAKE) CFG=callgrind build_cfg

$(OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@
	
$(OBJDIR)/%.o: $(TOOLS_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(OBJDIR)/cipher_provider.o: $(COMMON_SRC_DIR)/cipher_provider.c $(COMMON_INC_CIPHERS_DIR)/cipher_provider.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(OBJDIR)/aes_cbc_provider.o: $(COMMON_SRC_DIR)/aes_cbc_provider.c $(COMMON_INC_CIPHERS_DIR)/cipher_provider.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(OBJDIR)/aes_ctr_provider.o: $(COMMON_SRC_DIR)/aes_ctr_provider.c $(COMMON_INC_CIPHERS_DIR)/cipher_provider.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(OBJDIR)/chacha20_poly1305_provider.o: $(COMMON_SRC_DIR)/chacha20_poly1305_provider.c $(COMMON_INC_CIPHERS_DIR)/cipher_provider.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(OBJDIR)/blowfish_ecb_provider.o: $(COMMON_SRC_DIR)/blowfish_ecb_provider.c $(COMMON_INC_CIPHERS_DIR)/cipher_provider.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(OBJDIR)/dvco_padding.o: $(PADDING_SRC_DIR)/dvco_padding.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_CFG) -c $< -o $@

$(SO_libaes_cbc_provider): $(OBJS_libaes_cbc_provider)
	@mkdir -p $(@D)
	$(CC) -shared -o $@ $^ $(LDLIBS_AES_CBC_SO)

$(SO_libaes_ctr_provider): $(OBJS_libaes_ctr_provider)
	@mkdir -p $(@D)
	$(CC) -shared -o $@ $^ $(LDLIBS_AES_CTR_SO)

$(SO_libchacha20_poly1305_provider): $(OBJS_libchacha20_poly1305_provider)
	@mkdir -p $(@D)
	$(CC) -shared -o $@ $^ $(LDLIBS_CHACHA20_POLY1305_SO)

$(SO_libblowfish_ecb_provider): $(OBJS_libblowfish_ecb_provider)
	@mkdir -p $(@D)
	$(CC) -shared -o $@ $^ $(LDLIBS_BLOWFISH_ECB_SO)


$(BIN_test_cipher_provider): $(OBJS_test_cipher_provider)
	@mkdir -p $(@D)
	$(CC) -o $@ $^ $(LDLIBS_RL_TEST)

clean:
	$(RM) -r $(BUILD_ROOT)

clean_debug:
	$(RM) -r $(BUILD_ROOT)/debug

clean_release:
	$(RM) -r $(BUILD_ROOT)/release

clean_callgrind:
	$(RM) -r $(BUILD_ROOT)/callgrind

-include $(ALL_DEPS)
