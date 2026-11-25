# SPDX-License-Identifier: Apache-2.0
CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Iinclude -Ithird_party/moonlab
LDFLAGS ?= -lm

ifeq ($(OS),Windows_NT)
  EXE := .exe
  LDFLAGS += -lbcrypt
else
  EXE :=
endif

MOONLAB_SRCS := \
  third_party/moonlab/crypto/sha3/sha3.c \
  third_party/moonlab/crypto/aes/aes.c \
  third_party/moonlab/crypto/drbg/ctr_drbg.c \
  third_party/moonlab/crypto/mlkem/poly.c \
  third_party/moonlab/crypto/mlkem/mlkem.c \
  third_party/moonlab/applications/health_tests.c \
  third_party/moonlab/applications/qrng_di.c

CORE_SRCS := \
  src/secmesh_entropy.c \
  src/secmesh_it_crypto.c \
  src/secmesh_quantum_geo.c

BUILD_DIR := build

.PHONY: all test sanitizers clean

all: $(BUILD_DIR)/secmesh_core$(EXE) $(BUILD_DIR)/test_native_core$(EXE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/secmesh_core$(EXE): $(CORE_SRCS) $(MOONLAB_SRCS) src/secmesh_cli.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wno-pedantic $(CORE_SRCS) $(MOONLAB_SRCS) src/secmesh_cli.c -o $@ $(LDFLAGS)

$(BUILD_DIR)/test_native_core$(EXE): $(CORE_SRCS) $(MOONLAB_SRCS) tests/test_native_core.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -Wno-pedantic $(CORE_SRCS) $(MOONLAB_SRCS) tests/test_native_core.c -o $@ $(LDFLAGS)

test: all
	./$(BUILD_DIR)/test_native_core$(EXE)

sanitizers: | $(BUILD_DIR)
	$(CC) -std=c11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer \
	  -Iinclude -Ithird_party/moonlab $(CORE_SRCS) $(MOONLAB_SRCS) tests/test_native_core.c \
	  -o $(BUILD_DIR)/test_native_core_san$(EXE) $(LDFLAGS)
	./$(BUILD_DIR)/test_native_core_san$(EXE)

clean:
	rm -rf $(BUILD_DIR)
