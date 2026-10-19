# SPDX-License-Identifier: GPL-2.0 OR MIT
# ML-KEM userspace: standalone sanitizer build-and-run targets.
# Put this file in portable/tests/test_memory_leak/.
# All paths are relative to that directory, so the repository directory
# and the C test filename may contain spaces or parentheses.

.DEFAULT_GOAL := help

CC := clang
CORE_DIR ?= ../../src
PORT_DIR ?= ../../ports/userspace
BUILD_DIR ?= build
# Leave empty to auto-select the single test*.c in this directory.
# When there are multiple tests, pass TEST_SRC='filename.c' to make.
TEST_SRC ?=

CORE_FILES := \
    ml_kem.c \
    ml_kem_create_keys.c \
    ml_kem_encaps.c \
    ml_kem_decrypt.c \
    ml_kem_ntt_main.c \
    ml_kem_sha3.c \
    ml_kem_shake.c \
    keccak1600.c \
    ml_kem_decaps_pool.c \
    ml_kem_encaps_pool.c

COMMON_FLAGS := -std=c11 -O1 -g -Wall -Wextra \
                -fno-omit-frame-pointer -fno-optimize-sibling-calls \
                -fPIE -pthread -DUSERSPACE \
                -I"$(CORE_DIR)" -I"$(PORT_DIR)"

SAN_FLAGS_asan := -fsanitize=address
SAN_FLAGS_lsan := -fsanitize=leak
SAN_FLAGS_msan := -fsanitize=memory -fsanitize-memory-track-origins=2
SAN_FLAGS_ubsan := -fsanitize=undefined -fno-sanitize-recover=undefined
SAN_FLAGS_tsan := -fsanitize=thread

# Leak detection is deliberately disabled for ASan, since LSan has its own run.
RUN_ENV_asan := ASAN_OPTIONS=detect_leaks=0:halt_on_error=1
RUN_ENV_lsan := LSAN_OPTIONS=exitcode=23
RUN_ENV_msan := MSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
RUN_ENV_ubsan := UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
RUN_ENV_tsan := TSAN_OPTIONS=halt_on_error=1

.PHONY: help asan lsan msan ubsan tsan clean

help:
	@printf '%s\n' \
	    'ML-KEM sanitizer tests (Clang, C11, userspace)' \
	    '  make asan   - build and run AddressSanitizer' \
	    '  make lsan   - build and run LeakSanitizer' \
	    '  make msan   - build and run MemorySanitizer' \
	    '  make ubsan  - build and run UndefinedBehaviorSanitizer' \
	    '  make tsan   - build and run ThreadSanitizer' \
	    '  make clean  - remove sanitizer build outputs' \
	    "  make asan TEST_SRC='test(3).c'  - select an explicit test file"

# Phony targets intentionally build a fresh executable each run.
# In particular, there are NO path-containing make targets/prerequisites:
# GNU make would otherwise split a directory named 'ml-kem (copy 1)' on spaces.
asan lsan msan ubsan tsan:
	@set -eu; \
	  test_src='$(TEST_SRC)'; \
	  if [ -z "$$test_src" ]; then \
	    set -- ./test*.c; \
	    if [ ! -f "$$1" ]; then \
	      printf '%s\n' 'ERROR: no test*.c file in this directory' >&2; \
	      exit 2; \
	    fi; \
	    if [ "$$#" -ne 1 ]; then \
	      printf '%s\n' "ERROR: found $$# test*.c files; specify TEST_SRC='filename.c'" >&2; \
	      exit 2; \
	    fi; \
	    test_src="$$1"; \
	  fi; \
	  if [ ! -f "$$test_src" ]; then \
	    printf 'ERROR: test source not found: %s\n' "$$test_src" >&2; \
	    exit 2; \
	  fi; \
	  if [ ! -f "$(CORE_DIR)/ml_kem.c" ] || [ ! -f "$(PORT_DIR)/ml_kem_userspace_port.c" ]; then \
	    printf '%s\n' 'ERROR: ML-KEM sources not found (check CORE_DIR and PORT_DIR)' >&2; \
	    exit 2; \
	  fi; \
	  mkdir -p "$(BUILD_DIR)/$@"; \
	  printf '\nBuilding %s from %s...\n' '$@' "$$test_src"; \
	  "$(CC)" $(COMMON_FLAGS) $(SAN_FLAGS_$@) \
	    "$$test_src" \
	    $(foreach source,$(CORE_FILES),"$(CORE_DIR)/$(source)") \
	    "$(PORT_DIR)/ml_kem_userspace_port.c" \
	    -pie $(SAN_FLAGS_$@) -o "$(BUILD_DIR)/$@/ml_kem_test"; \
	  printf '\nRunning %s...\n\n' '$@'; \
	  env $(RUN_ENV_$@) "$(BUILD_DIR)/$@/ml_kem_test"

clean:
	rm -rf "$(BUILD_DIR)"
