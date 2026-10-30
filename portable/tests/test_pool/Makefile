CC = gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra \
         -DUSERSPACE \
         -I../../src \
         -pthread \
         -I../../ports/userspace \
         -DFULL_MATRIX=0

SRC_CORE = \
    ../../ports/userspace/ml_kem_userspace_port.c \
    ../../src/keccak_1600.c \
    ../../src/ml_kem.c \
    ../../src/ml_kem_create_keys.c \
    ../../src/ml_kem_decrypt.c \
    ../../src/ml_kem_encaps.c \
    ../../src/ml_kem_ntt_main.c \
    ../../src/ml_kem_decaps_pool.c \
    ../../src/ml_kem_sha3.c \
    ../../src/ml_kem_shake.c \
    ../../src/ml_kem_encaps_pool.c

TARGETS = test_decaps_pool test_encaps_pool

.PHONY: all run run-decaps run-encaps clean

all: $(TARGETS)

test_decaps_pool: test_decaps_pool.c $(SRC_CORE)
	$(CC) $(CFLAGS) $(SRC_CORE) $< -lm -o $@

test_encaps_pool: test_encaps_pool.c $(SRC_CORE)
	$(CC) $(CFLAGS) $(SRC_CORE) $< -lm -o $@

run: run-decaps run-encaps

run-decaps: test_decaps_pool
	./test_decaps_pool

run-encaps: test_encaps_pool
	./test_encaps_pool

clean:
	rm -f $(TARGETS)
