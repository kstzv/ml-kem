CC ?= gcc

CFLAGS = -O3 -Wall -Wextra -std=c11 \
          -I. \
          -I../../src

SRC_CORE = ml_kem_create_keys.c \
    ../../src/keccak1600.c \
    ../../src/ml_kem.c \
    ../../src/ml_kem_decrypt.c \
    ../../src/ml_kem_encaps.c \
    ../../src/ml_kem_ntt_main.c \
    ../../src/ml_kem_pool.c \
    ../../src/ml_kem_sha3.c \
    ../../src/ml_kem_shake.c

TEST = test.c

TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC_CORE) $(TEST) -lm -o $(TARGET)

clean:
	rm -f $(TARGET)
