CC ?= gcc

CFLAGS = -O3 -Wall -Wextra -std=c11 \
          -I. \
          -I../../userspace

SRC_CORE = ml_kem_encaps.c \
    ../../userspace/keccak1600.c \
    ../../userspace/math_operations.c \
    ../../userspace/ml_kem.c \
    ../../userspace/ml_kem_decrypt.c \
    ../../userspace/ml_kem_create_keys.c \
    ../../userspace/ml_kem_ntt_main.c \
    ../../userspace/ml_kem_pool.c \
    ../../userspace/ml_kem_sha3.c \
    ../../userspace/ml_kem_shake.c

TEST = test.c

TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC_CORE) $(TEST) -lm -o $(TARGET)

clean:
	rm -f $(TARGET)
