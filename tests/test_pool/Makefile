CC ?= gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra \
         -I../../userspace \
         -pthread \

SRC_CORE = \
    ../../userspace/keccak1600.c \
    ../../userspace/math_operations.c \
    ../../userspace/ml_kem.c \
    ../../userspace/ml_kem_create_keys.c \
    ../../userspace/ml_kem_decrypt.c \
    ../../userspace/ml_kem_encaps.c \
    ../../userspace/ml_kem_ntt_main.c \
    ../../userspace/ml_kem_pool.c \
    ../../userspace/ml_kem_sha3.c \
    ../../userspace/ml_kem_shake.c

TEST = TEST_pool.c

TARGET = test_pool

all:
	$(CC) $(CFLAGS) $(SRC_CORE) $(TEST) -lm -o $(TARGET)

clean:
	rm -f $(TARGET)
