CC ?= gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra \
         -I../../src \
         -pthread \

SRC_CORE = \
    ../../src/keccak1600.c \
    ../../src/ml_kem.c \
    ../../src/ml_kem_create_keys.c \
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
