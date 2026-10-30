CC ?= gcc

CFLAGS = -O3 -Wall -Wextra -std=c11 \
		 -DUSERSPACE \
		 -DML_KEM_TEST \
          -I. \
          -I../../src \
          -I../../ports/userspace \
          -DFULL_MATRIX=0

SRC_CORE = \
	../../ports/userspace/ml_kem_userspace_port.c \
	../../src/ml_kem_create_keys.c \
    ../../src/keccak_1600.c \
    ../../src/ml_kem.c \
    ../../src/ml_kem_decrypt.c \
    ../../src/ml_kem_encaps.c \
    ../../src/ml_kem_ntt_main.c \
    ../../src/ml_kem_decaps_pool.c \
    ../../src/ml_kem_sha3.c \
    ../../src/ml_kem_shake.c \
    ../../src/ml_kem_encaps_pool.c

TEST = test.c

TARGET = test

all:
	$(CC) $(CFLAGS) $(SRC_CORE) $(TEST) -lm -o $(TARGET)

clean:
	rm -f $(TARGET)
