CC = gcc

CFLAGS = -O2 -std=c11 -Wall -Wextra \
         -I../userspace \
         -pthread \
         -fno-tree-vectorize \
         -fno-builtin \
         -fno-omit-frame-pointer

SRC_CORE = \
    ../userspace/keccak1600.c \
    ../userspace/math_operations.c \
    ../userspace/ml_kem.c \
    ../userspace/ml_kem_create_keys.c \
    ../userspace/ml_kem_decrypt.c \
    ../userspace/ml_kem_encaps.c \
    ../userspace/ml_kem_ntt_main.c \
    ../userspace/ml_kem_pool.c \
    ../userspace/ml_kem_sha3.c \
    ../userspace/ml_kem_shake.c

OBJ_CORE = $(SRC_CORE:.c=.o)

TEST = TEST_rand.c
TEST_OBJ = $(TEST:.c=.o)

TARGET = test_rand

all: $(TARGET)

$(TARGET): $(OBJ_CORE) $(TEST_OBJ)
	$(CC) $(CFLAGS) $^ -lm -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_CORE) $(TEST_OBJ) $(TARGET)
