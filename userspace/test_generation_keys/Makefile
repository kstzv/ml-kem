CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11

SRC = \
	test.c \
	ml_kem.c \
	ml_kem_create_keys.c \
	ml_kem_encaps.c \
	ml_kem_decrypt.c \
	ml_kem_ntt_main.c \
	ml_kem_sha3.c \
	ml_kem_shake.c \
	keccak1600.c \
	ml_kem_pool.c \
	math_operations.c

OBJ = $(SRC:.c=.o)

TARGET = test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)


