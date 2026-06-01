CC ?= cc
CFLAGS ?= -O2 -std=c11

SRC = \
    ml_kem.c \
    ml_kem_create_keys.c \
    ml_kem_encaps.c \
    ml_kem_decrypt.c \
    ml_kem_pool.c \
    ml_kem_ntt_main.c \
    ml_kem_shake.c \
    ml_kem_sha3.c \
    math_operations.c \
    keccak1600.c

OBJ = $(SRC:.c=.o)

libmlkem.a: $(OBJ)
	ar rcs $@ $(OBJ)

all: libmlkem.a

clean:
	rm -f $(OBJ) libmlkem.a
