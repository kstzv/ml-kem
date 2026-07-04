CC ?= cc
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -DUSERSPACE -I../../src -I.

SRC = ../../src

USERSPACE = \
	ml_kem_userspace_port.c \
    $(SRC)/ml_kem.c \
    $(SRC)/ml_kem_create_keys.c \
    $(SRC)/ml_kem_encaps.c \
    $(SRC)/ml_kem_decrypt.c \
    $(SRC)/ml_kem_pool.c \
    $(SRC)/ml_kem_ntt_main.c \
    $(SRC)/ml_kem_shake.c \
    $(SRC)/ml_kem_sha3.c \
    $(SRC)/keccak1600.c

OBJ = $(USERSPACE:.c=.o)

libmlkem.a: $(OBJ)
	ar rcs $@ $(OBJ)

all: libmlkem.a

clean:
	rm -f $(OBJ) libmlkem.a
