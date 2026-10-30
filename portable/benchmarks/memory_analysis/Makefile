CC      = gcc
CFLAGS  = -O3 -std=c11 -Wall -Wextra -pedantic \
			-DUSERSPACE \
			-I../../src \
			-I../../ports/userspace

SRC = ../../src
USERSPACE = ../../ports/userspace

USERSPACE_SRCS = \
	$(USERSPACE)/ml_kem_userspace_port.c \
	$(SRC)/keccak_1600.c \
	$(SRC)/ml_kem.c \
	$(SRC)/ml_kem_create_keys.c \
	$(SRC)/ml_kem_decrypt.c \
	$(SRC)/ml_kem_encaps.c \
	$(SRC)/ml_kem_ntt_main.c \
	$(SRC)/ml_kem_decaps_pool.c \
	$(SRC)/ml_kem_sha3.c \
	$(SRC)/ml_kem_shake.c \
	$(SRC)/ml_kem_encaps_pool.c
	
test: test.c $(USERSPACE_SRCS)
	$(CC) -I$(CFLAGS) $^ -o $@
	
clean:
	rm -f test
