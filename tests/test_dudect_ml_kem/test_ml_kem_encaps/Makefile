CC ?= gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra -Wpedantic \
         -I../../src \
         -I../userspace \
			
LDFLAGS = -lm

SRC = \
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

TESTS = $(wildcard TEST_*.c)
TARGETS = $(TESTS:.c=)

all: $(TARGETS)

%: %.c $(SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
