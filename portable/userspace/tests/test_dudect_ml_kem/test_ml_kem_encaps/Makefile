CC ?= gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra -Wpedantic \
         -I../../src \
         -DML_KEM_DUDECT_TEST \
         -I../../../../src \
			
LDFLAGS = -lm

SRC = \
		../../../../src/keccak1600.c \
		../../../../src/ml_kem.c \
		../../../../src/ml_kem_create_keys.c \
		../../../../src/ml_kem_decrypt.c \
		../../../../src/ml_kem_encaps.c \
		../../../../src/ml_kem_ntt_main.c \
		../../../../src/ml_kem_pool.c \
		../../../../src/ml_kem_sha3.c \
		../../../../src/ml_kem_shake.c

TESTS = $(wildcard TEST_*.c)
TARGETS = $(TESTS:.c=)

all: $(TARGETS)

%: %.c $(SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
