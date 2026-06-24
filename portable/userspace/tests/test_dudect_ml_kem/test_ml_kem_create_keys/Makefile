CC ?= gcc

CFLAGS = -O3 -std=c11 -Wall -Wextra \
         -I../../src \
         -I../src_ml_kem \
			
LDFLAGS = -lm

SRC = \
../src_ml_kem/keccak1600.c \
../src_ml_kem/ml_kem.c \
../src_ml_kem/ml_kem_create_keys.c \
../src_ml_kem/ml_kem_decrypt.c \
../src_ml_kem/ml_kem_encaps.c \
../src_ml_kem/ml_kem_ntt_main.c \
../src_ml_kem/ml_kem_pool.c \
../src_ml_kem/ml_kem_sha3.c \
../src_ml_kem/ml_kem_shake.c

TESTS = $(wildcard TEST_*.c)
TARGETS = $(TESTS:.c=)

all: $(TARGETS)

%: %.c $(SRC)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
