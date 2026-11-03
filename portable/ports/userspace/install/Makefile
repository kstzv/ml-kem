CC = cc
CFLAGS = -O2 -std=c11 -Wall -Wextra -I. -DUSERSPACE -DFULL_MATRIX=0

SOURCES = ml_kem.c ml_kem_create_keys.c ml_kem_decaps_pool.c \
          ml_kem_decrypt.c ml_kem_encaps.c ml_kem_encaps_pool.c \
          ml_kem_ntt_main.c ml_kem_sha3.c ml_kem_shake.c \
          keccak_1600.c ml_kem_userspace_port.c test_api_userspace.c

.PHONY: all clean
all: test_api_userspace
	./test_api_userspace

test_api_userspace: $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $@

clean:
	rm -f test_api_userspace
