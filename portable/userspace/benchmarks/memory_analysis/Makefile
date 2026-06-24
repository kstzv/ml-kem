CC      = gcc
CFLAGS  = -O3 -std=c11 -Wall -Wextra -pedantic

USERSPACE = ../../src

USERSPACE_SRCS = \
	$(USERSPACE)/keccak1600.c \
	$(USERSPACE)/ml_kem.c \
	$(USERSPACE)/ml_kem_create_keys.c \
	$(USERSPACE)/ml_kem_decrypt.c \
	$(USERSPACE)/ml_kem_encaps.c \
	$(USERSPACE)/ml_kem_ntt_main.c \
	$(USERSPACE)/ml_kem_pool.c \
	$(USERSPACE)/ml_kem_sha3.c \
	$(USERSPACE)/ml_kem_shake.c
	
test: test.c $(USERSPACE_SRCS)
	$(CC) $(CFLAGS) -I$(USERSPACE) \
	$^ -o $@
	
clean:
	rm -f \
	test
