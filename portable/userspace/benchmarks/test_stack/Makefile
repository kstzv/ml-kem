CC = gcc
CFLAGS = -O3 -std=c11 -Wall -Wextra -pthread -fstack-usage

USERSPACE = ../../src
PQCLEAN = ../pqclean/PQClean/crypto_kem
COMMON = ../pqclean/PQClean/common

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

COMMON_SRCS = \
	$(COMMON)/fips202.c \
	$(COMMON)/randombytes.c

PQCLEAN512 = \
	$(PQCLEAN)/ml-kem-512/clean/cbd.c \
	$(PQCLEAN)/ml-kem-512/clean/indcpa.c \
	$(PQCLEAN)/ml-kem-512/clean/kem.c \
	$(PQCLEAN)/ml-kem-512/clean/ntt.c \
	$(PQCLEAN)/ml-kem-512/clean/poly.c \
	$(PQCLEAN)/ml-kem-512/clean/polyvec.c \
	$(PQCLEAN)/ml-kem-512/clean/reduce.c \
	$(PQCLEAN)/ml-kem-512/clean/symmetric-shake.c \
	$(PQCLEAN)/ml-kem-512/clean/verify.c

PQCLEAN768 = \
	$(PQCLEAN)/ml-kem-768/clean/cbd.c \
	$(PQCLEAN)/ml-kem-768/clean/indcpa.c \
	$(PQCLEAN)/ml-kem-768/clean/kem.c \
	$(PQCLEAN)/ml-kem-768/clean/ntt.c \
	$(PQCLEAN)/ml-kem-768/clean/poly.c \
	$(PQCLEAN)/ml-kem-768/clean/polyvec.c \
	$(PQCLEAN)/ml-kem-768/clean/reduce.c \
	$(PQCLEAN)/ml-kem-768/clean/symmetric-shake.c \
	$(PQCLEAN)/ml-kem-768/clean/verify.c

PQCLEAN1024 = \
	$(PQCLEAN)/ml-kem-1024/clean/cbd.c \
	$(PQCLEAN)/ml-kem-1024/clean/indcpa.c \
	$(PQCLEAN)/ml-kem-1024/clean/kem.c \
	$(PQCLEAN)/ml-kem-1024/clean/ntt.c \
	$(PQCLEAN)/ml-kem-1024/clean/poly.c \
	$(PQCLEAN)/ml-kem-1024/clean/polyvec.c \
	$(PQCLEAN)/ml-kem-1024/clean/reduce.c \
	$(PQCLEAN)/ml-kem-1024/clean/symmetric-shake.c \
	$(PQCLEAN)/ml-kem-1024/clean/verify.c

userspace:
	rm -f *.o *.su
	$(CC) $(CFLAGS) -I$(USERSPACE) -c $(USERSPACE_SRCS)
	echo
	echo "===== KSTZV ====="
	cat *.su | sort -k2 -n | tail -30

pq512:
	rm -f *.o *.su
	$(CC) $(CFLAGS) -I$(PQCLEAN)/ml-kem-512/clean -I$(COMMON) -c $(PQCLEAN512) $(COMMON_SRCS)
	echo
	echo "===== PQClean ML-KEM-512 ====="
	cat *.su | sort -k2 -n | tail -30

pq768:
	rm -f *.o *.su
	$(CC) $(CFLAGS) -I$(PQCLEAN)/ml-kem-768/clean -I$(COMMON) -c $(PQCLEAN768) $(COMMON_SRCS)
	echo
	echo "===== PQClean ML-KEM-768 ====="
	cat *.su | sort -k2 -n | tail -30

pq1024:
	rm -f *.o *.su
	$(CC) $(CFLAGS) -I$(PQCLEAN)/ml-kem-1024/clean -I$(COMMON) -c $(PQCLEAN1024) $(COMMON_SRCS)
	echo
	echo "===== PQClean ML-KEM-1024 ====="
	cat *.su | sort -k2 -n | tail -30

clean:
	rm -f *.o *.su

.PHONY: userspace pq512 pq768 pq1024 clean68 pq1024 clean
