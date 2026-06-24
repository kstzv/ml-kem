CC      = gcc
CFLAGS  = -O3 -std=c11 -Wall -Wextra -pthread

USERSPACE = ../../src

PQCLEAN = ../pqclean/PQClean/crypto_kem

PQCLEAN_COMMON = \
	../pqclean/PQClean/common/fips202.c \
	../pqclean/PQClean/common/randombytes.c

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

all: \
	kstzv_throughput_ml_kem_512 \
	kstzv_throughput_ml_kem_768 \
	kstzv_throughput_ml_kem_1024 \
	pqclean_throughput_ml_kem_512 \
	pqclean_throughput_ml_kem_768 \
	pqclean_throughput_ml_kem_1024

#
# KSTZV
#

kstzv_throughput_ml_kem_512: kstzv_throughput_ml_kem_512.c $(USERSPACE_SRCS)
	$(CC) $(CFLAGS) -I$(USERSPACE) \
	$^ -o $@

kstzv_throughput_ml_kem_768: kstzv_throughput_ml_kem_768.c $(USERSPACE_SRCS)
	$(CC) $(CFLAGS) -I$(USERSPACE) \
	$^ -o $@

kstzv_throughput_ml_kem_1024: kstzv_throughput_ml_kem_1024.c $(USERSPACE_SRCS)
	$(CC) $(CFLAGS) -I$(USERSPACE) \
	$^ -o $@

#
# PQClean 512
#

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

pqclean_throughput_ml_kem_512: pqclean_throughput_ml_kem_512.c
	$(CC) $(CFLAGS) \
	-I$(PQCLEAN)/ml-kem-512/clean \
	-I../pqclean/PQClean/common \
	$^ $(PQCLEAN512) $(PQCLEAN_COMMON) \
	-o $@

#
# PQClean 768
#

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

pqclean_throughput_ml_kem_768: pqclean_throughput_ml_kem_768.c
	$(CC) $(CFLAGS) \
	-I$(PQCLEAN)/ml-kem-768/clean \
	-I../pqclean/PQClean/common \
	$^ $(PQCLEAN768) $(PQCLEAN_COMMON) \
	-o $@

#
# PQClean 1024
#

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

pqclean_throughput_ml_kem_1024: pqclean_throughput_ml_kem_1024.c
	$(CC) $(CFLAGS) \
	-I$(PQCLEAN)/ml-kem-1024/clean \
	-I../pqclean/PQClean/common \
	$^ $(PQCLEAN1024) $(PQCLEAN_COMMON) \
	-o $@

clean:
	rm -f \
	kstzv_throughput_ml_kem_512 \
	kstzv_throughput_ml_kem_768 \
	kstzv_throughput_ml_kem_1024 \
	pqclean_throughput_ml_kem_512 \
	pqclean_throughput_ml_kem_768 \
	pqclean_throughput_ml_kem_1024
