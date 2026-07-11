# SPDX-License-Identifier: GPL-2.0 OR MIT

ccflags-y += -DLINUX_KERNEL

obj-$(CONFIG_ML_KEM) += pqc_ml_kem.o

pqc_ml_kem-y := \
        ml_kem.o \
        ml_kem_create_keys.o \
        ml_kem_encaps.o \
        ml_kem_decrypt.o \
        ml_kem_ntt_main.o \
        ml_kem_sha3.o \
        ml_kem_shake.o \
        keccak1600.o \
        ml_kem_pool.o \
        ml_kem_linux_kernel_port.o
