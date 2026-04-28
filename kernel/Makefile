obj-m += ml_kem_module.o

ml_kem_module-objs := \
    ml_kem_init.o \
    ml_kem.o \
    ml_kem_create_keys.o \
    ml_kem_encaps.o \
    ml_kem_decrypt.o \
    ml_kem_ntt_main.o \
    math_operations.o \
    ml_kem_pool.o \
    keccak1600.o \
    ml_kem_sha3.o \
    ml_kem_shake.o

ccflags-y += -Wall -Wextra

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
