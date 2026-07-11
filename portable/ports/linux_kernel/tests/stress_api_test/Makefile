obj-m += test.o

ccflags-y += -I$(srctree)/lib/crypto/ml_kem
ccflags-y += -DLINUX_KERNEL

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
