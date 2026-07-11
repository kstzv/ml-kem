# Linux Kernel Port

The commands below assume that the Linux kernel source tree is available in the directory linux/.

## Overview

This is a port of the ML-KEM implementation to the Linux kernel and a description of the process of building and adding this implementation ML-KEM to the Linux kernel

## Directory Layout

	-**lib/**
		-**crypto/**
			-**ml_kem/**

## Integration

For integration, you need to create a corresponding directory in the Linux kernel tree at a specific location and copy the implementation files: there:

		mkdir -p linux/lib/crypto/ml_kem
		
		cp portable/src/*.c linux/lib/crypto/ml_kem/
		cp portable/src/*.h linux/lib/crypto/ml_kem/
		
		cp portable/ports/linux_kernel/*.c linux/lib/crypto/ml_kem/
		cp portable/ports/linux_kernel/*.h linux/lib/crypto/ml_kem/
		cp portable/ports/linux_kernel/Makefile linux/lib/crypto/ml_kem/
		cp portable/ports/linux_kernel/Kconfig linux/lib/crypto/ml_kem/
		cp portable/ports/linux_kernel/README.md linux/lib/crypto/ml_kem/

In the file

		linux/lib/crypto/Makefile 
		
you should add

		obj-$(CONFIG_ML_KEM) += ml_kem/
		
In the file

		linux/lib/crypto/Kconfig
		
you should add

		source "lib/crypto/ml_kem/Kconfig"

## Build

Configure the kernel:

		cd linux
		make menuconfig
		
Enable:

		ML-KEM (FIPS 203) support
		
And then execute the following command:

		make -j$(nproc)
		
## Installation

To install, run the following commands:

		sudo make modules_install
		sudo make install
		
Reboot the system into the newly built kernel.

## Verification

Verify that ML-KEM support is enabled:

		grep ML_KEM .config
		
## Remove the port

Remove the directory:

        lib/crypto/ml_kem/

Remove the following line from:

        lib/crypto/Makefile

        obj-$(CONFIG_ML_KEM) += ml_kem/

Remove the following line from:

        lib/crypto/Kconfig

        source "lib/crypto/ml_kem/Kconfig"

Rebuild the kernel.

## Port testing

The Linux kernel port introduces only a thin platform adaptation layer. The complete ML-KEM implementation, including all cryptographic operations, memory management, reusable decapsulation pool, and public API logic, resides in the shared `portable/src` directory, which is used unchanged across all supported platforms.

Because the implementation is shared, comprehensive functional testing is performed against the common source tree in the userspace environment. These tests validate the implementation itself and therefore apply equally to every platform using the same `portable/src` codebase.

The Linux kernel tests are therefore focused exclusively on validating the platform integration layer. They verify that the shared implementation operates correctly through the Linux kernel abstraction layer and that the kernel-specific port behaves as expected.

The following kernel-specific tests are provided:

- **Build test** — verifies successful integration and compilation inside the Linux kernel.
- **API test** — validates successful object creation, encapsulation, decapsulation, shared-secret verification, and public API operation from a loadable kernel module.
- **API stress test** — repeatedly executes encapsulation and decapsulation operations through the Linux kernel API to verify long-running stability of the integration layer.

## Notes

When compiling code against this port, ensure that:

- the compiler include path contains `lib/crypto/ml_kem`;
- the `LINUX_KERNEL` preprocessor macro is defined.

These settings select the Linux kernel platform layer and allow the shared implementation to include the correct platform-specific abstractions.
