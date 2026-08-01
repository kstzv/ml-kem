# Tested configuration

This FreeRTOS port was integrated and tested using the following reference configuration:

- FreeRTOS demonstration project: `CORTEX_MPS2_QEMU_IAR_GCC`
- Target platform: Arm MPS2 AN385
- Processor: Arm Cortex-M3
- Architecture: Armv7-M
- Nearest FreeRTOS release tag: `202212.00` 
- FreeRTOS repository revision: `202212.00-323-g592732b4d`
- Execution environment: QEMU system emulation
- Host operating system used for testing: Linux
- Toolchain: GNU Arm Embedded Toolchain (`arm-none-eabi-gcc`)
- Build system: GNU Make
- Emulator: `qemu-system-arm`

The test application performs ML-KEM key generation, encapsulation and
decapsulation for all supported parameter sets. The reference test was
successfully executed for 1000 iterations under QEMU.

The port was tested on an emulated Arm MPS2 AN385 platform. Testing under
QEMU verifies compilation, execution and integration with FreeRTOS, but
does not replace validation on physical hardware, particularly for
platform-specific entropy sources, timing, performance, stack usage and
hardware-dependent behavior.

# Required software

The following software is required to reproduce the reference build and
test:

- Git, including support for Git submodules
- GNU Make
- GNU Arm Embedded Toolchain providing `arm-none-eabi-gcc`
- QEMU with `qemu-system-arm`
- A POSIX-compatible host environment

The exact compiler and QEMU versions used for the reference test are:

- `arm-none-eabi-gcc`: 14.2.1
- `qemu-system-arm`: QEMU emulator version 11.0.2
- GNU Make 4.4.1

Other versions may also work, but the configuration listed above is the
one for which the port was tested.

# Overview

This directory contains a FreeRTOS port and an integration example for the ML-KEM implementation. 
The cryptographic core is shared with the other supported environments, 
while the FreeRTOS-specific layer provides memory management, synchronization, entropy integration, and build-system support. 
The reference configuration was built and executed for an emulated Arm Cortex-M3 target using QEMU.

The primary purpose of this port is to demonstrate and verify the portability of the common ML-KEM C implementation outside POSIX and Linux-kernel environments. 
FreeRTOS was selected as a representative operating system for embedded and memory-constrained targets. 
The port is intentionally kept thin so that platform-independent cryptographic code remains shared between all supported environments.

FreeRTOS was chosen because it represents a substantially different execution environment from both Linux userspace and the Linux kernel. 
Its explicit task-stack allocation, configurable heap implementation, platform-dependent entropy facilities, 
and embedded-oriented synchronization primitives make it a useful target for validating the separation between the portable cryptographic core and the operating-system integration layer.

ML-KEM does not depend on MPS2-specific hardware. MPS2 AN385 is used only as the tested reference configuration for the FreeRTOS port.

Successful execution under QEMU validates the software integration for this target configuration, but does not replace testing on physical hardware, 
particularly for hardware entropy sources, timing behaviour, and platform-specific fault conditions.

# Stack size

The test task was assigned a 2048-byte stack. This is a deliberately conservative embedded-oriented budget rather than the measured minimum required by the ML-KEM implementation. 
A smaller task stack may be sufficient, particularly because the implementation avoids large stack allocations, but no portable minimum can be guaranteed across platforms. 
Stack usage may vary with the target architecture, data type sizes and alignment, compiler version and optimization options, FreeRTOS configuration, diagnostic code, entropy provider, and selected ML-KEM parameter set.

The 2048-byte task stack used by the reference configuration is not a minimum requirement or a lower limit of the implementation; a smaller stack may be sufficient. 
Because actual stack usage depends on the target platform and build configuration, it must be measured for the intended environment using the dedicated stack-benchmark programs provided in ml-kem/portable/benchmarks/test_stack.
Applications that require a stack smaller than 2048 bytes should use the stack benchmarks provided in this repository and repeat the measurements on the exact target platform and build configuration. 
The FreeRTOS stack high-water mark should be monitored while exercising all relevant ML-KEM operations and parameter sets. 
An appropriate safety margin must then be added to the maximum observed usage before selecting the final task-stack size.

# Reproducing the reference test

## Obtaining FreeRTOS

This integration uses the `CORTEX_MPS2_QEMU_IAR_GCC` demonstration project included in the complete FreeRTOS distribution. Clone the official FreeRTOS repository together with all of its submodules:

     git clone --recurse-submodules https://github.com/FreeRTOS/FreeRTOS.git
     
     cd FreeRTOS
     
All paths in the following instructions are relative to the root of the cloned FreeRTOS repository.
The reference demonstration project used by this port is located at:

     FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC
     
Do not clone only the standalone FreeRTOS-Kernel repository: it contains the kernel sources but not the complete collection of demonstration projects required by this integration.
If the repository was cloned without --recurse-submodules, initialize its submodules separately:

    git submodule update --init --recursive
    
    
## Adding the ML-KEM Sources

Navigate to the FreeRTOS demonstration project:

    cd FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC
    
Create a directory for the ML-KEM sources:
    
    mkdir ml_kem

Copy the two FreeRTOS-specific port files from the ML-KEM repository into the new directory:

    cp <path-to-ml-kem>/portable/ports/freertos/ml_kem_freertos_port.c ml_kem/
    cp <path-to-ml-kem>/portable/ports/freertos/ml_kem_freertos_port.h ml_kem/
    
Then copy all files that form the portable ML-KEM implementation:

    cp <path-to-ml-kem>/portable/src/* ml_kem/
    
Here, `<path-to-ml-kem>` must be replaced with the path to the cloned ML-KEM repository. After copying, the FreeRTOS demonstration project should contain the following directory:

    FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC/ml_kem
    
This directory contains both the shared platform-independent ML-KEM implementation and the thin FreeRTOS-specific port layer.

## Configuring the Makefile

To include the ML-KEM sources in the reference build, modify the FreeRTOS demonstration project's `build/gcc/Makefile` as described below.
Locate the existing CFLAGS definitions and add the following lines immediately after them:
    
    # ML-KEM FreeRTOS port configuration
    CFLAGS += -std=c11
    CFLAGS += -DFREERTOS
    CFLAGS += -DML_KEM_ATOMIC_FREERTOS

Locate the section in which SOURCE_FILES and INCLUDE_DIRS are defined. 
Add the following block after the existing source-directory definitions and before SOURCE_FILES is converted into the final object-file list:

    # ML-KEM source directory, relative to build/gcc
    ML_KEM_DIR = ../../ml_kem
    INCLUDE_DIRS += -I$(ML_KEM_DIR)
    VPATH += $(ML_KEM_DIR)
    
    SOURCE_FILES += $(ML_KEM_DIR)/keccak1600.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_create_keys.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_decrypt.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_encaps.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_freertos_port.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_ntt_main.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_pool.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_sha3.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_shake.c

The block must appear before the Makefile derives the object-file list from SOURCE_FILES; otherwise the ML-KEM sources will not be included in that list.

## Installing the Reference Test Application

This operation overwrites the demonstration project's existing `main.c`. If that file contains changes that must be preserved, back it up before continuing.
The complete ML-KEM test application is provided as a replacement `main.c` for the tested FreeRTOS demonstration project. From the `CORTEX_MPS2_QEMU_IAR_GCC` directory, run:

    cp <path-to-ml-kem>/portable/ports/freertos/examples/CORTEX_MPS2_QEMU_IAR_GCC/main.c ./main.c
    
This command replaces the original demonstration application's main.c. It is intended to reproduce the tested ML-KEM reference 
configuration and should be used with the FreeRTOS revision identified in this document.

The supplied application initializes the target, registers the test
entropy provider, creates the ML-KEM test task, exercises key generation, encapsulation and decapsulation, and starts the FreeRTOS scheduler.
The deterministic entropy provider included in this test application is
intended solely for reproducible testing under QEMU. It must not be used in production.

## Run the test

Navigate to `FreeRTOS/FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC/build/gcc/` and run:
    
    make
    qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -kernel ./output/RTOSDemo.out -monitor none -serial stdio -display none
    
After the test results are displayed, press Ctrl+C to stop QEMU.



