# Tested configuration

The ML-KEM FreeRTOS port was successfully built and tested using the following configuration:

- FreeRTOS demonstration project: `CORTEX_MPS2_QEMU_IAR_GCC`
- Target platform: Arm MPS2 AN385
- Processor: Arm Cortex-M3
- Architecture: Armv7-M
- FreeRTOS distribution: Official repository, obtained without pinning a specific release or revision
- Execution environment: QEMU system emulation
- Host operating system: Linux
- Toolchain: GNU Arm Embedded Toolchain (`arm-none-eabi-gcc`)
- Build system: GNU Make
- Emulator: `qemu-system-arm`

The test application successfully completed 1000 iterations of ML-KEM key generation, encapsulation, and decapsulation for each supported parameter set:

- ML-KEM-512: 1000/1000 — PASS
- ML-KEM-768: 1000/1000 — PASS
- ML-KEM-1024: 1000/1000 — PASS

A total of 3000 iterations were completed successfully. Both encapsulation modes were tested: reusable encapsulation pools and standalone encapsulation with temporary contexts, with 500 iterations per mode for each parameter set. Every iteration verified that the encapsulated and decapsulated shared secrets matched.

The FreeRTOS distribution was obtained using the version-unpinned installation procedure described below, initializing only the submodules required by the demonstration project. The ML-KEM implementation itself does not require a specific FreeRTOS release. Compatibility with future FreeRTOS versions and other hardware configurations must be validated separately.

Testing under QEMU confirms successful compilation, execution, and functional integration with FreeRTOS on the emulated Arm Cortex-M3 platform. It does not replace cryptographic known-answer testing, constant-time analysis, or validation on physical hardware, particularly for platform-specific entropy sources, timing, memory usage, and hardware-dependent behavior.

The test application uses a deterministic entropy callback exclusively for reproducible testing. A cryptographically secure entropy source must be provided in production environments.

# Required software

The following software is required to build and run the QEMU example:

- Git, including support for Git submodules
- GNU Make
- GNU Arm Embedded Toolchain providing `arm-none-eabi-gcc`
- QEMU with `qemu-system-arm`
- A POSIX-compatible host environment

The exact compiler and QEMU versions used for the reference test are:

- `arm-none-eabi-gcc`: 14.2.1
- `qemu-system-arm`: QEMU emulator version 11.0.2
- GNU Make 4.4.1

The versions above document the original reference test; they are not
installation requirements. Compiler, emulator, and FreeRTOS compatibility
should be validated for each target configuration.

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

# Building and running the QEMU example

## Obtaining FreeRTOS

The QEMU integration uses the `CORTEX_MPS2_QEMU_IAR_GCC` demonstration
project from the official FreeRTOS distribution. This demo is only one example
of integrating the ML-KEM FreeRTOS port: the portable cryptographic code does
not depend on the Arm MPS2 hardware or on a particular FreeRTOS demo revision.

Clone the current FreeRTOS distribution without automatically downloading all
its submodules:

```sh
git clone --depth 1 --no-recurse-submodules https://github.com/FreeRTOS/FreeRTOS.git
cd FreeRTOS
```

Initialize only the two submodules required by the QEMU demo: the FreeRTOS
kernel and FreeRTOS-Plus-Trace (TraceRecorder). The demo's Makefile references
both; all other FreeRTOS submodules are unnecessary for this build.

```sh
git submodule update --init --depth 1 \
    FreeRTOS/Source \
    FreeRTOS-Plus/Source/FreeRTOS-Plus-Trace
```

These commands use the default branch of the FreeRTOS distribution and the
matching submodule commits recorded by that checkout. No FreeRTOS release tag
or manual `git checkout` is required. The shallow clones reduce download size
and history; `--recurse-submodules` and `git submodule update --init --recursive`
are intentionally *not* used.

If the FreeRTOS distribution has already been cloned, run only the
`git submodule update` command above from its repository root.

The example directory is:

```text
FreeRTOS/Demo/CORTEX_MPS2_QEMU_IAR_GCC
```

All relative paths below assume the current working directory is the
FreeRTOS distribution root immediately after `cd FreeRTOS`, unless another
working directory is specified.

The standalone `FreeRTOS-Kernel` repository does not include this demonstration
project, so it is not sufficient for the exact QEMU instructions below.

**Compatibility note:** This is a version-unpinned acquisition procedure, not
a promise that every future FreeRTOS release will preserve the demo's files,
Makefile layout, TraceRecorder integration, or configuration. The documented
reference revision above records the original tested environment. For another
FreeRTOS version or board, integrate the same ML-KEM sources and port layer
into the corresponding application build and validate it there.

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
    
    SOURCE_FILES += $(ML_KEM_DIR)/keccak_1600.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_create_keys.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_decrypt.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_encaps.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_freertos_port.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_ntt_main.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_decaps_pool.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_sha3.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_shake.c
    SOURCE_FILES += $(ML_KEM_DIR)/ml_kem_encaps_pool.c

The block must appear before the Makefile derives the object-file list from SOURCE_FILES; otherwise the ML-KEM sources will not be included in that list.

## Installing the Reference Test Application

This operation overwrites the demonstration project's existing `main.c`. If that file contains changes that must be preserved, back it up before continuing.
The complete ML-KEM test application is provided as a replacement `main.c` for the tested FreeRTOS demonstration project. From the `CORTEX_MPS2_QEMU_IAR_GCC` directory, run:

    cp <path-to-ml-kem>/portable/ports/freertos/examples/CORTEX_MPS2_QEMU_IAR_GCC/main.c ./main.c
    
This replaces the demonstration project's original `main.c` with the ML-KEM
example. The example uses the public ML-KEM API supplied in this repository;
keep it in sync with the API when updating the cryptographic implementation.
This procedure targets the documented QEMU demo without requiring a specific
FreeRTOS revision.

The supplied application initializes the target, passes the test entropy
callback to ML-KEM, creates the ML-KEM test task, exercises key generation,
encapsulation and decapsulation, and starts the FreeRTOS scheduler.
The deterministic entropy provider included in this test application is
intended solely for reproducible testing under QEMU. It must not be used in production.

## Run the test

From the demonstration project directory, change to `build/gcc` and run:

```sh
cd build/gcc
make -j4
qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -kernel ./output/RTOSDemo.out -monitor none -serial stdio -display none
```

After the test results are displayed, press Ctrl+C to stop QEMU.

For subsequent changes to ML-KEM, copy the modified source/header files to
`ml_kem/` and rebuild with `make`; a fresh FreeRTOS clone is not necessary.
If needed, use `make clean` before rebuilding. Ensure the FreeRTOS heap is large
enough for the test's allocations, and monitor the task's stack high-water mark.
The actual heap/stack requirements depend on the FreeRTOS configuration,
compiler options, and ML-KEM parameter set.



