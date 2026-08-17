# ML-KEM (FIPS 203) — Pure C Implementation

A low-level implementation of the ML-KEM (Kyber) post-quantum key encapsulation mechanism, written in pure C.

This project focuses on correctness, transparency, architectural clarity and predictable resource usage.

## 📌 Overview

The implementation focuses on architectural clarity, portability, and explicit memory control.

The project is organized as a portable implementation with environment-specific ports, allowing the same cryptographic core to be reused across different platforms.

The design avoids external dependencies and introduces a custom decapsulation pool to reduce allocation overhead and improve performance in constrained or kernel environments.

The implementation follows standard C semantics to simplify porting across different platforms.

---

## Architecture and Recommended Reading Order

This implementation is organized primarily around the execution flow of ML-KEM and the explicit management of its memory resources, 
rather than around individual mathematical objects such as polynomials and polynomial vectors.

The recommended reading order is:

1. Memory creation and resource management (ml_kem_pool.c). Begin with the creation and organization of the memory required by an ML-KEM key and its associated operations. 
This module shows how reusable contexts and decapsulation slots are created, organized, acquired, and released. It defines the memory environment in which the main algorithmic phases execute.

2. Key creation. Follow the generation of the public and private key material and observe how the previously created memory is divided and reused during the process.

3. Encapsulation. Read the encapsulation procedure as a sequential transformation from the public key and fresh randomness to the ciphertext and shared secret. 
The internal encapsulation functionality is also reused later as part of decapsulation.

4. Decryption. Follow the internal decryption procedure separately. It recovers the candidate message from the ciphertext using the private key and provides 
the intermediate result required by the complete decapsulation flow.

5. Decapsulation in the public API. Complete decapsulation is assembled directly in the public API wrapper rather than implemented as another independent internal algorithmic module.
The wrapper combines the existing internal decryption and encapsulation functions: it decrypts the received ciphertext, reuses the encapsulation logic to reconstruct the expected ciphertext, 
performs the required verification and implicit rejection, and derives the final shared secret. 

Reading decapsulation at the API level therefore shows how the existing internal phases are composed into the complete standardized operation, 
while avoiding a duplicate implementation of encapsulation logic.

These modules are intended to be read as sequential data flows. They explicitly control the placement, lifetime, ownership, reuse, and transformation of intermediate values.

Lower-level modules provide reusable computational mechanisms invoked by the main execution phases:

 - NTT and polynomial arithmetic

 - SHA3 and SHAKE

 - Keccak-f[1600]

 - Modular arithmetic and reductions

 - Sampling and centered binomial distribution

For this reason, the implementation should generally be read from the resource-management layer into one of the high-level algorithmic phases, and then from input to output within that phase. 
Lower-level modules should be consulted when they are invoked by the execution flow.

This differs from implementations organized primarily around mathematical abstractions such as poly, polyvec, and indcpa. 
Here, mathematical primitives are separated when they form substantial reusable computational mechanisms, while simpler operations remain visible within the phase in which they are performed.

This organization is intentional. It supports explicit memory management, predictable data lifetimes, reusable operation contexts, bounded concurrency, reuse of complete internal phases, and direct inspection of the complete algorithmic flow.

---

## ⚠️ Status

### Portable core

Stable (v1.4.0)

The portable ML-KEM core is shared across all supported environments and is the primary implementation maintained by the project.

### Linux userspace port

Stable

The Linux userspace port is extensively tested and serves as the primary environment for comprehensive validation and performance benchmarking.

Validated using:

✔ NIST KAT tests (key generation & encapsulation)

✔ End-to-end decapsulation validation

✔ dudect constant-time leakage testing

✔ Stress testing of the decapsulation pool

✔ Invalid ciphertext handling tests

✔ Input validation and error-handling tests

✔ ASAN / TSAN / Valgrind testing

✔ Multi-million iteration stress tests

✔ GCC and Clang testing

### Linux kernel port

Tested

The Linux kernel port integrates the same portable ML-KEM core into the Linux kernel environment through a platform-specific port layer.

Validated using:

✔ Successful kernel build

✔ Module load/unload testing

✔ Functional ML-KEM testing in kernel space

✔ Reuse of the common portable cryptographic core

### FreeRTOS port

Tested

The FreeRTOS port integrates the same portable ML-KEM core into an RTOS environment through a platform-specific port layer.

The reference FreeRTOS configuration has been successfully built and tested using QEMU with repeated end-to-end ML-KEM operations.

Detailed platform configurations and testing information are documented in the corresponding port directories.

### Notes

The project provides a portable cryptographic core with tested integrations across userspace, kernel-space, and RTOS environments.

Additional testing on other architectures, toolchains, and platforms is encouraged.

No formal third-party security audit has been performed.
---

## 🎯 Goals

- Provide a **clean, readable implementation** of ML-KEM (FIPS 203)
- Maintain **strict control over memory and data flow**
- Avoid external dependencies (including crypto libraries)
- Enable straightforward porting across different execution environments

---

## ✨ Features

- Pure C (C11), no external libraries
- Zero-dependency cryptographic core
- Own implementations of:
  - SHA3-256 / SHA3-512
  - SHAKE128 / SHAKE256
  - Keccak-f[1600]
- Full polynomial arithmetic:
  - NTT / inverse NTT
  - Barrett reduction
- ML-KEM components:
  - Key generation
  - Encapsulation
  - Decapsulation
- Memory pool for decapsulation contexts (lock-free with atomics)
- Designed for portability across different execution environments

## 🔧 Ongoing Work

 - Extended multi-architecture and toolchain validation
 - Additional compiler and optimization-level testing
 - Performance and memory optimization
 - Fuzzing and long-term robustness testing
 - External security review and independent validation
 - Documentation improvements
 - Additional platform ports where useful

### 🔧 Hardware Acceleration (Exploration)

Potential future investigation of hardware-assisted acceleration paths includes:

- CPU-specific optimizations (e.g. SIMD and specialized instruction sets)
- Platform-provided cryptographic accelerators
- Optional hardware backend abstraction layers
- Analysis of constant-time implications of hardware-assisted paths

Any hardware-specific optimization should preserve the portability of the cryptographic core and avoid introducing mandatory platform dependencies.

---

## 🧱 Project Structure

- **portable/**
  - **src/** — Core portable ML-KEM implementation
  - **benchmarks/** — Performance evaluation and implementation comparisons
  - **tests/** — Functional, security and robustness tests
  - **ports/**
    - **userspace/** — Linux userspace integration
    - **linux_kernel/** — Linux kernel integration
    - **freertos/** - FreeRTOS integration

---

## 🧠 Architecture Overview

The implementation is built around explicit context structures:

- `ml_kem_ctx` — persistent key material
- `ml_kem_temp` — temporary buffers for key generation
- `ml_kem_encaps_ctx` — encapsulation context
- `ml_kem_decrypt_ctx` — decapsulation context
- `ml_kem_pool_decaps_ctx` — pool of reusable decapsulation slots

Key design ideas:

- Separation of **persistent vs temporary memory**
- Avoidance of hidden allocations
- Explicit lifecycle control (alloc / wipe / destroy)
- Minimal abstraction overhead

---

## 🔐 Security Considerations

- No secret-dependent branching in critical cryptographic paths (where applicable)
- Constant-time oriented implementation design
- Explicit memory zeroization (`ml_kem_memzero`)
- Separation of public and secret data flows
- Constant-time selection logic for decapsulation fallback handling
- Designed to minimize secret-dependent behavior across cryptographic operations

Validation performed on tested x86-64 environments includes:

- ✔ dudect constant-time leakage testing
- ✔ GCC and Clang testing
- ✔ ASAN / TSAN / Valgrind validation
- ✔ Stress testing and malformed ciphertext testing
- ✔ Input validation and error-handling tests

⚠️ However:

- Constant-time behavior is not formally proven
- Compiler optimizations may still affect generated machine code
- Additional validation on other architectures and toolchains is encouraged
- No formal third-party security audit has been performed
---

## 🧪 Testing

The implementation includes dedicated test suites covering correctness, robustness, concurrency, memory safety, and constant-time behavior.

Implemented test categories include:

### ✔ NIST KAT Validation
- Key generation KAT tests
- Encapsulation KAT tests
- End-to-end decapsulation validation

### ✔ Constant-Time Validation
- dudect testing for primary secret-dependent execution paths
- Validation of decapsulation logic
- Validation of polynomial arithmetic and modular operations
- Validation of SHA3 / SHAKE wrapper usage
- GCC and Clang testing

### ✔ Stress Testing
- Multi-million iteration stress tests
- High-contention decapsulation pool testing
- Multi-thread validation using atomic slot management

### ✔ Memory Safety Validation
- AddressSanitizer (ASAN)
- ThreadSanitizer (TSAN)
- Valgrind memory analysis

### ✔ Robustness Testing
- Invalid ciphertext handling tests
- Decapsulation fallback (`z`) logic validation
- Input validation and error-handling tests

### ✔ Kernel Validation
- Linux kernel module builds successfully
- Kernel module load/unload validation
- Functional testing of the ML-KEM implementation port in kernel space

### ✔ FreeRTOS Validation
- FreeRTOS integration and build validation
- Functional ML-KEM testing under FreeRTOS
- Repeated end-to-end key generation, encapsulation, and decapsulation testing
- Reference testing on Arm Cortex-M3 under QEMU

Detailed reproducible test setups and instructions are available in the `tests/` directory and its subdirectories.

---

## Performance Evaluation

Reproducible benchmark procedures, throughput measurements, stack usage analysis, memory usage measurements and PQClean comparisons are documented in:

     portable/benchmarks/README.md
     
## ⚙️ Platform Support

Platform-specific integration, build instructions, and configuration details are documented in the corresponding port directories:

- Linux userspace: portable/ports/userspace/README.md
- Linux kernel: portable/ports/linux_kernel/README.md
- FreeRTOS: portable/ports/freertos/README.md

For information about porting the implementation to a new environment, see:

- Porting guide: portable/ports/PORTING.pdf

---

## 📌 Notes

- This project intentionally avoids external crypto libraries.
- If your compiler aggressively optimizes memory operations,
  consider replacing `ml_kem_memzero()` with a platform-specific secure wipe.

---

## License

This project is dual-licensed under:

- GNU General Public License v2.0
- MIT License

You may choose either license.

---

## 🤝 Contributing

Feedback, reviews, and suggestions are welcome.

---

## 📬 Contact

- GitHub: https://github.com/kstzv
- Email: kstzavertaylo@gmail.com

