# ML-KEM (FIPS 203) — Pure C Implementation

A low-level implementation of the ML-KEM (Kyber) post-quantum key encapsulation mechanism, written in pure C.

This project focuses on correctness, transparency, architectural clarity and predictable resource usage.

## 📌 Overview

The implementation focuses on architectural clarity, portability, and explicit memory control.

The project is organized as a portable implementation with environment-specific ports, allowing the same cryptographic core to be reused across different platforms.

The design avoids external dependencies and introduces a custom decapsulation pool to reduce allocation overhead and improve performance in constrained or kernel environments.

The implementation follows standard C semantics to simplify porting across different platforms.

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

✔ ASAN / TSAN / UBSAN / Valgrind testing

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
- Designed for portability (userspace + kernel)

## 🚀 Future Work

- Extended multi-architecture validation
- Additional compiler and optimization-level testing
- AF_ALG integration for Linux kernel testing
- Kernel-space KAT validation
- Extended kernel-space stress testing
- Additional performance optimization passes
- Fuzzing and long-term robustness testing
- External security review and independent validation
- Documentation improvements

### 🔧 Hardware Acceleration (Exploration)

Planned investigation of hardware-assisted acceleration paths, including:

- Feasibility of integrating CPU-specific optimizations (e.g. SIMD, instruction sets)
- Potential use of platform-provided cryptographic accelerators
- Evaluation of abstraction layers for optional hardware backends
- Analysis of constant-time implications of hardware-assisted paths

The goal is to explore performance improvements without compromising portability or introducing mandatory dependencies.

---

## 🧱 Project Structure

- **portable/**
  - **src/** — Core portable ML-KEM implementation
  - **benchmarks/** — Performance evaluation and implementation comparisons
  - **tests/** — Functional, security and robustness tests
  - **ports/**
    - **userspace/** — Linux userspace integration
    - **linux_kernel/** — Linux kernel integration

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
- UndefinedBehaviorSanitizer (UBSAN)

### ✔ Robustness Testing
- Invalid ciphertext handling tests
- Decapsulation fallback (`z`) logic validation
- Input validation and error-handling tests

### ✔ Kernel Validation
- Linux kernel module builds successfully
- Kernel module load/unload validation

Detailed reproducible test setups and instructions are available in the `tests/` directory and its subdirectories.

### Planned
- AF_ALG-based kernel-space validation
- Extended kernel-space stress testing
- Additional multi-architecture testing
- Additional fuzzing and robustness testing
- Randomness quality analysis
---

## Performance Evaluation

Reproducible benchmark procedures, throughput measurements, stack usage analysis, memory usage measurements and PQClean comparisons are documented in:

     portable/benchmarks/README.md
     
## Userspace Support

For build instructions, API usage, and integration details, see: portable/ports/userspace/README.md

## 🐧 Kernel Support

The repository includes an experimental Linux kernel integration prototype.

Current kernel-related work is primarily intended for architectural exploration and future integration with Linux kernel cryptographic infrastructure.

Potential future directions include:

- Integration with Linux crypto subsystems
- Embedded and resource-constrained environments
- In-kernel cryptographic services
- Evaluation of reusable workspace and memory-management strategies

More details in: portable/ports/linux_kernel/README.md

---

## ⚙️ Build and Usage

Build instructions, integration examples, API documentation and environment-specific notes are provided in the corresponding implementation directories.

Available documentation:

- portable/ports/userspace/README.md — Linux userspace implementation
- portable/ports/linux_kernel/README.md — Linux kernel implementation

Please refer to the README file of the target environment before building or integrating the project.

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

