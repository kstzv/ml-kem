# ML-KEM (FIPS 203) — Pure C Implementation

A low-level implementation of the ML-KEM (Kyber) post-quantum key encapsulation mechanism, written in pure C.

This project focuses on correctness, transparency, and architectural clarity rather than premature optimization or production readiness.

## 📌 Overview

The implementation focuses on architectural clarity, portability, and explicit memory control.

The design avoids external dependencies and introduces a custom decapsulation pool to reduce allocation overhead and improve performance in constrained or kernel environments.

The implementation follows standard C semantics to simplify porting across different platforms, including userspace and Linux kernel.

---

## ⚠️ Status
Beta (v0.3.0)

**This is an early (beta) version.**

- ✔ Userspace implementation is functional
- ✔ NIST KAT tests (key generation & encapsulation) are passing
- ✔ End-to-end decapsulation validated against valid encapsulation outputs
- ✔ Linux kernel module builds and loads/unloads correctly
- ✔ Stress testing of decapsulation pool (see `test_pool/`)

**Not yet:**
- ❌ Full constant-time validation (planned via dudect)
- ❌ Extensive fuzzing
- ❌ Kernel-space validation against KAT
- ❌ Formal security audit

> This implementation is **NOT production-ready**.

---

## 🎯 Goals

- Provide a **clean, readable implementation** of ML-KEM (FIPS 203)
- Maintain **strict control over memory and data flow**
- Avoid external dependencies (including crypto libraries)
- Support both:
  - Userspace
  - Linux kernel environment
- Serve as a **research and educational primary implementation of this project**

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

- Constant-time verification (dudect)
- AF_ALG integration for kernel testing
- Additional optimization passes
- Extended test coverage
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

| File | Description |
|------|------------|
| `ml_kem.c` | Public API layer |
| `ml_kem_core_header.h` | Core definitions, constants, and structures |
| `ml_kem_create_keys.c` | Key generation |
| `ml_kem_encaps.c` | Encapsulation logic |
| `ml_kem_decrypt.c` | Decapsulation (decryption + re-encapsulation) |
| `ml_kem_ntt_main.c` | NTT and polynomial operations |
| `math_operations.c` | Modular arithmetic (Barrett reduction, etc.) |
| `ml_kem_sha.c` | SHA3-256 / SHA3-512 |
| `ml_kem_shake.c` | SHAKE128 / SHAKE256 |
| `keccak_f1600_ct.c` | Keccak permutation |
| `ml_kem_pool.c` | Decapsulation pool implementation |

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

- No secret-dependent branching in core cryptographic paths (where applicable)
- Explicit memory zeroization (`ml_kem_memzero`)
- Separation of public and secret data flows
- Designed with constant-time execution principles in mind

⚠️ However:

- Constant-time guarantees are **not yet formally verified**
- Compiler optimizations may affect behavior
- Further validation is planned

---

## 🧪 Testing

Currently implemented:

- ✔ NIST KAT (KeyGen, Encapsulation)
- ✔ Functional decapsulation validation
- ✔ High-contention stress test of:
  - Decapsulation pool (256 threads / 16 slots)  
  - ThreadSanitizer (TSan) clean  
  - AddressSanitizer (ASan) / UBSan clean 
  - (See `test_pool/` for reproducible stress testing setup and sanitizer runs)
- ✔ Preliminary constant-time testing using dudect has been added for the primary secret-dependent execution paths of the ML-KEM implementation.

Planned:

- Additional isolated coverage for lower-level arithmetic and SHA3/SHAKE internals is planned for future releases.
- Kernel-space KAT validation
- Stress testing of pool subsystem
- Randomness quality checks

---

## 🐧 Kernel Support

The project includes a Linux kernel-compatible build:

- No reliance on userspace-only APIs
- Suitable for integration with kernel crypto subsystems (future work)
- Potential use cases:
  - Embedded systems
  - Secure firmware
  - In-kernel cryptographic services

---

## ⚙️ Build

### Userspace

```bash
gcc -std=c11 -O2 -Wall -Wextra *.c -o ml_kem

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

- GitHub: kstzv(https://github.com/kstzv)
- Email: kstzavertaylo@gmail.com

