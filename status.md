# Project Status

## Userspace Implementation

Status: Stable (v1.0.0)

The userspace implementation is considered stable for tested x86-64 environments using GCC and Clang toolchains.

Current validation includes:
- NIST KAT validation
- End-to-end decapsulation testing
- dudect constant-time leakage testing
- ASAN / TSAN / Valgrind validation
- Stress testing
- Invalid ciphertext handling
- Input validation and robustness testing

The implementation is intended as a practical low-level ML-KEM implementation focused on correctness, portability, and explicit memory control.

---

## Linux Kernel Implementation

Status: Experimental

The Linux kernel implementation is currently under active development.

Current capabilities:
- Builds successfully
- Loads/unloads correctly
- Shares the same core architecture as the userspace implementation

Planned work:
- AF_ALG integration
- Kernel-space KAT validation
- Extended kernel-space testing
- Additional validation of concurrency and timing behavior

---

## Supported / Tested Environments

Validated:
- x86-64
- Linux userspace
- GCC
- Clang

Additional architecture validation is encouraged.

---

## Security Notes

The implementation follows constant-time oriented design principles where applicable.

Validation includes:
- dudect testing
- compiler diversity testing
- sanitizer validation
- stress testing

However:
- no formal proof of constant-time behavior is claimed
- no third-party security audit has been performed
