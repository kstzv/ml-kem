# Introduction

--- ML-KEM implementation in ISO C11

--- Reusable decapsulation pool

--- No allocations during decapsulation

--- Focus on environments with constrained memory resources or where minimizing runtime memory management overhead is important

--- Comparison against PQClean

# Test Environment

All benchmarks were performed on an x86-64 system using GCC and Clang with optimization level -O3 and the following compilation flags:

-Wall -Wextra -pthread -fstack-usage

# Throughput Benchmark

By default, throughput benchmarks use 16 threads and 100,000 iterations per thread. These values are defined as compile-time constants and may be adjusted freely for additional testing.

| Security Level | This Implementation | PQClean   |
|----------------|---------------------|---------- |
| ML-KEM-512     |      125500.68      | 121938.03 |
| ML-KEM-768     |      75957.61       | 77478.29  |
| ML-KEM-1024    |      50054.52       | 53649.98​  |

Throughput is roughly equal to PQClean at security levels 512 and 768, and slightly inferior at level 1024 (approximately in the range of 6 - 8%), but it maintains significantly less stack usage.

# Stack Usage


| Security Level | This Implementation | PQClean |
|----------------|---------------------|---------|
| ML-KEM-512     |       1040 B        | 7824 B  |
| ML-KEM-768     |       1040 B        | 12432 B |
| ML-KEM-1024    |       1040 B        | 18624 B​ |

The stack usage values are not derived using identical methodologies.

For this implementation, the reported value (~1040 B) is an estimate of the deepest cumulative call chain during decapsulation:
ml_kem_decaps_core() -> ml_kem_encapsulation() -> ml_kem_shake256() -> keccak_f1600_ct()

For PQClean, the values are taken from GCC `-fstack-usage` reports for the largest decapsulation-related function of each security level:
PQCLEAN_MLKEM512_CLEAN_indcpa_enc(), PQCLEAN_MLKEM768_CLEAN_indcpa_enc and PQCLEAN_MLKEM1024_CLEAN_indcpa_enc()

# Memory Usage

| Security Level | Persistent memory | Per-slot memory  |
|----------------|-------------------|------------------|
| ML-KEM-512     |     2040 B        | 11 kB 128 bytes  |
| ML-KEM-768     |     2936 B        | 14 kB 128 bytes  |
| ML-KEM-1024    |     3832 B        | 17 kB 448 bytes​  |


Notes:

- Persistent memory. This memory is used by all slots and is only available in one copy. Therefore, it will not grow when increasing the number of slots.
- Per-slot memory. This memory is allocated for each slot individually. Therefore, it directly depends on the number of slots.
- The memory reported above corresponds to a single decapsulation slot.
- Key material and shared resources are allocated once per ML-KEM object and shared by all slots.
- Memory is reused across all decapsulation operations.
- No dynamic allocations are performed during decapsulation.


Design trade-off:

This implementation intentionally allocates additional persistent memory during object creation in order to reduce stack usage and eliminate
runtime memory allocations during decapsulation.

PQClean memory consumption is not included in this comparison because PQClean primarily relies on stack allocation and does not allocate large
persistent memory regions during initialization.


# Conclusions

The benchmark results demonstrate that the implementation achieves throughput comparable to PQClean while following a different memory-management strategy.

The design focuses on three primary goals:

* low stack usage;
* allocation-free decapsulation;
* predictable memory consumption through preallocated reusable resources.

To achieve these goals, the implementation allocates additional persistent memory during object creation and reuses it for all subsequent operations. This approach increases long-lived memory consumption compared to stack-oriented implementations, but eliminates dynamic memory allocations during decapsulation and keeps stack requirements small and independent of the selected ML-KEM security level.

The presented benchmarks should therefore be viewed as a comparison of different implementation trade-offs rather than an attempt to optimize for a single metric. The implementation prioritizes predictable resource usage and reusable memory structures while maintaining competitive throughput.


# Contact

- GitHub: kstzv(https://github.com/kstzv)
- Email: kstzavertaylo@gmail.com
