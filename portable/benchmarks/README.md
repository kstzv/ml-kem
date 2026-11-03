# Introduction

--- ML-KEM implementation in ISO C11

--- Reusable decapsulation pool

--- No allocations during decapsulation

--- Focus on environments with constrained memory resources or where minimizing runtime memory management overhead is important

--- Comparison against PQClean

# Test Environment

All benchmarks were performed on an x86-64 system using GCC with optimization level -O3 and the following compilation flags:

-Wall -Wextra -pthread -fstack-usage

# Using

## Prerequisites

To reproduce the benchmark results, you need to obtain the PQClean ML-KEM implementation.

Go to: 

portable/userspace/benchmarks/pqclean/

and run:

     git clone https://github.com/PQClean/PQClean

This will download the PQClean implementation used for the comparisons presented in this document.

## Memory Usage

Go to:

portable/userspace/benchmarks/test_memory

And run:

     make
     ./memory_usage

## Stack Usage

Go to:

portable/userspace/benchmarks/test_stack

And run:

     make userspace
     make pq512
     make pq768
     make pq1024

## Throughput decaps pool

Go to:

portable/userspace/benchmarks/test_decaps_throughput

And run:

     make
     ./kstzv_throughput_ml_kem_512
     ./pqclean_throughput_ml_kem_512
     ./kstzv_throughput_ml_kem_768
     ./pqclean_throughput_ml_kem_768
     ./kstzv_throughput_ml_kem_1024
     ./pqclean_throughput_ml_kem_1024

## Throughput encaps pool

Go to:

portable/userspace/benchmarks/test_encaps_throughput

And run:

     make
     ./kstzv_throughput_ml_kem_512
     ./pqclean_throughput_ml_kem_512
     ./kstzv_throughput_ml_kem_768
     ./pqclean_throughput_ml_kem_768
     ./kstzv_throughput_ml_kem_1024
     ./pqclean_throughput_ml_kem_1024

# Throughput decaps Benchmark

By default, throughput benchmarks use 16 threads and 100,000 iterations per thread. These values are defined as compile-time constants and may be adjusted freely for additional testing.

| Security Level | This Implementation (ops/s) | PQClean (ops/s) |
|----------------|---------------------|---------- |
| ML-KEM-512     |      142717.10      | 124537.57 |
| ML-KEM-768     |      87488.08       | 77062.56  |
| ML-KEM-1024    |      58032.95       | 53935.32​  |

In the reported benchmark runs, this implementation achieved higher throughput than PQClean across all three security levels, with improvements ranging from approximately 7.6% to 14.6%.

# Throughput encaps Benchmark

By default, throughput benchmarks use 16 threads and 100,000 iterations per thread. These values are defined as compile-time constants and may be adjusted freely for additional testing.

| Security Level | This Implementation (ops/s) | PQClean (ops/s) |
|----------------|---------------------|---------- |
| ML-KEM-512     |      175225.62      | 163218.62 |
| ML-KEM-768     |      103501.98      | 98966.70  |
| ML-KEM-1024    |      66861.54       | 65625.39  |

In the reported benchmark runs, this implementation achieved higher throughput than PQClean across all three security levels, with improvements ranging from approximately 1.9% to 7.4%.

# Stack Usage


| Security Level | This Implementation | PQClean |
|----------------|---------------------|---------|
| ML-KEM-512     |       1032 B        | 7824 B  |
| ML-KEM-768     |       1032 B        | 12432 B |
| ML-KEM-1024    |       1032 B        | 18624 B​ |

The stack usage values are not derived using identical methodologies.

For this implementation, the reported value (1032 B) is an estimate based on the cumulative stack frames of the following decapsulation call chain:

`ml_kem_decaps_core() -> ml_kem_encapsulation() -> ml_kem_create_u() -> shake128() -> keccak_f1600()`

The estimate is based on GCC `-fstack-usage` reports and is not a measurement of the complete runtime stack high-water mark.

For PQClean, the values are taken from GCC `-fstack-usage` reports for the largest decapsulation-related function of each security level:
PQCLEAN_MLKEM512_CLEAN_indcpa_enc(), PQCLEAN_MLKEM768_CLEAN_indcpa_enc and PQCLEAN_MLKEM1024_CLEAN_indcpa_enc()

Note: Stack usage may vary across architectures, compiler versions, and optimization settings. The reported numbers correspond to the tested GCC -O3 build configuration.

# Memory Usage

| Security Level | Persistent memory | Per-slot memory | Total (1 slot) |
|----------------|-------------------|-----------------|----------------|
| ML-KEM-512     | 2040 B            | 9792 B          | 11832 B        |
| ML-KEM-768     | 2936 B            | 12864 B         | 15800 B        |
| ML-KEM-1024    | 3832 B            | 16256 B         | 20088 B        |


The reported memory sizes exclude allocator metadata and correspond to the default build configuration without full matrix precomputation.

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

Note: performance may vary depending on processor microarchitecture, cache hierarchy, memory subsystem, and compiler optimizations. On the author's newer test system the implementation achieved throughput comparable to PQClean, while on an older system PQClean showed a moderate throughput advantage.


# Contact

- GitHub: [kstzv](https://github.com/kstzv)
- Email: kstzavertaylo@gmail.com
