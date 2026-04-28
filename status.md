Project Status and Future Plans (UA draft)

1.Current state
1.1. This ML-KEM implementation is currently at an early stage of development and requires further refinement and testing.
At this stage, it is not suitable for production use.
1.2. The implementation is based on the NIST FIPS 203 specification; however, it has not yet undergone a full validation cycle or comprehensive security testing.

2.Planned work
2.1 Perform detailed constant-time leakage analysis using dudect.
2.2 Testing of:
		- input parameter validation;
		- handling of invalid or malformed inputs;
		- correct behavior in case of ciphertext mismatch during decapsulation.
2.3. Perform stress testing of the slot pool to:
		- identify potential race conditions;
		- evaluate behavior under high parallel load.
2.4. Testing of the kernel implementation via the AF_ALG interface.
2.5. Memory leak detection and analysis.
2.6. Large-scale testing with a high number of randomly generated seeds to verify stability and correctness of the algorithm.
2.7. Verification of the correctness of the memory zeroization function (ml_kem_memzero) under different compiler behaviors and optimization settings.
2.8. Evaluation of portability to resource-constrained environments (embedded systems / RTOS).
2.9. Investigation of potential assembly-level optimizations (e.g., for NTT) to improve performance.

3. This implementation has not undergone a formal cryptographic audit and may contain vulnerabilities.

4. Constant-time guarantees apply only to operations involving secret data. Parts of the algorithm operating solely on public data may not be constant-time.

5. The kernel version has currently been tested only at the level of module load/unload and basic functional consistency with the userspace implementation.

6. The overall cryptographic security depends on the reliability of the entropy source (getrandom() or its equivalents).
