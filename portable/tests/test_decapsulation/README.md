# ML-KEM Decapsulation KAT Test (NIST FIPS 203)

This directory contains a Known Answer Test (KAT) for the ML-KEM decapsulation implementation, using test vectors provided by NIST through the Automated Cryptographic Validation Protocol (ACVP).

The test verifies that the implementation produces the expected 32-byte shared secret for predefined decapsulation inputs.

The following ML-KEM parameter sets are supported:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

The test uses 30 NIST decapsulation test vectors.

## What this test verifies

Unlike a simple encapsulation/decapsulation round-trip test, this test compares the shared secret produced by the implementation against a predefined expected result from the NIST test vectors.

Each test case contains the necessary input data, including the decapsulation key material, ciphertext, and expected shared secret.

For each test case, the implementation must satisfy:

```text
K_decaps == K_expected
```

The test verifies:

1. Correct processing of the decapsulation key material.
2. Correct decryption of the received ciphertext.
3. Correct re-encapsulation and ciphertext verification.
4. Correct derivation of the final 32-byte shared secret.
5. Correct handling of the implicit rejection mechanism for modified ciphertexts, where such cases are included in the test vectors.

A successful result indicates that the implementation produces the expected output for the tested NIST decapsulation cases.

## Test Vectors

The test vectors are obtained from the official NIST ACVP-Server repository:

https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203

Source file:

```text
ML-KEM-encapDecap-FIPS203/internalProjection.json
```

Source retrieval date: October 30, 2026.

The vectors belong to the ML-KEM encapsulation/decapsulation testing specification defined for FIPS 203.

## Test Logic

For each test vector, the test performs the following operations:

1. Selects the corresponding ML-KEM security level.
2. Initializes the required ML-KEM key context and decapsulation pool using the provided key material.
3. Reads the predefined ciphertext from the test vector.
4. Executes the ML-KEM decapsulation operation.
5. Obtains the resulting 32-byte shared secret.
6. Compares the result against the expected shared secret provided by NIST.
7. Reports success or failure for the corresponding test case.
8. Releases the allocated resources before proceeding to the next test case.

The shared secrets are compared using `memcmp()`.

This is acceptable because the comparison is performed only within a functional correctness test. Constant-time properties of the implementation are evaluated separately using dedicated dudect tests.

## Build

Build the test using:

```sh
make
```

## Run

Execute the compiled test:

```sh
./test
```

## Clean

Remove generated build files:

```sh
make clean
```

## Expected Result

A successful execution indicates that all processed test vectors produced the expected shared secrets.

If a mismatch occurs, the test reports the corresponding vector and ML-KEM security level.

A mismatch means that the implementation did not reproduce the expected NIST decapsulation result and requires investigation.

## Notes

This test focuses on validating the functional correctness of the ML-KEM decapsulation implementation against predefined NIST test vectors.

It does not replace:

1. Constant-time leakage testing.
2. Memory-safety testing using sanitizers.
3. Additional malformed-input and error-handling tests.
4. Multithreaded decapsulation pool stress testing.
5. Complete algorithm validation and certification through the NIST ACVP process.

Passing these test vectors demonstrates correctness for the tested cases but does not constitute official NIST certification.
