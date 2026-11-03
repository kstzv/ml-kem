# ML-KEM userspace API smoke test

Copy **into a single directory**:

- `test_api_userspace.c` and `Makefile` from this test;
- all `.c` and `.h` files from `portable/src/`;
- `ml_kem_userspace_port.c` and `ml_kem_userspace_port.h` from the userspace port.

Run on Linux:

```sh
make
```

The test checks all **9 API functions** for ML-KEM-512/768/1024: context creation and destruction, key export/import, encapsulation (with and without a pool), decapsulation, and shared secret matching.

Success: `[PASS] All 9 API functions`. Failure: `[FAIL]` and a non-zero exit code.

This is only a quick functional test, not a KAT, dudect, or stress test.
