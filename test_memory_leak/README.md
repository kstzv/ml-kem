# ML-KEM Memory Leak Test

This directory contains a memory lifecycle validation test for the userspace ML-KEM implementation.

The purpose of the test is to repeatedly execute the full ML-KEM workflow and verify that:

* no memory leaks occur,
* no invalid memory operations are detected,
* all dynamically allocated objects are correctly destroyed.

The test repeatedly performs:

* ML-KEM object creation,
* key generation,
* encapsulation,
* decapsulation,
* ciphertext destruction,
* decapsulation pool destruction.

---

# Build

```bash
make
```

---

# AddressSanitizer (ASan) Test

To enable AddressSanitizer testing, uncomment the following line in the Makefile:

```makefile
# CFLAGS += -fsanitize=address
```

After enabling ASan:

```bash
make clean
make
make run
```

The program should complete successfully and print:

```text
done
```

AddressSanitizer is used to detect:

* invalid memory accesses,
* heap corruption,
* use-after-free,
* double free,
* out-of-bounds access.

---

# Valgrind Memcheck Test

For Valgrind testing, keep AddressSanitizer disabled.

Run:

```bash
make clean
make
make valgrind
```

Expected successful result:

```text
All heap blocks were freed -- no leaks are possible
ERROR SUMMARY: 0 errors from 0 contexts
```

Valgrind Memcheck is used to detect:

* memory leaks,
* invalid memory operations,
* broken cleanup paths,
* incorrect allocation lifecycle handling.

---

# Notes

This test validates the userspace implementation only.

The test is intended as an engineering validation tool and does not formally prove the absence of all possible memory-related issues.
