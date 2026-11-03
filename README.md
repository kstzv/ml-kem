# ML-KEM — Portable C11 Implementation (FIPS 203)

A portable implementation of the **Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)** specified in [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203).

The project implements **ML-KEM-512**, **ML-KEM-768**, and **ML-KEM-1024**, including key generation, encapsulation, and decapsulation. Its primary architectural feature is explicit management of reusable working memory: a decapsulation pool associated with a key pair and an optional, independent encapsulation pool.

The cryptographic core is written in C11, without depending on an external cryptographic library. Environment-specific integration is provided for Linux userspace, the Linux kernel, and FreeRTOS.

### A note on the decapsulation pool

**The decapsulation pool is created automatically as part of the main key context.** No separate pool initialization is required.

If you do not need parallel decapsulation, simply set the number of slots to **`1`** when calling `ml_kem_create_object()` or `ml_kem_create_object_from_imported_sk()`.

For example: `ml_kem_create_object(ML_KEM_768, 1, NULL)`.

With a single slot, the implementation behaves like a conventional sequential ML-KEM decapsulation interface. The internal pool architecture remains in place, but no additional configuration or concurrency management is necessary for sequential use.

**The pool is an architectural feature, not an obligation to use parallelism.**

### A not on the API usage

For more detailed instructions on using the API of this implementation, please refer to document ML_KEM_API_Usage_Guide.pdf.

## Security status

> **This implementation has not undergone a formal independent security audit and is not claimed to be a FIPS-validated cryptographic module.** Implementing the FIPS 203 algorithm does not, by itself, establish implementation security or regulatory validation.

- The code is designed with constant-time processing in mind, particularly for decapsulation and implicit rejection. This is a **design objective, not an independently verified constant-time guarantee**; compiler output, target architecture, and platform integrations require assessment.
- Use an up-to-date maintained revision. Review changes and test the exact build configuration before security-sensitive deployment. No version should be assumed free from vulnerabilities.
- Randomness must come from a cryptographically secure source. The default entropy backend depends on the selected port; **FreeRTOS requires an application-provided entropy callback**.
- Secret keys, derived shared secrets, and intermediate working data must be protected throughout their lifetimes. Callers are responsible for the security and eventual erasure of their own output buffers.
- **Never enable `ML_KEM_TEST` in a production build.** It replaces normal random-input handling in relevant code paths for testing.

## Features

- All three FIPS 203 ML-KEM parameter sets.
- Key generation, encapsulation, and decapsulation, including ciphertext verification and implicit rejection.
- Import and export of serialized decapsulation (secret) keys.
- Separate reusable memory pools for decapsulation and optional encapsulation.
- Configurable upper bounds on concurrent operations through pool slot counts.
- Atomic acquisition and release of per-operation slots, without a pool-wide mutex in the supplied backends.
- No memory allocation during decapsulation or **pooled** encapsulation; standalone encapsulation allocates and releases a temporary context.
- Working buffers arranged in contiguous allocations where practical, with explicit ownership and cleanup.
- Optional pre-expansion of the matrix used during decapsulation (`FULL_MATRIX`).
- Local implementations of Keccak-f[1600], SHA3-256, SHA3-512, SHAKE128, and SHAKE256.
- NTT/inverse NTT, polynomial operations, modular reduction, and sampling implemented within the project.
- A portability layer for allocation, secure erasure, entropy, atomics, and error handling.

## Parameter sets and serialized sizes

All sizes below are in **bytes**.

| Parameter set | `k` | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: | ---: |
| ML-KEM-512 | 2 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 3 | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 4 | 1568 | 3168 | 1568 | 32 |

The corresponding constants and parameter identifiers are defined in `ml_kem_core_header.h`:

- `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`
- `RES_PUBL_PART_LVL_512`, `RES_PUBL_PART_LVL_768`, `RES_PUBL_PART_LVL_1024`
- `LEN_SK_512`, `LEN_SK_768`, `LEN_SK_1024`
- `LEN_CIPHERTEXT_512`, `LEN_CIPHERTEXT_768`, `LEN_CIPHERTEXT_1024`
- `ML_KEM_SEED_BYTES` (32)

## Architecture

The implementation is organized around **algorithm execution and memory lifetime**, rather than predominantly around polynomial and polynomial-vector abstractions. High-level operations own the sequence of transformations; lower-level modules implement reusable mathematical and cryptographic mechanisms.

### Decapsulation and encapsulation pools

**Decapsulation pool.** `ml_kem_create_object()` generates one key pair and prepares a reusable decapsulation pool for that key pair. `ml_kem_create_object_from_imported_sk()` constructs the same kind of object from serialized secret-key material. The persistent key context is shared by the pool's slots; each slot has its own decryption and re-encapsulation working contexts.

Decapsulation follows this sequence:

1. Acquire an available slot atomically.
2. Decrypt the received ciphertext to recover a candidate message.
3. Reuse the encapsulation implementation to reconstruct the expected ciphertext and candidate shared secret.
4. Compare the ciphertexts and select the candidate or fallback shared secret using a mask-based path.
5. Wipe per-operation working data and release the slot.

Complete decapsulation is composed in `ml_kem.c`. There is no separate duplicate implementation of the encapsulation algorithm for ciphertext reconstruction.

**Encapsulation pool.** `create_encaps_pool()` creates a distinct pool object with independently configurable slot counts for ML-KEM-512, ML-KEM-768, and ML-KEM-1024. Each selected parameter set has its own slot array and working-memory regions. One encapsulation pool can therefore service different parameter sets, subject to the configured per-level limits.

Passing a non-`NULL` pool to `ml_kem_encaps_core()` uses one of its existing slots. Passing `NULL` selects standalone encapsulation, which creates and destroys a temporary working context for that call.

In both pool types, **the number of slots limits simultaneous operations**, rather than creating an internal worker-thread pool. The implementation does not create threads; the caller controls scheduling and concurrency. When all slots of the required pool are occupied, the operation returns `-EBUSY` instead of blocking.

Each pool accepts at most `ML_KEM_MAX_POOL_SLOTS` (**128**) slots per applicable configuration. A decapsulation pool must have at least one slot. An encapsulation pool must enable at least one parameter set; a count of `0` disables a particular parameter set.

### Memory ownership and lifetime

- `ml_kem_ctx` stores persistent key material associated with one decapsulation pool.
- `ml_kem_temp` contains temporary working data used during key generation.
- `ml_kem_encaps_ctx` contains an encapsulation operation's working state.
- `ml_kem_decrypt_ctx` contains the decryption stage's working state.
- `ml_kem_decaps_ctx` combines a decryption context, a re-encapsulation context, and an atomic availability flag.
- `ml_kem_general_keys_decaps_ctx` owns the decapsulation slot array and its pool allocations.
- `ml_kem_encaps_slot` represents one reusable encapsulation slot.
- `ml_kem_pool_encaps_ctx` owns the per-level encapsulation subpools.

Allocation is performed when creating keys or initializing a pool (and on each standalone encapsulation). Working data is reused between pooled operations, with per-operation wiping before slot release. Pool destructors release the allocations they own. **Do not destroy a pool while any thread is using it**, and do not use a context after destruction.

### Optional full-matrix expansion

When compiled with `FULL_MATRIX=1`, the decapsulation-pool initialization path expands and stores the matrix for its key pair and makes it available to the slots' internal re-encapsulation path. With `FULL_MATRIX=0`, the relevant matrix polynomials are generated as needed.

This is a **memory-versus-recomputation choice**: pre-expansion increases persistent pool memory use and initialization work, potentially reducing repeated matrix-generation work during decapsulation. It is not a blanket performance guarantee; benchmark both variants for the intended platform and workload.

The stored matrix requires `k * k * 256 * sizeof(u16)` bytes: 2,048 bytes for ML-KEM-512, 4,608 bytes for ML-KEM-768, or 8,192 bytes for ML-KEM-1024, excluding allocation overhead.

Use the **same** `FULL_MATRIX` definition for every translation unit, because it affects context structure layouts and compiled code paths.

## Source modules

The portable core is located in `portable/src/` in the repository layout described by this project.

| File | Responsibility |
| --- | --- |
| `ml_kem.c` | Public API, composition of decapsulation, key import/export |
| `ml_kem.h` | Public API declarations |
| `ml_kem_core_header.h` | Internal types, constants, contexts, and cross-module declarations |
| `ml_kem_create_keys.c` | Key generation and key-context allocation/cleanup |
| `ml_kem_encaps.c` | Encapsulation and re-encapsulation logic |
| `ml_kem_decrypt.c` | Internal K-PKE decryption stage |
| `ml_kem_decaps_pool.c` | Decapsulation pool allocation, memory layout, and destruction |
| `ml_kem_encaps_pool.c` | Per-level encapsulation pools and their working buffers |
| `ml_kem_ntt_main.c` | NTT, inverse NTT, and polynomial operations |
| `ml_kem_sha3.c` | SHA3-256 and SHA3-512 |
| `ml_kem_shake.c` | SHAKE128 and SHAKE256 |
| `keccak_1600.c` | Keccak-f[1600] permutation |

### Recommended reading order

1. **`ml_kem_core_header.h`** — understand the context structures, parameters, and ownership relationships.
2. **`ml_kem_decaps_pool.c` and `ml_kem_encaps_pool.c`** — see how memory is allocated, partitioned into slots, reused, and released.
3. **`ml_kem_create_keys.c`** — follow key generation and the distinction between temporary and persistent key data.
4. **`ml_kem_encaps.c`** — trace encapsulation from public-key bytes and randomness to ciphertext and shared secret.
5. **`ml_kem_decrypt.c`** — follow recovery of the candidate message from a ciphertext.
6. **`ml_kem.c`** — read the complete public decapsulation flow, including the re-encapsulation check, implicit rejection, and key selection; then review key import/export and public API validation.
7. **`ml_kem_ntt_main.c`, `ml_kem_sha3.c`, `ml_kem_shake.c`, and `keccak_1600.c`** — inspect the arithmetic and cryptographic primitives referenced by the higher-level phases.

## Public API

The public interface is declared in `ml_kem.h`:

```c
/* Create a key pair and its reusable decapsulation pool. */
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object(
    enum ml_kem_k level,
    size_t ml_kem_pool_count,
    ml_kem_entropy_fn entropy);

/* Import an existing serialized secret key and create a decapsulation pool. */
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object_from_imported_sk(
    u8 *sk,
    size_t size_sk,
    size_t size_pool);

/* Destroy the key object and its decapsulation pool. */
void ml_kem_destroy_core(struct ml_kem_general_keys_decaps_ctx *ctx);

/* Create/destroy an optional encapsulation pool. */
struct ml_kem_pool_encaps_ctx *create_encaps_pool(
    size_t number_slots_512,
    size_t number_slots_768,
    size_t number_slots_1024);

void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx);

/* Encapsulate with a pool, or pass NULL to use a temporary context. */
int ml_kem_encaps_core(
    struct ml_kem_pool_encaps_ctx *ctx_pool,
    u8 *pk, size_t size_pk,
    u8 *buffer_ct, size_t size_ct,
    u8 *buffer_ss, size_t size_ss,
    ml_kem_entropy_fn entropy);

/* Decapsulate using the key-associated reusable pool. */
int ml_kem_decaps_core(
    struct ml_kem_general_keys_decaps_ctx *ctx,
    u8 *ciphertext, size_t len_ciphertext,
    u8 *result, size_t len_result);

/* Export the public key or serialized secret key. */
int ml_kem_get_public_key(
    struct ml_kem_general_keys_decaps_ctx *ctx,
    u8 *buffer_for_public_key,
    size_t size_buffer);

int ml_kem_get_sk(
    struct ml_kem_general_keys_decaps_ctx *ctx,
    u8 *buffer_for_sk,
    size_t size_buffer_for_sk);
```

### API behavior and return values

| Operation | Successful result | Important details |
| --- | --- | --- |
| `ml_kem_create_object()` | Initialized key/decapsulation-pool pointer | Selects one level and a nonzero slot count; generates key material. |
| `ml_kem_create_object_from_imported_sk()` | Initialized key/decapsulation-pool pointer | Selects the level from the exact serialized secret-key length; checks the stored public-key hash and encoded public-key coefficients. |
| `ml_kem_destroy_core()` | `void` | Releases the decapsulation pool and its associated key material. |
| `create_encaps_pool()` | Initialized encapsulation-pool pointer | Counts are specified independently for 512/768/1024; zero disables a level. |
| `ml_kem_encaps_pool_destroy()` | `void` | Releases the encapsulation pool's resources. |
| `ml_kem_encaps_core()` | `0` | Uses the selected pool level, or a temporary context if the pool argument is `NULL`. |
| `ml_kem_decaps_core()` | `0` | Produces a 32-byte secret for a correctly sized ciphertext, including the implicit-rejection path. |
| `ml_kem_get_public_key()` | `0` | Copies the public key to a buffer of the exact required length. |
| `ml_kem_get_sk()` | Number of serialized bytes written | Requires a buffer at least as large as the selected secret-key size; this output is sensitive. |

Except for `ml_kem_get_sk()`, integer-returning public operations use `0` for success and a negative error value for failure. For pooled encapsulation or decapsulation, `-EBUSY` indicates that no matching slot is currently free; the caller decides whether and when to retry. Creation errors are represented as `NULL` in the supplied userspace and FreeRTOS ports; the Linux-kernel port uses **error pointers (`ERR_PTR`)** for creation failures, which must be checked with the kernel's `IS_ERR()` convention.

**Important:** An invalid-but-correctly-sized ciphertext is handled by ML-KEM's implicit rejection. A successful `ml_kem_decaps_core()` return value does **not** mean the ciphertext was authenticated or that it matched the re-encapsulated ciphertext.

### Entropy callback

```c
typedef int (*ml_kem_entropy_fn)(void *buf, size_t len);
```

The callback must fill `buf` with `len` cryptographically secure random bytes and return `0` on success or nonzero on failure.

- In **Linux userspace**, `NULL` selects the port implementation backed by `getrandom()`.
- In the **Linux kernel**, `NULL` selects the port implementation backed by `get_random_bytes()`.
- In **FreeRTOS**, there is no universal built-in entropy source in this port. Its default `ml_kem_entropy()` reports failure; pass a suitable callback for key generation and encapsulation.

Secret-key import does not generate a new key pair, and therefore has no entropy callback argument.

### Key serialization and input validation

- Public keys, ciphertexts, and shared secrets use the sizes in the parameter table above. Encapsulation selects the parameter set from the provided buffer lengths.
- Secret-key export uses the standard serialized format containing the secret-vector encoding, public key, stored public-key hash, and fallback value `z`.
- Secret-key import selects a parameter set by secret-key length and checks that the stored public-key hash matches the embedded public key and that the embedded public-key coefficients use valid encodings. These checks should **not** be interpreted as exhaustive validation of every aspect of an imported secret key.
- **External encapsulation keys require validation as specified in FIPS 203.** The current `ml_kem_encaps_core()` checks lengths for parameter selection but does not invoke the public-key coefficient validation routine used by secret-key import. Integrators must not assume that length checking alone validates an untrusted public key.
- Buffer ownership remains with the caller. In particular, securely erase exported secret-key buffers and shared-secret buffers when they are no longer needed.

## Platform integration

The repository organizes environment-specific integrations under `portable/ports/`. Select **one** platform macro when compiling the core, and build the corresponding port implementation alongside it.

| Port | Selection macro | Allocation | Entropy backend | Atomics / memory erasure |
| --- | --- | --- | --- | --- |
| Linux userspace | `USERSPACE` | `malloc` / `free` | `getrandom()` | C11 atomics / volatile-byte wipe |
| Linux kernel | `LINUX_KERNEL` | `kzalloc` / `kfree` | `get_random_bytes()` | Kernel atomics / `memzero_explicit()` |
| FreeRTOS | `FREERTOS` | `pvPortMalloc` / `vPortFree` | Application callback required | Selectable C11 or FreeRTOS atomics / volatile-byte wipe |

The corresponding files are `ml_kem_userspace_port.[ch]`, `ml_kem_linux_kernel_port.[ch]`, and `ml_kem_freertos_port.[ch]`. The port layer implements memory allocation, release, erasure, entropy, atomic slot operations, and environment-specific error mapping. The Linux-kernel API functions are exported using `EXPORT_SYMBOL_GPL` in the kernel build.

For FreeRTOS, choose **one** atomic implementation at build time:

- `ML_KEM_ATOMIC_STDATOMIC` — C11 `<stdatomic.h>`.
- `ML_KEM_ATOMIC_FREERTOS` — FreeRTOS `atomic.h`.

Which backend is usable depends on the FreeRTOS version, target, and toolchain. The kernel and userspace ports select their own atomic types.

### Alignment and portability requirements

The Keccak state is represented as 25 `u64` lanes (200 bytes). Several allocation paths place that state inside a larger byte-oriented working-memory region and then access it through a `u64 *` pointer.

**The selected allocator must provide memory aligned to at least 8 bytes**, and integrations must preserve the alignment of the Keccak-state subregions. Merely allocating enough bytes is not sufficient on a target whose allocator does not meet this requirement. Check the FreeRTOS heap configuration (`portBYTE_ALIGNMENT`) or any replacement allocator before integration.

The implementation also depends on the behavior of the selected compiler and platform for cryptographic operations and secure erasure. The supplied volatile-byte wipe is a best-effort mechanism; platforms with an appropriate dedicated secure-zeroization primitive may replace it in their port.

### Build-time definitions

| Definition | Meaning |
| --- | --- |
| `USERSPACE`, `LINUX_KERNEL`, `FREERTOS` | Select the environment-specific port; define exactly one. |
| `FULL_MATRIX=0` or `FULL_MATRIX=1` | Select on-demand matrix generation or pre-expansion for decapsulation; define consistently across all source files. |
| `ML_KEM_ATOMIC_STDATOMIC` / `ML_KEM_ATOMIC_FREERTOS` | Select one FreeRTOS atomic backend. |
| `ML_KEM_TEST` | Test-only deterministic input path; **not for production**. |
| `ML_KEM_DUDECT_TEST` | Exposes selected internal functions for constant-time testing; **not part of the normal public interface**. |

For build commands, include paths, compiler options, and usage examples specific to each environment, see that port's documentation. A normal integration compiles the portable core plus **one matching port**, not all ports together.

## Getting started

1. Choose the target environment and configure its port, including entropy, allocation, and atomics.
2. Compile the portable core and the selected port with consistent feature definitions.
3. Create a key/decapsulation object with `ml_kem_create_object()`, or import existing key material with `ml_kem_create_object_from_imported_sk()`.
4. Retrieve the public key with `ml_kem_get_public_key()` and provide it to the encapsulating party through an authenticated mechanism appropriate to the surrounding protocol.
5. Use `ml_kem_encaps_core()` with an optional reusable encapsulation pool to produce a ciphertext and a 32-byte shared secret.
6. Use `ml_kem_decaps_core()` with the key-associated pool to derive the corresponding secret from the ciphertext.
7. Coordinate the completion of all concurrent operations, destroy both pool objects, and erase any sensitive caller-owned buffers.

For a typical nonconcurrent use case, one decapsulation slot is sufficient. For repeated or parallel encapsulations, an encapsulation pool avoids repeated temporary-context allocation. Select pool sizes according to the actual upper bound on concurrent operations, available memory, and measured workload.

## Tests

The project's test suite is located at [`portable/tests/`](portable/tests/). Refer to the README in that directory for test descriptions, build instructions, and required dependencies.

Before deployment, validate the **exact** port, compiler, optimization settings, and build-time definitions being used. In particular, test all three parameter sets; key generation, encapsulation, decapsulation, import/export, malformed inputs, error paths, slot contention, and both `FULL_MATRIX` configurations where relevant. Known-answer testing, stress testing, memory sanitizers, and constant-time analysis are complementary checks; passing any one of them is not equivalent to a security audit.

## License

This project is dual-licensed under either of the following licenses, at your option:

- GNU General Public License v2.0 (GPL-2.0)
- MIT License

See the repository's license files for the complete terms. Platform-specific integration may also be subject to the licensing requirements of its environment.

## Contact

- GitHub: https://github.com/kstzv
- Email: kstzavertaylo@gmail.com
