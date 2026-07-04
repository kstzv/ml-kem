# Linux Userspace Port

## Overview

This directory provides a Linux userspace integration layer for the portable ML-KEM core implementation located in:

portable/src/

The userspace port supplies the platform-specific components required by the portable implementation, including:

- memory allocation
- secure random source
- atomic operations
- platform abstraction layer

The cryptographic implementation itself remains entirely inside the portable core.

---

## Port Architecture

The userspace port implements the platform-dependent interfaces required by the portable core.

This includes:

- allocation wrappers
- entropy provider
- atomic primitives
- userspace-specific configuration

No cryptographic functionality is implemented in this directory.

---
## Building

Build the userspace port by running the command in this directory:

    make

This builds the ML-KEM static library together with the userspace integration layer.

### Example

An example application is provided in:

    example/

To build and run the example:

    cd example
    make
    ./test
    
The example demonstrates how to use the library built in the parent directory.

The example Makefile links against the library built by the userspace port and explicitly includes the required header files:
 - portable/src/ml_kem.h — public ML-KEM API
 - portable/src/ml_kem_core_header.h — core implementation definitions
 - portable/ports/userspace/ml_kem_userspace_port.h — Linux userspace port layer

The example Makefile is intended as a reference for integrating the library into your own projects.

### Installation

The userspace port also provides installation support.

To install the library and public headers into the system, you need to go to the /install directory and execute:

    cd install
    sudo make install

To remove the installed files:

    cd install
    sudo make uninstall
    
## API Usage

The userspace port exposes a minimal public API through:

```c
#include <ml_kem.h>
```

A typical workflow is:

1. Create an ML-KEM object.
2. Obtain the generated public key.
3. Perform encapsulation (client side).
4. Perform decapsulation (server side).
5. Destroy allocated resources.

### Creating an ML-KEM object

```c
struct ml_kem_pool_decaps_ctx *ctx = ml_kem_create_object(ML_KEM_768, 8, NULL);
```

Parameters:

- `ML_KEM_512`, `ML_KEM_768` or `ML_KEM_1024` — security level.
- Pool size — number of reusable decapsulation slots.
- `NULL` — use the operating system entropy source.
  Alternatively, a user-supplied entropy callback may be provided.

---

### Obtaining the public key

```c
ml_kem_get_public_key(ctx, public_key, sizeof(public_key));
```

The returned public key is intended to be distributed to remote peers.
Parameters:

- pool — initialized decapsulation pool (contains the PK within the structure hierarchy)
- buffer_for_public_key - buffer where the PK will be copied
- size_buffer - size of the buffer (must conform to the ML-KEM security level)

---

### Client-side encapsulation

```c
u8 *ciphertext =
    ml_kem_encaps_core(public_key, ML_KEM_768, shared_secret, NULL);
```

This function:

- generates a ciphertext,
- derives the shared secret,
- returns an allocated ciphertext buffer.

Parameters:

- public_key (serialized, standard format)
- `ML_KEM_512`, `ML_KEM_768` or `ML_KEM_1024` — security level.
- buffer for shared_secret, size - 32 bytes
- `NULL` — use the operating system entropy source.
  Alternatively, a user-supplied entropy callback may be provided.

The ciphertext must later be released using:

```c
ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
```

---

### Server-side decapsulation

```c
ml_kem_decaps_core(ctx, ciphertext, len_ciphertext, shared_secret, sizeof(shared_secret));
```

The function:

- acquires a reusable decapsulation slot,
- performs ML-KEM decapsulation,
- writes the recovered shared secret,
- releases the slot automatically.

Parameters:

- ctx - decapsulation pool object
- ciphertext - input ciphertext (serialized)
- len_ciphertext - ciphertext length (must match level)
- shared_secret - output buffer (must be 32 bytes)
- sizeof(shared_secret) — size of output buffer

---

### Cleanup

```c
ml_kem_destroy_core(ctx);
```

This securely wipes sensitive data and releases all allocated resources.
