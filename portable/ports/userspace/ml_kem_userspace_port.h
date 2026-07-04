// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// Porting ML-KEM in userspace
#ifndef ML_KEM_USERSPACE_PORT_H
#define ML_KEM_USERSPACE_PORT_H

// @>@@>@@@>@@@@>@@@@@>@@@@@@>@@@@@@@>@@@@@@@@>@@@@@@@@@>@@@@@@@@@@>@@@@@@@@@@@>@@@@@@@@@@@@@>@@@@@@@@@@@@@
// Including libraries from userspace OS based Linux kernel

#include <stdlib.h>   
#include <string.h>   
#include <sys/random.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>


// Atomic type for implementation
typedef atomic_int ml_kem_atomic_t;

// ^>^^>^^^>^^^^>^^^^^>^^^^^^>^^^^^^^>^^^^^^^^>^^^^^^^^^>^^^^^^^^^^>^^^^^^^^^^^>^^^^^^^^^^^^>^^^^^^^^^^^^^
// Prototypes of functions that depend on a this platform

// Fixed-width integer aliases (kernel-style, userspace-safe)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

#include <ml_kem_core_header.h>
// #include <ml_kem.h>

#endif // ML_KEM_USERSPACE_PORT_H
