// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// Porting ML-KEM to FreeRTOS
#ifndef ML_KEM_FREERTOS_PORT_H
#define ML_KEM_FREERTOS_PORT_H

// @>@@>@@@>@@@@>@@@@@>@@@@@@>@@@@@@@>@@@@@@@@>@@@@@@@@@>@@@@@@@@@@>@@@@@@@@@@@>@@@@@@@@@@@@@>@@@@@@@@@@@@@
// Standard C library headers

#include "FreeRTOS.h"   
#include <string.h>   
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>


// Atomic type for implementation
#if defined(ML_KEM_ATOMIC_STDATOMIC) // Stdatomic implementation

#include <stdatomic.h>
typedef atomic_int ml_kem_atomic_t;

#elif defined(ML_KEM_ATOMIC_FREERTOS) // FreeRTOS atomic.h

#include <atomic.h>
typedef uint32_t ml_kem_atomic_t;

#else

#error "Atomic operations are not defined on this platform."

#endif // Atomic operations

// ^>^^>^^^>^^^^>^^^^^>^^^^^^>^^^^^^^>^^^^^^^^>^^^^^^^^^>^^^^^^^^^^>^^^^^^^^^^^>^^^^^^^^^^^^>^^^^^^^^^^^^^
// Prototypes of functions that depend on a this platform

// Fixed-width integer aliases (kernel-style, userspace-safe)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

#endif // ML_KEM_FREERTOS_PORT_H
