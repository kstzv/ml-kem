// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// Porting ML-KEM in Linux kernel
#ifndef ML_KEM_LINUX_KERNEL_PORT_H
#define ML_KEM_LINUX_KERNEL_PORT_H

// @>@@>@@@>@@@@>@@@@@>@@@@@@>@@@@@@@>@@@@@@@@>@@@@@@@@@>@@@@@@@@@@>@@@@@@@@@@@>@@@@@@@@@@@@@>@@@@@@@@@@@@@
// Including libraries from Linux kernel

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/random.h>

// Atomic type for implementation
typedef atomic_t ml_kem_atomic_t;

// ^>^^>^^^>^^^^>^^^^^>^^^^^^>^^^^^^^>^^^^^^^^>^^^^^^^^^>^^^^^^^^^^>^^^^^^^^^^^>^^^^^^^^^^^^>^^^^^^^^^^^^^

#endif // ML_KEM_LINUX_KERNEL_PORT_H
