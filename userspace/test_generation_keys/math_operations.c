// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #6 — constant-time modular arithmetic (multiplication, addition, subtraction)
// using Barrett reduction for ML-KEM

#include "ml_kem_core_header.h"

// Special constants for Barrett reduction in ML-KEM.
// The ML-KEM standard (FIPS 203) defines the modulus q = 3329,
// but does not mandate a specific reduction algorithm.
// This implementation follows a Kyber-style Barrett reduction
// with parameter k = 26, which is a well-established choice
// for 16-bit coefficients with 32-bit intermediate values.

// The constant mu is computed as:
// mu = round(2^k / q) = 20159
#define BARRETT_K 26
#define BARRETT_MU 20159

// Forward declarations of externally visible functions
u16 ml_kem_barrett_reduce(u32 a);
u16 ml_kem_multipl_mod(u16 a, u16 b);
u16 ml_kem_add_mod(u16 a, u16 b);
u16 ml_kem_sub_mod(u16 a, u16 b);

// Constant-time conditional subtraction:
// Computes x mod q assuming x is in [0, 2q)
static inline u16 ml_kem_ct_sub_if_ge(u16 x)
{
	u16 diff  = x - ML_KEM_Q; // Subtract modulus
	u16 borrow = diff >> 15;  // Extract sign bit (underflow indicator)
	u16 mask   = 0 - borrow;  // All-ones if underflow occurred, else 0

	// If underflow occurred, add q back; otherwise return diff
	return diff + (ML_KEM_Q & mask);
}
	
typedef int32_t s32;

// Barrett reduction: reduces a 32-bit value modulo q in constant time
u16 ml_kem_barrett_reduce(u32 a)
{
    // Approximate division: t ≈ floor(a / q)
    u32 t = (u32)(((u64)a * (u64)BARRETT_MU) >> BARRETT_K);

    // Compute remainder candidate: r = a - t * q
    s32 r = (s32)a - (s32)t * (s32)ML_KEM_Q;

    // If r < 0, add q 
    r += (r >> 31) & ML_KEM_Q;

    // If r >= q, subtract q 
    r -= ML_KEM_Q;
    r += (r >> 31) & ML_KEM_Q;

    return (u16)r;
}

// Modular multiplication: (a * b) mod q
u16 ml_kem_multipl_mod(u16 a, u16 b)
{
	u32 res = (u32)a * (u32)b;
	return ml_kem_barrett_reduce(res);
}

// Modular addition: (a + b) mod q
u16 ml_kem_add_mod(u16 a, u16 b)
{
	u16 x = a + b;
    return ml_kem_ct_sub_if_ge(x);
}
	
// Modular subtraction: (a - b) mod q
// Uses extended range to avoid negative intermediate values
u16 ml_kem_sub_mod(u16 a, u16 b)
{
	u16 x = (u16)(a + ML_KEM_Q - b);
    return ml_kem_ct_sub_if_ge(x);
}



