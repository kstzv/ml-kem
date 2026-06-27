// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #1 ml_kem_core_header.h - Core header for ML-KEM (Kyber) implementation

#ifndef ML_KEM_KYBER_H
#define ML_KEM_KYBER_H

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdbool.h>

#define ML_KEM_Q                      3329 // Ring modulus
#define ML_KEM_N                      256  // Polynomial degree
#define ML_KEM_COEFF_NORMALIZATION    3303 // Normalization constant used after polynomial coefficient reduction (per ML-KEM requirements)

#define ML_KEM_SEED_BYTES 32  					 // Seed size for matrix A, noise generation, and secret vector (all use 32 bytes)
#define ML_KEM_MSG_COEFF 1665  					 // (Q + 1) / 2, used for bit-to-polynomial encoding of message bits (FIPS-203 Encode(m))
#define ML_KEM_Q_RECIP_48 ((u64)0x13AFB7680Bull) // Precomputed reciprocal for fast modular operations (48-bit domain)

// Compression-related constants
#define ML_KEM_Q_HALF  (ML_KEM_Q >> 1)

// XOF buffer sizes (chosen with margin to ensure sufficient output in a single pass)
#define ML_KEM_MATRIX_XOF_BYTES         1024 // Raw bytes buffer for a single matrix polynomial (sufficient upper bound)
#define ML_KEM_VECTOR_XOF_BYTES_L2      192  // Raw bytes buffer for vector polynomial (level 2)
#define ML_KEM_VECTOR_XOF_BYTES_L34     128  // Raw bytes buffer for vector polynomial (levels 3 and 5)

#define ML_KEM_SHAKE128_RATE 168 // SHAKE128 rate (used for matrix generation)
#define ML_KEM_SHAKE256_RATE 136 // SHAKE256 rate (used for noise and secret vectors)

// CBD parameters (number of bits extracted per coefficient)
#define ML_KEM_CBD_ETA_3   3  // η for level 1
#define ML_KEM_CBD_ETA_2   2  // η for levels 3 and 5

// Public key lengths (per FIPS-203, depending on security level)
#define RES_PUBL_PART_LVL_512  800
#define RES_PUBL_PART_LVL_768  1184
#define RES_PUBL_PART_LVL_1024 1568

// Ciphertext lengths (per security level)
#define LEN_CIPHERTEXT_512  768
#define LEN_CIPHERTEXT_768  1088
#define LEN_CIPHERTEXT_1024 1568

// Maximum number of slots in decapsulation pool
#define ML_KEM_MAX_POOL_SLOTS 128

// The constant mu is computed as:
// mu = round(2^k / q) = 20159
#define BARRETT_K 26
#define BARRETT_MU 20159

// Fixed-width integer aliases (kernel-style, userspace-safe)
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;

// Callback used to obtain cryptographically secure random bytes.
// Parameters:
//   buf - destination buffer
//   len - number of bytes to generate
// Returns:
//   0 on success
//   non-zero on failure
typedef int (*ml_kem_entropy_fn)(void *buf, size_t len);

// The massive for test
extern u8 mass_m[ML_KEM_SEED_BYTES];

// ML-KEM security level parameter k:
// Defines matrix/vector dimensions:
//   k = 2 (ML_KEM_512)
//   k = 3 (ML_KEM_768)
//   k = 4 (ML_KEM_1024)
// Matrix A has k*k polynomials, vectors have 2*k polynomials (s + e)
enum ml_kem_k {
    ML_KEM_512 =  2,
    ML_KEM_768 =  3,
    ML_KEM_1024 = 4,
};

// Persistent key context for ML-KEM
struct ml_kem_ctx {
	u8 seed_rho[ML_KEM_SEED_BYTES];  // Seed used to deterministically generate matrix A
	enum ml_kem_k k;                 // Security level / dimension parameter
	u16 *secret;                     // Secret key (vector s)
	u8  *public_key_msg;             // Packed public key (t || seed_rho)
	size_t public_key_msg_len;       // Length of packed public key
	u8 z[ML_KEM_SEED_BYTES];         // Random fallback value used in decapsulation (implicit rejection mechanism)
	u8 h_pk[ML_KEM_SEED_BYTES];      // Hash of public key
};

// Temporary structure used during key generation
struct ml_kem_temp {
	u8 seed_sigma[ML_KEM_SEED_BYTES]; // Seed for noise and secret vector generation
	u8 seed_rho[ML_KEM_SEED_BYTES];   // Seed for matrix A
	enum ml_kem_k k;                  // Security level
	u16 *poly;                        // Temporary polynomial buffer (256 coefficients)
	u16 *public_key;                  // Public key (t)
	u16 *secret;                      // Secret vector (s)
	u8 *raw_bytes;                    // Raw byte buffer (XOF output)
	size_t number_raw_bytes_vectors;  // Size of raw buffer for vectors (depends on level)
	u8 eta;                           // CBD parameter (bits per coefficient)
};

// Encapsulation context (used both for client encapsulation and internal re-encapsulation in decapsulation)
struct ml_kem_encaps_ctx {
	u8 seed_rho[ML_KEM_SEED_BYTES];   // Seed for matrix A
	u8 seed_m[ML_KEM_SEED_BYTES];     // Message seed
	u8 K_bar[ML_KEM_SEED_BYTES];      // Derived shared secret
	enum ml_kem_k k;                  // Security level
	u16 *public_key;                  // Public key (t)
	u16 *u;                           // Vector u (encodes ephemeral secret)
	u16 *v;                           // Vector v (encodes message)
	u16 *y;                           // Ephemeral secret vector
	u16 *poly;                        // Temporary polynomial buffer
	u8  *public_key_msg;              // Packed public key
	size_t public_key_msg_len;        // Length of packed public key
	u8 *ciphertext;                   // Final ciphertext buffer
	size_t ciphertext_len;            // Ciphertext length
	u8 *raw_bytes;                    // XOF buffer for polynomial generation
};

// Decryption context (used during decapsulation)
struct ml_kem_decrypt_ctx {
	struct ml_kem_ctx *ctx;           // Reference to persistent key context
	size_t ciphertext_len;            // Ciphertext length (fixed per level)
	u16 *u;                           // Vector u
	u16 *v;                           // Vector v
	u16 *poly;                        // Temporary polynomial buffer
	u8 *ciphertext;                   // Input ciphertext buffer
	u8 m[ML_KEM_SEED_BYTES];          // Recovered message seed
};

// Single decapsulation slot
struct ml_kem_decaps_ctx {
	struct ml_kem_encaps_ctx *encaps_ctx;               // Encapsulation context
	struct ml_kem_decrypt_ctx *decrypt_ctx;             // Decryption context
	u8 kdf_buf[LEN_CIPHERTEXT_1024 + ML_KEM_SEED_BYTES];// Buffer for KDF (z-based fallback)
	atomic_int is_free;                                 // Atomic flag for slot availability
};

// Pool of decapsulation slots
struct ml_kem_pool_decaps_ctx {
	struct ml_kem_decaps_ctx *ml_kem_pool; // Array of slots
	size_t ml_kem_pool_count;              // Number of slots
	
	// Memory regions for efficient allocation/deallocation
	size_t ciphertext_len;
	size_t public_key_msg_len;
	size_t two_bytes_ptrs_total;
	u16 *two_bytes_mem_ptrs;
	u8 *public_key_msgs_mem_ptr;
	u8 *ciphertexts_mem_ptr;
	u8 *raw_bytes_mem_ptr;
	struct ml_kem_decrypt_ctx *decrypt_mem_ptr;
	struct ml_kem_encaps_ctx *encaps_mem_ptr;
};

// Key generation API (File #2)
extern int ml_kem_create_ctx_struct(struct ml_kem_temp *temp, struct ml_kem_ctx *ctx, ml_kem_entropy_fn entropy);
extern struct ml_kem_temp *ml_kem_temp_alloc(enum ml_kem_k level);
extern struct ml_kem_ctx *ml_kem_ctx_alloc(enum ml_kem_k level);
extern void ml_kem_destroy_temp_struct(struct ml_kem_temp *temp);
extern void ml_kem_destroy_ctx_struct(struct ml_kem_ctx *ctx);
extern int ml_kem_entropy(void *buf, size_t len);

// Secure memory wipe (File #2)
extern void ml_kem_memzero(void *ptr, size_t len);

// Encapsulation API (File #3)
extern struct ml_kem_encaps_ctx *ml_kem_alloc_encaps(u8 *public_key_msg, enum ml_kem_k k);
extern void ml_kem_wipe_encaps(struct ml_kem_encaps_ctx *ctx);
extern void ml_kem_destroy_encaps(struct ml_kem_encaps_ctx *ctx);
extern void ml_kem_encapsulation(struct ml_kem_encaps_ctx *ctx, u8 *msg, u8 *hash_pk, ml_kem_entropy_fn entropy);
extern void ml_kem_unpack_pk_t_u16(struct ml_kem_encaps_ctx *ctx);

// Decryption API (File #4)
extern void ml_kem_wipe_decrypt(struct ml_kem_decrypt_ctx *ctx_decry);
extern void ml_kem_decrypt(struct ml_kem_decrypt_ctx *ctx_decry, u8 *ciphertext);

// NTT and polynomial operations (File #5)
extern void ml_kem_add(u16 result[ML_KEM_N], u16 first[ML_KEM_N], u16 second[ML_KEM_N]);
extern void ml_kem_multiply(u16 result[ML_KEM_N], u16 first[ML_KEM_N], u16 second[ML_KEM_N]);
extern void ml_kem_intt_fips203(u16 f[ML_KEM_N]);
extern void ml_kem_ntt_fips203(u16 f[ML_KEM_N]);

// SHA3 wrappers (File #6)
extern void ml_kem_sha3_512(u8 out[64], const u8 *in, size_t inlen);
extern void ml_kem_sha3_256(u8 out[32], const u8 *in, size_t inlen);
	
// SHAKE wrappers (File #7)
extern void ml_kem_shake128(u8 *out, size_t outlen, const u8 *in, size_t inlen);
extern void ml_kem_shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen);

// Keccak-f[1600] permutation (File #8)
extern void keccak_f1600_ct(u64 state[25]);

// Decapsulation pool API (File #9)
extern struct ml_kem_pool_decaps_ctx *ml_kem_alloc_decaps_pool(enum ml_kem_k level, size_t ml_kem_pool_count, struct ml_kem_ctx *private_keys);
extern void ml_kem_pool_destroy(struct ml_kem_pool_decaps_ctx *head_pool);
extern bool try_acquire_slot(atomic_int *is_free);

// ---------------------------Functions of Barrett Reductions for NTT--------------------------------------------------------------------------------
// Special constants for Barrett reduction in ML-KEM.
// The ML-KEM standard (FIPS 203) defines the modulus q = 3329,
// but does not mandate a specific reduction algorithm.
// This implementation follows a Kyber-style Barrett reduction
// with parameter k = 26, which is a well-established choice
// for 16-bit coefficients with 32-bit intermediate values.

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

// Barrett reduction: reduces a 32-bit value modulo q in constant time
static inline u16 ml_kem_barrett_reduce(u32 a)
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
static inline u16 ml_kem_multipl_mod(u16 a, u16 b)
{
	u32 res = (u32)a * (u32)b;
	return ml_kem_barrett_reduce(res);
}

// Modular addition: (a + b) mod q
static inline u16 ml_kem_add_mod(u16 a, u16 b)
{
	u16 x = a + b;
    return ml_kem_ct_sub_if_ge(x);
}
	
// Modular subtraction: (a - b) mod q
// Uses extended range to avoid negative intermediate values
static inline u16 ml_kem_sub_mod(u16 a, u16 b)
{
	u16 x = (u16)(a + ML_KEM_Q - b);
    return ml_kem_ct_sub_if_ge(x);
}

//====================================CBD=============================================================


// CBD for eta == 3
static inline u32 load24_littleendian(const u8 *x)
{
    return (u32)x[0]
         | ((u32)x[1] << 8)
         | ((u32)x[2] << 16);
}

static inline void cbd3(u16 *r, const u8 *buf)
{
    for (int i = 0; i < ML_KEM_N / 4; i++) {

        u32 t = load24_littleendian(buf + 3 * i);

        u32 d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (int j = 0; j < 4; j++) {

            u32 a = (d >> (6 * j)) & 0x7;
            u32 b = (d >> (6 * j + 3)) & 0x7;

            r[4 * i + j] = ml_kem_sub_mod((u16)a, (u16)b);
        }
    }
}


// CBD for eta == 2
static inline u32 load32_littleendian(const u8 *x)
{
    return (u32)x[0]
         | ((u32)x[1] << 8)
         | ((u32)x[2] << 16)
         | ((u32)x[3] << 24);
}

static inline void cbd2(u16 *r, const u8 *buf)
{
    for (int i = 0; i < ML_KEM_N / 8; i++) {
        u32 t = load32_littleendian(buf + 4 * i);

        u32 d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (int j = 0; j < 8; j++) {
            u32 a = (d >> (4 * j)) & 0x3;
            u32 b = (d >> (4 * j + 2)) & 0x3;

            r[8 * i + j] = ml_kem_sub_mod((u16)a, (u16)b);
        }
    }
}

static inline void ml_kem_gen_polynomial_for_cbd(u16 *poly, const u8 *stream, const u8 eta)
{
	if(eta == ML_KEM_CBD_ETA_3)
	{
		cbd3(poly, stream);
	}else if(eta == ML_KEM_CBD_ETA_2)
	{
		cbd2(poly, stream);
	}else{
		return;
	}
}

//----------------------------------------------------ALGORITHM-7----------------------------------------------

// Sample polynomial coefficients for matrix A using rejection sampling (FIPS 203, Algorithm 7 - SampleNTT).
// Input stream is interpreted as a sequence of 12-bit values.
// Every 3 bytes produce two 12-bit candidates:
//   d1 = lower 12 bits  (byte0 + lower 4 bits of byte1)
//   d2 = upper 12 bits  (upper 4 bits of byte1 + byte2)
// Only values < q (3329) are accepted.
// Rejected values are skipped, and sampling continues.
// NOTE:
//   If input bytes are insufficient, function returns -ENOMEM.
//   Caller is expected to extend the stream (e.g., via SHAKE) and retry.
static inline int ml_kem_gen_polynomial_for_matrix(u16 *poly, const u8 *stream, int suma_bytes)
{
	int j = 0;		// Output coefficient index
	size_t pos = 0; // Position in input stream

	// Temporary candidates (12-bit values)
	u16 d1 = 0;
	u16 d2 = 0;
        
	// Generate ML_KEM_N coefficients
	while (j < ML_KEM_N)
	{
		if(suma_bytes < 3) { return -ENOMEM; } 			 // Need at least 3 bytes to extract two candidates
		d1 = stream[pos] | ((stream[pos+1] & 0xF) << 8); // Extract first 12-bit value: byte0 + lower 4 bits of byte1
		d2 = (stream[pos+1] >> 4) | (stream[pos+2] << 4);// Extract second 12-bit value: upper 4 bits of byte1 + byte2

		// Accept values strictly less than q
		if (d1 < ML_KEM_Q) { poly[j++] = d1; }
        if (d2 < ML_KEM_Q && j < ML_KEM_N) { poly[j++] = d2; }

		// Advance stream position
        pos += 3;

		// Reset temporary variables
        d1 = d2 = 0;

		// Track remaining bytes
        suma_bytes -= 3;
	} 

	return suma_bytes;
}

#endif /* ML_KEM_KYBER_H */
