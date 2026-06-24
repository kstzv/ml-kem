// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File №5 NTT mathematics in ML-KEM

#include "ml_kem_core_header.h"

// All 128 twiddle factors used across the seven butterfly stages of the NTT transformation,
// These values are strictly defined by the standard and specified on page 44
#define HALF_NUMB_COEF_TWIDDLES 128
static const u16 ml_kem_zetas[HALF_NUMB_COEF_TWIDDLES] = {
	1, 1729, 2580, 3289, 2642, 630, 1897, 848,
	1062, 1919, 193, 797, 2786, 3260, 569, 1746,
	296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
	1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
	289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
	650, 1977, 2513, 632, 2865, 33, 1320, 1915,
	2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
	2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
	17, 2761, 583, 2649, 1637, 723, 2288, 1100,
	1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
	1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
	939, 2308, 2437, 2388, 733, 2337, 268, 641,
	1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
	1063, 319, 2773, 757, 2099, 561, 2466, 2594,
	2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
	1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
};

// All 128 gamma values, special fixed constants required in a specific order for multiplication,
// Taken from page 45 of the ML-KEM standard
static const u16 ml_kem_gammas[HALF_NUMB_COEF_TWIDDLES] = {
	17, 3312, 2761, 568, 583, 2746, 2649, 680,
	1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
	1409, 1920, 2662, 667, 3281, 48, 233, 3096,
	756, 2573, 2156, 1173, 3015, 314, 3050, 279,
	1703, 1626, 1651, 1678, 2789, 540, 1789, 1540,
	1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
	939, 2390, 2308, 1021, 2437, 892, 2388, 941,
	733, 2596, 2337, 992, 268, 3061, 641, 2688,
	1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
	375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
	1063, 2266, 319, 3010, 2773, 556, 757, 2572,
	2099, 1230, 561, 2768, 2466, 863, 2594, 735,
	2804, 525, 1092, 2237, 403, 2926, 1026, 2303,
	1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
	1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
	2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
};

// Forward declarations of cross-file functions
void ml_kem_add(u16 result[ML_KEM_N], u16 first[ML_KEM_N], u16 second[ML_KEM_N]);
void ml_kem_multiply(u16 result[ML_KEM_N], u16 first[ML_KEM_N], u16 second[ML_KEM_N]);
void ml_kem_intt_fips203(u16 f[ML_KEM_N]);
void ml_kem_ntt_fips203(u16 f[ML_KEM_N]);


// NTT transformation to point-value representation
void ml_kem_ntt_fips203(u16 f[ML_KEM_N])
{
	u16 len, start, j;
	u16 i = 1; // Algorithm 9: i <- 1

	for (len = HALF_NUMB_COEF_TWIDDLES; len >= 2; len >>= 1) 
	{
		for (start = 0; start < ML_KEM_N; start += 2 * len) 
		{
			u16 zeta = ml_kem_zetas[i++];

			for (j = start; j < start + len; j++) 
			{
				u16 t  = ml_kem_multipl_mod(zeta, f[j + len]);
				u16 fj = f[j];

				f[j + len] = ml_kem_sub_mod(fj, t);
				f[j]       = ml_kem_add_mod(fj, t);
			}
		}
	}
}

// Inverse NTT transformation to coefficient representation
void ml_kem_intt_fips203(u16 f[ML_KEM_N])
{
    u16 len, start, j;
    u16 i = HALF_NUMB_COEF_TWIDDLES - 1;

    for (len = 2; len <= HALF_NUMB_COEF_TWIDDLES; len <<= 1) 
    {
        for (start = 0; start < ML_KEM_N; start += 2 * len) 
        {
            u16 zeta = ml_kem_zetas[i--];

            for (j = start; j < start + len; j++) 
            {
                u16 t = f[j];
                u16 u = f[j + len];

                f[j]       = ml_kem_add_mod(t, u);
                f[j + len] = ml_kem_multipl_mod(zeta, ml_kem_sub_mod(u, t));
            }
        }
    }

    // multiply by n^{-1}
    for (j = 0; j < ML_KEM_N; j++) 
    {
        f[j] = ml_kem_multipl_mod(f[j], ML_KEM_COEFF_NORMALIZATION); 
    }
}

// Multiplication in ML-KEM in NTT domain
void ml_kem_multiply(u16 result[ML_KEM_N], u16 first[ML_KEM_N], u16 second[ML_KEM_N])
{
	u16 a0, a1, b0, b1, t0, t1, u0, u1;
	for(int i = 0; i < HALF_NUMB_COEF_TWIDDLES; i++)
	{
		a0 = first[2*i];
        a1 = first[2*i + 1];
        b0 = second[2*i];
        b1 = second[2*i + 1];
        
        t0 = ml_kem_multipl_mod(a0, b0);
        t1 = ml_kem_multipl_mod(a1, b1);
        t1 = ml_kem_multipl_mod(t1, ml_kem_gammas[i]);
        result[2 * i] = ml_kem_add_mod(t0, t1);
        
        u0 = ml_kem_multipl_mod(a0, b1);
        u1 = ml_kem_multipl_mod(a1, b0);
        result[2 * i + 1] = ml_kem_add_mod(u0, u1);
	}
}

// Addition in NTT domain
void ml_kem_add(u16 result[ML_KEM_N], u16 first[ML_KEM_N], u16 second[ML_KEM_N])
{
	for(int i = 0; i < ML_KEM_N; i++)
	{
		result[i] = ml_kem_add_mod(first[i], second[i]);
	}
}



















