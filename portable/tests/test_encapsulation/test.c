// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ml_kem.h"
#include "ml_kem_core_header.h"

// Number of test vectors per security level and
// Buffer size for reading JSON lines.

#define NUMBER_VECTORS_ONE_LEVEL 25
#define SIZE_BUFFER 4096

// Step increments between ML-KEM parameter sets: 512 → 768 → 1024.

#define LEVEL_STEP 256
#define SIZE_EK_STEP 384
#define K_STEP 1

// Buffers for test vectors: 
// mass_d  - input message (seed for encapsulation)
// mass_k  - expected shared secret (reference)
// mass_ek - public key
// mass_c  - expected ciphertext
// mass_k_from_encaps - output shared secret from implementation

u8 mass_d[ML_KEM_SEED_BYTES];
u8 mass_k[ML_KEM_SEED_BYTES];
u8 mass_ek[RES_PUBL_PART_LVL_1024];
u8 mass_c[LEN_CIPHERTEXT_1024];

// Output buffer for shared secret produced by encapsulation
u8 mass_k_from_encaps[ML_KEM_SEED_BYTES];

// Helper functions for HEX parsing
static int hexval(int c);
int read_hex_byte(const char *in, u8 *out, size_t size_out_mass);

int main()
{
	// Test description output.
	// This test verifies ML-KEM encapsulation against NIST vectors.
	printf("\nThis is test encaps vectors in ML-KEM");
	printf("\nThis is show 75 messages about everyone of 75 vectors NIST");
	printf("\nIf you to see");
	printf("\n\"Wrong! In *** vector, in ML-KEM-*** level sequrity!\"");
	printf("\nso this ML-KEM version is wrong\n");
	printf("\nIf you to see everything");
	printf("\nDone.... In *** vector, in ML-KEM-*** level sequrity is identical with vector NIST....");
	printf("\nso this ML-KEM version is good\n");
	printf("\nIn test using memcmp()....\n");
	printf("...................................................................................................................................................\n");
	
	// Explicit zeroing of all buffers before use.
	// Prevents residual data from affecting test correctness.
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_d[i] = 0;
	}
	
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_k[i] = 0;
	}
	
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_k_from_encaps[i] = 0;
	}
	
	for(size_t i = 0; i < RES_PUBL_PART_LVL_1024; i++)
	{
		mass_ek[i] = 0;
	}
	
	for(size_t i = 0; i < LEN_CIPHERTEXT_1024; i++)
	{
		mass_c[i] = 0;
	}
	
	// Buffer for reading lines from JSON test vector file
	char buffer[SIZE_BUFFER];
	
	// Open NIST encapsulation test vector file.
	FILE *f = fopen("ML-KEM-encapDecap-FIPS203/internalProjection.json", "r");
	if(!f) { return -1; }
	
	// Skip metadata until first "parameterSet" entry.
	while(fgets(buffer, sizeof(buffer), f))
	{
		if(strstr(buffer, "parameterSet"))
		{
			break;
		}
	}
	
	// Initialize counters: security level, public key size, ciphertext size, vector index, ML-KEM parameter k
	size_t level_counter = 512;
	size_t size_ek_counter = 800;
	size_t size_ciphertext_counter = 768;
	size_t vectors_counter = 0;
	enum ml_kem_k k = 2;
	while(fgets(buffer, sizeof(buffer), f))
	{
		// New parameter set detected (switching security level).
		if(strstr(buffer, "parameterSet"))
		{
			printf("\n");
			printf("...................................................................................................................................................\n");
			printf("\nThis is 25 tests encaps vectors in ML-KEM-");
			printf("%zu\n", level_counter);
			level_counter += LEVEL_STEP;
			size_ek_counter += SIZE_EK_STEP;
			vectors_counter = 0;
			k += K_STEP;
			
			if(k ==  ML_KEM_512) { size_ciphertext_counter = LEN_CIPHERTEXT_512; }
			else if(k ==  ML_KEM_768) { size_ciphertext_counter = LEN_CIPHERTEXT_768; }
			else if(k ==  ML_KEM_1024) { size_ciphertext_counter = LEN_CIPHERTEXT_1024; }
			else { return -1; }
		}else if(strstr(buffer, "\"ek\": \"")) // Read 'ek' public key 
		{
			size_t ret = read_hex_byte(buffer, mass_ek, RES_PUBL_PART_LVL_1024);
			if(ret != size_ek_counter) { return -1; }
		}else if(strstr(buffer, "\"c\": \"")) // Read 'c' expected ciphertext
		{
			size_t ret = read_hex_byte(buffer, mass_c, LEN_CIPHERTEXT_1024);
			if(ret != size_ciphertext_counter) { return -1; }
		}else if(strstr(buffer, "\"k\": \"")) // Read expected shared secret 'k'.
		{
			size_t ret = read_hex_byte(buffer, mass_k, ML_KEM_SEED_BYTES);
			if(ret != ML_KEM_SEED_BYTES) { return -1; }
		}else if(strstr(buffer, "\"m\": \"")) // Read seed for encaps 'm'
		{
			size_t ret = read_hex_byte(buffer, mass_d, ML_KEM_SEED_BYTES);
			if(ret != ML_KEM_SEED_BYTES) { return -1; }
			
			// Perform encapsulation: input: public key + message seed
			// Output: shared secret (mass_k_from_encaps) and ciphertext (returned pointer)
			u8 *curr_ciphertext;
			curr_ciphertext = ml_kem_encaps_core(mass_ek, k, mass_k_from_encaps, NULL);
			if(curr_ciphertext == NULL) { return -1; }
			
			// Verify shared secret
			if(memcmp(mass_k_from_encaps, mass_k, ML_KEM_SEED_BYTES) != 0)
			{
				printf("\nWrong! In %zu vector, in ML-KEM-%zu level sequrity, error KEY SHARE!", vectors_counter, level_counter);
			}else{
				printf("\nDone.... In %zu vector, in ML-KEM-%zu level sequrity KEY SHARE is identical with vector NIST....", vectors_counter, level_counter);
			}
			
			// Verify ciphertext
			if(memcmp(curr_ciphertext, mass_c, size_ciphertext_counter) != 0)
			{
				printf("\nWrong! In %zu vector, in ML-KEM-%zu level sequrity, error CIPHERTEXT!", vectors_counter, level_counter);
			}else{
				printf("\nDone.... In %zu vector, in ML-KEM-%zu level sequrity CIPHERTEXT is identical with vector NIST....", vectors_counter, level_counter);
			}
			
			// Free ciphertext buffer using dedicated destructor.
			// Ensures proper zeroization before deallocation.
			ml_kem_ciphertext_destroy_core(curr_ciphertext, k);
			
			vectors_counter++;
		}
			
	}
	printf("\n");	
	printf("...................................................................................................................................................\n");
	
	return 0;
}

// Convert single HEX character to numeric value. 
// Returns:  0..15 on success or -1 on invalid input
static int hexval(int c)
{
	if(c >= '0' && c <= '9') { return c - '0'; }
	else if(c >= 'a' && c <= 'f') { return c - 'a' + 10; }
	else if(c >= 'A' && c <= 'F') { return c - 'A' + 10; }
	else { return -1; }
}

// Parse HEX string from JSON line into byte array.
// Expected format: "key": "A1B2C3..."
// Behavior: 1. Skips until third quote (start of HEX data)
// 2. Converts each pair of HEX chars into one byte
// 3. Performs validation on input format
// Returns: number of bytes written or -1 on error	
int read_hex_byte(const char *in, u8 *out, size_t size_out_mass)
{
	if(!in || !out) { return -1; }
	
	int symb;
	size_t in_counter = 0;
	
	// Skip until HEX data start (after third quote)
	size_t dq_counter = 0;
	while(dq_counter != 3 && in_counter < SIZE_BUFFER)
	{
		symb = in[in_counter];
		if(symb == '"') { dq_counter++; }
		in_counter++;
	}
	
	size_t out_counter = 0;
	while(out_counter < size_out_mass && in_counter < SIZE_BUFFER)
	{
		// High nibble
		symb = in[in_counter];
		if(symb == '"') { break; }
		if(symb == '\0' || symb == ' ' || symb == '\n') { return -1; }
		symb = hexval(symb);
		if(symb < 0) { return symb; }
		
		out[out_counter] = symb;
		out[out_counter] <<= 4;
		in_counter++;
		
		// Low nibble
		symb = in[in_counter];
		if(symb == '\0' || symb == ' ' || symb == '\n' || symb == '"') { return -1; }
		symb = hexval(symb);
		if(symb < 0) { return symb; }
		
		out[out_counter] |= symb;
		
		out_counter++;
		in_counter++;
	}
	return out_counter;
}
