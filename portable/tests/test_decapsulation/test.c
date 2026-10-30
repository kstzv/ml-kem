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

// Number of slots in the decapsulation pool (controls parallelism level)
#define NUMBER_SLOTS 1

// Number of test vectors per parameter set and buffer size for JSON line reading
#define NUMBER_VECTORS_ONE_LEVEL 10
#define SIZE_BUFFER 8192

// Step increments for switching between ML-KEM parameter sets
#define LEVEL_STEP 256
#define SIZE_EK_STEP 384
#define SIZE_DK_STEP 768
#define K_STEP 1

// Buffers for seed (d) and shared secrets from encapsulation/decapsulation
u8 mass_c[LEN_CIPHERTEXT_1024];
u8 mass_dk[LEN_SK_1024];
u8 decaps_res[ML_KEM_SEED_BYTES];
u8 mass_d[ML_KEM_SEED_BYTES];

// Helper functions for HEX parsing
static int hexval(int c);
int read_hex_byte(const char *in, u8 *out, size_t size_out_mass);

int main()
{
	printf("\nThis is test decapsulation test and finally test in ML-KEM");
	printf("\nThis is show 30 messages about everyone of 30 vectors NIST(76 - 105 vectors in file)\n");
	printf("\nfrom vector d from file keygen, with this seed going to ALL algorithm\n");
	printf("\nVectors dk, c and k is being unpacked\n");
	printf("\nDecapsulation is performed using a function of this implementation\n");
	printf("\nAnd the vectors obtained from the file will be checked against the output produced by the functions of this implementation\n");
	printf("\nIf you to see");
	printf("\n\"Wrong! In *** vector, in ML-KEM-*** level sequrity!\"");
	printf("\nso this ML-KEM version is wrong\n");
	printf("\nIf you to see everything");
	printf("\nDone.... In *** vector, in ML-KEM-*** level sequrity is identical with vector NIST....");
	printf("\nso this ML-KEM version is good\n");
	printf("\nIn test using memcmp()....\n");
	printf("...................................................................................................................................................\n");
	
	// Buffer for reading lines from JSON test vector file
	char buffer[SIZE_BUFFER];
	
	// Open NIST test vectors (keygen projection)
	FILE *f = fopen("ML-KEM-encapDecap-FIPS203/internalProjection.json", "r");
	if(!f) { return -1; }
	
	// Skip initial content until first "parameterSet" entry
	while(fgets(buffer, sizeof(buffer), f))
	{
		if(strstr(buffer, "\"tgId\": 4"))
		{
			break;
		}
	}
	
	// Initialize counters for the first parameter set: ML-KEM-512 (k = 2). These values are incremented per parameter set transition.
	size_t level_counter = 512;
	size_t size_dk_counter = 1632;
	size_t vectors_counter = 0;
	size_t len_ciphertext = LEN_CIPHERTEXT_512;
	enum ml_kem_k k = 2;
	while(fgets(buffer, sizeof(buffer), f))
	{
		if(strstr(buffer, "\"tgId\": 4"))
		{
			printf("\n");
			printf("...................................................................................................................................................\n");
			printf("\nThis is 25 tests vectors all algorithm and decaps in ML-KEM-512\n");
			len_ciphertext = LEN_CIPHERTEXT_512;
			level_counter += LEVEL_STEP;
			size_dk_counter = LEN_SK_512;
			k += K_STEP;
			vectors_counter = 0;
		}else if(strstr(buffer, "\"tgId\": 5"))
		{
			printf("\n");
			printf("...................................................................................................................................................\n");
			printf("\nThis is 25 tests vectors all algorithm and decaps in ML-KEM-768\n");
			len_ciphertext = LEN_CIPHERTEXT_768;
			level_counter += LEVEL_STEP;
			size_dk_counter = LEN_SK_768;
			k += K_STEP;
			vectors_counter = 0;
		}else if(strstr(buffer, "\"tgId\": 6"))
		{
			printf("\n");
			printf("...................................................................................................................................................\n");
			printf("\nThis is 25 tests vectors all algorithm and decaps in ML-KEM-1024\n");
			len_ciphertext = LEN_CIPHERTEXT_1024;
			level_counter += LEVEL_STEP;
			size_dk_counter = LEN_SK_1024;
			k += K_STEP;
			vectors_counter = 0;
		}else if(strstr(buffer, "\"dk\": \""))
		{
			size_t ret = read_hex_byte(buffer, mass_dk, size_dk_counter);
			if(ret != size_dk_counter) { return -1; }
		}else if(strstr(buffer, "\"c\": \""))
		{
			size_t ret = read_hex_byte(buffer, mass_c, len_ciphertext);
			if(ret != len_ciphertext) { return -1; }
		}else if(strstr(buffer, "\"k\": \""))
		{
			size_t ret = read_hex_byte(buffer, decaps_res, ML_KEM_SEED_BYTES);
			if(ret != ML_KEM_SEED_BYTES) { return -1; }
			
			u8 local_decaps_res[ML_KEM_SEED_BYTES];
			
			struct ml_kem_general_keys_decaps_ctx *ctx;
			ctx = ml_kem_create_object_from_imported_sk(mass_dk, size_dk_counter, NUMBER_SLOTS);
			if(!ctx) { printf("Error in ml_kem_create_object_from_imported_sk()\n"); return -1; }
			
			int res = ml_kem_decaps_core(ctx, mass_c, len_ciphertext, local_decaps_res, ML_KEM_SEED_BYTES);
			if(res != 0) { printf("Error in ml_kem_decaps_core()\n"); ml_kem_destroy_core(ctx); return res; }
			
			if(memcmp(local_decaps_res, decaps_res, ML_KEM_SEED_BYTES) != 0)
			{
				printf("\nWrong! In %zu vector, in ML-KEM-%zu level sequrity!", vectors_counter, level_counter);
			}else{
				printf("\nDone.... In %zu vector, in ML-KEM-%zu level sequrity is identical with vector NIST....", vectors_counter, level_counter);
			}
			
			ml_kem_destroy_core(ctx);
			vectors_counter++;
		}else if(strstr(buffer, "\"tgId\": 7")) { break; }
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
