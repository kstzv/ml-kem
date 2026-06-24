// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo
#include <stdio.h>
#include <ml_kem.h>

// This test analyze and count memory in ML-KEM implementation with pool

const size_t KB = 1024;

int main()
{
	// Counters
	size_t total_persistent_memory = 0;
	size_t total_per_slot_memory = 0;
	size_t total_temp_memory = 0;
	
	// Input message 
	printf("\n\n=)=))=)))=))))=)))))=))))))=)))))))=))))))))=)))))))))=))))))))))=)))))))))))=))))))))))))=)))))))))))))=))))))))))))))=)))))))))))))))\n\n");
	printf("\nThis program estimates the memory consumption of the ML-KEM implementation\n");
	printf("Memory is divided into two categories:\n");
	printf("\t1. Persistent memory. Allocated once per ML-KEM object and shared by all slots\n");
	printf("\t2.  Per-slot memory. Allocated separately for each decapsulation slot and scales linearly with the pool size\n");
	printf("\t3. Temporary initialization memory. Allocated only during key generation\n");
	printf("\n");
	printf("A slot represents one concurrent decapsulation context\n");
	printf("Example persistent memory: struct for persistent key context for ML-KEM - struct ml_kem_ctx\n");
	printf("Example per-slot memory: struct for encapsulation context for ML-KEM - struct ml_kem_encaps_ctx\n");
	printf("About temporary initialization memory: struct ml_kem_temp is used only during key generation\n");
	printf("\t\tIt is released immediately after the keys are created\n");
	
	printf("\n\n=>=>>=>>>=>>>>=>>>>>=>>>>>>=>>>>>>>=>>>>>>>>=>>>>>>>>>=>>>>>>>>>>=>>>>>>>>>>>=>>>>>>>>>>>>=>>>>>>>>>>>>>=>>>>>>>>>>>>>>\n\n");
	
	printf("For ML-KEM-512 level sequrity:\n");
	
	// Count keys struct
	total_persistent_memory += sizeof(struct ml_kem_ctx);
	total_persistent_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // secret s
	total_persistent_memory += RES_PUBL_PART_LVL_512;               // message pk
	
	// Count head pool
	total_persistent_memory += sizeof(struct ml_kem_pool_decaps_ctx);
	printf("\tOnly for persistent memory in ML-KEM-512 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_persistent_memory, total_persistent_memory/KB, total_persistent_memory%KB);
	
	// Count temp struct
	total_temp_memory += sizeof(struct ml_kem_temp);          
	total_temp_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_temp_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // secret s
	total_temp_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // unpack pk
	total_temp_memory += ML_KEM_MATRIX_XOF_BYTES;             // massive for rae bytes from SHA3/SHAKE
	printf("\tOnly for temporary memory in ML-KEM-512 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_temp_memory, total_temp_memory/KB, total_temp_memory%KB);
	
	// Counter slot struct
	total_per_slot_memory += sizeof(struct ml_kem_decaps_ctx);
	
	total_per_slot_memory += sizeof(struct ml_kem_decrypt_ctx);
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // v
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // u
	total_per_slot_memory += LEN_CIPHERTEXT_512;                  // ciphertext in message
	
	total_per_slot_memory += sizeof(struct ml_kem_encaps_ctx);
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // unpack pk
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // u
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // v
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_512; // y
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_per_slot_memory += RES_PUBL_PART_LVL_512;               // pk in message
	total_per_slot_memory += LEN_CIPHERTEXT_512;                  // ciphertext in message
	total_per_slot_memory += ML_KEM_MATRIX_XOF_BYTES;             // massive for rae bytes from SHA3/SHAKE
	printf("\tOnly for one slot in per-slot memory in ML-KEM-512 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_per_slot_memory, total_per_slot_memory/KB, total_per_slot_memory%KB);
	
	printf("\n\t\tAll memory for 1 slot: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory, (total_persistent_memory + total_per_slot_memory)/KB,
		(total_persistent_memory + total_per_slot_memory)%KB);
	printf("\n\t\tAll memory for 2 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 2, (total_persistent_memory + total_per_slot_memory * 2)/KB,
		(total_persistent_memory + total_per_slot_memory * 2)%KB);
	printf("\n\t\tAll memory for 4 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 4, (total_persistent_memory + total_per_slot_memory * 4)/KB,
		(total_persistent_memory + total_per_slot_memory * 4)%KB);
	printf("\n\t\tAll memory for 8 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 8, (total_persistent_memory + total_per_slot_memory * 8)/KB,
		(total_persistent_memory + total_per_slot_memory * 8)%KB);
	printf("\n\t\tAll memory for 16 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 16, (total_persistent_memory + total_per_slot_memory * 16)/KB,
		(total_persistent_memory + total_per_slot_memory * 16)%KB);
	printf("\n\t\tAll memory for 32 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 32, (total_persistent_memory + total_per_slot_memory * 32)/KB,
		(total_persistent_memory + total_per_slot_memory * 32)%KB);
	printf("\n\t\tAll memory for 64 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 64, (total_persistent_memory + total_per_slot_memory * 64)/KB,
		(total_persistent_memory + total_per_slot_memory * 64)%KB);
	printf("\n\t\tAll memory for 128 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 128, (total_persistent_memory + total_per_slot_memory * 128)/KB,
		(total_persistent_memory + total_per_slot_memory * 128)%KB);

	
	printf("\n\n=+=++=+++=++++=+++++=++++++=+++++++=+++++++++=+++++++++=+++++++++++=+++++++++++=++++++++++++=+++++++++++++=++++++++++++++\n\n");
	
	// Reset counters
	total_persistent_memory = 0;
	total_per_slot_memory = 0;
	total_temp_memory = 0;
	
	printf("For ML-KEM-768 level sequrity:\n");
	
	// Count keys struct
	total_persistent_memory += sizeof(struct ml_kem_ctx);
	total_persistent_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // secret s
	total_persistent_memory += RES_PUBL_PART_LVL_768;               // message pk
	
	// Count head pool
	total_persistent_memory += sizeof(struct ml_kem_pool_decaps_ctx);
	printf("\tOnly for persistent memory in ML-KEM-768 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_persistent_memory, total_persistent_memory/KB, total_persistent_memory%KB);
	
	// Count temp struct
	total_temp_memory += sizeof(struct ml_kem_temp);          
	total_temp_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_temp_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // secret s
	total_temp_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // unpack pk
	total_temp_memory += ML_KEM_MATRIX_XOF_BYTES;             // massive for rae bytes from SHA3/SHAKE
	printf("\tOnly for temporary memory in ML-KEM-512 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_temp_memory, total_temp_memory/KB, total_temp_memory%KB);
	
	// Counter slot struct
	total_per_slot_memory += sizeof(struct ml_kem_decaps_ctx);
	
	total_per_slot_memory += sizeof(struct ml_kem_decrypt_ctx);
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // v
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // u
	total_per_slot_memory += LEN_CIPHERTEXT_768;                  // ciphertext in message
	
	total_per_slot_memory += sizeof(struct ml_kem_encaps_ctx);
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // unpack pk
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // u
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // v
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_768; // y
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_per_slot_memory += RES_PUBL_PART_LVL_768;               // pk in message
	total_per_slot_memory += LEN_CIPHERTEXT_768;                  // ciphertext in message
	total_per_slot_memory += ML_KEM_MATRIX_XOF_BYTES;             // massive for rae bytes from SHA3/SHAKE
	printf("\tOnly for one slot in per-slot memory in ML-KEM-768 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_per_slot_memory, total_per_slot_memory/KB, total_per_slot_memory%KB);
	
	printf("\n\t\tAll memory for 1 slot: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory, (total_persistent_memory + total_per_slot_memory)/KB,
		(total_persistent_memory + total_per_slot_memory)%KB);
	printf("\n\t\tAll memory for 2 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 2, (total_persistent_memory + total_per_slot_memory * 2)/KB,
		(total_persistent_memory + total_per_slot_memory * 2)%KB);
	printf("\n\t\tAll memory for 4 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 4, (total_persistent_memory + total_per_slot_memory * 4)/KB,
		(total_persistent_memory + total_per_slot_memory * 4)%KB);
	printf("\n\t\tAll memory for 8 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 8, (total_persistent_memory + total_per_slot_memory * 8)/KB,
		(total_persistent_memory + total_per_slot_memory * 8)%KB);
	printf("\n\t\tAll memory for 16 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 16, (total_persistent_memory + total_per_slot_memory * 16)/KB,
		(total_persistent_memory + total_per_slot_memory * 16)%KB);
	printf("\n\t\tAll memory for 32 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 32, (total_persistent_memory + total_per_slot_memory * 32)/KB,
		(total_persistent_memory + total_per_slot_memory * 32)%KB);
	printf("\n\t\tAll memory for 64 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 64, (total_persistent_memory + total_per_slot_memory * 64)/KB,
		(total_persistent_memory + total_per_slot_memory * 64)%KB);
	printf("\n\t\tAll memory for 128 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 128, (total_persistent_memory + total_per_slot_memory * 128)/KB,
		(total_persistent_memory + total_per_slot_memory * 128)%KB);
		
		
	printf("\n\n=-=--=---=----=-----=------=-------=--------=---------=----------=-----------=-------------=-------------=--------------=---------------\n\n");
	
	// Reset counters
	total_persistent_memory = 0;
	total_per_slot_memory = 0;
	total_temp_memory = 0;
	
	printf("For ML-KEM-1024 level sequrity:\n");
	
	// Count keys struct
	total_persistent_memory += sizeof(struct ml_kem_ctx);
	total_persistent_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // secret s
	total_persistent_memory += RES_PUBL_PART_LVL_1024;               // message pk
	
	// Count head pool
	total_persistent_memory += sizeof(struct ml_kem_pool_decaps_ctx);
	printf("\tOnly for persistent memory in ML-KEM-1024 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_persistent_memory, total_persistent_memory/KB, total_persistent_memory%KB);
	
	// Count temp struct
	total_temp_memory += sizeof(struct ml_kem_temp);          
	total_temp_memory += sizeof(u16) * ML_KEM_N;              // poly
	total_temp_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // secret s
	total_temp_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // unpack pk
	total_temp_memory += ML_KEM_MATRIX_XOF_BYTES;             // massive for rae bytes from SHA3/SHAKE
	printf("\tOnly for temporary memory in ML-KEM-1024 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_temp_memory, total_temp_memory/KB, total_temp_memory%KB);
	
	// Counter slot struct
	total_per_slot_memory += sizeof(struct ml_kem_decaps_ctx);
	
	total_per_slot_memory += sizeof(struct ml_kem_decrypt_ctx);
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;               // v
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;               // poly
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // u
	total_per_slot_memory += LEN_CIPHERTEXT_1024;                  // ciphertext in message
	
	total_per_slot_memory += sizeof(struct ml_kem_encaps_ctx);
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // unpack pk
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // u
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;               // v
	total_per_slot_memory += sizeof(u16) * ML_KEM_N * ML_KEM_1024; // y
	total_per_slot_memory += sizeof(u16) * ML_KEM_N;               // poly
	total_per_slot_memory += RES_PUBL_PART_LVL_1024;               // pk in message
	total_per_slot_memory += LEN_CIPHERTEXT_1024;                  // ciphertext in message
	total_per_slot_memory += ML_KEM_MATRIX_XOF_BYTES;              // massive for rae bytes from SHA3/SHAKE
	printf("\tOnly for one slot in per-slot memory in ML-KEM-1024 level sequrity: %zu bytes(%zu kB and %zu bytes)\n", total_per_slot_memory, total_per_slot_memory/KB, total_per_slot_memory%KB);
	
	printf("\n\t\tAll memory for 1 slot: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory, (total_persistent_memory + total_per_slot_memory)/KB,
		(total_persistent_memory + total_per_slot_memory)%KB);
	printf("\n\t\tAll memory for 2 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 2, (total_persistent_memory + total_per_slot_memory * 2)/KB,
		(total_persistent_memory + total_per_slot_memory * 2)%KB);
	printf("\n\t\tAll memory for 4 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 4, (total_persistent_memory + total_per_slot_memory * 4)/KB,
		(total_persistent_memory + total_per_slot_memory * 4)%KB);
	printf("\n\t\tAll memory for 8 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 8, (total_persistent_memory + total_per_slot_memory * 8)/KB,
		(total_persistent_memory + total_per_slot_memory * 8)%KB);
	printf("\n\t\tAll memory for 16 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 16, (total_persistent_memory + total_per_slot_memory * 16)/KB,
		(total_persistent_memory + total_per_slot_memory * 16)%KB);
	printf("\n\t\tAll memory for 32 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 32, (total_persistent_memory + total_per_slot_memory * 32)/KB,
		(total_persistent_memory + total_per_slot_memory * 32)%KB);
	printf("\n\t\tAll memory for 64 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 64, (total_persistent_memory + total_per_slot_memory * 64)/KB,
		(total_persistent_memory + total_per_slot_memory * 64)%KB);
	printf("\n\t\tAll memory for 128 slots: %zu(%zu kB and %zu bytes)\n", total_persistent_memory + total_per_slot_memory * 128, (total_persistent_memory + total_per_slot_memory * 128)/KB,
		(total_persistent_memory + total_per_slot_memory * 128)%KB);
	
	
	printf("\n\n=`=``=```=````=`````=``````=```````=````````=`````````=``````````=```````````=````````````=`````````````=``````````````=```````````````\n\n");
	
	
	return 0;
}
