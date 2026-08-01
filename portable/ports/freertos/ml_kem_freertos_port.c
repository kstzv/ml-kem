#include "ml_kem_core_header.h"

// Functions for allocations
void *ml_kem_alloc(size_t size_alloc) { return pvPortMalloc(size_alloc); }
void ml_kem_free(void *ptr) { vPortFree(ptr); }

// Universal entropy function is missing in FreeRTOS - it all depends on the environment 
// Therefore, this function should be passed directly in the parameters
int ml_kem_entropy(void *buf, size_t len)
{
	(void)buf;
    (void)len;
	return -ML_KEM_SYSTEM_ENTROPY_FAILED;
}

// Secure memory wipe
// Uses a volatile pointer to reduce the likelihood that the compiler
// removes the memory clearing operation as dead code
// NOTE:
//   On platforms providing a dedicated secure zeroization primitive,
//   that implementation may be preferred
void ml_kem_memzero(void *ptr, size_t len)
{
	if(!ptr) { return; }
	
	volatile unsigned char *inside_ptr = (volatile unsigned char *)ptr;

	for(size_t i = 0; i < len; i++)
	{
		inside_ptr[i] = 0;
	}
}


// Functions for atomic operations 
#if defined(ML_KEM_ATOMIC_STDATOMIC) // Stdatomic implementation

// Get slot
bool ml_kem_try_acquire_slot(ml_kem_atomic_t *slot)
{
	int expected = 1;
	return atomic_compare_exchange_strong_explicit(slot, &expected, 0, memory_order_acquire, memory_order_relaxed);
}

// Create atomic variable
void ml_kem_release_slot(ml_kem_atomic_t *slot) { atomic_store_explicit(slot, 1, memory_order_release); }

// Free slot
void ml_kem_atomic_init_slot(ml_kem_atomic_t *slot) { atomic_init(slot, 1); }

#elif defined(ML_KEM_ATOMIC_FREERTOS) // FreeRTOS atomic.h

// Get slot
bool ml_kem_try_acquire_slot(ml_kem_atomic_t *slot)
{
	return Atomic_CompareAndSwap_u32((u32 volatile *)slot, 0, 1) == ATOMIC_COMPARE_AND_SWAP_SUCCESS;
}

// Create atomic variable
void ml_kem_release_slot(ml_kem_atomic_t *slot) { (void)Atomic_CompareAndSwap_u32((u32 volatile *)slot, 1, 0); }

// Free slot
void ml_kem_atomic_init_slot(ml_kem_atomic_t *slot) { *slot = 1; }

#else

#error "Atomic operations are not defined on this platform."

#endif // Atomic operations

// TODO:
// - add GCC/Clang __atomic builtins backend
// - optionally add direct critical-section backend for FreeRTOS
//   versions or ports without atomic.h

// Error handling

// Error in create keys
struct ml_kem_pool_decaps_ctx *err_create_keys(const int err)
{
	(void)err;
	return NULL;
}

// Error in encaps
u8 *err_encaps(const int err)
{
	(void)err;
	return NULL;
}


// Error in decaps
int err_decaps(const int err) { return err; }

// Error in get oublic key
int err_get_pk(const int err) { return err; }
