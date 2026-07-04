#include "ml_kem_userspace_port.h"


// Functions for allocations
void *ml_kem_alloc(size_t size_alloc) { return malloc(size_alloc); }
void ml_kem_free(void *ptr) { free(ptr); }

// Local function entropy ML-KEM (Using in Linux OS userspace)
int ml_kem_entropy(void *buf, size_t len)
{
	ssize_t ret = 0;
	size_t offset = 0;
	while(offset < len)
	{
		ret = getrandom((u8 *)buf + offset, len - offset, 0);
		if(ret < 0) 
		{
			if(errno == EINTR) { continue; }
			return -1;
		}
		offset += ret;
	}
	return 0;
}

// Secure memory wipe function.
//
// Uses a volatile pointer to prevent compiler optimizations
// that could remove the memory clearing operation.
//
// NOTE:
//   Effectiveness depends on compiler behavior.
//   For high-assurance environments, consider platform-specific primitives
//   (e.g., explicit_bzero, memset_s, or kernel equivalents).
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
