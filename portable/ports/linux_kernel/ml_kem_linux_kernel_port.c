#include "ml_kem_linux_kernel_port.h"
#include <ml_kem_core_header.h>

// Memory allocations and free memory
void *ml_kem_alloc(size_t size_alloc) { return kzalloc(size_alloc, GFP_KERNEL); }
void ml_kem_free(void *ptr) { kfree(ptr); }

// Get random bytes from kernel
int ml_kem_entropy(void *buf, size_t len)
{
	get_random_bytes((u8 *)buf, len);
	return 0;
}

// Memzero 
void ml_kem_memzero(void *ptr, size_t len)
{
	memzero_explicit(ptr, len);
}

// Functions for atomic operations
// Get slot
bool ml_kem_try_acquire_slot(ml_kem_atomic_t *slot)
{
    return atomic_cmpxchg(slot, 1, 0) == 1;
}

// Create atomic variable
void ml_kem_release_slot(ml_kem_atomic_t *slot)
{
    atomic_set(slot, 1);
}

// Free slot
void ml_kem_atomic_init_slot(ml_kem_atomic_t *slot)
{
    atomic_set_release(slot, 1);
}


// Error handling

// Error in create keys
struct ml_kem_pool_decaps_ctx *err_create_keys(const int err)
{
	if(err == -ML_KEM_EINVAL) { return ERR_PTR(-EINVAL); }
	else if( err == -ML_KEM_ENOMEM) { return ERR_PTR(-ENOMEM); }
	else if( err == -ML_KEM_SYSTEM_ENTROPY_FAILED) { return ERR_PTR(-EIO); }
	else if( err == -ML_KEM_CALLBACK_ENTROPY_FAILED) { return ERR_PTR(-EIO); }
	else if( err == -ML_KEM_EAGAIN) { return ERR_PTR(-EAGAIN); }
	else { return ERR_PTR(-EFAULT); }
}

// Error in encaps
u8 *err_encaps(const int err)
{
	if(err == -ML_KEM_EINVAL) { return ERR_PTR(-EINVAL); }
	else if( err == -ML_KEM_ENOMEM) { return ERR_PTR(-ENOMEM); }
	else if( err == -ML_KEM_SYSTEM_ENTROPY_FAILED) { return ERR_PTR(-EIO); }
	else if( err == -ML_KEM_CALLBACK_ENTROPY_FAILED) { return ERR_PTR(-EIO); }
	else if( err == -ML_KEM_ENCAPS_PARAM_ERR) { return ERR_PTR(-EINVAL); }
	else { return ERR_PTR(-EFAULT); }
}

// Error in decaps
int err_decaps(const int err) { return err; }

// Error in get oublic key
int err_get_pk(const int err) { return err; }


