// SPDX-License-Identifier: MIT
// Minimal smoke test for all 9 public API functions through the Linux userspace port.

#include <stdio.h>
#include <string.h>
#include "ml_kem.h"

#define CHECK(expr) do {                                 \
    if (!(expr)) {                                       \
        fprintf(stderr, "FAIL: %s\n", #expr);           \
        goto cleanup;                                    \
    }                                                    \
} while (0)

int main(void)
{
    struct ml_kem_general_keys_decaps_ctx *keys = NULL;
    struct ml_kem_general_keys_decaps_ctx *imported = NULL;
    struct ml_kem_pool_encaps_ctx *pool = NULL;
    u8 pk[RES_PUBL_PART_LVL_512];
    u8 sk[LEN_SK_512];
    u8 ct[LEN_CIPHERTEXT_512];
    u8 ss_enc[ML_KEM_SEED_BYTES];
    u8 ss_dec[ML_KEM_SEED_BYTES];
    int ok = 0;

    keys = ml_kem_create_object(ML_KEM_512, 1, NULL);
    CHECK(keys != NULL);
    CHECK(ml_kem_get_public_key(keys, pk, sizeof(pk)) == 0);
    CHECK(ml_kem_get_sk(keys, sk, sizeof(sk)) == (int)sizeof(sk));

    imported = ml_kem_create_object_from_imported_sk(sk, sizeof(sk), 1);
    CHECK(imported != NULL);

    pool = create_encaps_pool(1, 0, 0);
    CHECK(pool != NULL);
    CHECK(ml_kem_encaps_core(pool, pk, sizeof(pk), ct, sizeof(ct),
                             ss_enc, sizeof(ss_enc), NULL) == 0);
    CHECK(ml_kem_decaps_core(imported, ct, sizeof(ct),
                             ss_dec, sizeof(ss_dec)) == 0);
    CHECK(memcmp(ss_enc, ss_dec, sizeof(ss_enc)) == 0);

    ok = 1;

cleanup:
    ml_kem_encaps_pool_destroy(pool);
    ml_kem_destroy_core(imported);
    ml_kem_destroy_core(keys);
    ml_kem_memzero(sk, sizeof(sk));
    ml_kem_memzero(ss_enc, sizeof(ss_enc));
    ml_kem_memzero(ss_dec, sizeof(ss_dec));
    puts(ok ? "PASS: ML-KEM userspace port works" : "FAIL: ML-KEM userspace port");
    return ok ? 0 : 1;
}
