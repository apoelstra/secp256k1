/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdint.h>
#include <time.h>

#include "secp256k1.c"
#include "../include/secp256k1.h"
#include "print.h"
#include "testrand_impl.h"

#include "segwit_addr.c"

int check(secp256k1_ge* pub) {
    unsigned char buf[32];
    char output[80];

    secp256k1_fe_normalize_var(&pub->x);
    secp256k1_fe_get_b32(&buf[0], &pub->x);

    segwit_addr_encode(output, "bc", 1, buf, 32);
    if (memcmp(output, "bc1pandrewpoel", 13) == 0) {
        int i;
        for (i = 0; i < 32; ++i) printf("%02x", buf[i]);
        printf("\n%s\n", output);
        return 1;
    }

    return 0;
}

int main(void) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char start_sec[32];
    secp256k1_scalar start_sec_s;
    uint64_t double_count = 0;
    secp256k1_gej pubj;
    const size_t n_rzr = 1000;
    secp256k1_fe *rzr = malloc(n_rzr * sizeof(*rzr));
    secp256k1_ge *effective_ges = malloc(n_rzr * sizeof(*effective_ges));
    secp256k1_gej *gejs = malloc(n_rzr * sizeof(*gejs));
    int overflow = 1;

    puts("Starting");
    if (rzr == NULL || effective_ges == NULL || gejs == NULL) {
        puts("OOM");
        exit(EXIT_FAILURE);
    }

    /* Set initial key */
    while (overflow || secp256k1_scalar_is_zero(&start_sec_s)) {
        FILE* fh = fopen("/dev/urandom", "rb");
        if (fread(start_sec, 32, 1, fh) != 1) {
            puts("fread!");
        }
        fclose(fh);
        secp256k1_scalar_set_b32(&start_sec_s, start_sec, &overflow);
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubj, &start_sec_s);

    /* qpzry9x8gf2tvdw0s3jn54khce6mua7l */
    /* Search */
    while(1) {
        size_t i;
        secp256k1_fe z_sq_inv;

        secp256k1_gej_double_var(&gejs[0], &pubj, NULL);
        effective_ges[0].x = gejs[0].x;
        effective_ges[0].y = gejs[0].y;
        rzr[0] = gejs[0].z;
        for (i = 1; i < n_rzr; ++i) {
            secp256k1_gej_double_var(&gejs[i], &gejs[i - 1], &rzr[i]);
            effective_ges[i].x = gejs[i].x;
            effective_ges[i].y = gejs[i].y;
        }
        pubj = gejs[n_rzr - 1];
        secp256k1_ge_table_set_globalz(n_rzr, effective_ges, rzr);

        secp256k1_fe_inv_var(&z_sq_inv, &pubj.z);
        secp256k1_fe_sqr(&z_sq_inv, &z_sq_inv);

        for (i = 0; i < n_rzr; ++i) {
            ++double_count;
            secp256k1_fe_mul(&effective_ges[i].x, &effective_ges[i].x, &z_sq_inv);
            if (check(&effective_ges[i])) goto done;
            secp256k1_ge_mul_lambda(&effective_ges[i], &effective_ges[i]);
            if (check(&effective_ges[i])) goto done;
            secp256k1_ge_mul_lambda(&effective_ges[i], &effective_ges[i]);
            if (check(&effective_ges[i])) goto done;
        }

    }

done:
    printf("Starting scalar: "); println_scalar(&start_sec_s);
    printf("Double count: %lu\n", (unsigned long) double_count);
    printf("Endo count: 0 or 1 or 2\n");
    free(rzr);
    free(effective_ges);
    free(gejs);
    secp256k1_context_destroy(ctx);
    return 0;
}

