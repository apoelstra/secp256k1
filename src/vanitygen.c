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

#if 0
#include "ripemd160.c"
#include "segwit_addr.c"
/* Returns 1 for a match, 0 for no match */
int check(secp256k1_ge* pub) {
    unsigned char buf[33];
    unsigned char hash[32];
    char output[64];
    size_t bufsiz = sizeof(buf);
    secp256k1_sha256 hasher;

    secp256k1_eckey_pubkey_serialize(pub, buf, &bufsiz, 1);
    secp256k1_fe_normalize_var(&pub->x);
    secp256k1_fe_get_b32(&buf[1], &pub->x);

    /* Try both even and odd */
    buf[0] = 2;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, buf, 33);
    secp256k1_sha256_finalize(&hasher, hash);
    ripemd160(hash, 32, hash);
    segwit_addr_encode(output, "bc", 0, hash, 20);
    if (memcmp(output, "bc1qandyt0sh", 12) == 0) {
        int i;
        for (i = 0; i < 33; ++i) printf("%02x", buf[i]);
        printf("\n%s\n", output);
        return 1;
    }

    buf[0] = 3;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, buf, 33);
    secp256k1_sha256_finalize(&hasher, hash);
    ripemd160(hash, 32, hash);
    segwit_addr_encode(output, "bc", 0, hash, 20);
    if (memcmp(output, "bc1qandyt", 9) == 0) {
        int i;
        for (i = 0; i < 33; ++i) printf("%02x", buf[i]);
        printf("\n%s\n", output);
        return 1;
    }

    return 0;
}
#endif

int check_rusty(secp256k1_ge* pub) {
    unsigned char buf[33];
    size_t bufsiz = sizeof(buf);
    size_t idx;
    int zero_count = 0;
    int state = 0;

    secp256k1_eckey_pubkey_serialize(pub, buf, &bufsiz, 1);

    for (idx = 1; idx < sizeof(buf); ++idx) {
        switch (state) {
        /* Initial 0 search */
        case 0:
            if (buf[idx] == 0x00) {
                zero_count += 2;
            } else if (buf[idx] == 0x0b) {
                zero_count += 1;
                state = 10;
            } else if (buf[idx] == 0xba) {
                state = 20;
            } else {
                return 0;
            }
            break;
        /* Final 0 search */
        case 1:
            if (buf[idx] == 0) {
                zero_count += 2;
            } else if ((buf[idx] & 0xf0) == 0) {
                zero_count += 1;
                state = 2;
            } else {
                state = 2;
            }
            break;
        /* Inside 0x0bad */
        case 10:
            if (buf[idx] == 0xad) {
                state = 1;
            } else {
                return 0;
            }
            break;
        /* Inside 0xbad0 */
        case 20:
            if (buf[idx] == 0xd0) {
                zero_count += 1;
                state = 1;
            } else if ((buf[idx] & 0xf0) == 0xd0) {
                state = 2;
            } else{
                return 0;
            }
            break;
        }

        if (state == 2) {
            break;
        }
    }

    if (zero_count > 10) {
        int i;
        for (i = 0; i < 33; ++i) printf("%02x", buf[i]);
        printf("\n");
        return 1;
    }

    return 0;
}

int check_rusty2(secp256k1_ge* pub) {
    unsigned char buf[33];
    size_t bufsiz = sizeof(buf);
    size_t idx;
    size_t b8_count = 0;

    secp256k1_eckey_pubkey_serialize(pub, buf, &bufsiz, 1);
    for (idx = 1; idx < bufsiz; idx++) {
	unsigned char lo = buf[idx] & 0xf;
	unsigned char hi = buf[idx] >> 4;
	if (lo == 8 || lo == 12 || lo == 11) b8_count++;
	if (hi == 8 || hi == 12 || hi == 11) b8_count++;
    }

    if (b8_count > 40) {
        int i;
        for (i = 0; i < 33; ++i) printf("%02X", buf[i]);
        printf("\n");
        return 1;
    }
    return 0;
}

#define check check_rusty2

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
        rzr[0] = gejs[0].z;
        for (i = 1; i < n_rzr; ++i) {
            secp256k1_gej_double_var(&gejs[i], &gejs[i - 1], &rzr[i]);
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

