/* test_main.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfcrypt/test/test.h>
#include <stdio.h>
#include "hw.h"

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

static func_args args = { 0 } ;

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/logging.h>

static ecc_key keyU;
#define ECC_CURVE_SZ 48
#define ECC_CURVE_ID ECC_SECP384R1

static void print_hex(uint8_t* data, int sz)
{
    int i;
    for (i = 0; i < sz; i++) {
        printf("%02X ", data[i]);
        if (i > 0 && ((i+1) % 16) == 0)
            printf("\n");
    }
    printf("\n");
}


int ecc_pubkey_test(void)
{
    static const unsigned char keypriv[] = {
        0xF9, 0x2C, 0x02, 0xED, 0x62, 0x9E, 0x4B, 0x48, 0xC0, 0x58, 0x4B, 0x1C,
        0x6C, 0xE3, 0xA3, 0xE3, 0xB4, 0xFA, 0xAE, 0x4A, 0xFC, 0x6A, 0xCB, 0x04,
        0x55, 0xE7, 0x3D, 0xFC, 0x39, 0x2E, 0x6A, 0x0A, 0xE3, 0x93, 0xA8, 0x56,
        0x5E, 0x6B, 0x97, 0x14, 0xD1, 0x22, 0x4B, 0x57, 0xD8, 0x3F, 0x8A, 0x08
    };
    int ret;
    uint8_t pubKey[ECC_CURVE_SZ*2];
    uint32_t pubQxSz = ECC_CURVE_SZ, pubQySz = ECC_CURVE_SZ;
    WC_RNG rng;

    if (wc_ecc_init((struct ecc_key *)&keyU)) { return -1; }
 
    /* RNG for ECC_TIMING_RESISTANCE option */
    
    ret = wc_InitRng(&rng);
    if (ret != 0) { printf("wc_InitRng %d\n", ret); return -1; }
    if (wc_ecc_set_rng((struct ecc_key *)&keyU, &rng)) { return -1; }
 
    ret = wc_ecc_import_private_key(keypriv, sizeof(keypriv), NULL, 0, &keyU);
    if (ret != 0) { printf("wc_ecc_import_private_key %d\n", ret); return -1; }
    ret = wc_ecc_make_pub(&keyU, NULL);
    if (ret != 0) { printf("wc_ecc_make_pub %d\n", ret); return -1; }
 
    ret = wc_ecc_export_public_raw(&keyU,
            pubKey, &pubQxSz,               /* public Qx */
            pubKey+ECC_CURVE_SZ, &pubQySz   /* public Qy */
    );
    if (ret != 0) { printf("wc_ecc_export_public_raw %d\n", ret); return -1; }

    printf("Public Key Qx: %d\n", pubQxSz);
    print_hex(pubKey, ECC_CURVE_SZ);
    printf("Public Key Qy: %d\n", pubQySz);
    print_hex(pubKey+ECC_CURVE_SZ, ECC_CURVE_SZ);

    wc_ecc_free(&keyU);
    wc_FreeRng(&rng);
    return 0;
}



void main(void)
{
    int test_num = 0;

    wolfCrypt_Init(); /* required for ksdk_port_init */
    do
    {
        /* Used for testing, must have a delay so no data is missed while serial is initializing */
        #ifdef WOLFSSL_FRDM_K64_JENKINS
            /* run twice */
            if(test_num == 2){
                printf("\n&&&&&&&&&&&&& done &&&&&&&&&&&&&&&");
                delay_us(1000000);
                break;
            }
            delay_us(1000000); /* 1 second */
        #endif

        (void)ecc_pubkey_test();

        printf("\nCrypt Test %d:\n", test_num);
        wolfcrypt_test(&args);
        printf("Crypt Test %d: Return code %d\n", test_num, args.return_code);

        test_num++;
    } while(args.return_code == 0);

    /* Print this again for redundancy */
    #ifdef WOLFSSL_FRDM_K64_JENKINS
        printf("\n&&&&&&&&&&&&&& done &&&&&&&&&&&&&\n");
        delay_us(1000000);
    #endif

    wolfCrypt_Cleanup();
}


/* SAMPLE OUTPUT:
Crypt Test 0:
SHA      test passed!
SHA-256  test passed!
SHA-384  test passed!
SHA-512  test passed!
HMAC-SHA test passed!
HMAC-SHA256 test passed!
HMAC-SHA384 test passed!
HMAC-SHA512 test passed!
GMAC     test passed!
Chacha   test passed!
POLY1305 test passed!
ChaCha20-Poly1305 AEAD test passed!
AES      test passed!
AES-GCM  test passed!
AES-CCM  test passed!
RANDOM   test passed!
RSA      test passed!
ECC      test passed!
CURVE25519 test passed!
ED25519  test passed!
Crypt Test 0: Return code 0
*/
