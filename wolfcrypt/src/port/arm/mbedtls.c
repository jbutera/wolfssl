/* mbedtls.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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
#include <wolfssl/wolfcrypt/port/arm/mbedtls.h>

#ifdef WOLF_MBEDTLS_COMPAT

void mbedtls_pk_init( mbedtls_pk_context *pk )
{
    if (pk)
        memset(pk, 0, sizeof(*pk));
}

void mbedtls_pk_free( mbedtls_pk_context *pk )
{
    /* cleanup keys */
    switch (pk->type) {
        case MBEDTLS_PK_RSA:
        case MBEDTLS_PK_RSA_ALT:
        case MBEDTLS_PK_RSASSA_PSS:
    #ifndef NO_RSA
            wc_FreeRsaKey(&pk->key.rsa);
    #endif
            break;
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
    #ifdef HAVE_ECC
            wc_ecc_free(&pk->key.ecc);
    #endif
            break;

    }
}

mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *pk )
{
    return pk->type;

}

size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *pk )
{
    return pk->keySz;
}

int mbedtls_pk_parse_key( mbedtls_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen )
{
    int ret, derLen;
    byte der[2048];
    word32 idx = 0;

    (void)pwdlen;

    if (pk == NULL || key == NULL)
        return -1;

    ret = wc_KeyPemToDer(key, keylen, der, sizeof(der), (const char*)pwd);
    if (ret <= 0)
        return -1;

    derLen = ret;
    ret = -1; /* default to failure */

    switch (pk->type) {
        case MBEDTLS_PK_RSA:
        case MBEDTLS_PK_RSA_ALT:
        case MBEDTLS_PK_RSASSA_PSS:
        #ifndef NO_RSA
            ret = wc_InitRsaKey(&pk->key.rsa, NULL);
            if (ret == 0) {
                ret = wc_RsaPrivateKeyDecode(der, &idx, &pk->key.rsa, ret);
            }
        #endif
            break;
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
        #ifdef HAVE_ECC
            ret = wc_ecc_init(&pk->key.ecc);
            if (ret == 0) {
                ret = wc_EccPrivateKeyDecode(key, &idx, &pk->key.ecc, keylen);
            }
        #endif
            break;
    }

    return ret;
}


#endif /* WOLF_MBEDTLS_COMPAT */
