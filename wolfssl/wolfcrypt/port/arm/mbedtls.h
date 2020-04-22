/* mbedtls.h
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

/*!
    \file wolfssl/wolfcrypt/port/arm/mbedtls.h
*/


#ifndef _WOLF_MBEDTLS_H_
#define _WOLF_MBEDTLS_H_

#if defined(WOLF_MBEDTLS) || defined(WOLF_MBEDTLS_COMPAT) || defined(WOLF_AWSTLS)

/* REMOVE ME: WOLF_MBEDTLS_COMPAT */
#define WOLF_MBEDTLS_COMPAT

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>


#ifdef WOLF_MBEDTLS_COMPAT

    /* TLS */
    #define mbedtls_ssl_context                     WOLFSSL
    #define mbedtls_ssl_config                      WOLFSSL_CTX

    #define mbedtls_ssl_init(ctx)                   wolfSSL_new(ctx)

    #define mbedtls_ssl_config_init(method)         wolfSSL_CTX_new(method)
    
    #define mbedtls_ssl_handshake(ssl)              wolfSSL_connect(ssl)

    #define mbedtls_ssl_set_hostname(ssl, alpn)     wolfSSL_UseALPN(ssl, alpn, \
        XSTRLEN(alpn), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)

    #define mbedtls_ssl_conf_verify(ctx, cb, userCtx) \
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, cb)

    #define mbedtls_ssl_read(ssl, buf, len)         wolfSSL_read(ssl, buf, len)
    #define mbedtls_ssl_write(ssl, buf, len)        wolfSSL_write(ssl, buf, len)

    #define mbedtls_ssl_close_notify(ssl)           wolfSSL_shutdown(ssl)
    #define mbedtls_ssl_free(ssl)                   wolfSSL_free(ssl)

    #define mbedtls_ssl_config_free(config)         wolfSSL_CTX_free(config)



    #define mbedtls_x509_crt                        WOLFSSL_X509*
    #define mbedtls_x509_crt_init(x509)             memset(x509, 0, sizeof(*x509))
    #define mbedtls_x509_crt_free(x509)             wolfSSL_X509_free(*(x509))
    #define mbedtls_x509_crt_parse(x509,cert,len)   *(x509) = wolfSSL_X509_load_certificate_buffer((cert), (len), WOLFSSL_FILETYPE_PEM)

    typedef enum {
        MBEDTLS_PK_NONE=0,
        MBEDTLS_PK_RSA,
        MBEDTLS_PK_ECKEY,
        MBEDTLS_PK_ECKEY_DH,
        MBEDTLS_PK_ECDSA,
        MBEDTLS_PK_RSA_ALT,
        MBEDTLS_PK_RSASSA_PSS,
    } mbedtls_pk_type_t;

    typedef struct mbedtls_pk_context {
        union {
        #ifndef NO_RSA
            RsaKey rsa;
        #endif
        #ifdef HAVE_ECC
            ecc_key  ecc;
        #endif
            void* ptr;
        } key;
        int type;
        int keySz;
    } mbedtls_pk_context;

    void mbedtls_pk_init( mbedtls_pk_context *ctx );
    void mbedtls_pk_free( mbedtls_pk_context *ctx );
    mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *ctx );
    size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *ctx );
    int mbedtls_pk_parse_key( mbedtls_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen );

    /* Crypto */
    typedef enum {
        MBEDTLS_MD_NONE=0,
        MBEDTLS_MD_MD2,
        MBEDTLS_MD_MD4,
        MBEDTLS_MD_MD5,
        MBEDTLS_MD_SHA1,
        MBEDTLS_MD_SHA224,
        MBEDTLS_MD_SHA256,
        MBEDTLS_MD_SHA384,
        MBEDTLS_MD_SHA512,
        MBEDTLS_MD_RIPEMD160,
    } mbedtls_md_type_t;

    #define mbedtls_sha256_context                  wc_Sha256
    #define mbedtls_sha256_init(ctx)
    #define mbedtls_sha256_starts(ctx, is224)       wc_InitSha256(ctx)
    #define mbedtls_sha256_update(ctx, data, len)   wc_Sha256Update(ctx, data, len)
    #define mbedtls_sha256_finish(ctx, hash)        wc_Sha256Final(ctx, hash)
    #define mbedtls_sha256_free(ctx)                wc_Sha256Free(ctx)
    #define mbedtls_sha256_clone(dst, src)          wc_Sha256Copy(src, dst)
    #define mbedtls_sha256(data, len, out, is224)   wc_Sha256Hash(data, len, out)

    #define mbedtls_sha1_context                    wc_Sha
    #define mbedtls_sha1_init(ctx)
    #define mbedtls_sha1_starts(ctx, is224)         wc_InitSha(ctx)
    #define mbedtls_sha1_update(ctx, data, len)     wc_ShaUpdate(ctx, data, len)
    #define mbedtls_sha1_finish(ctx, hash)          wc_ShaFinal(ctx, hash)

    #define mbedtls_aes_init(ctx)                   wc_AesInit(ctx, NULL, INVALID_DEVID)
    #define mbedtls_aes_setkey_enc(ctx, key, len)   wc_AesSetKey(ctx, key, len, NULL, AES_ENCRYPTION)
    #define mbedtls_aes_setkey_dec(ctx, key, len)   wc_AesSetKey(ctx, key, len, NULL, AES_DECRYPTION)

    #define mbedtls_base64_decode(dst, dlen, olen, src, slen) \
        Base64_Decode((src), (slen), (dst), (olen))

    #define mbedtls_ctr_drbg_context                WC_RNG*
    #define mbedtls_ctr_drbg_init(rng)              wc_InitRng(*(rng))
    #define mbedtls_ctr_drbg_free(rng)              wc_FreeRng(*(rng))
    #define mbedtls_ctr_drbg_random(rng,buf,sz)     wc_RNG_GenerateBlock(*(rng), (buf), (sz))

    /* HMAC */
    #define mbedtls_md_context_t Hmac
    #define mbedtls_md_init(ctx)                    wc_HmacInit(ctx, NULL, INVALID_DEVID)
    #define mbedtls_md_setup(&ctx, type, 1)         
    #define mbedtls_md_hmac_starts(ctx, key, klen)  wc_HmacSetKey(ctx, WC_SHA, key, klen)
    #define mbedtls_md_hmac_update(ctx, data, len)  wc_HmacUpdate(ctx, data, len)
    #define mbedtls_md_hmac_finish(ctx, result)     wc_HmacFinal(ctx, result)
    #define mbedtls_md_free(ctx)                    wc_HmacFree(ctx)

    /* entropy */
    #define MBEDTLS_ERR_ENTROPY_SOURCE_FAILED -0x003C

#endif /* WOLF_MBEDTLS_COMPAT */

#endif /* WOLF_MBEDTLS ||  WOLF_MBEDTLS_COMPAT || WOLF_AWSTLS */

#endif /* _WOLF_MBEDTLS_H_ */
