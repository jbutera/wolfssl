/* user_settings_wolftpm.h
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

/* wolfCrypt build settings for wolfTPM. Enabled via WOLFSSL_USER_SETTINGS.
 * Example user_settings.h generated from `./configure --enable-wolftpm`.
 * Cleaned by David Garske */

#ifndef WOLFSSL_USER_SETTINGS_TPM_H
#define WOLFSSL_USER_SETTINGS_TPM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Math Configuration */
#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define HAVE_FFDHE_2048
#define HAVE_DH_DEFAULT_PARAMS

/* Features */
#define WOLFSSL_TLS13
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT
#define WOLF_CRYPTO_CB
#define WOLFSSL_BASE64_ENCODE

/* Algorithms */
#define HAVE_HASHDRBG
#define HAVE_PKCS7
#define HAVE_X963_KDF
#define WOLFSSL_SHA224
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define HAVE_HKDF
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define WC_RSA_PSS
#define WOLFSSL_SHA3
#define HAVE_POLY1305
#define HAVE_CHACHA
#define GCM_TABLE_4BIT
#define HAVE_AESGCM
#define WOLFSSL_AES_CFB
#define HAVE_AES_KEYWRAP
#define WOLFSSL_AES_DIRECT

/* TLS Extensions */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_EXTENDED_MASTER
#define HAVE_SUPPORTED_CURVES
#define HAVE_ONE_TIME_AUTH /* required for chacha */

/* Disables */
#define NO_DES3
#define NO_DSA
#define NO_RABBIT
#define NO_RC4
#define NO_PSK
#define NO_MD4


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_TPM_H */
