/* safestack.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

/* safestack.h for openSSL */

#ifndef WOLFSSL_SAFE_STACK_H_
#define WOLFSSL_SAFE_STACK_H_

#ifdef __cplusplus
    extern "C" {
#endif

#include <wolfssl/openssl/stack.h>

WOLFSSL_API void wolfSSL_sk_GENERIC_pop_free(WOLFSSL_STACK* sk, wolfSSL_sk_freefunc);
WOLFSSL_API void wolfSSL_sk_GENERIC_free(WOLFSSL_STACK *);
WOLFSSL_API int wolfSSL_sk_GENERIC_push(WOLFSSL_STACK *sk, void *data);
WOLFSSL_API void wolfSSL_sk_CONF_VALUE_free(WOLF_STACK_OF(WOLFSSL_CONF_VALUE)* sk);
WOLFSSL_API void wolfSSL_sk_CONF_VALUE_pop_free(WOLF_STACK_OF(WOLFSSL_CONF_VALUE)* sk,
    void (*f) (WOLFSSL_CONF_VALUE*));

WOLFSSL_API int wolfSSL_sk_CIPHER_push(WOLFSSL_STACK *st,WOLFSSL_CIPHER *cipher);
WOLFSSL_API WOLFSSL_CIPHER* wolfSSL_sk_CIPHER_pop(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);



WOLFSSL_API int wolfSSL_sk_ACCESS_DESCRIPTION_push(
                                       WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk,
                                       WOLFSSL_ACCESS_DESCRIPTION* access);

WOLFSSL_API int wolfSSL_sk_X509_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
                                                            WOLFSSL_X509* x509);
WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_dup(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_X509_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);
WOLFSSL_API int wolfSSL_sk_GENERAL_NAME_push(WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk,
                                                      WOLFSSL_GENERAL_NAME* gn);
WOLFSSL_API WOLFSSL_GENERAL_NAME* wolfSSL_sk_GENERAL_NAME_value(
        WOLFSSL_STACK* sk, int i);
WOLFSSL_API int wolfSSL_sk_GENERAL_NAME_num(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_GENERAL_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)*,
                                       void (*f) (WOLFSSL_GENERAL_NAME*));
WOLFSSL_API void wolfSSL_sk_GENERAL_NAME_free(WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)*);

WOLFSSL_API int wolfSSL_sk_ACCESS_DESCRIPTION_num(WOLFSSL_STACK* sk);
WOLFSSL_API WOLFSSL_ACCESS_DESCRIPTION* wolfSSL_sk_ACCESS_DESCRIPTION_value(
        WOLFSSL_STACK* sk, int idx);
WOLFSSL_API void wolfSSL_sk_ACCESS_DESCRIPTION_free(WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)*);
WOLFSSL_API void wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk,
        void (*f) (WOLFSSL_ACCESS_DESCRIPTION*));
WOLFSSL_API void wolfSSL_sk_X509_EXTENSION_pop_free(
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk,
        void f (WOLFSSL_X509_EXTENSION*));
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* wolfSSL_sk_X509_EXTENSION_new_null(void);
WOLFSSL_API int wolfSSL_sk_ASN1_OBJECT_push(WOLF_STACK_OF(WOLFSSL_ASN1_OBJEXT)* sk,
                                                      WOLFSSL_ASN1_OBJECT* obj);
WOLFSSL_API WOLFSSL_ASN1_OBJECT* wolfSSL_sk_ASN1_OBJECT_pop(
                                            WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);
WOLFSSL_API void wolfSSL_sk_ASN1_OBJECT_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);
WOLFSSL_API void wolfSSL_sk_ASN1_OBJECT_pop_free(
                WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
                void (*f)(WOLFSSL_ASN1_OBJECT*));
WOLFSSL_API int wolfSSL_sk_X509_EXTENSION_num(WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk);
WOLFSSL_API WOLFSSL_X509_EXTENSION* wolfSSL_sk_X509_EXTENSION_value(
                            WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk, int idx);
WOLFSSL_API void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);
WOLFSSL_API void wolfSSL_sk_CIPHER_pop_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk,
    void (*f) (WOLFSSL_CIPHER*));
WOLFSSL_API int       wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED*);
WOLFSSL_API WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                                      WOLFSSL_X509_REVOKED*,int);
WOLFSSL_API int wolfSSL_sk_X509_EXTENSION_push(WOLFSSL_STACK* sk,
                                       WOLFSSL_X509_EXTENSION* ext);
WOLFSSL_API void wolfSSL_sk_X509_EXTENSION_free(WOLFSSL_STACK* sk);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_new(void);
WOLFSSL_API int wolfSSL_sk_X509_num(const WOLF_STACK_OF(WOLFSSL_X509) *s);

WOLFSSL_API WOLFSSL_X509_INFO *wolfSSL_X509_INFO_new(void);
WOLFSSL_API void wolfSSL_X509_INFO_free(WOLFSSL_X509_INFO* info);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_X509_INFO_new_null(void);
WOLFSSL_API int wolfSSL_sk_X509_INFO_num(const WOLF_STACK_OF(WOLFSSL_X509_INFO)*);
WOLFSSL_API WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_value(
    const WOLF_STACK_OF(WOLFSSL_X509_INFO)*, int);
WOLFSSL_API int wolfSSL_sk_X509_INFO_push(WOLF_STACK_OF(WOLFSSL_X509_INFO)*,
    WOLFSSL_X509_INFO*);
WOLFSSL_API WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_pop(WOLF_STACK_OF(WOLFSSL_X509_INFO)*);
WOLFSSL_API void wolfSSL_sk_X509_INFO_pop_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)*,
    void (*f) (WOLFSSL_X509_INFO*));
WOLFSSL_API void wolfSSL_sk_X509_INFO_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)*);

typedef int (*wolf_sk_compare_cb)(const void* const *a,
                                  const void* const *b);
WOLFSSL_API WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_sk_X509_NAME_new(
    wolf_sk_compare_cb);
WOLFSSL_API int wolfSSL_sk_X509_NAME_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_sk_X509_NAME_find(const WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    WOLFSSL_X509_NAME*);
WOLFSSL_API int wolfSSL_sk_X509_NAME_set_cmp_func(
    WOLF_STACK_OF(WOLFSSL_X509_NAME)*, wolf_sk_compare_cb);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_value(const WOLF_STACK_OF(WOLFSSL_X509_NAME)*, int);
WOLFSSL_API int wolfSSL_sk_X509_NAME_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)*);
WOLFSSL_API void wolfSSL_sk_X509_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)*,
    void (*f) (WOLFSSL_X509_NAME*));
WOLFSSL_API void wolfSSL_sk_X509_NAME_free(WOLF_STACK_OF(WOLFSSL_X509_NAME) *);

WOLFSSL_API int wolfSSL_sk_X509_OBJECT_num(const WOLF_STACK_OF(WOLFSSL_X509_OBJECT) *s);
WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_value(WOLF_STACK_OF(WOLFSSL_X509)*, int);

WOLFSSL_API WOLFSSL_X509* wolfSSL_sk_X509_shift(WOLF_STACK_OF(WOLFSSL_X509)*);

WOLFSSL_API WOLFSSL_X509_OBJECT* wolfSSL_sk_X509_OBJECT_value(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)*, int);

WOLFSSL_API WOLFSSL_X509_OBJECT*
        wolfSSL_sk_X509_OBJECT_delete(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk, int i);
WOLFSSL_API void wolfSSL_X509_OBJECT_free(WOLFSSL_X509_OBJECT *a);

WOLFSSL_API void wolfSSL_sk_X509_pop_free(WOLF_STACK_OF(WOLFSSL_X509)* sk, void (*f) (WOLFSSL_X509*));
WOLFSSL_API char* wolfSSL_sk_WOLFSSL_STRING_value(
    WOLF_STACK_OF(WOLFSSL_STRING)* strings, int idx);


#ifdef  __cplusplus
}
#endif

#endif /* WOLFSSL_SAFE_STACK_H_ */
