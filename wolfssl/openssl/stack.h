/* stack.h
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

/* stack.h for openSSL */

#ifndef WOLFSSL_STACK_H_
#define WOLFSSL_STACK_H_

#ifdef __cplusplus
    extern "C" {
#endif

typedef void (*wolfSSL_sk_freefunc)(void *);

WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_new_null(void);
WOLFSSL_API WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx);
WOLFSSL_API int wolfSSL_sk_num(WOLFSSL_STACK* sk);
WOLFSSL_API void* wolfSSL_sk_value(WOLFSSL_STACK* sk, int i);
WOLFSSL_API int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in);
WOLFSSL_API int wolfSSL_sk_push(WOLFSSL_STACK *st, const void *data);
WOLFSSL_API void wolfSSL_sk_pop_free(WOLFSSL_STACK *st, wolfSSL_sk_freefunc);
WOLFSSL_API void wolfSSL_sk_free(WOLFSSL_STACK* sk);
WOLFSSL_API void wolfSSL_sk_free_node(WOLFSSL_STACK* in);

#define OPENSSL_sk_free       wolfSSL_sk_free
#define OPENSSL_sk_pop_free   wolfSSL_sk_pop_free
#define OPENSSL_sk_new_null   wolfSSL_sk_new_null
#define OPENSSL_sk_push       wolfSSL_sk_push
#define OPENSSL_sk_num        wolfSSL_sk_num
#define OPENSSL_sk_value      wolfSSL_sk_value

/* provides older OpenSSL API compatibility  */
#define sk_free         OPENSSL_sk_free
#define sk_pop_free     OPENSSL_sk_pop_free
#define sk_new_null     OPENSSL_sk_new_null
#define sk_push         OPENSSL_sk_push
#define sk_num          OPENSSL_sk_num
#define sk_value        OPENSSL_sk_value

#ifdef  __cplusplus
}
#endif

#endif
