/* safestack.c
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

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_SAFESTACK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning safestack.c does not need to be compiled separately from ssl.c
    #endif
#else


/* Creates and returns a new null stack. */
WOLFSSL_STACK* wolfSSL_sk_new_null(void)
{
    WOLFSSL_STACK* sk;
    WOLFSSL_ENTER("wolfSSL_sk_new_null");

    sk = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
                                 DYNAMIC_TYPE_OPENSSL);
    if (sk == NULL) {
        WOLFSSL_MSG("WOLFSSL_STACK memory error");
        return NULL;
    }

    XMEMSET(sk, 0, sizeof(WOLFSSL_STACK));
    sk->type = STACK_TYPE_NULL;

    return sk;
}

/* create a generic wolfSSL stack node
 * returns a new WOLFSSL_STACK structure on success */
WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap)
{
    WOLFSSL_STACK* sk = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), heap,
                                                          DYNAMIC_TYPE_OPENSSL);
    if (sk == NULL) {
        WOLFSSL_MSG("Memory error");
    }
    else {
        XMEMSET(sk, 0, sizeof(*sk));
        sk->heap = heap;
    }
    return sk;
}

/* free's node but does not free internal data such as in->data.x509 */
void wolfSSL_sk_free_node(WOLFSSL_STACK* in)
{
    if (in != NULL) {
        XFREE(in, in->heap, DYNAMIC_TYPE_OPENSSL);
    }
}

/* returns the node at index "idx", NULL if not found */
WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx)
{
    int i;
    WOLFSSL_STACK* ret = NULL;
    WOLFSSL_STACK* current = NULL;

    current = sk;
    for (i = 0; i <= idx && current != NULL; i++) {
        if (i == idx) {
            ret = current;
            break;
        }
        current = current->next;
    }
    return ret;
}

/* pushes node "in" onto "stack" and returns pointer to the new stack on success
 * also handles internal "num" for number of nodes on stack
 * return WOLFSSL_SUCCESS on success
 */
int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in)
{
    if (stack == NULL || in == NULL) {
        return WOLFSSL_FAILURE;
    }

    if (*stack == NULL) {
        in->num = 1;
        *stack = in;
        return WOLFSSL_SUCCESS;
    }

    in->num  = (*stack)->num + 1;
    in->next = *stack;
    *stack   = in;
    return WOLFSSL_SUCCESS;
}


int wolfSSL_sk_num(WOLFSSL_STACK* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_num");
    if (sk == NULL)
        return 0;
    return (int)sk->num;
}

void* wolfSSL_sk_value(WOLFSSL_STACK* sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_value");

    sk = wolfSSL_sk_get_node(sk, i);
    if (sk == NULL)
        return NULL;

    switch (sk->type) {
        case STACK_TYPE_X509:
            return (void*)sk->data.x509;
        case STACK_TYPE_GEN_NAME:
            return (void*)sk->data.gn;
        case STACK_TYPE_BIO:
            return (void*)sk->data.bio;
        case STACK_TYPE_OBJ:
            return (void*)sk->data.obj;
        case STACK_TYPE_CIPHER:
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            sk->data.cipher.offset = i;
        #endif
            return (void*)&sk->data.cipher;
        case STACK_TYPE_ACCESS_DESCRIPTION:
            return (void*)sk->data.access;
        case STACK_TYPE_X509_EXT:
            return (void*)sk->data.ext;
        case STACK_TYPE_NULL:
            return (void*)sk->data.generic;
        case STACK_TYPE_X509_NAME:
            return (void*)sk->data.name;
        case STACK_TYPE_CONF_VALUE:
            return (void*)sk->data.conf;
        case STACK_TYPE_X509_INFO:
            return (void*)sk->data.info;
        default:
            return (void*)sk->data.generic;
    }
}

/* Free the structure for ASN1_OBJECT stack */
void wolfSSL_sk_free(WOLFSSL_STACK* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_free");

    if (sk == NULL) {
        WOLFSSL_MSG("Error, BAD_FUNC_ARG");
        return;
    }

    switch (sk->type) {
        case STACK_TYPE_X509:
            wolfSSL_sk_X509_free(sk);
            break;
        case STACK_TYPE_GEN_NAME:
            wolfSSL_sk_GENERAL_NAME_free(sk);
            break;
        case STACK_TYPE_OBJ:
            wolfSSL_sk_ASN1_OBJECT_free(sk);
            break;
    #ifdef OPENSSL_ALL
        case STACK_TYPE_CIPHER:
            wolfSSL_sk_CIPHER_free(sk);
            break;
    #endif
        case STACK_TYPE_ACCESS_DESCRIPTION:
            wolfSSL_sk_ACCESS_DESCRIPTION_free(sk);
            break;
        case STACK_TYPE_X509_EXT:
            wolfSSL_sk_X509_EXTENSION_free(sk);
            break;
        case STACK_TYPE_X509_NAME:
            wolfSSL_sk_X509_NAME_free(sk);
            break;
        case STACK_TYPE_CONF_VALUE:
            wolfSSL_sk_CONF_VALUE_free(sk);
            break;
    #ifdef OPENSSL_ALL
        case STACK_TYPE_X509_INFO:
            wolfSSL_sk_X509_INFO_free(sk);
            break;
    #endif
        case STACK_TYPE_BIO:
        case STACK_TYPE_NULL:
        default:
            wolfSSL_sk_GENERIC_free(sk);
            break;
    }
}

/* Free all nodes in a stack */
void wolfSSL_sk_pop_free(WOLFSSL_STACK* sk, wolfSSL_sk_freefunc func)
{
    WOLFSSL_ENTER("wolfSSL_sk_pop_free");

    if (sk == NULL) {
        return;
    }

    switch (sk->type) {
        case STACK_TYPE_X509:
            wolfSSL_sk_X509_pop_free(sk, (void (*)(WOLFSSL_X509*))func);
            break;
        case STACK_TYPE_GEN_NAME:
            wolfSSL_sk_GENERAL_NAME_pop_free(sk,
                (void (*)(WOLFSSL_GENERAL_NAME*))func);
            break;
        case STACK_TYPE_BIO:
            /* wolfssl_sk_BIO_pop_free(sk, (void (*)(WOLFSSL_BIO*))func); */
            break;
        case STACK_TYPE_OBJ:
            wolfSSL_sk_ASN1_OBJECT_pop_free(sk,
                (void (*)(WOLFSSL_ASN1_OBJECT*))func);
            break;
    #ifdef OPENSSL_ALL
        case STACK_TYPE_CIPHER:
            wolfSSL_sk_CIPHER_pop_free(sk, (void (*)(WOLFSSL_CIPHER*))func);
            break;
    #endif
        case STACK_TYPE_ACCESS_DESCRIPTION:
            wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(sk,
                (void (*)(WOLFSSL_ACCESS_DESCRIPTION*))func);
            break;
        case STACK_TYPE_X509_EXT:
            wolfSSL_sk_X509_EXTENSION_pop_free(sk,
                (void (*)(WOLFSSL_X509_EXTENSION*))func);
            break;
        case STACK_TYPE_X509_NAME:
            wolfSSL_sk_X509_NAME_pop_free(sk,
                (void (*)(WOLFSSL_X509_NAME*))func);
            break;
        case STACK_TYPE_CONF_VALUE:
            wolfSSL_sk_CONF_VALUE_pop_free(sk,
                (void (*)(WOLFSSL_CONF_VALUE*))func);
            break;
    #ifdef OPENSSL_ALL
        case STACK_TYPE_X509_INFO:
            wolfSSL_sk_X509_INFO_pop_free(sk,
                (void (*)(WOLFSSL_X509_INFO*))func);
            break;
    #endif
        case STACK_TYPE_NULL:
        default:
            wolfSSL_sk_GENERIC_pop_free(sk, (void (*)(void*))func);
            break;
    }
}




WOLFSSL_STACK* wolfSSL_sk_X509_new(void)
{
    WOLFSSL_STACK* sk = wolfSSL_sk_new_node(NULL);
    if (sk) {
        sk->type = STACK_TYPE_X509;
    }
    return sk;
}


int wolfSSL_sk_X509_num(const WOLF_STACK_OF(WOLFSSL_X509) *s)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_num");

    if (s == NULL)
        return -1;
    return (int)s->num;
}


/* make shallow copy of the stack, data pointers are copied by reference */
WOLFSSL_STACK* wolfSSL_sk_X509_dup(WOLFSSL_STACK* sk)
{
    unsigned long i;
    WOLFSSL_STACK* dup = NULL;
    WOLFSSL_STACK* node = NULL;
    WOLFSSL_STACK *dIdx = NULL, *sIdx = sk;

    if (sk == NULL) {
        return NULL;
    }

    for (i = 0; i < sk->num; i++) {

        node = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
                                         DYNAMIC_TYPE_X509);
        if (node == NULL) {
            if (i != 0) {
                wolfSSL_sk_free_node(dup);
            }
            WOLFSSL_MSG("Memory error");
            return NULL;
        }
        XMEMSET(node, 0, sizeof(WOLFSSL_STACK));

        /* copy sk node to new node, data by reference */
        node->data.x509 = sIdx->data.x509;
        node->num = sIdx->num;

        /* insert node into list, progress idx */
        if (i == 0) {
            dup = node;
        } else {
            dIdx->next = node;
        }

        dIdx = node;
        sIdx = sIdx->next;
    }

    return dup;
}

/* return 1 on success 0 on fail */
int wolfSSL_sk_X509_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk, WOLFSSL_X509* x509)
{
    WOLFSSL_STACK* node;

    if (sk == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.x509 == NULL) {
        sk->data.x509 = x509;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* push new x509 onto head of stack */
    node->data.x509 = sk->data.x509;
    node->next      = sk->next;
    node->type      = sk->type;
    sk->next        = node;
    sk->data.x509   = x509;
    sk->num        += 1;

    return WOLFSSL_SUCCESS;
}

WOLFSSL_X509* wolfSSL_sk_X509_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_X509*  x509;

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    x509 = sk->data.x509;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.x509 = node->data.x509;
        sk->next = node->next;
        wolfSSL_sk_free_node(node);
        node = NULL;
    }
    else { /* last x509 in stack */
        sk->data.x509 = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return x509;
}

/* Getter function for WOLFSSL_X509 pointer
 *
 * sk is the stack to retrieve pointer from
 * i  is the index value in stack
 *
 * returns a pointer to a WOLFSSL_X509 structure on success and NULL on
 *         fail
 */
WOLFSSL_X509* wolfSSL_sk_X509_value(STACK_OF(WOLFSSL_X509)* sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_value");

    sk = wolfSSL_sk_get_node(sk, i);
    if (sk)
        return sk->data.x509;
    return NULL;
}

WOLFSSL_X509* wolfSSL_sk_X509_shift(WOLF_STACK_OF(WOLFSSL_X509)* sk)
{
    return wolfSSL_sk_X509_pop(sk);
}


/* Free's all nodes in X509 stack. This is different then wolfSSL_sk_X509_free
 * in that it allows for choosing the function to use when freeing an X509s.
 *
 * sk  stack to free nodes in
 * f   X509 free function
 */
void wolfSSL_sk_X509_pop_free(WOLF_STACK_OF(WOLFSSL_X509)* sk,
    void (*f) (WOLFSSL_X509*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_X509_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.x509);
        else
            wolfSSL_X509_free(tmp->data.x509);
        tmp->data.x509 = NULL;

        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.x509);
        else
            wolfSSL_X509_free(sk->data.x509);
        sk->data.x509 = NULL;
    }
    wolfSSL_sk_free_node(sk);
}


/* free structure for x509 stack */
void wolfSSL_sk_X509_free(WOLF_STACK_OF(WOLFSSL_X509)* sk)
{
    wolfSSL_sk_X509_pop_free(sk, NULL);
}




WOLFSSL_X509_OBJECT* wolfSSL_sk_X509_OBJECT_delete(
    WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_OBJECT_delete");
    WOLFSSL_STUB("wolfSSL_sk_X509_OBJECT_delete");
    (void)sk;
    (void)i;
    return NULL;
}

void wolfSSL_X509_OBJECT_free(WOLFSSL_X509_OBJECT *a)
{
    WOLFSSL_ENTER("wolfSSL_X509_OBJECT_free");
    WOLFSSL_STUB("wolfSSL_X509_OBJECT_free");
    (void)a;
}

WOLFSSL_X509_OBJECT* wolfSSL_sk_X509_OBJECT_value(
    WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk, int x)
{
    sk = wolfSSL_sk_get_node(sk, x);
    if (sk)
        return sk->data.x509obj;
    return NULL;
}


int wolfSSL_sk_X509_OBJECT_num(const WOLF_STACK_OF(WOLFSSL_X509_OBJECT) *s)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_OBJECT_num");
    if (s) {
        return (int)s->num;
    } else {
        return 0;
    }
}



/* Frees each node in the stack and frees the stack.
 * Does not free any internal members of the stack nodes.
 */
void wolfSSL_sk_GENERIC_pop_free(WOLFSSL_STACK* sk,
    void (*f) (void*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_GENERIC_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.generic);
        tmp->data.generic = NULL;

        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.generic);
        sk->data.generic = NULL;
    }
    wolfSSL_sk_free_node(sk);
}

void wolfSSL_sk_GENERIC_free(WOLFSSL_STACK* sk)
{
    wolfSSL_sk_GENERIC_pop_free(sk, NULL);
}



/* Free the structure for WOLFSSL_CONF_VALUE stack
 *
 * sk  stack to free nodes in
 */
void wolfSSL_sk_CONF_VALUE_pop_free(WOLF_STACK_OF(WOLFSSL_CONF_VALUE)* sk,
    void (*f) (WOLFSSL_CONF_VALUE*))
{
    WOLFSSL_STACK* node;
    WOLFSSL_STACK* tmp;
    WOLFSSL_ENTER("wolfSSL_sk_CONF_VALUE_pop_free");

    if (sk == NULL)
        return;

    /* parse through stack freeing each node */
    node = sk->next;
    while (node) {
        tmp  = node;
        node = node->next;
        if (f)
            f(tmp->data.conf);
        wolfSSL_sk_free_node(tmp);
    }

    /* free head of stack */
    wolfSSL_sk_free_node(sk);
}

void wolfSSL_sk_CONF_VALUE_free(WOLF_STACK_OF(WOLFSSL_CONF_VALUE)* sk)
{
    wolfSSL_sk_CONF_VALUE_pop_free(sk, NULL);
}






/* return 1 on success 0 on fail */
int wolfSSL_sk_ACCESS_DESCRIPTION_push(WOLF_STACK_OF(ACCESS_DESCRIPTION)* sk,
                                            WOLFSSL_ACCESS_DESCRIPTION* access)
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_ACCESS_DESCRIPTION_push");

    if (sk == NULL || access == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.access == NULL) {
        sk->data.access = access;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* push new obj onto head of stack */
    node->data.access  = sk->data.access;
    node->next         = sk->next;
    node->type         = sk->type;
    sk->next           = node;
    sk->data.access    = access;
    sk->num            += 1;

    return WOLFSSL_SUCCESS;
}


/* returns the number of nodes in stack on success and WOLFSSL_FATAL_ERROR
 * on fail */
int wolfSSL_sk_ACCESS_DESCRIPTION_num(WOLFSSL_STACK* sk)
{
    if (sk == NULL) {
        return WOLFSSL_FATAL_ERROR;
    }

    return (int)sk->num;
}

/* returns NULL on fail and pointer to internal data on success */
WOLFSSL_ACCESS_DESCRIPTION* wolfSSL_sk_ACCESS_DESCRIPTION_value(
        WOLFSSL_STACK* sk, int idx)
{
    sk = wolfSSL_sk_get_node(sk, idx);
    if (sk != NULL) {
        return sk->data.access;
    }
    return NULL;
}

/* Frees all nodes in ACCESS_DESCRIPTION stack
*
* sk stack of nodes to free
* f  free function to use, not called with wolfSSL
*/
void wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(
    WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk,
    void (*f) (WOLFSSL_ACCESS_DESCRIPTION*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_ACCESS_DESCRIPTION_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.access);
        else
            wolfSSL_ACCESS_DESCRIPTION_free(tmp->data.access);
        tmp->data.access = NULL;

        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.access);
        else
            wolfSSL_ACCESS_DESCRIPTION_free(sk->data.access);
        sk->data.access = NULL;
    }
    wolfSSL_sk_free_node(sk);
}

void wolfSSL_sk_ACCESS_DESCRIPTION_free(
    WOLF_STACK_OF(WOLFSSL_ACCESS_DESCRIPTION)* sk)
{
    wolfSSL_sk_ACCESS_DESCRIPTION_pop_free(sk, NULL);
}


/* Creates and returns new GENERAL_NAME structure */
WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_new(void)
{
    WOLFSSL_GENERAL_NAME* gn;
    WOLFSSL_ENTER("GENERAL_NAME_new");

    gn = (WOLFSSL_GENERAL_NAME*)XMALLOC(sizeof(WOLFSSL_GENERAL_NAME), NULL,
                                                             DYNAMIC_TYPE_ASN1);
    if (gn == NULL) {
        return NULL;
    }
    XMEMSET(gn, 0, sizeof(WOLFSSL_GENERAL_NAME));

    gn->d.ia5 = wolfSSL_ASN1_STRING_new();
    if (gn->d.ia5 == NULL) {
        WOLFSSL_MSG("Issue creating ASN1_STRING struct");
        wolfSSL_GENERAL_NAME_free(gn);
        return NULL;
    }
    return gn;
}



/* return 1 on success 0 on fail */
int wolfSSL_sk_GENERAL_NAME_push(WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk,
                                                      WOLFSSL_GENERAL_NAME* gn)
{
    WOLFSSL_STACK* node;
    WOLFSSL_ENTER("wolfSSL_sk_GENERAL_NAME_push");

    if (sk == NULL || gn == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.gn == NULL) {
        sk->data.gn = gn;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* push new obj onto head of stack */
    node->data.gn = sk->data.gn;
    node->next    = sk->next;
    node->type    = sk->type;
    sk->next      = node;
    sk->data.gn   = gn;
    sk->num      += 1;

    return WOLFSSL_SUCCESS;
}

/* Returns the general name at index i from the stack
 *
 * sk  stack to get general name from
 * idx index to get
 *
 * return a pointer to the internal node of the stack
 */
WOLFSSL_GENERAL_NAME* wolfSSL_sk_GENERAL_NAME_value(WOLFSSL_STACK* sk, int idx)
{
    sk = wolfSSL_sk_get_node(sk, idx);
    if (sk != NULL) {
        return sk->data.gn;
    }
    return NULL;
}

/* Gets the number of nodes in the stack
 *
 * sk  stack to get the number of nodes from
 *
 * returns the number of nodes, -1 if no nodes
 */
int wolfSSL_sk_GENERAL_NAME_num(WOLFSSL_STACK* sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_GENERAL_NAME_num");

    if (sk == NULL) {
        return -1;
    }

    return (int)sk->num;
}

/* Frees all nodes in a GENERAL NAME stack
 *
 * sk stack of nodes to free
 * f  free function to use, not called with wolfSSL
 */
void wolfSSL_sk_GENERAL_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk,
        void (*f) (WOLFSSL_GENERAL_NAME*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_GENERAL_NAME_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.gn);
        else
            wolfSSL_GENERAL_NAME_free(tmp->data.gn);
        tmp->data.gn = NULL;
        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.gn);
        else
            wolfSSL_GENERAL_NAME_free(sk->data.gn);
        sk->data.gn = NULL;
    }
    wolfSSL_sk_free_node(sk);
}

void wolfSSL_sk_GENERAL_NAME_free(WOLF_STACK_OF(WOLFSSL_GENERAL_NAME)* sk)
{
    wolfSSL_sk_GENERAL_NAME_pop_free(sk, NULL);
}


WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* wolfSSL_sk_X509_EXTENSION_new_null(void)
{
    WOLFSSL_STACK* sk = wolfSSL_sk_new_node(NULL);
    if (sk) {
        sk->type = STACK_TYPE_X509_EXT;
    }

    return (WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)*)sk;;
}

/* returns the number of nodes on the stack */
int wolfSSL_sk_X509_EXTENSION_num(WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk)
{
    if (sk != NULL) {
        return (int)sk->num;
    }
    return WOLFSSL_FATAL_ERROR;
}

/* returns null on failure and pointer to internal value on success */
WOLFSSL_X509_EXTENSION* wolfSSL_sk_X509_EXTENSION_value(
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk, int idx)
{
    sk = wolfSSL_sk_get_node(sk, idx);
    if (sk != NULL) {
        return sk->data.ext;
    }
    return NULL;
}

/* return 1 on success 0 on fail */
int wolfSSL_sk_X509_EXTENSION_push(WOLFSSL_STACK* sk,
    WOLFSSL_X509_EXTENSION* ext)
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_X509_EXTENSION_push");

    if (sk == NULL || ext == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.ext == NULL) {
        sk->data.ext = ext;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* push new obj onto head of stack */
    node->data.ext  = sk->data.ext;
    node->next      = sk->next;
    node->type      = sk->type;
    sk->next        = node;
    sk->data.ext    = ext;
    sk->num        += 1;

    return WOLFSSL_SUCCESS;
}

/* frees all of the nodes and the values in stack */
void wolfSSL_sk_X509_EXTENSION_pop_free(
        WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk,
        void (*f) (WOLFSSL_X509_EXTENSION*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_X509_EXTENSION_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.ext);
        else
            wolfSSL_X509_EXTENSION_free(tmp->data.ext);
        tmp->data.ext = NULL;
        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.ext);
        else
            wolfSSL_X509_EXTENSION_free(sk->data.ext);
        sk->data.ext = NULL;
    }
    wolfSSL_sk_free_node(sk);
}

/* Free the structure for X509_EXTENSION stack
 *
 * sk  stack to free nodes in
 */
void wolfSSL_sk_X509_EXTENSION_free(WOLFSSL_STACK* sk)
{
    wolfSSL_sk_X509_EXTENSION_pop_free(sk, NULL);
}


/* return 1 on success 0 on fail */
int wolfSSL_sk_ASN1_OBJECT_push(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
                                              WOLFSSL_ASN1_OBJECT* obj)
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_ASN1_OBJECT_push");

    if (sk == NULL || obj == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.obj == NULL) {
        sk->data.obj = obj;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* push new obj onto head of stack */
    node->data.obj  = sk->data.obj;
    node->next      = sk->next;
    node->type      = sk->type;
    sk->next        = node;
    sk->data.obj    = obj;
    sk->num        += 1;

    return WOLFSSL_SUCCESS;
}


WOLFSSL_ASN1_OBJECT* wolfSSL_sk_ASN1_OBJECT_pop(
                                        WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_ASN1_OBJECT* obj;

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    obj = sk->data.obj;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.obj = node->data.obj;
        sk->next = node->next;
        wolfSSL_sk_free_node(node);
        node = NULL;
    }
    else { /* last obj in stack */
        sk->data.obj = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return obj;
}

/* Free's all nodes in ASN1_OBJECT stack.
 * This is different then wolfSSL_ASN1_OBJECT_free in that it allows for
 * choosing the function to use when freeing an ASN1_OBJECT stack.
 *
 * sk  stack to free nodes in
 * f   X509 free function
 */
void wolfSSL_sk_ASN1_OBJECT_pop_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk,
                                     void (*f) (WOLFSSL_ASN1_OBJECT*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_ASN1_OBJECT_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;
        if (f)
            f(tmp->data.obj);
        else
            wolfSSL_ASN1_OBJECT_free(tmp->data.obj);
        tmp->data.obj = NULL;
        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.obj);
        else
            wolfSSL_ASN1_OBJECT_free(sk->data.obj);
        sk->data.obj = NULL;
    }
    wolfSSL_sk_free_node(sk);
}


/* Free the structure for ASN1_OBJECT stack
 *
 * sk  stack to free nodes in
 */
void wolfSSL_sk_ASN1_OBJECT_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk)
{
    wolfSSL_sk_ASN1_OBJECT_pop_free(sk, NULL);
}


#ifdef OPENSSL_ALL
/* Free the structure for WOLFSSL_CIPHER stack
 *
 * sk  stack to free nodes in
 */
void wolfSSL_sk_CIPHER_pop_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk,
    void (*f) (WOLFSSL_CIPHER*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_CIPHER_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(&tmp->data.cipher);
        else
            wolfSSL_CIPHER_free(&tmp->data.cipher);

        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(&sk->data.cipher);
        else
            wolfSSL_CIPHER_free(&sk->data.cipher);
    }
    wolfSSL_sk_free_node(sk);
}

void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk)
{
    wolfSSL_sk_CIPHER_pop_free(sk, NULL);
}
#endif

#ifndef NO_WOLFSSL_STUB
int wolfSSL_sk_X509_REVOKED_num(WOLFSSL_X509_REVOKED* revoked)
{
    (void)revoked;
    WOLFSSL_STUB("sk_X509_REVOKED_num");
    return 0;
}
#endif

#ifndef NO_WOLFSSL_STUB
WOLFSSL_X509_REVOKED* wolfSSL_sk_X509_REVOKED_value(
                                    WOLFSSL_X509_REVOKED* revoked, int value)
{
    (void)revoked;
    (void)value;
    WOLFSSL_STUB("sk_X509_REVOKED_value");
    return 0;
}
#endif


#ifdef OPENSSL_ALL
WOLFSSL_STACK* wolfSSL_sk_X509_INFO_new_null(void)
{
    WOLFSSL_STACK* sk = wolfSSL_sk_new_node(NULL);
    if (sk) {
        sk->type = STACK_TYPE_X509_INFO;
    }
    return sk;
}


int wolfSSL_sk_X509_INFO_num(const WOLF_STACK_OF(WOLFSSL_X509_INFO) *sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_INFO_num");

    if (sk == NULL)
        return -1;
    return (int)sk->num;
}

WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_value(
    const WOLF_STACK_OF(WOLFSSL_X509_INFO) *sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_INFO_value");

    sk = wolfSSL_sk_get_node((WOLFSSL_STACK*)sk, i);
    if (sk)
        return sk->data.info;
    return NULL;
}

WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_pop(WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_X509_INFO* info;

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    info = sk->data.info;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.info = node->data.info;
        sk->next = node->next;
        wolfSSL_sk_free_node(node);
        node = NULL;
    }
    else { /* last x509 in stack */
        sk->data.info = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return info;
}

void wolfSSL_sk_X509_INFO_pop_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk,
    void (*f) (WOLFSSL_X509_INFO*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_X509_INFO_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.info);
        else
            wolfSSL_X509_INFO_free(tmp->data.info);
        tmp->data.info = NULL;

        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.info);
        else
            wolfSSL_X509_INFO_free(sk->data.info);
        sk->data.info = NULL;
    }
    wolfSSL_sk_free_node(sk);
}

void wolfSSL_sk_X509_INFO_free(WOLF_STACK_OF(WOLFSSL_X509_INFO) *sk)
{
    wolfSSL_sk_X509_INFO_pop_free(sk, NULL);
}


/* Adds the WOLFSSL_X509_INFO to the stack "sk". "sk" takes control of "in" and
 * tries to free it when the stack is free'd.
 *
 * return 1 on success 0 on fail
 */
int wolfSSL_sk_X509_INFO_push(WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk,
                                                      WOLFSSL_X509_INFO* in)
{
    WOLFSSL_STACK* node;

    if (sk == NULL || in == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.info == NULL) {
        sk->data.info = in;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* push new obj onto head of stack */
    node->data.info = sk->data.info;
    node->next      = sk->next;
    node->type      = sk->type;
    sk->next        = node;
    sk->data.info   = in;
    sk->num        += 1;

    return WOLFSSL_SUCCESS;
}
#endif


WOLF_STACK_OF(WOLFSSL_X509_NAME)* wolfSSL_sk_X509_NAME_new(wolf_sk_compare_cb cb)
{
    WOLFSSL_STACK* sk;

    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_new");

    sk = wolfSSL_sk_new_node(NULL);
    if (sk != NULL) {
        sk->type = STACK_TYPE_X509_NAME;
        sk->comp = cb;
    }

    return sk;
}

int wolfSSL_sk_X509_NAME_push(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
    WOLFSSL_X509_NAME* name)
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_push");

    if (sk == NULL || name == NULL) {
        return BAD_FUNC_ARG;
    }

    /* no previous values in stack */
    if (sk->data.name == NULL) {
        sk->data.name = name;
        sk->num += 1;
        return 0;
    }

    /* stack already has value(s) create a new node and add more */
    node = wolfSSL_sk_new_node(NULL);
    if (node == NULL) {
        return MEMORY_E;
    }

    /* push new obj onto head of stack */
    node->data.name = sk->data.name;
    node->next      = sk->next;
    node->type      = sk->type;
    sk->next        = node;
    sk->data.name   = name;
    sk->num        += 1;

    return 0;
}

/* return index of found, or negative to indicate not found */
int wolfSSL_sk_X509_NAME_find(const WOLF_STACK_OF(WOLFSSL_X509_NAME) *sk,
    WOLFSSL_X509_NAME *name)
{
    int i;

    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_find");

    if (sk == NULL)
        return BAD_FUNC_ARG;

    for (i = 0; sk; i++, sk = sk->next) {
        if (wolfSSL_X509_NAME_cmp(sk->data.name, name) == 0) {
            return i;
        }
    }
    return -1;
}


int wolfSSL_sk_X509_NAME_set_cmp_func(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
    wolf_sk_compare_cb cb)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_set_cmp_func");

    if (sk == NULL)
        return BAD_FUNC_ARG;

    sk->comp = cb;

    return 0;
}

int wolfSSL_sk_X509_NAME_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME) *sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_num");

    if (sk == NULL)
        return BAD_FUNC_ARG;

    return (int)sk->num;
}

/* Getter function for WOLFSSL_X509_NAME pointer
 *
 * sk  is the stack to retrieve pointer from
 * idx is the index value in stack
 *
 * returns a pointer to a WOLFSSL_X509_NAME structure on success and NULL on
 *         fail
 */
WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_value(
    const WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk, int idx)
{
    sk = wolfSSL_sk_get_node((WOLFSSL_STACK*)sk, idx);
    if (sk)
        return sk->data.name;
    return NULL;
}

WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_X509_NAME* name;

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    name = sk->data.name;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.name = node->data.name;
        sk->next = node->next;
        wolfSSL_sk_free_node(node);
        node = NULL;
    }
    else { /* last x509 in stack */
        sk->data.name = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return name;
}

void wolfSSL_sk_X509_NAME_pop_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk,
    void (*f) (WOLFSSL_X509_NAME*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_X509_NAME_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.name);
        else
            wolfSSL_X509_NAME_free(tmp->data.name);
        tmp->data.info = NULL;

        wolfSSL_sk_free_node(tmp);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.name);
        else
            wolfSSL_X509_NAME_free(sk->data.name);
        sk->data.name = NULL;
    }
    wolfSSL_sk_free_node(sk);
}

/* Free only the sk structure */
void wolfSSL_sk_X509_NAME_free(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk)
{
    wolfSSL_sk_X509_NAME_pop_free(sk, NULL);
}


char* wolfSSL_sk_WOLFSSL_STRING_value(WOLF_STACK_OF(WOLFSSL_STRING)* strings,
    int idx)
{
    strings = wolfSSL_sk_get_node(strings, idx);
    if (strings)
        return strings->data.string;
    return NULL;
}

#endif /* WOLFSSL_SAFESTACK_INCLUDED */
