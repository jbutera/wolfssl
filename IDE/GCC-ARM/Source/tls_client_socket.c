/* tls_client_socket.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Socket based TLS example */
/*
 * This example client connects to localhost on on port 11111 by default.
 * These can be overriden using `TLS_HOST` and `TLS_PORT`.
 *
 * You can validate using the wolfSSL example server this like:
 *   ./examples/server/server -b -p 11111 -g -l ECDHE-ECDSA-AES128-SHA256 -c ./certs/server-ecc.pem -k ./certs/ecc-key.pem -d
 *
 */


#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CRYPT_TEST)

#include <wolfssl/ssl.h>

/* TLS Configuration */
#ifndef TLS_HOST
    #define TLS_HOST "localhost"
#endif
#ifndef TLS_PORT
    #define TLS_PORT 11111
#endif

#ifndef MAX_MSG_SZ
    #define MAX_MSG_SZ   (1 * 1024)
#endif

/* force use of a TLS cipher suite */
#if 0
    #ifndef TLS_CIPHER_SUITE
        #define TLS_CIPHER_SUITE "ECDHE-RSA-AES128-SHA256"
    #endif
#endif

/* disable mutual auth for client */
#if 1
    #define NO_TLS_MUTUAL_AUTH
#endif

/* enable for testing ECC key/cert when RSA is enabled */
#if 1
    #define TLS_USE_ECC
#endif

#undef  USE_CERT_BUFFERS_2048
#if !defined(NO_RSA) && !defined(TLS_USE_ECC)
#define USE_CERT_BUFFERS_2048
#endif
#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256
#include <wolfssl/certs_test.h>

/******************************************************************************/
/* --- BEGIN Socket IO Callbacks --- */
/******************************************************************************/

typedef struct SockIoCbCtx {
    int listenFd;
    int fd;
} SockIoCbCtx;

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

static int SockIORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int recvd;

    (void)ssl;

    /* Receive message from socket */
    if ((recvd = (int)recv(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO RECEIVE ERROR: ");
        switch (errno) {
    #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
    #endif
        case EWOULDBLOCK:
            if (wolfSSL_get_using_nonblock(ssl)) {
                printf("would block\n");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                printf("socket timeout\n");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        case ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case ECONNREFUSED:
            printf("connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNABORTED:
            printf("connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        printf("Connection closed\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

#ifdef DEBUG_WOLFTPM
    /* successful receive */
    printf("SockIORecv: received %d bytes from %d\n", sz, sockCtx->fd);
#endif

    return recvd;
}

static int SockIOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    SockIoCbCtx* sockCtx = (SockIoCbCtx*)ctx;
    int sent;

    (void)ssl;

    /* Receive message from socket */
    if ((sent = (int)send(sockCtx->fd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO SEND ERROR: ");
        switch (errno) {
    #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
    #endif
        case EWOULDBLOCK:
            printf("would block\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case EPIPE:
            printf("socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        printf("Connection closed\n");
        return 0;
    }

#ifdef DEBUG_WOLFTPM
    /* successful send */
    printf("SockIOSend: sent %d bytes to %d\n", sz, sockCtx->fd);
#endif

    return sent;
}

static int SetupSocketAndConnect(SockIoCbCtx* sockIoCtx, const char* host,
    word32 port)
{
    struct sockaddr_in servAddr;
    struct hostent* entry;

    /* Setup server address */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);

    /* Resolve host */
    entry = gethostbyname(host);
    if (entry) {
        XMEMCPY(&servAddr.sin_addr.s_addr, entry->h_addr_list[0],
            entry->h_length);
    }
    else {
        servAddr.sin_addr.s_addr = inet_addr(host);
    }

    /* Create a socket that uses an Internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockIoCtx->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
        return -1;
    }

    /* Connect to the server */
    if (connect(sockIoCtx->fd, (struct sockaddr*)&servAddr,
                                                    sizeof(servAddr)) == -1) {
        printf("ERROR: failed to connect\n");
        return -1;
    }

    return 0;
}

static void CloseAndCleanupSocket(SockIoCbCtx* sockIoCtx)
{
    if (sockIoCtx->fd != -1) {
        close(sockIoCtx->fd);
        sockIoCtx->fd = -1;
    }
    if (sockIoCtx->listenFd != -1) {
        close(sockIoCtx->listenFd);
        sockIoCtx->listenFd = -1;
    }
}

/******************************************************************************/
/* --- END Socket IO Callbacks --- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN Supporting TLS functions --- */
/******************************************************************************/

static int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    /* Verify Callback Arguments:
     * preverify:           1=Verify Okay, 0=Failure
     * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
     * store->error_depth:  Current Index
     * store->domain:       Subject CN as string (null term)
     * store->totalCerts:   Number of certs presented by peer
     * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
     * store->store:        WOLFSSL_X509_STORE with CA cert chain
     * store->store->cm:    WOLFSSL_CERT_MANAGER
     * store->ex_data:      The WOLFSSL object pointer
     */

    printf("In verification callback, error = %d, %s\n",
        store->error, wolfSSL_ERR_reason_error_string(store->error));
    printf("\tPeer certs: %d\n", store->totalCerts);
    printf("\tSubject's domain name at %d is %s\n",
        store->error_depth, store->domain);

    (void)preverify;

    /* If error indicate we are overriding it for testing purposes */
    if (store->error != 0) {
        printf("\tAllowing failed certificate check, testing only "
            "(shouldn't do this in production)\n");
    }

    /* A non-zero return code indicates failure override */
    return 1;
}

#if defined(WOLF_CRYPTO_DEV) || defined(WOLF_CRYPTO_CB)
/* Function checks key to see if its the "dummy" key */
static int myTpmCheckKey(wc_CryptoInfo* info, TpmCryptoDevCtx* ctx)
{
    int ret = 0;

#ifndef NO_RSA
    if (info && info->pk.type == WC_PK_TYPE_RSA) {
        byte    e[sizeof(word32)], e2[sizeof(word32)];
        byte    n[WOLFTPM2_WRAP_RSA_KEY_BITS/8], n2[WOLFTPM2_WRAP_RSA_KEY_BITS/8];
        word32  eSz = sizeof(e), e2Sz = sizeof(e);
        word32  nSz = sizeof(n), n2Sz = sizeof(n);
        RsaKey  rsakey;
        word32  idx = 0;

        /* export the raw public RSA portion */
        ret = wc_RsaFlattenPublicKey(info->pk.rsa.key, e, &eSz, n, &nSz);
        if (ret == 0) {
            /* load the modulus for the dummy key */
            ret = wc_InitRsaKey(&rsakey, NULL);
            if (ret == 0) {
                ret = wc_RsaPrivateKeyDecode(DUMMY_RSA_KEY, &idx, &rsakey,
                    (word32)sizeof(DUMMY_RSA_KEY));
                if (ret == 0) {
                    ret = wc_RsaFlattenPublicKey(&rsakey, e2, &e2Sz, n2, &n2Sz);
                }
                wc_FreeRsaKey(&rsakey);
            }
        }

        if (ret == 0 && XMEMCMP(n, n2, nSz) == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Detected dummy key, so using TPM RSA key handle\n");
        #endif
            ret = 1;
        }
    }
#endif
#if defined(HAVE_ECC)
    if (info && info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
        byte    qx[WOLFTPM2_WRAP_ECC_KEY_BITS/8], qx2[WOLFTPM2_WRAP_ECC_KEY_BITS/8];
        byte    qy[WOLFTPM2_WRAP_ECC_KEY_BITS/8], qy2[WOLFTPM2_WRAP_ECC_KEY_BITS/8];
        word32  qxSz = sizeof(qx), qx2Sz = sizeof(qx2);
        word32  qySz = sizeof(qy), qy2Sz = sizeof(qy2);
        ecc_key eccKey;
        word32  idx = 0;

        /* export the raw public ECC portion */
        ret = wc_ecc_export_public_raw(info->pk.eccsign.key, qx, &qxSz, qy, &qySz);
        if (ret == 0) {
            /* load the ECC public x/y for the dummy key */
            ret = wc_ecc_init(&eccKey);
            if (ret == 0) {
                ret = wc_EccPrivateKeyDecode(DUMMY_ECC_KEY, &idx, &eccKey,
                    (word32)sizeof(DUMMY_ECC_KEY));
                if (ret == 0) {
                    ret = wc_ecc_export_public_raw(&eccKey, qx2, &qx2Sz, qy2, &qy2Sz);
                }
                wc_ecc_free(&eccKey);
            }
        }

        if (ret == 0 && XMEMCMP(qx, qx2, qxSz) == 0 &&
                        XMEMCMP(qy, qy2, qySz) == 0) {
        #ifdef DEBUG_WOLFTPM
            printf("Detected dummy key, so using TPM ECC key handle\n");
        #endif
            ret = 1;
        }
    }
#endif
    (void)info;
    (void)ctx;

    /* non-zero return code means its a "dummy" key (not valid) and the
        provided TPM handle will be used, not the wolf public key info */
    return ret;
}
#endif /* WOLF_CRYPTO_DEV || WOLF_CRYPTO_CB */

/******************************************************************************/
/* --- END Supporting TLS functions --- */
/******************************************************************************/

/******************************************************************************/
/* --- BEGIN Profiling functions --- */
/******************************************************************************/
#ifdef HAVE_STACK_SIZE

#include <pthread.h>
typedef void*         THREAD_RETURN;
typedef pthread_t     THREAD_TYPE;
#define WOLFSSL_THREAD
#define INFINITE -1
#define WAIT_OBJECT_0 0L

typedef THREAD_RETURN WOLFSSL_THREAD (*thread_func)(void);
#define STACK_CHECK_VAL 0x01

static int StackSizeCheck(thread_func tf)
{
    int            ret, i, used;
    void*          status;
    unsigned char* myStack = NULL;
    int            stackSize = 1024*128;
    pthread_attr_t myAttr;
    pthread_t      threadId;

#ifdef PTHREAD_STACK_MIN
    if (stackSize < PTHREAD_STACK_MIN)
        stackSize = PTHREAD_STACK_MIN;
#endif

    ret = posix_memalign((void**)&myStack, sysconf(_SC_PAGESIZE), stackSize);
    if (ret != 0 || myStack == NULL) {
        printf("posix_memalign failed\n");
    }

    XMEMSET(myStack, STACK_CHECK_VAL, stackSize);

    ret = pthread_attr_init(&myAttr);
    if (ret != 0) {
        printf("attr_init failed\n");
        return -1;
    }

    ret = pthread_attr_setstack(&myAttr, myStack, stackSize);
    if (ret != 0) {
        printf("attr_setstackaddr failed\n");
        return -1;
    }

    ret = pthread_create(&threadId, &myAttr, tf, NULL);
    if (ret != 0) {
        printf("pthread_create failed\n");
        return -1;
    }

    ret = pthread_join(threadId, &status);
    if (ret != 0)
        printf("pthread_join failed\n");

    for (i = 0; i < stackSize; i++) {
        if (myStack[i] != STACK_CHECK_VAL) {
            break;
        }
    }

    free(myStack);

    used = stackSize - i;
    printf("stack used = %d\n", used);

    return (int)((size_t)status);
}
#endif /* HAVE_STACK_SIZE */
/******************************************************************************/
/* --- END Profiling functions --- */
/******************************************************************************/


/******************************************************************************/
/* --- BEGIN TLS Client Example -- */
/******************************************************************************/
#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD TLS_Client(void* args)
#else
int TLS_Client(void* args)
#endif
{
    int rc = 0;
    SockIoCbCtx sockIoCtx;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    const char webServerMsg[] = "GET /index.html HTTP/1.0\r\n\r\n";
    char msg[MAX_MSG_SZ];
    int msgSz = 0;

    (void)args;

    /* initialize variables */
    XMEMSET(&sockIoCtx, 0, sizeof(sockIoCtx));
    sockIoCtx.fd = -1;

    printf("TLS Client Example\n");

    wolfSSL_Debugging_ON();

    wolfSSL_Init();

    /* Setup the WOLFSSL context (factory) */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        rc = MEMORY_E; goto exit;
    }

    /* Setup IO Callbacks */
    wolfSSL_CTX_SetIORecv(ctx, SockIORecv);
    wolfSSL_CTX_SetIOSend(ctx, SockIOSend);

    /* Server certificate validation */
#if 1
    /* skip server cert validation for this test */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, myVerify);
#else
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, myVerify);

    /* Load CA Certificates from Buffer */
	#if !defined(NO_RSA) && !defined(TLS_USE_ECC)
        rc = wolfSSL_CTX_load_verify_buffer(ctx,
            ca_cert_der_2048, sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1)
    	if (rc != WOLFSSL_SUCCESS) {
			printf("Error loading ca_cert_der_2048 DER cert\n");
			goto exit;
		}
	#elif defined(HAVE_ECC)
        rc = wolfSSL_CTX_load_verify_buffer(ctx,
            ca_ecc_cert_der_256, sizeof_ca_ecc_cert_der_256, WOLFSSL_FILETYPE_ASN1);
    	if (rc != WOLFSSL_SUCCESS) {
			printf("Error %d loading ca_ecc_cert_der_256 DER cert\n", rc);
			goto exit;
		}
	#endif
#endif

#ifndef NO_TLS_MUTUAL_AUTH
    /* Client Certificate and Key using buffer */
    #if !defined(NO_RSA) && !defined(TLS_USE_ECC)
        if (wolfSSL_CTX_use_certificate_buffer(ctx,
                client_cert_der_2048, sizeof_client_cert_der_2048,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                client_key_der_2048, sizeof_client_key_der_2048,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
    #elif defined(HAVE_ECC)
        if (wolfSSL_CTX_use_certificate_buffer(ctx,
                cliecc_cert_der_256, sizeof_cliecc_cert_der_256,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx,
                ecc_clikey_der_256, sizeof_ecc_clikey_der_256,
                WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
            goto exit;
        }
    #endif
#endif /* !NO_TLS_MUTUAL_AUTH */

#ifdef TLS_CIPHER_SUITE
    /* Optionally choose the cipher suite */
    rc = wolfSSL_CTX_set_cipher_list(ctx, TLS_CIPHER_SUITE);
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }
#endif

    /* Create wolfSSL object/session */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        rc = wolfSSL_get_error(ssl, 0);
        goto exit;
    }

    /* Setup socket and connection */
    rc = SetupSocketAndConnect(&sockIoCtx, TLS_HOST, TLS_PORT);
    if (rc != 0) goto exit;

    /* Setup read/write callback contexts */
    wolfSSL_SetIOReadCtx(ssl, &sockIoCtx);
    wolfSSL_SetIOWriteCtx(ssl, &sockIoCtx);

    /* perform connect */
    do {
        rc = wolfSSL_connect(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            rc = wolfSSL_get_error(ssl, 0);
        }
    } while (rc == WOLFSSL_ERROR_WANT_READ || rc == WOLFSSL_ERROR_WANT_WRITE);
    if (rc != WOLFSSL_SUCCESS) {
        goto exit;
    }

    printf("Cipher Suite: %s\n", wolfSSL_get_cipher(ssl));

    {
        /* initialize write */
        msgSz = sizeof(webServerMsg);
        XMEMCPY(msg, webServerMsg, msgSz);

        /* perform write */
        do {
            rc = wolfSSL_write(ssl, msg, msgSz);
            if (rc != msgSz) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_WRITE);
        if (rc >= 0) {
            msgSz = rc;
            printf("Write (%d): %s\n", msgSz, msg);
            rc = 0; /* success */
        }
        if (rc != 0) goto exit;

        /* perform read */
        do {
            /* attempt to fill msg buffer */
            rc = wolfSSL_read(ssl, msg, sizeof(msg));
            if (rc < 0) {
                rc = wolfSSL_get_error(ssl, 0);
            }
        } while (rc == WOLFSSL_ERROR_WANT_READ);
        if (rc >= 0) {
            msgSz = rc;

            /* null terminate */
            if (msgSz >= (int)sizeof(msg))
                msgSz = (int)sizeof(msg) - 1;
            msg[msgSz] = '\0';
            printf("Read (%d): %s\n", msgSz, msg);

            rc = 0; /* success */
        }
    }

exit:

    if (rc != 0) {
        printf("Failure %d (0x%x): %s\n", rc, rc, wolfSSL_ERR_reason_error_string(rc));
    }

    wolfSSL_shutdown(ssl);

    CloseAndCleanupSocket(&sockIoCtx);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return rc;
}

/******************************************************************************/
/* --- END TLS Client Example -- */
/******************************************************************************/

#endif /* !WOLFCRYPT_ONLY && !NO_CRYPT_TEST */

int main(void)
{
    int rc = -1;

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CRYPT_TEST)
    #ifdef HAVE_STACK_SIZE
        StackSizeCheck(TLS_Client);
    #else
        rc = TLS_Client();
    #endif
#else
    printf("WolfSSL Client code not compiled in\n");
#endif

    return rc;
}
