/*
 * Copyright (c) 2024-2024, Yanruibing <yanruibing@kxyk.com> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/decoder.h>
#endif
#include <sys/uio.h>
#include <arpa/inet.h>

#define WB_TLS_PROTO_TLSv1       (1<<0)
#define WB_TLS_PROTO_TLSv1_1     (1<<1)
#define WB_TLS_PROTO_TLSv1_2     (1<<2)
#define WB_TLS_PROTO_TLSv1_3     (1<<3)

/* Use safe defaults */
#ifdef TLS1_3_VERSION
#define WB_TLS_PROTO_DEFAULT     (WB_TLS_PROTO_TLSv1_2|WB_TLS_PROTO_TLSv1_3)
#else
#define WB_TLS_PROTO_DEFAULT     (WB_TLS_PROTO_TLSv1_2)
#endif

static void tlsInit(void) {
    /* 
     * Enable configuring OpenSSL using the standard openssl.cnf
     * OPENSSL_config()/OPENSSL_init_crypto() should be the first 
     * call to the OpenSSL* library.
     *  - OPENSSL_config() should be used for OpenSSL versions < 1.1.0
     *  - OPENSSL_init_crypto() should be used for OpenSSL versions >= 1.1.0
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OPENSSL_config(NULL);
    SSL_load_error_strings();
    SSL_library_init();
#elif OPENSSL_VERSION_NUMBER < 0x10101000L
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG|OPENSSL_INIT_ATFORK, NULL);
#endif
}