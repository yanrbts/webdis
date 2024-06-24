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
#ifndef __TLS__
#define __TLS__

#include <string.h>
#include <strings.h>
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

struct http_client;

typedef enum {
    OK,
    ERROR,
    RETRY
} status;

typedef struct ConnectionType {
    void (*cleanup)(void);
    void (*shutdown)(struct http_client *conn);
    void (*close)(struct http_client *conn);
    /* IO */
    int (*write)(struct http_client *conn, const void *data, size_t data_len);
    int (*read)(struct http_client *conn, void *buf, size_t buf_len);
} ConnectionType;

SSL_CTX *ssl_init(void *priv);
// status ssl_connect(connection *, char *);
// status ssl_close(connection *);
// status ssl_read(connection *, size_t *);
// status ssl_write(connection *, char *, size_t, size_t *);
// size_t ssl_readable(connection *);

#endif