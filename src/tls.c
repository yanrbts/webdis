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
#include "conf.h"
#include "client.h"
#include "slog.h"

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

SSL_CTX *tls_ctx = NULL;

/* Create a new char string with the content specified by the 'init' pointer
 * and 'initlen'.
 * If NULL is used for 'init' the string is initialized with zero bytes.
 *
 * The string is always null-termined (all the sds strings are, always) so
 * even if you create an sds string with:
 *
 * mystring = newstrlen("abc",3);
 *
 * You can print the string with printf() as there is an implicit \0 at the
 * end of the string. However the string is binary safe and can contain
 * \0 characters in the middle, as the length is stored in the sds header. */
char *newstrlen(const void *init, size_t initlen) {
    char *s;

    s = malloc(initlen+1);
    if (s == NULL) return NULL;
    if (!init)
        memset(s, 0, initlen+1);
    if (initlen && init)
        memcpy(s, init, initlen);
    s[initlen] = '\0';
    return s;
}

/* Split 's' with separator in 'sep'. An array
 * of sds strings is returned. *count will be set
 * by reference to the number of tokens returned.
 *
 * On out of memory, zero length string, zero length
 * separator, NULL is returned.
 *
 * Note that 'sep' is able to split a string using
 * a multi-character separator. For example
 * split("foo_-_bar","_-_"); will return two
 * elements "foo" and "bar".
 *
 * This version of the function is binary-safe but
 * requires length arguments. 
 */
static char **splitlen(const char *s, int len, const char *sep, int seplen, int *count) {
    int elements = 0, slots = 5, start = 0, j;
    char **tokens;

    if (seplen < 1 || len < 0) return NULL;

    tokens = malloc(sizeof(char*) * slots);
    if (tokens == NULL) return NULL;

    if (len == 0) {
        *count = 0;
        return tokens;
    }

    for (j = 0; j < (len-(seplen-1)); j++) {
        /* make sure there is room for the next element and the final one */
        if (slots < elements+2) {
            char **newtokens;

            slots *= 2;
            newtokens = realloc(tokens, sizeof(char*)*slots);
            if (newtokens == NULL) goto cleanup;
            tokens = newtokens;
        }
        /* search the separator */
        if ((seplen == 1 && *(s+j) == sep[0]) || (memcmp(s+j, sep, seplen) == 0)) {
            tokens[elements] = newstrlen(s+start, j-start);
            if (tokens[elements] == NULL) goto cleanup;
            elements++;
            start = j+seplen;
            j = j+seplen-1; /* skip the separator */
        }
    }
    /* Add the final element. We are sure there is room in the tokens array. */
    tokens[elements] = newstrlen(s+start, len-start);
    if (tokens[elements] == NULL) goto cleanup;
    elements++;
    *count = elements;
    return tokens;

cleanup:
    {
        int i;
        for (i = 0; i < elements; i++) free(tokens[i]);
        free(tokens);
        *count = 0;
        return NULL;
    }
}

/* Free the result returned by splitlen(), or do nothing if 'tokens' is NULL. */
void sfreesplitres(char **tokens, int count) {
    if (!tokens) return;
    while(count--)
        free(tokens[count]);
    free(tokens);
}

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

static void tlsCleanup(void) {
    if (tls_ctx) {
        SSL_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
    // unavailable on LibreSSL
    OPENSSL_cleanup();
#endif
}

/* Callback for passing a keyfile password stored as an sds to OpenSSL */
static int tlsPasswordCallback(char *buf, int size, int rwflag, void *u) {
    (void)rwflag;

    const char *pass = u;
    size_t pass_len;

    if (!pass) return -1;
    pass_len = strlen(pass);
    if (pass_len > (size_t)size) return -1;
    memcpy(buf, pass, pass_len);

    return (int) pass_len;
}

/* Create a *base* SSL_CTX using the SSL configuration provided. The base context
 * includes everything that's common for both client-side and server-side connections.
 */
static SSL_CTX *createSSLContext(struct httpssl *ctx_config, int protocols, int client) {
    const char *cert_file = client ? ctx_config->client_cert_file : ctx_config->cert_file;
    const char *key_file = client ? ctx_config->client_key_file : ctx_config->key_file;
    const char *key_file_pass = client ? ctx_config->client_key_file_pass : ctx_config->key_file_pass;
    char errbuf[256];
    SSL_CTX *ctx = NULL;

    ctx = SSL_CTX_new(SSLv23_method());
    if (!ctx) goto error;

    /* These options turn off the SSLv3, SSLv2 protocol versions with TLS */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
    /* 
     * SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
     * Disables a countermeasure against a SSL 3.0/TLS 1.0 protocol 
     * vulnerability affecting CBC ciphers, which cannot be handled 
     * by some broken SSL implementations. This option has no effect 
     * for connections using other ciphers.
     */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif
    if (!(protocols & WB_TLS_PROTO_TLSv1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    if (!(protocols & WB_TLS_PROTO_TLSv1_1))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
#ifdef SSL_OP_NO_TLSv1_2
    if (!(protocols & WB_TLS_PROTO_TLSv1_2))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_3
    if (!(protocols & WB_TLS_PROTO_TLSv1_3))
        SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
#endif

    /* Do not use compression even if it is supported. */
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

    /* 
     * adds the mode set via bitmask in mode to ctx. Options already set before are not cleared. 
     * SSL_MODE_ENABLE_PARTIAL_WRITE:
     * Allow SSL_write(..., n) to return r with 0 < r < n 
     * (i.e. report success when just a single record has been written). 
     * When not set (the default), SSL_write() will only report success 
     * once the complete chunk was written. Once SSL_write() returns with r, 
     * r bytes have been successfully written and the next call to SSL_write() 
     * must only send the n-r bytes left, imitating the behaviour of write().
     * SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER:
     * Make it possible to retry SSL_write() with changed buffer location 
     * (the buffer contents must stay the same). This is not the default 
     * to avoid the misconception that non-blocking SSL_write() 
     * behaves like non-blocking write().
     */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    /*
     * sets the verification flags for ctx to be mode and specifies 
     * the verify_callback function to be used. If no callback function 
     * shall be specified, the NULL pointer can be used for verify_callback.
     * SSL_VERIFY_PEER:
     * Server mode: the server sends a client certificate request to the client. 
     * The certificate returned (if any) is checked. If the verification process fails, 
     * the TLS/SSL handshake is immediately terminated with an alert message 
     * containing the reason for the verification failure. The behaviour 
     * can be controlled by the additional
     * SSL_VERIFY_FAIL_IF_NO_PEER_CERT:
     * Server mode: if the client did not return a certificate, 
     * the TLS/SSL handshake is immediately terminated with a "handshake failure" alert. 
     * This flag must be used together with SSL_VERIFY_PEER.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    /* 
     * SSL_CTX_set_default_passwd_cb() sets the default password callback 
     * called when loading/storing a PEM certificate with encryption.
     * SSL_CTX_set_default_passwd_cb_userdata() sets a pointer to userdata 
     * which will be provided to the password callback on invocation.
     */
    SSL_CTX_set_default_passwd_cb(ctx, tlsPasswordCallback);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)key_file_pass);

    /* 
     * SSL_CTX_use_certificate_chain_file() loads a certificate chain from file into ctx. 
     * The certificates must be in PEM format and must be sorted starting with the subject's 
     * certificate (actual client or server certificate), followed by intermediate 
     * CA certificates if applicable, and ending at the highest level (root) CA. 
     * SSL_use_certificate_chain_file() is similar except it loads the certificate chain into ssl.
     */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        goto error;
    }
    /* 
     * SSL_CTX_use_PrivateKey_file() adds the first private key found in file to ctx. 
     * The formatting type of the private key must be specified from the known types SSL_FILETYPE_PEM,
     */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        goto error;
    }
    /*  set default locations for trusted CA certificates */
    if ((ctx_config->ca_cert_file || ctx_config->ca_cert_dir) &&
        SSL_CTX_load_verify_locations(ctx, ctx_config->ca_cert_file, ctx_config->ca_cert_dir) <= 0) {
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        goto error;
    }

    if (ctx_config->ciphers && !SSL_CTX_set_cipher_list(ctx, ctx_config->ciphers)) {
        goto error;
    }

#ifdef TLS1_3_VERSION
    if (ctx_config->ciphersuites && !SSL_CTX_set_ciphersuites(ctx, ctx_config->ciphersuites)) {
        goto error;
    }
#endif

    return ctx;

error:
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}

static int parseProtocolsConfig(const char *str) {
    int i, count = 0;
    int protocols = 0;

    if (!str) return WB_TLS_PROTO_DEFAULT;

    char **tokens = splitlen(str, strlen(str), " ", 1, &count);
    if (!tokens) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (!strcasecmp(tokens[i], "tlsv1")) protocols |= WB_TLS_PROTO_TLSv1;
        else if (!strcasecmp(tokens[i], "tlsv1.1")) protocols |= WB_TLS_PROTO_TLSv1_1;
        else if (!strcasecmp(tokens[i], "tlsv1.2")) protocols |= WB_TLS_PROTO_TLSv1_2;
        else if (!strcasecmp(tokens[i], "tlsv1.3")) {
#ifdef TLS1_3_VERSION
            protocols |= WB_TLS_PROTO_TLSv1_3;
#else
            protocols = -1;
            break;
#endif
        } else {
            protocols = -1;
            break;
        }
    }
    sfreesplitres(tokens, count);

    return protocols;
}

/* Attempt to configure/reconfigure TLS. This operation is atomic and will
 * leave the SSL_CTX unchanged if fails.
 * @priv: config of httpssl.
 * @reconfigure: if true, ignore the previous configure; if false, only
 * configure from @ctx_config if tls_ctx is NULL.
 */
SSL_CTX *ssl_init(void *priv) {
    struct httpssl *ctx_config = (struct httpssl *)priv;
    char errbuf[256];
    SSL_CTX *ctx = NULL;
    int protocols;

    if (tls_ctx) {
        return tls_ctx;
    }

    if (!ctx_config->cert_file) {
        // serverLog(LL_WARNING, "No tls-cert-file configured!");
        goto error;
    }

    if (!ctx_config->key_file) {
        // serverLog(LL_WARNING, "No tls-key-file configured!");
        goto error;
    }

    protocols = parseProtocolsConfig(ctx_config->protocols);
    if (protocols == -1) goto error;

    /* Create server side/general context */
    ctx = createSSLContext(ctx_config, protocols, 0);
    if (!ctx) goto error;

    if (ctx_config->session_caching) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ctx, ctx_config->session_cache_size);
        SSL_CTX_set_timeout(ctx, ctx_config->session_cache_timeout);
        SSL_CTX_set_session_id_context(ctx, (void *)"kserver", 7);
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }

#ifdef SSL_OP_NO_CLIENT_RENEGOTIATION
    SSL_CTX_set_options(ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
#endif
    /* 
     * When choosing a cipher, use the server's preferences instead of the client preferences. 
     * When not set, the SSL server will always follow the clients preferences. When set, 
     * the SSLv3/TLSv1 server will choose following its own preferences. Because of the different protocol, 
     * for SSLv2 the server will send its list of preferences to the client and the client chooses.
     */
    if (ctx_config->prefer_server_ciphers)
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

#if ((OPENSSL_VERSION_NUMBER < 0x30000000L) && defined(SSL_CTX_set_ecdh_auto))
    SSL_CTX_set_ecdh_auto(ctx, 1);
#endif
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

    if (ctx_config->dh_params_file) {
        FILE *dhfile = fopen(ctx_config->dh_params_file, "r");
        if (!dhfile) {
            goto error;
        }

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        EVP_PKEY *pkey = NULL;
        OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "PEM", NULL, "DH", OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, NULL, NULL);
        if (!dctx) {
            fclose(dhfile);
            goto error;
        }

        if (!OSSL_DECODER_from_fp(dctx, dhfile)) {
            OSSL_DECODER_CTX_free(dctx);
            fclose(dhfile);
            goto error;
        }

        OSSL_DECODER_CTX_free(dctx);
        fclose(dhfile);

        if (SSL_CTX_set0_tmp_dh_pkey(ctx, pkey) <= 0) {
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            EVP_PKEY_free(pkey);
            goto error;
        }
        /* Not freeing pkey, it is owned by OpenSSL now */
#else
        DH *dh = PEM_read_DHparams(dhfile, NULL, NULL, NULL);
        fclose(dhfile);
        if (!dh) {
            // serverLog(LL_WARNING, "%s: failed to read DH params.", ctx_config->dh_params_file);
            goto error;
        }

        if (SSL_CTX_set_tmp_dh(ctx, dh) <= 0) {
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            // serverLog(LL_WARNING, "Failed to load DH params file: %s: %s", ctx_config->dh_params_file, errbuf);
            DH_free(dh);
            goto error;
        }

        DH_free(dh);
#endif
    } else {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        SSL_CTX_set_dh_auto(ctx, 1);
#endif 
    }

    /* If a client-side certificate is configured, create an explicit client context */
    if (ctx_config->client_cert_file && ctx_config->client_key_file) {
        ctx = createSSLContext(ctx_config, protocols, 1);
        if (!ctx) goto error;
    }

    SSL_CTX_free(tls_ctx);
    tls_ctx = ctx;
    return tls_ctx;
    
error:
    if (ctx) SSL_CTX_free(ctx);
    return NULL;
}
