#ifndef _QUICTLS_H
#define _QUICTLS_H

#include <stdio.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX *ssl_ctx_new(const char *cafile, const char *key, int is_client);

SSL *ssl_new(SSL_CTX *ctx, const char *hostname, int is_client);

void setup_quictls_for_quic(SSL *ssl, ngtcp2_conn *conn, ngtcp2_crypto_conn_ref *ref);
#endif