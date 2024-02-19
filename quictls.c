#include "quictls.h"

static int verify_callback(int preverify_ok, X509_STORE_CTX *x509_store_ctx)
{
	int error_code = preverify_ok ? X509_V_OK : X509_STORE_CTX_get_error(x509_store_ctx);
	if (error_code != X509_V_OK)
	{
		const char *error_string = X509_verify_cert_error_string(error_code);
		fprintf(stderr, "verify_callback failed[%d]: %s\n", error_code, error_string);
	}
	return preverify_ok;
}

SSL_CTX *ssl_ctx_new(const char *cafile, const char *key, int is_client)
{
	int err;
	SSL_CTX *ssl_ctx;
	const SSL_METHOD *method;
	int verify_mode;

	method = is_client ? TLS_client_method() : TLS_server_method();
	ssl_ctx = SSL_CTX_new(method);
	if (!ssl_ctx)
	{
		fprintf(stderr, "SSL_CTX_new: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	if (is_client)
	{
		if (cafile)
			err = SSL_CTX_load_verify_locations(ssl_ctx, cafile, NULL);
		else
			SSL_CTX_set_default_verify_paths(ssl_ctx);
		if (err == 0)
		{
			fprintf(stderr, "Could not load trusted certificates: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto fail;
		}
	}
	else
	{
		err = SSL_CTX_use_certificate_file(ssl_ctx, cafile, SSL_FILETYPE_PEM);
		if (err <= 0)
		{
			fprintf(stderr, "Could not load server certificate chain from file %s\n", cafile);
			goto fail;
		}
		err = SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM);
		if (err <= 0)
		{
			fprintf(stderr, "Could not load server keypair from file %s\n", key);
			goto fail;
		}
	}
	verify_mode = is_client ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT : SSL_VERIFY_NONE;
	SSL_CTX_set_verify(ssl_ctx, verify_mode, verify_callback);

	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

	if (is_client)
	{
		if (ngtcp2_crypto_quictls_configure_client_context(ssl_ctx) != 0)
		{
			fprintf(stderr, "ngtcp2_crypto_quictls_configure_client_context failed\n");
			goto fail;
		}
	}
	else
	{
		if (ngtcp2_crypto_quictls_configure_server_context(ssl_ctx) != 0)
		{
			fprintf(stderr, "ngtcp2_crypto_quictls_configure_server_context failed\n");
			goto fail;
		}
	}

	return ssl_ctx;
fail:
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	return NULL;
}

SSL *ssl_new(SSL_CTX *ctx, const char *hostname, int is_client)
{
	int err;
	SSL *ssl;

	ssl = SSL_new(ctx);
	if (!ssl)
	{
		fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	if (is_client)
		SSL_set_connect_state(ssl);
	else
		SSL_set_accept_state(ssl);

	err = SSL_set_tlsext_host_name(ssl, hostname); // SNI
	if (err != 1)
	{
		fprintf(stderr, "SSL_set_tlsext_host_name: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}
	err = SSL_set1_host(ssl, hostname); // cert hostname
	if (err != 1)
	{
		fprintf(stderr, "SSL_set1_host: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto fail;
	}

	return ssl;
fail:
	if (ssl)
		SSL_free(ssl);
	return NULL;
}

void setup_quictls_for_quic(SSL *ssl, ngtcp2_conn *conn, ngtcp2_crypto_conn_ref *ref)
{
	ngtcp2_conn_set_tls_native_handle(conn, ssl);
	SSL_set_app_data(ssl, ref);

	/* For NGTCP2_PROTO_VER_V1 */
	SSL_set_quic_transport_version(ssl, TLSEXT_TYPE_quic_transport_parameters);
}