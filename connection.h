#ifndef _CONNECTION_H
#define _CONNECTION_H

#include <errno.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <time.h>

#include "list.h"
#include "quictls.h"
#include "stream.h"
#include "utils.h"

#define BUF_SIZE 1280

typedef struct _Connection Connection;

Connection *connection_new(int sock_fd, SSL_CTX *ctx, SSL *ssl);
void connection_free(Connection *conn);
void connection_add_stream(Connection *conn, Stream *stream);
int connection_get_sock_fd(Connection *conn);
int connection_get_timer_fd(Connection *conn);
void connection_set_ngtcp2_connection(Connection *conn, ngtcp2_conn *nt2_conn,
									  ngtcp2_crypto_conn_ref ref);

ngtcp2_conn *connection_get_ngtcp2_connection(Connection *conn);

struct sockaddr_storage *connection_get_local_addr(Connection *conn);
struct sockaddr_storage *connection_get_remote_addr(Connection *conn);

void connection_set_local_addr(Connection *connection,
							   struct sockaddr *local_addr,
							   size_t local_addrlen);

void connection_set_remote_addr(Connection *connection,
								struct sockaddr *remote_addr,
								size_t remote_addrlen);
Stream *connection_find_stream(Connection *conn, int64_t stream_id);
int connection_start(Connection *conn);
int connection_read(Connection *conn);
int connection_write(Connection *conn);
void connection_close(Connection *conn, uint64_t error_code);
void connection_set_socket_fd(Connection *conn, int fd);

#endif