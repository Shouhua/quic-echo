#include <errno.h>
#include <ngtcp2/ngtcp2.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>

#include "connection.h"
#include "list.h"
#include "quictls.h"
#include "utils.h"

#define MAX_EVENTS 64
#define BUFFER_SIZE 1280
#define MAX_CONNECTIONS 256

typedef struct _Connection_Item
{
	struct list_head link;
	Connection *connection;
} Connection_Item;

typedef struct _Server
{
	int sock_fd;
	int epoll_fd;

	char *hostname;

	ngtcp2_settings settings;
	ngtcp2_cid scid;
	char *cert;
	char *key;
	struct sockaddr_storage local_addr;
	size_t local_addrlen;
	struct list_head connections;
} Server;

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	Connection *connection = conn_ref->user_data;
	return connection_get_ngtcp2_connection(connection);
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn __attribute__((unused)),
									   int64_t stream_id, uint64_t offset,
									   uint64_t datalen,
									   void *user_data,
									   void *stream_user_data __attribute__((unused)))
{
	Connection *connection = user_data;
	Stream *stream = connection_find_stream(connection, stream_id);
	if (stream)
		stream_mark_acked(stream, offset + datalen);
	return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn __attribute__((unused)),
							   uint32_t flags __attribute__((unused)),
							   int64_t stream_id,
							   uint64_t offset __attribute__((unused)),
							   const uint8_t *data, size_t datalen,
							   void *user_data,
							   void *stream_user_data __attribute__((unused)))
{
	Connection *connection = user_data;
	struct sockaddr_storage *ss = connection_get_remote_addr(connection);
	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	(void)get_ip_port(ss, ip, &port);
	fprintf(stdout, "(%s, %d) sent %ld bytes: ", ip, port, datalen);
	fwrite(data, datalen, 1, stdout);
	fprintf(stdout, "\n");

	Stream *stream = connection_find_stream(connection, stream_id);
	if (stream)
		stream_push_data(stream, (uint8_t *)data, datalen);

	return 0;
}

static int stream_open_cb(ngtcp2_conn *conn __attribute__((unused)),
						  int64_t stream_id, void *user_data)
{
	Connection *connection = user_data;
	Stream *stream = NULL;

	stream = stream_new(stream_id);
	connection_add_stream(connection, stream);
	return 0;
}

void rand_cb(uint8_t *dest, size_t destlen,
			 const ngtcp2_rand_ctx *rand_ctx)
{
	size_t i;
	(void)rand_ctx;

	for (i = 0; i < destlen; ++i)
	{
		*dest = (uint8_t)random();
	}
}

int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
							 uint8_t *token, size_t cidlen,
							 void *user_data)
{
	(void)conn;
	(void)user_data;

	if (RAND_bytes(cid->data, (int)cidlen) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int handle_handshake_completed(ngtcp2_conn *conn, void *userdata)
{
	(void)conn;
	Connection *connection = (Connection *)userdata;
	struct sockaddr_storage *addr = connection_get_remote_addr(connection);
	char ip[INET_ADDRSTRLEN];
	uint16_t port;
	(void)get_ip_port(addr, ip, &port);
	fprintf(stdout, "(%s, %d) connected\n", ip, port);
	return 0;
}

static const ngtcp2_callbacks callbacks =
	{
		/* Use the default implementation from ngtcp2_crypto */
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_retry = ngtcp2_crypto_recv_retry_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

		.acked_stream_data_offset = acked_stream_data_offset_cb,
		.recv_stream_data = recv_stream_data_cb,
		.stream_open = stream_open_cb,
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.handshake_completed = handle_handshake_completed,
};

static Connection *accept_connection(Server *server,
									 struct sockaddr *remote_addr, size_t remote_addrlen,
									 const uint8_t *data, size_t data_size)
{
	ngtcp2_pkt_hd header;
	int ret;

	ret = ngtcp2_accept(&header, data, data_size);
	if (ret < 0)
		return NULL;

	SSL_CTX *ssl_ctx = ssl_ctx_new(server->cert, server->key, 0);
	if (!ssl_ctx)
	{
		fprintf(stderr, "ssl_ctx_new failed\n");
		return NULL;
	}
	SSL *ssl = ssl_new(ssl_ctx, server->hostname, 0);
	if (!ssl)
	{
		SSL_CTX_free(ssl_ctx);
		fprintf(stderr, "ssl_new failed\n");
		return NULL;
	}

	Connection *connection = NULL;

	connection = connection_new(server->sock_fd, ssl_ctx, ssl);
	if (!connection)
		return NULL;

	ngtcp2_path path =
		{
			.local = {
				.addrlen = server->local_addrlen,
				.addr = (struct sockaddr *)&server->local_addr},
			.remote = {.addrlen = remote_addrlen, .addr = (struct sockaddr *)remote_addr}};

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_uni = 3;
	params.initial_max_streams_bidi = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_stream_data_bidi_remote = 128 * 1024;
	params.max_idle_timeout = 10 * NGTCP2_SECONDS;
	params.initial_max_data = 1024 * 1024;
	params.original_dcid = header.dcid;
	params.original_dcid_present = 1;

	ngtcp2_cid scid;
	if (gen_random_cid(&scid) < 0)
		return NULL;

	ngtcp2_conn *conn = NULL;

	ret = ngtcp2_conn_server_new(&conn,
								 &header.scid,
								 &scid,
								 &path,
								 header.version,
								 &callbacks,
								 &server->settings,
								 &params,
								 NULL,
								 connection);
	if (ret < 0)
	{
		fprintf(stderr, "ngtcp2_conn_server_new: %s\n", ngtcp2_strerror(ret));
		return NULL;
	}

	ngtcp2_crypto_conn_ref conn_ref;
	conn_ref.get_conn = get_conn;
	conn_ref.user_data = connection;
	connection_set_ngtcp2_connection(connection, conn, conn_ref);
	connection_set_local_addr(connection,
							  (struct sockaddr *)&server->local_addr,
							  server->local_addrlen);
	connection_set_remote_addr(connection,
							   (struct sockaddr *)remote_addr,
							   remote_addrlen);

	Connection_Item *ci = (Connection_Item *)malloc(sizeof(Connection_Item));
	ci->connection = connection;
	init_list_head(&ci->link);
	list_add_tail(&ci->link, &server->connections);
	return connection;
}

static Connection *find_connection(Server *server, const uint8_t *dcid, size_t dcid_size)
{
	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &server->connections)
	{
		Connection_Item *ci = list_entry(el, Connection_Item, link);
		Connection *connection = ci->connection;
		ngtcp2_conn *conn = connection_get_ngtcp2_connection(connection);
		size_t n_scids = ngtcp2_conn_get_scid(conn, NULL);
		ngtcp2_cid *scids = NULL;

		scids = (ngtcp2_cid *)malloc(sizeof(ngtcp2_cid) * n_scids);
		if (!scids)
			return NULL;

		n_scids = ngtcp2_conn_get_scid(conn, scids);
		for (size_t i = 0; i < n_scids; i++)
		{
			if (dcid_size == scids[i].datalen && memcmp(dcid, scids[i].data, dcid_size) == 0)
			{
				free(scids);
				return connection;
			}
		}
		free(scids);
	}
	return NULL;
}

static int handle_incoming(Server *server)
{
	uint8_t buf[BUF_SIZE];

	for (;;)
	{
		ssize_t n_read;
		struct sockaddr_storage remote_addr;
		size_t remote_addrlen = sizeof(remote_addr);
		int ret;

		n_read = recv_packet(server->sock_fd, buf, sizeof(buf),
							 (struct sockaddr *)&remote_addr,
							 &remote_addrlen);
		if (n_read < 0)
		{
			if (n_read != EAGAIN && n_read != EWOULDBLOCK)
				return 0;
			fprintf(stderr, "recv_packet: %s\n", strerror(errno));
			return -1;
		}

		ngtcp2_version_cid version_cid;
		ret = ngtcp2_pkt_decode_version_cid(&version_cid,
											buf, n_read,
											NGTCP2_MIN_INITIAL_DCIDLEN);
		if (ret < 0)
		{
			fprintf(stderr, "ngtcp2_pkt_decode_version_cid: %s\n",
					ngtcp2_strerror(ret));
			return -1;
		}

		Connection *connection = find_connection(server, version_cid.dcid, version_cid.dcidlen);
		if (!connection)
		{
			connection = accept_connection(server,
										   (struct sockaddr *)&remote_addr,
										   remote_addrlen,
										   buf, n_read);
			if (!connection)
				return -1;

			ret = connection_start(connection);
			if (ret < 0)
				return -1;

			struct epoll_event ev;
			ev.events = EPOLLIN | EPOLLET;
			ev.data.fd = connection_get_timer_fd(connection);
			ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
			if (ret < 0)
			{
				perror("epoll_ctl EPOLL_CTL_ADD timer_fd");
				return -1;
			}
		}

		ngtcp2_conn *conn = connection_get_ngtcp2_connection(connection);

		ngtcp2_path path;
		memcpy(&path, ngtcp2_conn_get_path(conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *)&remote_addr;

		ngtcp2_pkt_info pi;
		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt(conn, &path, &pi, buf, n_read, timestamp());
		if (ret < 0)
		{
			if (ret == NGTCP2_ERR_DRAINING)
			{
				struct sockaddr_storage *addr = connection_get_remote_addr(connection);
				char ip[INET_ADDRSTRLEN];
				uint16_t port;
				(void)get_ip_port(addr, ip, &port);

				fprintf(stdout, "(%s, %d) closed\n", ip, port);
			}
			else
			{
				fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(ret));
			}

			ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL,
							connection_get_timer_fd(connection),
							NULL);
			if (ret < 0)
			{
				perror("epoll_ctl EPOLL_CTL_DEL timer_fd");
				return -1;
			}

			struct list_head *el, *el1;
			list_for_each_safe(el, el1, &server->connections)
			{
				Connection_Item *ci = list_entry(el, Connection_Item, link);
				if (ci->connection == connection)
				{
					list_del(el);
					connection_close(connection, NGTCP2_APPLICATION_ERROR);
					connection_set_socket_fd(connection, -1);
					connection_free(connection);
					free(ci);
				}
			}
		}
	}
	return 0;
}

static int run(Server *server)
{
	server->epoll_fd = epoll_create1(0);
	if (server->epoll_fd == -1)
	{
		perror("epoll_create1");
		return -1;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = server->sock_fd;
	if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
	{
		perror("epoll_ctl");
		return -1;
	}

	uint16_t port;
	(void)get_ip_port(&server->local_addr, NULL, &port);

	fprintf(stdout, "Now quic echo server is listening on %d\n", port);
	for (;;)
	{
		struct epoll_event events[MAX_EVENTS];
		int nfds;

		nfds = epoll_wait(server->epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0)
		{
			perror("epoll_wait");
			return -1;
		}

		for (int n = 0; n < nfds; n++)
		{
			int ret;

			if (events[n].data.fd == server->sock_fd)
			{
				if (events[n].events & EPOLLIN)
					(void)handle_incoming(server);

				if (events[n].events & EPOLLOUT)
				{
					struct list_head *el, *el1;
					list_for_each_safe(el, el1, &server->connections)
					{
						Connection_Item *connection_item = list_entry(el, Connection_Item, link);
						(void)connection_write(connection_item->connection);
					}
				}
			}
			else
			{
				struct list_head *el, *el1;
				list_for_each_safe(el, el1, &server->connections)
				{
					Connection_Item *connection_item = list_entry(el, Connection_Item, link);
					Connection *connection = connection_item->connection;
					if (events[n].data.fd == connection_get_timer_fd(connection))
					{
						ngtcp2_conn *conn = connection_get_ngtcp2_connection(connection);
						ret = ngtcp2_conn_handle_expiry(conn, timestamp());
						if (ret < 0)
						{
							fprintf(stderr, "Timeout and free connection, ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(ret));
							ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL,
											connection_get_timer_fd(connection),
											NULL);
							if (ret < 0)
							{
								perror("epoll_ctl EPOLL_CTL_DEL timer_fd");
								return -1;
							}
							list_del(el);
							connection_close(connection, NGTCP2_APPLICATION_ERROR);
							connection_set_socket_fd(connection, -1);
							connection_free(connection);
							free(connection_item);
							continue;
						}

						(void)connection_write(connection);
					}
				}
			}
		}
	}
}

int main(int argc, char *argv[])
{
	// server HOST PORT CERT KEY
	if (argc != 5)
	{
		fprintf(stderr, "server HOST PORT CERT KEY\n");
		return -1;
	}
	Server server = {
		.hostname = argv[1],
		.sock_fd = -1,
		.epoll_fd = -1,
		.cert = argv[3],
		.key = argv[4],
	};
	init_list_head(&server.connections);

	server.sock_fd = resolve_and_bind(
		argv[1],
		argv[2],
		(struct sockaddr *)&server.local_addr,
		&server.local_addrlen);
	if (server.sock_fd == -1)
	{
		fprintf(stderr, "resolve_and_bind failed\n");
		return -1;
	}

	ngtcp2_settings_default(&server.settings);
	server.settings.initial_ts = timestamp();
	// server.settings.log_printf = log_printf;

	return run(&server);
}