#include <fcntl.h>
#include <ngtcp2/ngtcp2.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "connection.h"
#include "quictls.h"
#include "stream.h"
#include "utils.h"

#ifdef __GNUC__
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#define MAX_STREAMS 10
#define MAX_EVENTS 64

int ssl_userdata_idx;

typedef struct
{
	Connection *connection;
	Stream *streams[MAX_STREAMS];
	size_t n_streams;
	size_t stream_index;
	size_t n_coalescing;
	size_t coalesce_count;
	char *keylogfile;

	int sig_fd;
} Client;

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

static int recv_stream_data_cb(ngtcp2_conn *conn __attribute__((unused)),
							   uint32_t flags __attribute__((unused)),
							   int64_t stream_id,
							   uint64_t offset __attribute__((unused)),
							   const uint8_t *data, size_t datalen,
							   void *user_data __attribute__((unused)),
							   void *stream_user_data __attribute__((unused)))
{
	char buf[datalen + 1];
	snprintf(buf, datalen + 1, "%s", data);
	fprintf(stdout, "Received %zu bytes from stream #%zd: %s\n", datalen, stream_id, buf);
	return 0;
}

UNUSED static int handle_handshake_completed(ngtcp2_conn *conn, void *userdata)
{
	(void)userdata;
	ngtcp2_duration timeout;
	const ngtcp2_transport_params *params;
	params = ngtcp2_conn_get_remote_transport_params(conn);
	if (!params)
	{
		fprintf(stderr, "transport params not existed\n");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	timeout = params->max_idle_timeout == 0 ? 0 : params->max_idle_timeout / NGTCP2_SECONDS - 1;

	ngtcp2_conn_set_keep_alive_timeout(conn, timeout * NGTCP2_SECONDS);
	return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	Connection *connection = conn_ref->user_data;
	return connection_get_ngtcp2_connection(connection);
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn __attribute__((unused)),
									   int64_t stream_id,
									   uint64_t offset, uint64_t datalen,
									   void *user_data,
									   void *stream_user_data __attribute__((unused)))
{
	Connection *connection = user_data;
	Stream *stream = connection_find_stream(connection, stream_id);
	if (stream)
		stream_mark_acked(stream, offset + datalen);
	return 0;
}

int setup_stdin(int epoll_fd)
{
	int flags;
	struct epoll_event ev;

	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	if (flags < 0)
	{
		perror("fcntl STDIN_FILENO F_GETFL");
		return -1;
	}
	flags = fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	if (flags < 0)
	{
		perror("fcntl STDIN_FILENO F_SETFL O_NONBLOCK");
		return -1;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = STDIN_FILENO;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) == -1)
	{
		perror("epoll_ctl EPOLL_CTL_ADD STDIN_FILENO");
		return -1;
	}
	return 0;
}

int handle_timer(Client *client)
{
	int ret;
	ret = ngtcp2_conn_handle_expiry(
		connection_get_ngtcp2_connection(client->connection),
		timestamp());
	if (ret < 0)
	{
		fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror((int)ret));
		return -1;
	}
	ret = connection_write(client->connection);
	if (ret < 0)
	{
		fprintf(stderr, "connection_write failed\n");
		return -1;
	}
	return 0;
}

static int handle_stdin(Client *client)
{
	uint8_t buf[BUF_SIZE];
	size_t n_read = 0;
	int ret;

	memset(buf, 0, BUF_SIZE);

	while (n_read < sizeof(buf))
	{
		ret = read(STDIN_FILENO, buf + n_read, sizeof(buf) - n_read);
		if (ret == 0)
		{
			connection_close(client->connection, 0);
			return 0;
		}
		else if (ret < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			perror("read");
			return -1;
		}
		else
			n_read += ret - 1;
	}
	if (n_read == sizeof(buf))
	{
		fprintf(stderr, "read buffer overflow\n");
		return -1;
	}

	int res;
	res = memcmp("\\show", buf, 5);
	if (res == 0)
	{
		fprintf(stdout, "streams: %ld, coalescing: %ld\n", client->n_streams, client->n_coalescing);
		return 0;
	}

	res = memcmp("\\set", buf, 4);
	if (res == 0)
	{
		char *key_value;
		long value;
		key_value = strstr((char *)buf, "streams");
		if (key_value)
		{
			value = strtol(key_value + 8, NULL, 10);
#ifdef DEBUG
			fprintf(stdout, "set streams to %ld\n", value);
#endif
			client->n_streams = value;
			return 0;
		}
		else
		{
			key_value = strstr((char *)buf, "coalescing");
			if (key_value)
			{
				value = strtol(key_value + 11, NULL, 10);
#ifdef DEBUG
				fprintf(stdout, "set coalescing to %ld\n", value);
#endif
				client->n_coalescing = value;
				return 0;
			}
		}
	}

	if (!client->streams[client->stream_index])
	{
		ngtcp2_conn *conn = connection_get_ngtcp2_connection(client->connection);
		if (!ngtcp2_conn_get_streams_bidi_left(conn))
		{
			fprintf(stderr, "no available bidi streams; skipping\n");
			return 0;
		}

		int64_t stream_id;

		ret = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
		if (ret < 0)
		{
			fprintf(stderr, "ngtcp2_conn_open_bidi_stream: %s\n",
					ngtcp2_strerror(ret));
			return -1;
		}

		Stream *stream = NULL;

		stream = stream_new(stream_id);
		if (!stream)
			return -1;

		client->streams[client->stream_index] = stream;
		connection_add_stream(client->connection,
							  client->streams[client->stream_index]);

#ifdef DEBUG
		fprintf(stdout, "opened stream #%zd\n", stream_id);
#endif
	}

	if (client->streams[client->stream_index])
	{
		uint8_t *input_data = (uint8_t *)malloc(sizeof(uint8_t) * n_read);
		memcpy(input_data, buf, n_read);
		ret = stream_push_data(client->streams[client->stream_index],
							   input_data, n_read);
		if (ret < 0)
			return -1;

#ifdef DEBUG
		fprintf(stdout, "#%ld[%ld] buffered %zd bytes\n",
				stream_get_id(client->streams[client->stream_index]),
				client->stream_index,
				n_read);
#endif

		if (++client->coalesce_count < client->n_coalescing)
			return 0;
	}

	ret = connection_write(client->connection);
	if (ret < 0)
		return -1;

	client->stream_index++;
	client->stream_index %= client->n_streams;
	client->coalesce_count = 0;

	return 0;
}

int setup_sig(int epoll_fd)
{
	sigset_t mask;
	int sig_fd;
	/*
	 * Setup SIGALRM to be delivered via SignalFD
	 * */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	/*
	 * Block these signals so that they are not handled
	 * in the usual way. We want them to be handled via
	 * SignalFD.
	 * */
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
	{
		perror("sigprocmask");
		return -1;
	}
	sig_fd = signalfd(-1, &mask, 0);
	if (sig_fd == -1)
	{
		perror("signalfd");
		return -1;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = sig_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sig_fd, &ev) == -1)
	{
		close(sig_fd);
		perror("epoll_ctl EPOLL_CTL_ADD sig_fd");
		return -1;
	}
	return sig_fd;
}

int handle_sig(Client *c)
{
	struct signalfd_siginfo sfd_si;
	if (read(c->sig_fd, &sfd_si, sizeof(struct signalfd_siginfo)) == -1)
		return -1;

#ifdef DEBUG
	if (sfd_si.ssi_signo == SIGQUIT)
		fprintf(stdout, "QUIT signal triggered\n");
	if (sfd_si.ssi_signo == SIGINT)
		fprintf(stdout, "INT signal triggered\n");
#endif

	if (c->connection)
	{
		connection_close(c->connection, NGTCP2_APPLICATION_ERROR);
		connection_free(c->connection);
	}
	exit(0);
}

static int run(Client *client)
{
	struct epoll_event ev;
	int epoll_fd = -1;
	int sock_fd = -1;
	int timer_fd = -1;
	int sig_fd = -1;

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
	{
		perror("epoll_create1");
		return -1;
	}

	sig_fd = setup_sig(epoll_fd);
	if (sig_fd < 0)
	{
		return -1;
	}
	client->sig_fd = sig_fd;

	if (setup_stdin(epoll_fd) < 0)
	{
		fprintf(stderr, "setup_stdin failed\n");
		return -1;
	}

	sock_fd = connection_get_sock_fd(client->connection);
	timer_fd = connection_get_timer_fd(client->connection);

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = timer_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1)
	{
		perror("epoll_ctl EPOLL_CTL_ADD timer_fd");
		return -1;
	}

	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = sock_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev) == -1)
	{
		perror("epoll_ctl EPOLL_CTL_ADD sock_fd");
		return -1;
	}

	for (;;)
	{
		struct epoll_event events[MAX_EVENTS];
		int nfds;

		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds < 0)
		{
			perror("epoll_wait");
			return -1;
		}

		for (int n = 0; n < nfds; n++)
		{
			if (events[n].data.fd == sig_fd)
			{
				if (handle_sig(client) < 0)
					return -1;
			}
			if (events[n].data.fd == sock_fd)
			{
				if (events[n].events & EPOLLIN)
				{
					if (connection_read(client->connection) < -1)
					{
						fprintf(stderr, "connection_read failed\n");
						return -1;
					}
				}
				if (events[n].events & EPOLLOUT)
				{
					if (connection_write(client->connection) < -1)
					{
						fprintf(stderr, "connection_write failed\n");
						return -1;
					}
				}
			}
			if (events[n].data.fd == timer_fd)
			{
				if (handle_timer(client) < 0)
					return -1;
			}
			if (events[n].data.fd == STDIN_FILENO)
			{
				if (handle_stdin(client) < 0)
					return -1;
			}
		}
	}
	return 0;
}

void keylog_callback(const SSL *ssl, const char *line)
{
	int res;

	char *keylogfile_path = (char *)SSL_get_ex_data(ssl, ssl_userdata_idx);
	if (!keylogfile_path)
	{
		fprintf(stderr, "keylogfile_path is NULL\n");
		return;
	}

	int keylogfile = open(keylogfile_path, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
	if (keylogfile == -1)
	{
		perror("open keylogfile");
		exit(-1);
	}

	res = write(keylogfile, line, strlen(line));
	if (res == -1)
	{
		perror("write keylogfile line");
		close(keylogfile);
		exit(-1);
	}
	res = write(keylogfile, "\n", 1);
	if (res == -1)
	{
		perror("write keylogfile nextline");
		close(keylogfile);
		exit(-1);
	}
	close(keylogfile);
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		fprintf(stdout, "client HOST PORT CAFILE\n");
		return -1;
	}

	const char *host = argv[1];
	const char *port = argv[2];
	const char *cafile = argv[3];

	Client client =
		{
			.connection = NULL,
			.streams = {
				NULL,
			},
			.n_streams = 0,
			.stream_index = 0,
			.n_coalescing = 0,
			.coalesce_count = 0,
			.keylogfile = NULL,
		};

	client.keylogfile = getenv("SSLKEYLOGFILE");

	struct sockaddr_storage local_addr, remote_addr;
	size_t local_addrlen = sizeof(local_addr), remote_addrlen;
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	ngtcp2_conn *nt2_conn = NULL;
	ngtcp2_crypto_conn_ref nt2_conn_ref;

	int sock_fd = resolve_and_connect(
		host, port,
		(struct sockaddr *)&local_addr,
		&local_addrlen,
		(struct sockaddr *)&remote_addr,
		&remote_addrlen);

	if (sock_fd < 0)
	{
		fprintf(stderr, "resolve_and_connect失败\n");
		return -1;
	}

	ssl_ctx = ssl_ctx_new(cafile, NULL, 1);
	if (!ssl_ctx)
	{
		fprintf(stderr, "ssl_ctx_new failed\n");
		return -1;
	}

	ssl = ssl_new(ssl_ctx, host, 1);
	if (!ssl)
	{
		fprintf(stderr, "ssl_new failed\n");
		return -1;
	}

	if (client.keylogfile)
	{
		SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
		ssl_userdata_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (SSL_set_ex_data(ssl, ssl_userdata_idx, client.keylogfile) == 0)
		{
			fprintf(stderr, "SSL_set_ex_data failed\n");
			return -1;
		}
	}

	Connection *conn = connection_new(sock_fd, ssl_ctx, ssl);
	client.connection = conn;

	ngtcp2_path path = {
		{
			(struct sockaddr *)&local_addr,
			local_addrlen,
		},
		{
			(struct sockaddr *)&remote_addr,
			remote_addrlen,
		},
		NULL,
	};
	ngtcp2_callbacks callbacks = {
		/* Use the default implementation from ngtcp2_crypto */
		.client_initial = ngtcp2_crypto_client_initial_cb,
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
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		// .handshake_completed = handle_handshake_completed,
	};
	ngtcp2_cid dcid, scid;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	int rv;

	if (gen_random_cid(&dcid) != 0)
	{
		fprintf(stderr, "gen_random_cid failed\n");
		return -1;
	}

	if (gen_random_cid(&scid) != 0)
	{
		fprintf(stderr, "gen_random_cid failed\n");
		return -1;
	}

	ngtcp2_settings_default(&settings);

	settings.initial_ts = timestamp();
	// settings.log_printf = log_printf;

	ngtcp2_transport_params_default(&params);

	params.initial_max_streams_uni = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_data = 1024 * 1024;
	params.max_idle_timeout = 20 * NGTCP2_SECONDS;

	rv = ngtcp2_conn_client_new(&nt2_conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
								&callbacks, &settings, &params, NULL, client.connection);
	if (rv != 0)
	{
		fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	connection_set_local_addr(conn, (struct sockaddr *)&local_addr, local_addrlen);
	connection_set_remote_addr(conn, (struct sockaddr *)&remote_addr, remote_addrlen);
	nt2_conn_ref.get_conn = get_conn;
	nt2_conn_ref.user_data = client.connection;
	connection_set_ngtcp2_connection(conn, nt2_conn, nt2_conn_ref);
	connection_start(conn);

	client.n_streams = 1;
	client.n_coalescing = 1;
	client.coalesce_count = 0;

	return run(&client);
}