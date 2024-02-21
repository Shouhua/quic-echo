#include "connection.h"

struct _Connection
{
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_conn *nt2_conn;
	ngtcp2_crypto_conn_ref ng2_conn_ref;
	ngtcp2_ccerr ng2_last_error;

	struct sockaddr_storage local_addr;
	size_t local_addrlen;
	struct sockaddr_storage remote_addr;
	size_t remote_addrlen;

	struct list_head streams;

	int sock_fd;  // UDP socket for send and receive quic stream data
	int timer_fd; // timer for idle

	int is_closed;
};

Connection *connection_new(int sock_fd, SSL_CTX *ctx, SSL *ssl)
{
	Connection *conn = (Connection *)malloc(sizeof(Connection));
	conn->ssl_ctx = ctx;
	conn->ssl = ssl;
	conn->sock_fd = sock_fd;
	conn->timer_fd = -1;
	conn->is_closed = 0;
	init_list_head(&conn->streams);
	return conn;
}

int connection_get_sock_fd(Connection *conn)
{
	return conn->sock_fd;
}
int connection_get_timer_fd(Connection *conn)
{
	return conn->timer_fd;
}

void connection_set_ngtcp2_connection(Connection *conn, ngtcp2_conn *nt2_conn,
									  ngtcp2_crypto_conn_ref ref)
{
	conn->nt2_conn = nt2_conn;
	conn->ng2_conn_ref = ref;
	ngtcp2_ccerr_default(&conn->ng2_last_error);
}

ngtcp2_conn *connection_get_ngtcp2_connection(Connection *conn)
{
	return conn->nt2_conn;
}

struct sockaddr_storage *connection_get_local_addr(Connection *conn)
{
	return &conn->local_addr;
}
struct sockaddr_storage *connection_get_remote_addr(Connection *conn)
{
	return &conn->remote_addr;
}

void connection_set_local_addr(Connection *conn,
							   struct sockaddr *local_addr,
							   size_t local_addrlen)
{
	memcpy(&conn->local_addr, local_addr, local_addrlen);
	conn->local_addrlen = local_addrlen;
}

void connection_set_remote_addr(Connection *conn,
								struct sockaddr *remote_addr,
								size_t remote_addrlen)
{
	memcpy(&conn->remote_addr, remote_addr, remote_addrlen);
	conn->remote_addrlen = remote_addrlen;
}

void connection_free(Connection *conn)
{
	if (!conn)
		return;

	if (conn->ssl)
		SSL_free(conn->ssl);
	if (conn->ssl_ctx)
		SSL_CTX_free(conn->ssl_ctx);
	if (conn->nt2_conn)
		ngtcp2_conn_del(conn->nt2_conn);
	if (conn->sock_fd >= 0)
		close(conn->sock_fd);
	if (conn->timer_fd >= 0)
		close(conn->timer_fd);

	stream_free_list(&conn->streams);
	free(conn);
}

void connection_add_stream(Connection *conn, Stream *stream)
{
	list_add_tail(&conn->streams, stream_get_link(stream));
}

Stream *connection_find_stream(Connection *conn, int64_t stream_id)
{
	return stream_get_by_id(&conn->streams, stream_id);
}

int connection_start(Connection *conn)
{
	setup_quictls_for_quic(conn->ssl, conn->nt2_conn, &conn->ng2_conn_ref);
	conn->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (conn->timer_fd < 0)
	{
		perror("timerfd_create");
		return -1;
	}

	return 0;
}

int connection_read(Connection *conn)
{
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize ret;

	for (;;)
	{
		struct sockaddr_storage remote_addr;
		size_t remote_addrlen = sizeof(remote_addr);
		ret = recv_packet(conn->sock_fd, buf, sizeof(buf),
						  (struct sockaddr *)&remote_addr, &remote_addrlen);
		if (ret < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fprintf(stderr, "recv_packet: %s\n", strerror(errno));
			return -1;
		}

		ngtcp2_path path;
		memcpy(&path, ngtcp2_conn_get_path(conn->nt2_conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *)&remote_addr;

		ngtcp2_pkt_info pi;
		memset(&pi, 0, sizeof(pi));

		ret = ngtcp2_conn_read_pkt(conn->nt2_conn, &path, &pi, buf, ret,
								   timestamp());
		if (ret < 0)
		{
			fprintf(stderr, "ngtcp2_conn_read_pkt: %s", ngtcp2_strerror(ret));
			return -1;
		}
	}

	return 0;
}

static int write_to_stream(Connection *conn, Stream *stream)
{
	uint8_t buf[BUF_SIZE];

	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	ngtcp2_pkt_info pi;
	uint64_t ts = timestamp();

	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

	for (;;)
	{
		ngtcp2_vec datav;
		int64_t stream_id;

		if (stream)
		{
			datav.base = (void *)stream_peek_data(stream, &datav.len);
			if (datav.len == 0)
			{
				/* No stream data to be sent */
				stream_id = -1;
				flags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE;
			}
			else
				stream_id = stream_get_id(stream);
		}
		else
		{
			datav.base = NULL;
			datav.len = 0;
			stream_id = -1;
		}

		ngtcp2_ssize n_read, n_written;

		n_written = ngtcp2_conn_writev_stream(conn->nt2_conn, &ps.path, &pi,
											  buf, sizeof(buf),
											  &n_read,
											  flags,
											  stream_id,
											  &datav, 1,
											  ts);
		if (n_written < 0)
		{
			if (n_written == NGTCP2_ERR_WRITE_MORE)
			{
				stream_mark_sent(stream, n_read);
				continue;
			}
			fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
					ngtcp2_strerror((int)n_written));
			return -1;
		}

		if (n_written == 0)
			return 0;

		if (stream && n_read > 0)
			stream_mark_sent(stream, n_read);

		int ret;

		ret = send_packet(conn->sock_fd, buf, n_written,
						  (struct sockaddr *)&conn->remote_addr,
						  conn->remote_addrlen);
		if (ret < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fprintf(stderr, "send_packet: %s\n", strerror(errno));
			return -1;
		}

		/* No stream data to be sent */
		if (stream && datav.len == 0)
			break;
	}

	return 0;
}

int connection_write(Connection *conn)
{
	int ret;

	if (list_empty(&conn->streams))
	{
		ret = write_to_stream(conn, NULL);
		if (ret < 0)
			return -1;
	}
	else
	{
		struct list_head *el, *el1;
		list_for_each_safe(el, el1, &conn->streams)
		{
			Stream *stream = list_entry(el, Stream, link);
			ret = write_to_stream(conn, stream);
			if (ret < 0)
				return -1;
		}
	}

	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->nt2_conn);
	ngtcp2_tstamp now = timestamp();
	struct itimerspec it;
	memset(&it, 0, sizeof(it));

	ret = timerfd_settime(conn->timer_fd, 0, &it, NULL);
	if (ret < 0)
	{
		fprintf(stderr, "timerfd_settime: %s\n", strerror(errno));
		return -1;
	}
	if (expiry < now)
	{
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 1;
	}
	else
	{
		it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
		it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
	}
	ret = timerfd_settime(conn->timer_fd, 0, &it, NULL);
	if (ret < 0)
	{
		fprintf(stderr, "timerfd_settime: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

void connection_close(Connection *conn, uint64_t error_code)
{
	ngtcp2_pkt_info pi;
	uint8_t buf[BUF_SIZE];

	ngtcp2_path_storage ps;
	ngtcp2_path_storage_zero(&ps);

	ngtcp2_ssize n_written;

	ngtcp2_ccerr error;
	ngtcp2_ccerr_default(&error);
	error.error_code = error_code;

	n_written = ngtcp2_conn_write_connection_close(conn->nt2_conn,
												   &ps.path, &pi,
												   buf, sizeof(buf),
												   &error,
												   timestamp());
	if (n_written < 0)
		fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
				ngtcp2_strerror((int)n_written));
	else
	{
		ssize_t ret;

		ret = send_packet(conn->sock_fd, buf, (size_t)n_written,
						  (struct sockaddr *)&conn->remote_addr,
						  conn->remote_addrlen);
		if (ret < 0)
			fprintf(stderr, "send_packet: %s\n", strerror(errno));
	}

	conn->is_closed = 1;
}

void connection_set_socket_fd(Connection *conn, int fd)
{
	conn->sock_fd = fd;
}