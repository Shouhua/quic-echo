#include "utils.h"

int resolve_and_connect(const char *host, const char *port,
						struct sockaddr *local_addr, size_t *local_addrlen,
						struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int ret, fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK,
					rp->ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
		{
			*remote_addrlen = rp->ai_addrlen;
			memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);

			socklen_t len = (socklen_t)*local_addrlen;
			if (getsockname(fd, local_addr, &len) == -1)
				return -1;
			*local_addrlen = len;
			break;
		}

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL)
		return -1;

	return fd;
}

int resolve_and_bind(const char *host, const char *port,
					 struct sockaddr *local_addr, size_t *local_addrlen)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int ret, fd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0)
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
		if (fd == -1)
			continue;

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
		{
			*local_addrlen = rp->ai_addrlen;
			memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
			break;
		}

		close(fd);
	}

	freeaddrinfo(result);

	if (rp == NULL)
		return -1;

	return fd;
}

uint64_t timestamp(void)
{
	struct timespec tp;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
		return 0;

	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

void log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void)user_data;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fprintf(stdout, "\n");
}

ssize_t
recv_packet(int fd, uint8_t *data, size_t data_size,
			struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct iovec iov;
	iov.iov_base = data;
	iov.iov_len = data_size;

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	msg.msg_name = remote_addr;
	msg.msg_namelen = *remote_addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t ret;

	do
		ret = recvmsg(fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	*remote_addrlen = msg.msg_namelen;

	return ret;
}

ssize_t
send_packet(int fd, const uint8_t *data, size_t data_size,
			struct sockaddr *remote_addr, size_t remote_addrlen)
{
	struct iovec iov;
	iov.iov_base = (void *)data;
	iov.iov_len = data_size;

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = remote_addr;
	msg.msg_namelen = remote_addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t ret;

	do
		ret = sendmsg(fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	return ret;
}

int gen_random_cid(ngtcp2_cid *cid)
{
	int ret;

	cid->datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	ret = RAND_bytes(cid->data, (int)cid->datalen);
	if (ret != 1)
	{
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	return 0;
}

int get_ip_port(struct sockaddr_storage *addr, char *ip, uint16_t *port)
{
	if (ip == NULL && port == NULL)
		return 0;
	if (addr->ss_family == AF_INET)
	{
		struct sockaddr_in *addrV4 = (struct sockaddr_in *)addr;
		if (port)
			*port = ntohs(addrV4->sin_port);
		if (ip)
			inet_ntop(addrV4->sin_family, &(addrV4->sin_addr), ip, INET_ADDRSTRLEN);
		return 0;
	}
	else if (addr->ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addrV6 = (struct sockaddr_in6 *)addr;
		if (ip)
			inet_ntop(addrV6->sin6_family, &(addrV6->sin6_addr), ip, INET6_ADDRSTRLEN);
		if (port)
			*port = ntohs(addrV6->sin6_port);
		return 0;
	}
	return -1;
}