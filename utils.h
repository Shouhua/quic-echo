#ifndef _UTILS_H
#define _UTILS_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <ngtcp2/ngtcp2.h>
#include <openssl/rand.h>

int resolve_and_connect(const char *host, const char *port,
						struct sockaddr *local_addr, size_t *local_addrlen,
						struct sockaddr *remote_addr, size_t *remote_addrlen);

int resolve_and_bind(const char *host, const char *port,
					 struct sockaddr *local_addr, size_t *local_addrlen);

uint64_t timestamp(void);

void log_printf(void *user_data, const char *fmt, ...);

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
					struct sockaddr *remote_addr, size_t *remote_addrlen);

ssize_t send_packet(int fd, const uint8_t *data, size_t data_size,
					struct sockaddr *remote_addr, size_t remote_addrlen);

int gen_random_cid(ngtcp2_cid *cid);
int get_ip_port(struct sockaddr_storage *addr, char *ip, uint16_t *port);
#endif