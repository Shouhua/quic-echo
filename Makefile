SHELL := /bin/bash
PROJECT_ROOT_DIR := $(shell pwd)
CA := ${PROJECT_ROOT_DIR}/certs/ca_cert.pem
SERVER_CERT := ${PROJECT_ROOT_DIR}/certs/server_cert.pem
SERVER_KEY := ${PROJECT_ROOT_DIR}/certs/server_key.pem
HOST := 127.0.0.1
PORT := 8443
SRC = $(wildcard *.c)
CLIENT_SRC = $(filter-out server.c, ${SRC})
SERVER_SRC = $(filter-out client.c, ${SRC})
EXE=client server

# -Wl,--trace-symbol,SYMBOL
# CREF=-Wl,--cref
TRACE=-Wl,--trace # 打印GCC搜寻共享库目录
RPATH=-Wl,-rpath=/usr/local/lib64
PEDANTIC=-pedantic

# NGTCP2_CFLAGS=-I/root/ngtcp2/include
NGTCP2_CFLAGS=-I/usr/local/include
CFLAGS= -g -Wall -Wextra \
	${NGTCP2_CFLAGS} \
	${PEDANTIC} \
	${RPATH} \
	# -DDEBUG \
	# ${CREF} \
	# ${TRACE} \

# quictls(openssl)
QUICTLS_LDFLAGS=-L/usr/local/lib64 -lssl -lcrypto
# NGTCP2_LDFLAGS=-L/root/ngtcp2/lib -lngtcp2 -lngtcp2_crypto_quictls
NGTCP2_LDFLAGS=-L/usr/local/lib -lngtcp2 -lngtcp2_crypto_quictls
LDFLAGS=${QUICTLS_LDFLAGS} ${NGTCP2_LDFLAGS}

.PHONY: build_dir certs all run run_server run_client debug_client debug_server client server clean
all: build_dir client server
	
build_dir: 
	@mkdir -p build

certs: ${PROJECT_ROOT_DIR}/certs/gen.sh
	@cd certs && ./gen.sh

client: build_dir ${CLIENT_SRC}
	@gcc ${CFLAGS} -o build/$@ ${CLIENT_SRC} ${LDFLAGS}

run_client: client
	@SSLKEYLOGFILE="${PROJECT_ROOT_DIR}/keylog.txt" ./build/client ${HOST} ${PORT} ${CA}

debug_client: client
	@SSLKEYLOGFILE="${PROJECT_ROOT_DIR}/keylog.txt" gdb --args ./build/client ${HOST} ${PORT} ${CA}

server: build_dir ${SERVER_SRC}
	@gcc ${CFLAGS} -o build/$@ ${SERVER_SRC} ${LDFLAGS}

run_server: server
	@./build/server ${HOST} ${PORT} ${SERVER_CERT} ${SERVER_KEY}
	
debug_server: server
	@gdb --args ./build/server ${HOST} ${PORT} ${SERVER_CERT} ${SERVER_KEY}

run: all
	@if tmux has-session -t quic &> /dev/null; then tmux kill-session -t quic; fi; \
	tmux new-session -s quic -c ${PROJECT_ROOT_DIR} -d; \
	tmux split-window -t quic -v -l 10; \
	tmux send-keys -t quic:0.0 "make run_server" C-m; \
	sleep 0.5; \
	tmux send-keys -t quic:0.1 "make run_client" C-m; \
	if [[ -z "$$TMUX" ]]; then tmux attach-session -t quic; else tmux switch-client -t quic; fi;

clean: 
	rm -rfv build certs/*.pem