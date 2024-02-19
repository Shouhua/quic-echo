## QUIC echo project for testing QUIC protocol by using [ngtcp2](https://github.com/ngtcp2/ngtcp2) project

### [Generate Certs](./certs/gen.sh)
**openssl(quictls version)'s maybe not found libssl.so**, need set ```export LD_LIBRARY_PATH=/usr/local/lib64```

### [Build ngtcp2, nghttp3, openssl(quictls version)](https://curl.se/docs/http3.html)
TODO: how to handle openssl conflicts between two versions

### Run
```shell
sudo apt install tmux
make clean
make certs
make run
```