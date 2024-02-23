## QUIC-ECHO project for testing QUIC protocol by using [ngtcp2](https://github.com/ngtcp2/ngtcp2) and [quictls](https://github.com/quictls/openssl)

### [Generate Certs](./certs/gen.sh)

### [Build ngtcp2, nghttp3, openssl(quictls version)](https://curl.se/docs/http3.html)
If you encounter the problem of not found libssl.so, you can refer to this [blog](https://juejin.cn/post/7337491274457841727)

### Run
```shell
sudo apt install tmux
make clean
make certs
make run
```

### Capture traffic
tshark有capture filter和display filter。display filter跟wireshark的一样，使用-Y指示，导出到文件时(-w)，该指示不能使用; capture filter使用-f指示; -O 'tcp,quic' 显示协议详情。
```shell
# display filter
tshark -o "tls.keylog_file: $PWD/keylog.txt" -i lo -Px -O quic -Y "udp.port == 4434"
```
```shell
# 使用capture filter过滤，导出15个packets到文件tshark.log, 里面依然包括QUIC协议展开
# 导出文件tshark.log可以导入到wireshark中查看
tshark -o "tls.keylog_file: $PWD/keylog.txt" -i lo -Px -O quic -f "udp port 4433" -w tshark.log -a packets:15
```