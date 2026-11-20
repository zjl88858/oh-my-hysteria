# NetFront：代理功能与传输验证

用户侧问题是：**在给定的较差线路上，应用能否通过 OMHY 正常访问服务？** `proxy_app.py` 用 Windows 候选启动本机 HTTP/SOCKS5 代理，经 VPS 访问只绑定在服务器回环的网页、文件、上传和 DNS 服务。页面与文件由服务端随机生成，上传摘要由源站计算；所有 TLS 客户端正常验证证书。一次 DNS 查询允许至多三次发送，并记录实际次数。

此前已独立执行[配对传输方案](PLAN-20261120.md)。它的逐样本 UDP 回显率检查保留在报告中，和应用是否正常完成事务分别判定。结果见[实测报告](../../../docs/network-test-netfront-2026-11-20.md)。

## 复现

`matrix.py` 是手动工具，不在 CI 中部署。使用新输出目录。公开测试需要同一 VPS 最近的有效回执作流量账本种子、已核对的 SSH 主机指纹、已构建的候选及其 `SHA256SUMS`；Linux 侧用 `python3`、`openssl`、`tcpdump`、AF_PACKET 和 libsodium 或 Python cryptography。测试程序只放入临时目录，服务端 ACL 限制到本轮回环源站。控制机用 Paramiko，口令交互输入。

```sh
# 仓库根目录，预先用该平台环境生成 Linux 测试程序
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o obfs-linux-amd64.test ./extras/obfs

uv run --no-project --with 'paramiko==4.0.0' python tests/network/netfront_matrix/matrix.py \
  --host "$TEST_VPS" --fingerprint "$VERIFIED_ED25519" --binaries "$CANDIDATE_DIR" \
  --linux-tests obfs-linux-amd64.test --seed "$PREVIOUS_RECEIPT" --out "$NEW_MATRIX_DIR"

uv run --no-project --with 'paramiko==4.0.0' python tests/network/netfront_matrix/matrix.py \
  --application --host "$TEST_VPS" --fingerprint "$VERIFIED_ED25519" --binaries "$CANDIDATE_DIR" \
  --seed "$NEW_MATRIX_DIR/evidence.json" --out "$NEW_APP_DIR"
```

`local_cases.py --exe EXE --output JSON` 只跑本机：不同端口延迟、活动会话副路阻断/恢复、两客户端同时传大文件。`compat.py --old EXE1 --new EXE2 --output JSON` 检查两个候选的双向互通，以及错误 CA、登录凭证、混淆密码是否被拒绝。

长时间的实际 socket 轮换测试为显式启用项：

```sh
OMHY_NETFRONT_SOAK=1 go test -count=1 -v -timeout=12m ./extras/obfs -run '^TestNetFrontLongSocketSoak$'
```

`analyze.py MATRIX_JSON LOCAL_CONTROLS_JSON ROTATION_LOG --output SUMMARY_JSON --apps APP_JSON --interop INTEROP_JSON` 从原始回执重算包数、四点序号、端口续期、累计账本及两套验收结果。脚本不保存网络载荷或登录凭证。
