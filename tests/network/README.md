# Gecko-only Linux 网络实验

`gecko_bench.py` 是手动运行的短传输对照工具，不是自动化性能验收或算法排名。
原创脚本及测试采用 MIT-0。认证密码、混淆密码、私钥和 VPS 登录信息不要提交。

## 前置条件

- 有 root / CAP_NET_ADMIN 的 Linux，安装 `python3 iproute2 iputils-ping ethtool`。
- 当前源码编译的 Linux 版 oh-my-hysteria。
- 已有 TLS 证书和对应私钥，客户端继续执行证书链和域名校验。
- 一个私有 JSON 服务端模板，含以下内容（替换占位符）：

```json
{
  "tls": {"cert": "/private/fullchain.pem", "key": "/private/key.pem"},
  "obfs": {"type": "gecko", "gecko": {"password": "REPLACE_OBFS_SECRET"}},
  "auth": {"type": "password", "password": "REPLACE_AUTH_SECRET"}
}
```

模板应设置为 `0600`；不要使用生产凭证。脚本拒绝非 Gecko 模板，不会在失败时
回退为裸 QUIC。隔离网络不能做公网 ACME 挑战，证书须事先申请。

## 运行

```sh
sudo python3 tests/network/gecko_bench.py \
  --binary /private/oh-my-hysteria-linux-amd64 \
  --server-template /private/server.json \
  --server-name test.example.com \
  --output /private/results-new \
  --repeats 3 --data-size 4194304
```

结果目录必须不存在，防止覆盖既有结果。默认六配置有效负载为 432 MiB，全部在本机
命名空间内传输，不走公网。单次传输超时为 120 秒，出现失败或字节数不完整
即停止。普通异常、SIGINT、SIGTERM 和 SIGHUP 均尝试停止测试进程并删除本次
创建的命名空间；SIGKILL / 机器故障后应检查 `ip netns list` 中本次的 `omh*`
名称，不要删除不属于本次测试的网络。

## 拓扑和结果

三个独立命名空间：客户端 → 路由器 → 服务端。没有默认路由、NAT 或公网
接口配置修改；只为两个私有 `/30` 网段添加路由。

- 两端各增加 100 ms 单向传播延迟，空载 RTT 约 200 ms。
- 路由器双向 TBF 限速 10 Mbit/s，burst 为 32 KiB。
- 浅队列：TBF 字节上限相当于 50 ms 的链路速率。
- 深队列：400 ms。
- 随机丢包：100 ms 队列，每方向 netem loss 0.1%，同时影响数据和 ACK。
- 所有 veth 禁用 TSO/GSO/GRO，减少大包对模拟丢包及队列统计的干扰。
- 每轮以固定种子打乱所选配置的执行顺序；种子只控制顺序，不固定内核随机丢包。

六个配置：BBR standard、实验性 BBRv3、CUBIC legacy、CUBIC HyStart++、Reno legacy、
Reno HyStart++。可用 `--modes bbr3 bbr` 只测新控制器与回退对照。两端均设置
对应算法，不填写 `bandwidth`，服务端设置
`ignoreClientBandwidth: true`，避免进入 Brutal。每次新建连接，先下载、后上传，
两方向各传指定字节数。因此上传共享下载后的连接状态，**不是独立冷启动样本**。

另提供显式 `--modes bbr3-conservative bbr3 bbr3-aggressive`，不改变原有六配置
默认负载。`--stress` 增加 80ms / 20 Mbit/s / 40ms 队列 / 1% loss，以及
350ms / 5 Mbit/s / 150ms 队列 / 1% loss 两个隔离场景；每个方向分别施加 loss。
这些均在 VPS 内部运行，不消耗用户 LTE 出口流量。

实验性 COPA 可显式使用 `--modes copa bbr3 bbr`，不加入默认负载；其研究、
参数和未实现的 TCP-competitive 模式见 [COPA](../../docs/copa.md)。
Geodesic 可显式使用 `--modes geodesic bbr3 copa bbr`；固定来源、round 级
G1/G2/G3 与未验证假设见 [Geodesic](../../docs/geodesic.md)。
可选 `--path-change` 追加80→240ms / 240→80ms两个RTT整形阶跃场景（启动2秒
后变更）；每方向至少4MiB，不改变默认场景。定时器结束后再清理命名空间，
未实际变更 / 变更失败会使样本无效。qdisc替换会重置计数并可能丢掉在排队包，
其统计不是全程丢包总量，也不证明算法识别了真实物理路径变化。
可选 `--path-change-data-size`（4..32MiB/方向）只扩大动态场景，默认仍与
`--data-size` 一致。JSON逐样本记录大小，汇总同时报告端到端 wall time，
不把分方向 speed 当作含握手/收尾的总耗时，也不统计 `valid: false` 的样本。

`traffic_budget.py` 提供测试专用 IPv4 UDP IP 长度与预算计数，另有单元测试。
它不是抓包程序本身，也不计运营商隧道 / 链路重传费用；调用方必须限制测试
端口 / 公网接口，在计数错误或超额时停止自有进程，不保存报文内容。

`results.json` 保存每次吞吐及 qdisc 前后快照；另有应用日志、空载 ping 和
传输期间的 ICMP ping。传输期 ping 含握手及方向切换间隙，不应直接标作纯满载
排队延迟；ICMP 也不等于 QUIC 内部 RTT。TBF 上限包括 burst，不能将队列
参数或丢包计数直接等同于控制器实际观测到的排队 / QUIC 丢包。

可用 `python3 tests/network/summarize.py /private/results-new/results.json`
按场景和配置汇总有效传输的中位数 / 范围；失败或字节数不完整的传输不会混入
吞吐统计，但仍计入总次数。

短传输、同机共享 CPU、随机丢包、用户态调度及 TBF burst 都限制结果的外推。
工具没有测公平性、稳态长传输、动态带宽、误判恢复或 ECN；这些需要另外设计实验。
BBRv3 的状态 / 采样诊断可用 `OH_MY_HYSTERIA_BBR3_DEBUG=1` 写入应用日志。

## 本次公网测试的特殊约束

2026-10 的专用 VPS 公网测试中，用户仅对
`oh-my-hysteria-windows-amd64.exe` 进程配置了中国大陆出口分流。
只有这个文件名的实际客户端可以作为该线路的公网对照；Python 等辅助程序
只连接本机转发端口，不能代替它直发 VPS UDP。所有公网测试也必须启用 Gecko。
这是该次环境约束，不是应用的一般部署要求。
