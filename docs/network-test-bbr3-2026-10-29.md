# 实验性 BBRv3 / BBR 回退网络验证

日期：2026-10-29（北京时间）。本轮使用当前完整控制器，不沿用第一阶段 sampler
的验证结论。`bbr3` 是显式实验选项，默认 BBR 和 Brutal 带宽协商优先级未变。

## 条件与身份

- 服务端：Ubuntu 24.04.4，Linux amd64，1 vCPU / 约 2 GiB，Go 1.26.0。
- 两端始终使用 Gecko；公网失败也没有裸 QUIC 回退。
- 使用有效 Let's Encrypt 证书，SNI `test-omhy.todspod.si`，正常验证证书链，
  未使用 `tls.insecure`；客户端显式连接 VPS IP，避免本机分流合成 DNS 地址。
- 公网客户端进程严格为 **`oh-my-hysteria-windows-amd64.exe`**；Python 只启动
  应用、读日志、通过 SSH 管理服务器及连接本机转发端口，不代替该进程测公网 QUIC。
- 使用用户提供的进程名中国大陆分流；未独立证实实际地理出口。
- 两端选择对应控制器，不填写客户端 bandwidth；服务端
  `ignoreClientBandwidth: true`，认证日志 `tx: 0`，不误测 Brutal。
- 二进制 SHA256 与源码 / 构建元数据归档于
  `build/bbr3-controller/artifacts.json`。没有 commit 或远程发布。

## 受控网络：18/18 次双向传输

使用 `tests/network/gecko_bench.py --modes bbr3 bbr --repeats 3 --data-size 4194304`。
三隔离命名空间，不设置默认路由或 NAT，不修改主机公网接口 / 防火墙。
RTT 200 ms、双向 10 Mbit/s，TBF burst 32 KiB，veth 关闭 TSO/GSO/GRO。
每个场景 / 算法三次连接，每次先下载、后上传，各 4 MiB。

| 场景 | 算法 | 完成 | 下载中位 Mbit/s | 上传中位 Mbit/s |
| --- | --- | --- | --- | --- |
| 浅队列（50ms） | BBR | 3/3 | 8.04 | 7.70 |
| 浅队列（50ms） | BBRv3 | 3/3 | 8.59 | 8.27 |
| 深队列（400ms） | BBR | 3/3 | 8.49 | 8.11 |
| 深队列（400ms） | BBRv3 | 3/3 | 8.60 | 8.22 |
| 100ms 队列、每方向随机丢包 0.1% | BBR | 3/3 | 8.14 | 7.72 |
| 100ms 队列、每方向随机丢包 0.1% | BBRv3 | 3/3 | 8.58 | 8.17 |

18/18 次均完整收到双向指定字节数，包含 BBR 回退对照，未以不完整传输计算吞吐。
203 条 BBRv3 诊断快照中实际出现七个状态：Startup、Drain、四个 ProbeBW 子状态
和 ProbeRTT；`SamplingErrors` 最大为 0，没有采样模型重置错误。
个别连接 `UnknownACKs` 为 2，对应安装前 / 已移除快照的正常排除，不伪造旧历史。

原始结果、应用日志、空载 / 传输期 ping、qdisc 快照位于
`build/bbr3-controller/linux/controlled/`，汇总及模型统计位于
`build/bbr3-controller/controlled-summary.json`、`controlled-models.json`。

## 公网：6/6 次双向传输

每种控制器三轮，固定种子 6306 打乱顺序；新连接先下载、后上传，每方向 1 MiB，
每次上限 180 秒。两方向共用连接，因此上传不是独立冷启动样本。

| 算法 | 完成 | 下载中位（范围）Mbit/s | 上传中位（范围）Mbit/s |
| --- | --- | --- | --- |
| BBR | 3/3 | 6.24（5.40–6.79） | 5.45（5.19–5.58） |
| BBRv3 | 3/3 | 6.98（6.12–7.22） | 5.52（5.45–5.68） |

6/6 次完整双向传输，本轮没有初始化失败、超时或不完整传输。
公网诊断快照仅观察到 Startup，`SamplingErrors` 为 0；这是约 4 秒的短连接，
**不能据此声称已在公网覆盖稳态 ProbeBW / ProbeRTT 或长期稳定性**。

另对两种控制器分别验证真实转发：

- TCP：512 KiB 确定性随机 echo，双向 SHA256 均匹配：
  `56f856d7625abb7cdd3ef09721624581323c65461924541c6f9b078766977ac8`。
- UDP：每种 12 个带序号 / 随机数据的独立报文，分别 **12/12 匹配**，合计 24/24；
  没有迟到报文被误算为下一次成功，没有为通过而重发失败样本。

原始结果、客户端 / 服务端日志位于 `build/bbr3-controller/network/`，
汇总和模型统计位于 `public-summary.json`、`public-models.json`。

## 验收边界与清理

- 这是功能、有限传输及回退验证，不是算法排名；不能把这些小幅吞吐差异当作
  BBRv3 在所有线路领先的证据，更不要求 CUBIC / HyStart++ 追平 BBR。
- 没有并发竞争流、公平性、L4S、动态带宽、长时稳态或所有规范附录场景的网络
  实验。CE / spurious undo / 路径迁移等另由确定性单元、rich hook 和 race 测试覆盖。
- 受控环境存在随机内核 loss、TBF burst、同机共享 CPU、用户态调度及方向共用
  连接的限制。传输期 ICMP ping 不是 QUIC 内部 RTT，也不等于纯满载排队时延。
- 本轮所有公网 server / client / echo 已停止，受控命名空间已由脚本清理。
  VPS、证书、私有配置及旧 / 新验证证据保留，不持续运行测速负载。

前一轮 CUBIC / HyStart++ 的独立历史结果仍见
[首轮网络报告](network-test-2026-10-29.md)，没有覆盖或改写旧失败记录。
