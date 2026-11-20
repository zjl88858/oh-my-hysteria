# COPA 接入验证（2026-10-29）

实现、TQUIC 固定版本及论文差异见 [COPA](copa.md)。这是独立实验性选择，
默认仍为旧 BBR。δ=0.04，不是论文默认 0.5；没有完整 TCP-competitive 模式。

## 功能与适配

- Windows `core` / `extras` / `app/cmd`，Linux 三应用模块及固定本地 QUIC
  根包 / internal / HTTP3 默认测试通过。
- Linux 全拥塞包 race、COPA 与 BBRv3 Gecko race、全模块 vet 通过。
- COPA 包 Windows / Linux 覆盖率 **99.6%**，Python **21/21**。
- 最终 Linux COPA event fuzz **30 秒，376609 次执行**通过，既有缓存种子参与。
- Gecko + 受信任 TLS：COPA 1 MiB TCP echo SHA256、32 次 UDP 回环通过，旧
  BBR / BBRv3 的 Gecko 回退测试保留；这里的回环不消耗 LTE 流量。

初版受控 30/30 虽完成，`StateErrors` 最大值却为 10：socket receive timestamp
与 send 回调可交错，不能因时间早于已处理 send 就丢掉 ACK 记账。最终实现以
单调模型时钟记账、单独过滤过时 RTT，新增回归测试；修正不是按测速结果重设 δ。
初版源码、二进制、Linux / fuzz / 受控日志均保留在 `build/copa/initial/`。

## 最终隔离对照

两端 Gecko、正常证书链 / SNI 校验，无客户端 bandwidth，服务端
`ignoreClientBandwidth: true`。使用旧 BBR standard、BBRv3 standard、COPA。
每场景每算法两个连接，先下载 4 MiB，再在同一连接上传 4 MiB；上传不是独立
冷启动样本。每轮随机顺序（seed 9406）。GSO/GRO 在隔离链路关闭，TBF burst
32 KiB，netem 在每方向分别配置损失。最终测量不与初版测量并行运行。

**30/30 双向完成**，240 MiB 应用负载全部留在 VPS 三个网络命名空间内部，
没有默认公网路由 / NAT，也不对 VPS 公网接口整形，不经过用户 LTE 出口。

表内为两个结果的中位数；“下载 / 上传”为应用 Mbit/s，“ping”为负载期间
每次成功 ICMP 回包的 RTT 平均值，再对两个连接取中位数（ms）。ping 包含
握手、Startup、方向切换及空闲间隙，且打印精度有限，**不是纯稳态排队延迟**。

| 场景（RTT / 速率 / 队列 / 每方向 loss） | COPA 下载 / 上传；ping | BBRv3 下载 / 上传；ping | 旧 BBR 下载 / 上传；ping |
| --- | --- | --- | --- |
| 200ms / 10M / 50ms / 0 | 8.630 / 8.260；222.1 | 8.585 / 8.285；228.9 | 8.240 / 7.765；221.2 |
| 200ms / 10M / 400ms / 0 | 8.630 / 8.265；227.4 | 8.600 / 8.210；354.5 | 8.495 / 8.110；291.9 |
| 200ms / 10M / 100ms / 0.1% | 8.590 / 7.780；223.0 | 8.590 / 8.145；251.8 | 8.110 / 7.780；238.1 |
| 80ms / 20M / 40ms / 1% | 17.450 / 16.090；88.9 | 16.430 / 16.340；98.8 | 17.210 / 16.420；98.7 |
| 350ms / 5M / 150ms / 1% | 4.190 / 4.065；418.1 | 4.225 / 4.030；398.5 | 4.230 / 4.075；423.8 |

COPA 在这次深队列实验中负载 RTT 更低，但并非所有场景 / 方向的吞吐或 RTT
都优于 BBRv3 / BBR；例如 350ms 场景的 ping 高于 BBRv3。每组只有两次，
不作统计显著性、全局最优或生产公平性结论，也不据此继续调参。

### 模型证据

- COPA 207 个限频快照，实际观察到 Startup / Steady；`StateErrors` 最大 **0**。
- 窗口增加 / 下降均被观察到，δ 观测范围 0.04..0.5；最大活跃历史 396。
- `UnknownACKs` 最大 3，不伪装成零：控制器安装前发送的包、退休后晚 ACK 等
  可以未知，未知包不增长窗口或注入 RTT，不能据此直接断言记账错误。
- BBRv3 的七状态均被观察到，`SamplingErrors` 最大 0。旧 BBR 未新增诊断或
  修改原算法，也没有把已知历史 sampler 接口问题当作本次吞吐差异的原因。

原始结果位于 `build/copa/linux/controlled/`，统计在 `controlled-summary.json`
和 `controlled-models.json`；共享 VPS CPU / 随机 loss / TBF burst 等限制仍适用。
不涵盖长期稳定性、多流公平性、与真实 CUBIC 竞争或高包率资源极限。

## LTE 出口小流量冒烟

公网客户端严格为 `oh-my-hysteria-windows-amd64.exe`；连 VPS IPv4，以证书域名
做 SNI，正常验证 TLS。两端 Gecko，**没有裸 QUIC 回退或失败重试**。

两个新连接、每方向 256 KiB，**2/2 双向完成**；COPA 12 个限频快照都处于
Startup，`StateErrors` 最大 0，`UnknownACKs` 最大 2。此处没有验证稳态控制，
也没有同期 BBR 对照，不能拿早先不同时间的 LTE 测试来认定 COPA 更快。

| 连接 | 下载 Mbit/s | 上传 Mbit/s |
| --- | --- | --- |
| 1 | 3.46 | 2.39 |
| 2 | 5.48 | 2.39 |

本轮 COPA LTE 应用负载 **1,048,576 字节（1 MiB）**；VPS eth0 观测到
**1,287,758 IPv4 IP 字节（约 1.23 MiB）**，1376 包，抓包丢弃为 0，低于
预设 3 MiB 观测预算。不保存包内容。该量不等于运营商计费，不含漫游隧道 /
链路层开销，也看不到到达 VPS 前已丢失的上行包。SSH、上传及日志回收走普通
宽带，不计入 LTE 实验量；没有因为 LTE 预算缩减 VPS 内部验证。

证据在 `build/copa/public/`、`public-summary.json`、`public-models.json`。
最终 UDP443 无监听、无命名空间，服务端、Windows 测试客户端、抓包进程均停止；
清理证明为 `build/copa/cleanup.json`。VPS 保留至正式发布。
