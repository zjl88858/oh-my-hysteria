# 实验性 COPA：研究与接入

## 使用

```yaml
congestion:
  type: copa
```

客户端与服务端分别设置，各自控制发送方向；算法类型不经协议协商。不填写客户端
`bandwidth.up/down`，服务端需要时用 `ignoreClientBandwidth: true`，否则原有 Brutal
带宽协商仍优先。默认算法仍为旧 `bbr`，回退改为 `type: bbr` 即可。

COPA 使用自己的 Startup，`slowStart: hystart++` 会报错；默认 `legacy` 在这里
不是旧 HyStart，而是沿用配置兼容值。`bbrProfile` 不参与 COPA，没有新增三档
COPA profile 或自动选型。当前固定参数是实验基线，不是性能承诺。

## 依据与来源

- Venkat Arun / Hari Balakrishnan，NSDI 2018，
  [Copa: Practical Delay-Based Congestion Control for the Internet](https://web.mit.edu/copa/)，
  [作者修订版论文](https://people.csail.mit.edu/venkatar/copa.pdf)，§2.1–2.2。
- [Tencent/TQUIC Rust COPA](https://github.com/Tencent/tquic/blob/d648bbe8cdd34d559cb542f1c83284432de67c0b/src/congestion_control/copa.rs)，
  固定到 `d648bbe8cdd34d559cb542f1c83284432de67c0b`，而非跟随 develop 漂移。

Rust 代码作为适配参考，保留 Apache-2.0 版权和完整许可；Go 传输层适配、滤波器、
pacer 及原创测试为 MIT-0。分发二进制附带 `LICENSE-tquic.txt`；没有引入 Rust
运行时或改动旧 BBR、BBRv3、CUBIC，也没有修改 Go 模块缓存。

### 核心机制

`dq = RTTstanding - RTTmin`，目标字节率为 `MSS / (δ × dq)`，当前字节率为
`cwnd / RTTstanding`。向目标方向按每个 ACK 的已确认字节调整窗口：

```text
Δcwnd = velocity × ACKedBytes × MSS / (δ × cwnd)
pacing = 2 × cwnd / RTTstanding
```

零排队时允许增加，而不是除零；Startup 按确认字节增长，目标率低于当前率时
永久退出 Startup。延迟方向持续三个 packet-round 后 velocity 可倍增；方向变化
立即重置。velocity、每轮增长、窗口、历史均有上限，窗口每轮至多翻倍。
16 位小数字节余额避免大窗口时整数取整导致停止调整。

## 与论文 / TQUIC 的区别（不能混称完整论文实现）

| 项目 | 本实现 |
| --- | --- |
| δ 默认 | **0.04**，沿用 TQUIC；论文默认 **0.5**，0.04 更重吞吐、更容忍队列 |
| 初始窗口 | 32 MSS，沿用本项目新控制器基线；TQUIC 默认配置为 80 MSS |
| 最小 / 最大窗口 | 4 / 20000 MSS |
| 长期 min RTT | 10 秒、仅新鲜 RTT 样本，精确过期 |
| standing RTT | `max(1µs, min(10s, srtt/2))`，依论文；TQUIC true 分支实际用 srtt |
| loss 策略 | packet-round 观测 loss/(loss+ACK) ≥10% 时 δ 倍增，上限 0.5；无高 loss 轮恢复 0.04 |
| delta 更新频率 | 每 round 一次；不照搬 TQUIC 每 ACK 重复倍增的 ACK 频率依赖 |
| ECN | Classic CE 每 flight episode 最多一次窗口 ×0.7，退出 Startup，本地安全扩展 |
| pacing/GSO | 2× 窗口/standing RTT，quantum 为约 1ms 数据，限制 MSS..64KiB |

TQUIC 定义了延迟震荡检测常量，但此文件实际没有实现论文的“四 RTT max RTT /
五 RTT 近空队列”竞争检测，也没有完整 `1/δ` AIMD。本实现**同样没有宣称实现**
该 TCP-competitive 模式；高 loss guard 只是保守扩展，不是检测到 CUBIC。
因此可能在 buffer-filling 流面前让出过多带宽，也不应引用论文的公平性结果
为本实现背书。没有把网络测试结果用于临时修改 δ。

## QUIC 适配与边界

- 使用本地 `congestion.AdvancedControl`：legacy 逐包回调不重复记账；只对
  Application 包号空间建模，after-send flight 不再加一次本包。
- 只确认已跟踪包的实际发送字节。重复 / 未知 ACK 不增长窗口；退休 / keys /
  PTO / Retry 移除不是拥塞丢包。loss-only 不伪造 RTT，也不推进 ACK round。
- PMTU probe 的 ACK/loss 不进入窗口增减和 loss 比例。含已知 PMTU ACK 的混合
  批次也不更新延迟基线，以免无法识别的 probe RTT 污染 min RTT。
- 只用传输层标记 `RTTUpdated` 的新鲜、ACK-delay-adjusted RTT，不能每包复用
  一个 RTT 样本；过滤器有硬容量（各 32768 个候选），环形单调队列摊销 O(1)。
  满容量时移除最旧候选，可能高估 min RTT、低估排队延迟，不能保证仍满足理论
  延迟目标；窗口变长也不恢复已删除候选。容量边界测试不等于高包率实机验证。
- 真正 app-limited 回调覆盖当时已发送包号，相关 ACK 不增长窗口；仍允许根据
  延迟下降。窗口 / pacer 限制不能冒充 app-limited。
- 路径迁移重置全部延迟 / velocity / 包历史；PMTU 增长保留已建立字节窗口，
  仅未增长的初始窗口按新 MSS 调整。socket 读时间与 send 回调可交错，模型时钟
  取单调最大值，仍正确处理 ACK/loss；早于上一 RTT 观测的样本不注入滤波器。
- 活跃包历史最多 131072；异常重复发送 / 历史溢出重置模型并增加 `StateErrors`，
  不静默把未知 ACK 当作成功交付。spurious loss 不恢复窗口：没有直接 loss 窗口
  乘法回退可撤销；已经用于 loss guard 的已完成轮统计不追溯修改。
- QUIC PTO 不按 TCP RTO 处理。当前 rich API 没有独立 persistent-congestion
  标志；不宣称提供 RFC 9002 全部持续拥塞恢复策略。没有 L4S / DCTCP 支持。

`OH_MY_HYSTERIA_COPA_DEBUG=1` 向 stderr 输出限频 `copa snapshot {..}`，含算法、
Startup/Steady、窗口、队列估计、δ、velocity、round、loss guard 和状态错误。
不输出地址、认证或数据内容。`Snapshot()` 支持并发读取。

## 验证原则

优先测试公式 / 窗口方向、过期 RTT、ACK 去重、PMTU、loss-only、CE、app-limited、
迁移、资源边界、pacing，并运行 fuzz / Linux race、真实 Gecko + TLS TCP/UDP。
受控网络显式 `--modes copa bbr3 bbr`，不会改变原有 benchmark 默认负载。
不以追平 BBR 为验收目标；吞吐与队列延迟必须一起报告。

公网仍只能用 Gecko + 正常 TLS 验证和指定 Windows 客户端名。若进行 LTE 冒烟，
使用两个连接、每方向 256KiB（共 1MiB 应用负载）、VPS 观测 3MiB IPv4 长度
预算，首次失败停止、无自动重试或裸 QUIC 回退。SSH/上传/VPS 内部测试不走 LTE。
这些短传输不验证稳态、公平性或长期稳定性，也不等于运营商计费流量。

实际测试和失败历史见 [COPA 网络验证](network-test-copa-2026-10-29.md)，
构建 / 产物对应关系见 [BUILD-REPORT.md](../BUILD-REPORT.md)。

本轮最终受控 **30/30**、LTE 冒烟 **2/2** 双向完成，状态错误最大 0；Linux
race / vet / 30 秒 fuzz 通过，Windows / Linux 包覆盖率 99.6%。LTE 应用负载
1 MiB，VPS 观测 IPv4 IP 长度约 1.23 MiB（不是运营商账单）。公网只观察到
Startup，不能据此确认稳态性能或优于 BBR。
