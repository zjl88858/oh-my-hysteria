# 实验性 BBRv3：实现与验证边界

更新时间：2026-10-29。算法目标固定为
[draft-ietf-ccwg-bbr-06](https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html)。

**已接入独立实验性控制器，支持显式 `congestion.type: bbr3`。**
不是旧 BBR 调参；未宣称规范认证、IETF 附录全部测试通过、性能领先或生产稳定。
现有 `bbr`、CUBIC、Reno、Brutal、带宽协商和默认值均保留。

## 配置和回退

```yaml
congestion:
  type: bbr3
```

客户端和服务端各自控制自己的发送方向，不通过线上协议协商算法。不要填写
客户端 `bandwidth.up/down`，否则仍可能优先安装 Brutal；服务端需要时设置
`ignoreClientBandwidth: true`。`bbrProfile` 支持 `standard`（空值的默认）、
`aggressive` / `conservative`，参数与旧 BBR 独立；仍拒绝 HyStart++。
默认参数保持本页的既有基线，另两档的明确差异见 [profiles](bbrv3-profiles.md)。
回退只需改回 `type: bbr`。

`OH_MY_HYSTERIA_BBR3_DEBUG=1` 启用限频 stderr 快照，包含状态、round、BW、
pacing、cwnd、flight、min RTT、采样错误、未知 ACK、CE、undo、路径重置计数和
当前 `profile`，
不包含认证、地址或数据内容。`Snapshot()` 可以由其他 goroutine 安全读取。

## 源码与依赖

- `core/internal/congestion/bbr3/sampler.go`：独立 delivery-rate 采样器。
- `sender.go` / `pacer.go`：网络模型、状态机、速率和窗口控制。
- `sampler*_test.go` / `sender*_test.go`：可重放事件、边界、并发和三项有界 fuzz。
- `third_party/quic-go/`：完整固定依赖及 opt-in AdvancedControl 扩展。
- `app/cmd/congestion_gecko_test.go`：真实 Gecko、校验 TLS、BBRv3 与 BBR 回退，
  双向 1 MiB 随机 TCP SHA256、32 次 UDP 完整性回环。

新控制器、pacer、sampler 和新增测试为独立编写的 MIT-0 代码，没有导入或翻译
Linux、QUICHE、TQUIC 或 bompus 控制器，也没有复用旧 BBR sampler。
本地 quic-go 基线为 `v0.63.1-0.20261004180939-a10df75c260c`，原 MIT 许可及
文件级声明保留；改动出处见 `third_party/quic-go/OHMY-FORK.md`。
不修改 Go 模块缓存，不用 unsafe 读取传输内部状态。

`go.work` 及三个应用模块的 replace 均指向本地副本，**源码打包不能遗漏
`third_party/quic-go/`**。版本输出标注 `+omhy-advanced1`。

## 采样与生命周期契约

1. 数据量为字节，速率为字节 / 秒，不与旧 BBR 的 bits/s 混用。
2. 发送快照使用传输层发送后的权威 Application flight，已包含本包，不重复加包。
   只处理 Application 包号空间（0-RTT / 1-RTT 共用递增编号），Initial / Handshake
   绝不混入同一个采样 map。
3. 只对 ACK-eliciting 报文记录交付历史；纯 ACK 不占容量。每个 ACK frame 一次
   批次，选最新发送报文，同时间戳以包号打破平局，不依赖输入顺序。
4. delivery-rate 使用发送 / ACK 两个区间的较大值，限制 ACK 压缩；缺少时钟、
   区间非正或短于 min RTT 时不产生可用速率。未知安装前 / 已移除快照先排除并
   累计 `UnknownACKs`，不伪造旧历史，剩余有快照的报文正常采样。
5. 空 flight 重置采样时钟，排除空闲；它自身不等于 app-limited。后者检查流控
   阻塞数据、重传、DATAGRAM、crypto、send queue 排队及正在写入，不从 pacing
   等待推断。ProbeRTT 按草案主动将受控制器限制的采样标为 app-limited。
6. RTT 只在 `RTTUpdated` 时使用经 QUIC ACK-delay 校正的新鲜观测，不反复读取
   陈旧 LatestRTT。采样器另保留 raw RTT；单调时间原点允许负数或零。
7. PMTU probe 在发送时显式标记；probe 损失保留 raw loss，但不计拥塞 loss。
   loss-only 不伪造 ACK / 速率；重复 loss 幂等；迟到 ACK 交付只计一次。
8. keys / PTO / Retry / 历史退休显式通知。移除不计 loss / delivery，不把 PTO
   当 TCP RTO，不由最大 ACK 包号推断全部旧包已可丢弃。迁移重置原 Advanced
   Sender 的模型，不静默变成 Reno。
9. 传输层损失历史最多 64 条，rich loss 批次完成后才通知退休，避免大损失批次
   尚未采样就先删快照。保留整个恢复 episode 的损失集合；只有全部被迟到 ACK
   确认才 undo，任何历史退休 / CE 都禁止该 episode undo。
10. 采样历史最多 131072 条；溢出 / 非法事件会计数、报告并重置模型，不静默
    驱逐仍有意义的记录。累计字节溢出报错，速率及窗口算术饱和，不整数回绕。

AdvancedControl 为 opt-in：旧逐包回调在新 Sender 不记账，rich 批次只处理一次。
旧 BBR / Brutal / CUBIC 保留原通知路径及 legacy ACK / loss 记录字段的原填值。
GSO batch 按 Sender 的 send quantum 限制；PMTU 增长更新报文单位及窗口下限。

## 状态机与模型映射

| 部分 | 当前实现 |
| --- | --- |
| Startup | 2.77 pacing gain、三 round 带宽平台；高丢包退出要求完整恢复 round、2% 及六个不连续区间 |
| Drain | 0.5 pacing gain，排空至估计 flight，或草案规定的 round 上限 |
| ProbeBW | DOWN / CRUISE / REFILL / UP 与 ACK phases；pacing gain 0.9 / 1 / 1 / 1.25，UP cwnd gain 2.25 |
| 长期模型 | 两探测周期 max BW；2% loss、0.7 下界、15% headroom、指数探测斜率、precautionary probe |
| 短期模型 | 按 loss-round 更新，与 startup 恢复门槛分离；REFILL / ProbeRTT 退出重置 |
| ProbeRTT | 5 秒调度、10 秒 min-RTT filter；半 BDP、至少四包；200ms 加完整 packet round；处理空闲重启 |
| ACK aggregation | Startup 保留一 round，之后十 round；补偿不超过窗口 |
| CE | 每 packet round 最多一次 0.7 cwnd / 短期带宽退避并使 startup 退出；不静默忽略 CE |
| undo | 恢复保存的 cwnd / 模型；只有由 loss 退出的 Startup / UP 才恢复相应状态 |

明确的传输适配：保留本项目初始 32 包、至少四包的 BBR 窗口下限；使用 QUIC
的新鲜 RTT 和经验证 CE；不实现 Linux TCP 的 RTO / PRR，不宣称 L4S / DCTCP。

## 验证与限制

命令、当前覆盖率、Linux race / fuzz 和实际网络证据见
[BUILD-REPORT.md](../BUILD-REPORT.md)。第一阶段 **99.1% 仅指当时 sampler**，
不是当前完整控制器覆盖率。现有测试覆盖包号空间、after-send、ACK 压缩、丢包、
PMTU、loss-only、迟到 ACK、退休顺序、PTO、keys、Retry、迁移、模型 / 状态、
资源边界、并发 Snapshot、Gecko TCP / UDP 及 BBR 回退。

三项有界 fuzz、单元、Linux race、本地 QUIC 和 Gecko 集成已加入 CI；未运行
远程 GitHub CI。长期稳定性、多流公平性、L4S、全部 22 个规范附录场景及广泛
运营商覆盖不在本次验证结论内。有限 VPS 样本不是生产可用性或性能排名证明。
