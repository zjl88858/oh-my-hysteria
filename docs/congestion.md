# CUBIC 与 HyStart++

现有 `bbr` 的代际确认及后续 BBRv3 接入评估见
[BBRv3 研究](bbrv3-research.md)；当前实验性 `type: bbr3` 的接入与边界见
[BBRv3 实施说明](bbrv3-implementation.md)。本页主要描述 CUBIC / HyStart++。
后续实验性 `type: copa` 的来源、参数与接入边界见 [COPA](copa.md)。
`type: geodesic` 的 KCC/UCP 研究与实验边界见 [Geodesic](geodesic.md)。

## 配置

两端均支持以下配置（只控制本端的 QUIC 发送方向）：

```yaml
congestion:
  type: cubic          # bbr（原有默认）、reno、cubic
  slowStart: hystart++ # legacy（默认）或 hystart++
```

需要回退时使用 `slowStart: legacy`。`reno + legacy` 不安装替代控制器，仍由
quic-go 原有 NewReno + HybridSlowStart 处理。`cubic + legacy` 使用本地适配的
CUBIC 与旧版 HybridSlowStart。这里的 legacy 不是“禁用慢启动”。

`bbrProfile` 只影响 BBR。为 BBR 配置 `hystart++` 会报 `congestion.slowStart`
错误，避免误以为该设置已经生效。Brutal 仍由原有带宽协商选择，不新增
`type: brutal`，也不覆盖它的启动机制。

### 带宽优先级与互通

算法选择位于原有认证成功后的控制器安装位置。认证前仍使用 quic-go 内置
NewReno，因此 HyStart++ 在本功能选中的控制器安装后开始工作，而非接管 TLS
握手。没有更改 Hysteria2 报文、认证头或分享 URI，旧客户端 / 服务端仍可互通。

原有选择逻辑保持不变：协商出发送带宽时使用 Brutal，否则使用 `congestion`
选择的控制器。服务端 `ignoreClientBandwidth: true` 时，服务端忽略客户端
带宽请求并要求客户端进行带宽探测；双方仍各自使用本地选择的控制器。
要验证双方均使用 CUBIC，可在两端设置上面的配置，省略客户端 `bandwidth`
设置。服务端本地 `bandwidth.up` 并非独立的算法强制选择开关。

当前 quic-go 的 `MigratedPath` 会将控制器重置为内置 Reno，公开的自定义
控制器 API 没有路径迁移通知。本次不改动该上游行为：主动路径迁移后不保证
继续使用所选自定义控制器；重新建立 Hysteria 连接会重新应用配置。这也是
现有自定义 BBR / Brutal 安装方式的限制，不等同于普通的同一路径数据传输。

## 研究结论与实现选择

当前依赖为 `github.com/apernet/quic-go`
`v0.63.1-0.20261004180939-a10df75c260c`。

- quic-go 的 `internal/congestion/cubic_sender.go` 确有 CUBIC / Reno 分支，
  但默认初始化和迁移路径固定选择 Reno。
- 该实现位于 Go 的 `internal` 包，不能从本项目直接导入；公开 API 仅提供
  `SetCongestionControl` 及控制器接口，没有切换内置 CUBIC 的选项。
- 休眠的 CUBIC 曲线还保留了“重新启用时应使用实际报文大小”的 TODO。
- 上游 `HybridSlowStart` 是旧版 HyStart，缺少 HyStart++ 的 CSS 阶段。

因此将 CUBIC 的窗口增长、TCP-friendly 区域、快速收敛、旧版 HyStart 和
pacing 适配到 `core/internal/congestion/cubic/`，通过公开接口安装。不修改
Go 模块缓存，也不需要维护整个 quic-go 的私有副本。

本地 CUBIC 曲线使用实际 datagram size，支持 PMTU 增长；保留 beta=0.7、
C=0.4、快速收敛及窗口上限，并在长时间空闲后避免整数溢出。Reno 的传统
回退路径完全不变。继承的 quic-go 实现按其 MIT 许可保留声明；原创 HyStart++
及测试使用 MIT-0。

## HyStart++（RFC 9406）

依据：[RFC 9406](https://www.rfc-editor.org/rfc/rfc9406.html)。该 RFC 明确指出
算法也适用于 QUIC，而不局限于 TCP。公开回调可获取 RTT、ACK 批次、发送包号
和拥塞事件，足以实现该算法，不需要新增 QUIC 协议字段。

本实现包括：

1. 通过发送包号划分 RTT round，使用当前 round 与上一 round 的最小 RTT。
2. 每个 round 至少 8 个 RTT 观测后，比较阈值
   `clamp(lastRoundMinRTT / 8, 4ms, 16ms)`。
3. 达到阈值后进入 Conservative Slow Start（CSS），以普通慢启动的 1/4
   ACK 字节增量增长窗口。发送端始终 pacing，因此使用 RFC 建议的 `L=∞`。
4. CSS 内取得至少 8 个 RTT 观测，若最小 RTT 低于进入 CSS 时的基线，则恢复
   普通慢启动并继续检测，避免延迟抖动造成过早退出。
5. CSS 最多持续 5 个 round；中途进入 CSS 的不完整 round 计入这 5 个。
   持续膨胀时将 `ssthresh` 设为当前窗口，进入对应的 CUBIC / Reno 拥塞避免。
6. 丢包或 ECN 会立即退出初始慢启动 / CSS，执行原控制器的拥塞回退。重传
   超时后仅使用普通慢启动，不重新开启 HyStart++（RFC 的初始启动建议）。

### QUIC 回调细节

一个 ACK frame 可确认多个 packet，但最多提供一个新的 RTT 样本。实现只在
`MaybeExitSlowStart` 收到 RTT 观测，在 `OnCongestionEventEx` 结束 ACK 批次时
处理检测与 round 边界，**不会把多个 OnPacketAcked 当成多个 RTT 样本**。
不增加最大已确认包号的重排 ACK 不复用旧 RTT；没有可用 RTT 的批次不计样本。
填补旧空洞的延迟 ACK 也不会利用历史最大 ACK 包号虚假推进 CSS round。

ACK 很稀疏、RTT 观测不足时，不会凭空构造样本；可能继续普通慢启动直到有
足够观测或发生拥塞。CSS 检测基于当前公开 RTTStats 的 RTT 定义，沿用 quic-go
对 ACK delay 的处理；本功能不更改 RTT 采样器或 peer 的 ACK 频率。

## 验证范围

单元测试覆盖 CUBIC 增长 / 退避 / PMTU、legacy 回退、逐 ACK 批次采样、8 个
样本门槛、CSS 的 1/4 增长、5 round 退出、抖动恢复、ECN / 丢包 / 超时。
集成测试使用真实 QUIC 客户端 / 服务端进行 TCP 大块回显及 UDP 往返，并覆盖
`ignoreClientBandwidth` 分支。

确定性 RTT 单元测试验证状态转换；本机回环测试不代表真实拥塞网络性能。
目前没有宣称提升吞吐、减少丢包或优于 BBR。真实链路评估还需在有带宽、RTT、
队列和丢包约束的环境中对比，建议部署前保留 `legacy` 回退配置。

专用 Linux VPS 的首轮受控实验和公网失败样本见
[2026-10-29 网络验证](network-test-2026-10-29.md)。45 次受控双向传输通过
不等于公网长传输稳定，也不足以证明 HyStart++ 的性能优势。
