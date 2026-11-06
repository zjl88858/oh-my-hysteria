# Servo：跨数据报装箱

Servo 保存内层 UDP 数据报边界，并将不同数据报的片段放入密码派生容量的认证容器。
一个外包可以同时携带上一数据报的尾部和下一数据报的开头；不发送 cover、不主动填充，
没有 FEC、外层 ARQ 或有序字节流。身份与权限仍使用内层 Hysteria2 `auth`。

v1.2.0 新增。共同要求见[混淆说明](obfuscation.md)，精确格式见[实现记录](designs/01-SERVO-IMPLEMENTATION.md)。

## 配置

两端使用相同类型、同一个监听端点的共享随机混淆密码：

```yaml
obfs:
  type: servo
  servo:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

密码按原始 UTF-8 字节处理，接受 32..1024 字节，不自动 Base64 解码。
容量、扰动和聚合等待由密码编译，无需额外参数。分享链接使用
`obfs=servo&obfs-password=...`，混淆密码与登录 `auth` 独立。

保持正常 TLS 验证、两端时钟同步（新会话 born ±30s），使用固定 UDP 服务端端口；
不支持端口跳跃或同一活动会话 NAT rebinding，不自动回退其它混淆。

## 传输行为

- 内层 1..1200B，外层 UDP payload ≤1232B。1200B 的握手和数据报均拆为两片。
- 每方向、每发送会话独立采样 640..1100B 的纯数据容量；每容器最多 8 条记录。
  聚合等待为密码派生的 200..500μs 目标上限，不是操作系统硬实时保证。
- 拆片前预留第二容器容量与记录槽；不足则提前结束旧容器，不把一条消息拆进第三包。
- 单包固定认证封装 52B，每条记录另需 10B 描述符。单条 64B 孤立消息为 126B；
  稠密跨包装箱可以摊薄固定成本。
- 接收完整数据报可独立乱序交付；缺片只阻塞该消息。包重放与完成消息去重分开。
- 单端点最多 64 条 / 64KiB 待发数据，全局 1024 条 / 2MiB。排队超过 100ms 的消息
  显式失败；写 deadline 与 Close 可解除阻塞的内核写。

封装倍率为实际外层 UDP payload / 接受的内层数据字节。QUIC 重传再次提交的数据报
仍是新的输入；失败/取消的已接受消息另行计数，不从分母悄悄删除。IP 层另加包头开销。

## 异步错误与诊断

`WriteTo` 返回完整长度表示已复制到有限队列，不表示已经上网。拒绝返回 `(0,error)`。
已接受消息的写失败、过期、Close 取消可从 `ServoErrors()` 取得；CLI 已接入消费与日志。
包级错误丢弃受影响消息，由 QUIC 恢复；终止性 socket 错误或错误通知队列溢出使连接
进入 sticky failure，停止接受新数据并唤醒读写者。

Go 集成者需持续消费 `ServoErrors()`。`ServoStats()` 报告接受/发送字节、包数、记录数、
队列峰值、失败、接收资源丢弃与排队时间；可选 `ServoOptions.Trace` 提供有限诊断事件，
包含入队、原 QUIC send time、实际开始/完成写和片段边界，不记录数据载荷。

初版禁止 OOB/GSO/ECN 旁路。vendored quic-go 的 opt-in hook 传递真实的原发送登记时间，
并观测 RTT、PTO 时长、probe 调用及 loss 快照；**不修改原拥塞算法的记账时间，也没有
把内层字节自动改算为外层 wire bytes**。probe 调用数不是独立 PTO 事件总数，loss 最大
快照也不是多个 QUIC 连接的丢包总和。

## 验证与限制

当前包括独立 Go/Python 向量、字段/认证/重组 fuzz、两容器与 8-record 边界、有限队列、
缓冲区复用、并发分配、会话轮换、deadline/Close、异步错误和 IPv4/IPv6 正常 TLS 的
TCP/代理 UDP 集成。完整环境、实际结果及失败保留在实现记录和本地
`build/servo-complete-20261106/`，不是 v1.2.0 发布附件。

Linux race、隔离 MTU1280、20ms 延迟及 5% 丢包下 TCP 验证通过；实际捕获的 762 个
目标外包均通过认证/语法检查。新 VPS 的 Gecko 对照和 Servo 各一次冷连接均完成
双向各 4096B 的正常 TLS 传输。这里只是小样本连通性结果，不是稳定速率测量。

未做真实其它 UDP 的未见密码低误报率分类；长期吞吐未定标。实现及测试为原创 MIT-0。

## 本地复现

```sh
go test ./extras/obfs ./app/cmd -run Servo -count=1
python -m unittest discover -s tests -p test_servo_reference.py
go test ./third_party/quic-go -run 'SendQueue|AsyncPacketConn' -count=1
go test ./extras/obfs -run '^$' -bench BenchmarkServoCodec -benchmem
```

`TestServoTrafficExperiment` 需显式设置全新 `OMHY_SERVO_EXPERIMENT` 输出目录，仅用
本机回环；结果分别报告 Servo、无等待消融与 Presto 的 UDP/IP/包数倍率和 echo 延迟。
这个直接 UDP 实验不等于应用 goodput、CPU 隔离吞吐排名或盲分类测试。
