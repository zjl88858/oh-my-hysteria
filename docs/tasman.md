# Tasman：有预算的短块纠删载波

v1.2.0 新增。两端只配置同一随机混淆密码；
同一监听端点共享 profile，用户身份仍由内层 `auth` 处理。共同说明见
[混淆选型](obfuscation.md)，精确冻结与原始结果见[实现记录](designs/02-TASMAN-IMPLEMENTATION.md)。

```yaml
obfs:
  type: tasman
  tasman:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

密码接受32..1024个原始 UTF-8 字节，不自动 Base64 解码。分享 URI 使用
`obfs=tasman&obfs-password=...`。保持正常 TLS、固定 UDP 端口及两端时钟同步；
不支持端口跳跃/活动会话 rebinding，不自动回退。默认 BBR、已有 profiles、
Brutal 协商和其它混淆行为不变。

## 传输与成本

- 1..1200B 内层数据报，UDP payload≤1232B。握手与数据走同一路径。
- PSK 编译双向窄416..500B/宽616..700B符号族、2..4ms收集期限、2..6ms载波窗口、
  1..2修复目标及0..2有限尾窗口。会话独立随机种子只在规则内选轨迹。
- 每代固定宽度，最多8源/2修复；实际发送包括 used、record10 与规范零尾的完整符号。
  系统码源片可直接交付；GF(256)/0x11d两行 Cauchy 修复最多两片擦除，不提供 ARQ。
  不保证每代都有足够预算发出目标修复数。
- 52B公共认证信封；SOURCE/REPAIR再加8B描述，成本60+s+padding。
  SHORT是一份完整record10，成本L+62，故仅适用于L≤1170。1200B必须走符号路径。
- 数据先保留独立可执行的紧凑计划，再承诺 repair/padding/cover。账本采用
  `Credit=2D+tiny_exception+Htiny-W-Rdata-Rrepair`；Htiny是锁定到待发SHORT的条件预留，
  只补相应真实数据成本，不能转成repair/cover信用；发送后仅实际必要超额计入tiny_exception，
  取消时撤销未使用Htiny。`ReservedTiny`单列该锁定额。取消不删除历史接受量，已发/部分写字节
  不回退。细小数据只在必要SHORT成本确实超额时计入 tiny 例外，不能给 cover/FEC融资。
- `L<62` 的孤立SHORT可能超过2×。具体倍率取决于装箱和可用信用。

## 队列、错误和核心接入

`WriteTo` 的生产路径必须有 vendored QUIC 的显式 wire reservation；直接无许可调用
返回错误。核心先把保守上界 `2*inner_packet_length+62` 计入所选拥塞算法的 flight、
ACK/loss记账和 pacing，再给实际数据报有限外层许可。QUIC合并包可能多预留，不少预留；
这不是把inner ACK解释成逐外包ACK，也不是精确外层带宽估计。tiny例外和整形deadline
都不能产生发送许可。相关接口穿过cleanup，OOB/GSO/ECN旁路禁用。
此模式下QUIC内置BytesSent/Lost随保守预留计费；实际UDP字节请看TasmanStats，而非
把该QUIC计数当作抓包值。其它模式仍沿用原统计语义。

收集和载波间隔共用原入队的绝对整形期限；期限到后不再主动等待，但仍须服从许可。
已获得的许可可用于本次短窗口中的源/修复；不会靠空闲timer无限发流量。
每peer64条/64KiB、全局1024条/2MiB，排队100ms后显式失败；写deadline/Close解除等待。
异步接受前复制buffer；`TasmanErrors()`必须持续消费，CLI已接入。错误通知256项，
溢出或终止socket错误进入sticky failure。
包级写失败撤销该peer当前计划和剩余队列，逐条报告未完成消息；由QUIC恢复，不在外层重试。
Close撤销未发修复/cover并释放预留，不把源数据已发送等同于目标冗余全部发送。

`TasmanStats()`区分接受/实际发送、四种包、零尾、padding、保留额、tiny、部分写、
恢复、丢弃和队列峰值；可选Trace记录原QUIC登记、入队及实际开始/完成写。
OuterSentBytes保守计入底层报告已经写出的n字节（即使同时返回错误）；PartialOuterBytes
是其中的部分写子集，不能再次相加。完整成功包才增加OuterPackets。
原QUIC发送时间定义为保守预留时刻，跨载波的实际末片时间另记。

为避免把FEC隐藏的损伤悄悄写成无损，接收恢复数单列，并在有反向预算的SOURCE填充中
携带认证的累积恢复报告（`TFB\x01`、目标session16、count8，共28B，全部计费）。
报告不建路由、不独立触发回复；核心收到新报告后增加一个RTT大小、最多100ms的保守
pacing guard。没有预算/反向源包时报告可能延迟或缺失；不保证完整outer loss反馈。
ECN关闭，未恢复的丢失继续由QUIC观察；当前不提供逐外包ACK/loss归因。

## 验证与边界

实现包含独立Python的profile/信封/GF向量、k=2..8额定单/双擦除组合、修复先到、
跨代乱序与消息去重、零尾/长度检查、资源限额和异步队列测试。实际执行结果及失败
随[实现记录](designs/02-TASMAN-IMPLEMENTATION.md)归档，未执行项不标通过。
接收FEC状态有3s独立TTL及每peer/全局硬上限；这些上限不承诺1Gbps下不触发容量丢弃。

未做真实其它UDP的未见密码低误报率分类；持续高PPS与单核吞吐未定标。

```sh
go test ./extras/obfs ./app/cmd ./third_party/quic-go -run Tasman -count=1
python -m unittest discover -s tests -p test_tasman_reference.py
go test ./extras/obfs -run '^$' -bench BenchmarkTasman -benchmem
```
