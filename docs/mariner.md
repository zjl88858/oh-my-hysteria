# Mariner：非线性关系织网

Mariner 在认证密文外增加见证字节，再按密码编译的图交织。不同密码改变关系阶数、
节点复用、非线性双射表和布局；接收端取回源字节、验证关系并完成AEAD认证。
v1.2.0 新增，配置仅需类型与随机密码。

```yaml
obfs:
  type: mariner
  mariner:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

两端使用同一随机密码，接受32..1024个原始UTF-8字节。共享监听器使用同一混淆密码，
用户身份仍由内层 `auth` 管理。URI使用 `obfs=mariner&obfs-password=...`。
TLS、时钟和固定端口要求见[混淆说明](obfuscation.md)。

## 传输与成本

- 内层1..1200B，外层UDP payload≤1232B。握手和数据统一处理，最多两片，切点在
  中点附近±32B内选择；完整报文独立乱序交付。
- 每方向密码编译16张非线性256元双射表、3/4/5输入关系权重、公共节点池及16..20密度。
  相同密码、方向和外包长度固定同图；会话前缀与切片采样独立随机。
- 每片先确定最终长度，再执行一次XChaCha20-Poly1305封装。24B受保护nonce、12B头、
  record10、16B tag，另有0..3B规范零填充；AAD绑定最终外包长度。
- `L=ceil((64+r)*(62+fragment)/64)+delta`，delta=0..3，受1232B上限约束。
  最大单片容量随r从923B降到876B，超过容量转为平衡两片。
- 关系编码增加约25%..31.25%结构冗余，另计每片封装；极小包倍率较高。
  无前导、cover、额外等待、FEC或外层ARQ。

## API与资源

`WriteTo` 同步返回：全部片成功才返回内层完整长度，写失败返回错误，由QUIC恢复。
每片消耗独立计数，失败后不回收；deadline和Close转交底层socket。
不暴露OOB/GSO/ECN快路径。`QUICPacketSizeLimit()=1200` 经cleanup传递。

每方向最多缓存32张热点图，图存储≤512KiB；未认证候选在固定scratch构造，认证和
规范校验通过后提升，不能通过非法报文驱逐热点。图编译全局4096/s、burst256，
未知端点另限128/s、burst32；会话/重组使用独立硬限额和3s重组TTL。

`MarinerStats()`报告实际字节、包数、分片、关系/填充开销、缓存、编译限流、接收丢弃、
写错误及QUIC计时观察。`PartialOuterBytes`包含在`OuterSentBytes`内，不重复相加。
QUIC原记账保持不变，实际外层字节以该统计或抓包为准。

## 验证

编译器、结构和认证有独立Python/Go向量；全长度/密度、篡改、并发nonce、两片重组和
TLS集成可本地复现。环境、实测倍率、性能、盲分类与消融结果见
[实现记录](designs/03-MARINER-IMPLEMENTATION.md)。数学关系不同不等于抗分类收益，
当前不以Mariner替代有明确协议伪装需求的方案。

```sh
go test ./extras/obfs ./app/cmd -run Mariner -count=1
python -m unittest discover -s tests -p test_mariner_reference.py
go test ./extras/obfs -run '^$' -bench BenchmarkMariner -benchmem
```
