# NetFrontLite：轻量主路与认证小包副路

NetFrontLite 从 [v1.3.1](release-v1.3.1.md) 起作为独立的多端口混淆模式提供。主路采用 [PrestoLite 的保守策略](prestolite.md#何时减少等待)；两到三个副端口沿用 [NetFront 的路径验证和调度](netfront.md#什么时候走副路)。持续大流比 `netfront` 少停顿，因此不能把两者的时序混淆视为等效。

## 配置

```yaml
# 服务端主端口；客户端这一行改为 server: example.com:443
listen: :443
obfs:
  type: netfrontlite
  netfrontlite:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    extraPorts: [31011, 31012, 31013]
```

- 两端都选 `netfrontlite`。`password` 为 32～1024 字节的随机秘密。`extraPorts` 必填两个或三个**服务端** UDP 副端口，1～65535、互不重复且不能包含主端口。两端顺序一致，放行并映射所有端口；`listen` / `server` 只写主端口。
- 不与端口跳跃、Realms 或 Mimic 组合。正常 TLS、代理认证和拥塞控制独立配置。分享链接使用 `obfs=netfrontlite`、`obfs-password`、`netfrontlite-extra-ports`。标准 `netfront` 的字段不用于填补 Lite 配置。

## 保留了哪些行为

副路角色仍由密码和端口顺序决定，会话独立抽样，不按固定百分比分流。副路通过挑战验证后，能装下的真实小帧可以走副路；大包继续走主路。主包数和字节额度、主路 ≤1232 B、副包 ≤384 B、副路验签上限、同地址续期的短宽限和换地址撤销规则均沿用标准 NetFront。副路不是独立 QUIC 连接，也不会单独放宽验证额度。额外端口、封装和填充仍有成本。

区别在于主路的持续大包采用 80 微秒/KiB 的停顿额度，以及 [仅供已建立端点支用的接收额度](prestolite.md#已建立端点的接收额度)。握手、稀疏负载和小包保留原有调度；实际到达时刻仍会受到与大包共享连接和排队的影响。

主路仍用 NetFront 的 `presto-root` 派生根密钥，再用 Lite 主路标签派生双向认证密钥。副路认证的 HKDF 标签独立为 `lite/side/<方向>`；副路角色和形态标签不变。与 NetFront、单端口 PrestoLite 或旧程序混配不会降级成功。

[双向文件吞吐：两副路与三副路分别对照](network-test-lite-2026-11-20.md)。
