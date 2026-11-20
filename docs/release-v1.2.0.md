# oh-my-hysteria v1.2.0

## 本版变化

- **Servo**：跨QUIC数据报装箱，最多两容器，有限异步队列与公平调度。
- **Tasman**：短块Cauchy纠删、预算账本、有限载波、恢复反馈与QUIC保守外层预留。
- **Mariner**：密码编译非线性关系图，认证密文的高阶字节关系与交织，最多两片。
- 整理配置、诊断、混淆选型与实现记录；默认BBR、已有预设和Brutal协商保持不变。
- 构建工具链更新到Go1.26.10，避开旧版Windows异步抢占的指针损坏问题。

[配置总览](../README.md#混淆配置) · [Servo](servo.md) · [Tasman](tasman.md) · [Mariner](mariner.md)

## 升级

新增三种模式均须显式选择，两端更新到支持相同类型的版本；仅要求类型和混淆密码。
登录 `auth`、正常TLS校验和Go模块 `/v2` 路径不变。Carakan继续使用v3，不增加旧格式回退。
新增模式固定UDP端口，内层1200B、外层payload≤1232B。

## 候选产物

准备目录 `build/release-v1.2.0/binaries/`：

- `oh-my-hysteria-windows-amd64.exe`
- `oh-my-hysteria-linux-amd64`
- `oh-my-hysteria-linux-arm64`
- 适用许可、`QUIC-FORK.md`、`SHA256SUMS`

研究数据、测试端点和本地凭据不进入发布包。具体测试与源码身份见
[构建记录](../BUILD-REPORT.md)及候选目录中的清单。

## 发布清单

- [x] 版本统一为v1.2.0，保留模块路径、许可和Co-Developer署名。
- [x] 最终回归、独立向量、race/fuzz、隔离网络与有界公网验证归档。
- [x] Go1.26.10三平台编译、CLI/share六项冒烟、许可和SHA256清单。
- [ ] 审核全部未提交改动，授权提交后从确定提交重建。
- [ ] 创建tag与Release。

当前为发布准备；本轮不创建提交、tag或Release。

验证摘要：Python63/63；Windows三模块全回归，Linux race/fuzz、MTU1280及损伤样本
通过。公网Gecko/Mariner各一次，均双向4KiB；累计3916992B/4440包/288s，已清理。
盲分类未证实Mariner的抗分类收益，完整方法与负结果在实现记录中。
