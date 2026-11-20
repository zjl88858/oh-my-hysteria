# oh-my-hysteria v1.1.0

## 发布摘要

- **Carakan**：可调目标熵的逆向 tANS 整形，52 字节认证封装、循环交织和 Cauchy
  GF(256) 纠删修复。仅保留当前线格式，握手和数据均自动分片。
- **Presto**：单密码生成双向包长、转移、前导、分片与突发节奏。
- **Trident**：单密码编译 64 指令 ISA，将认证密文编码为独立字节码报文。
- 重新组织混淆指南，分离当前功能说明与开发记录，集中说明部署及安全边界。
- 保留默认 BBR、既有拥塞预设、Brutal 协商和其他混淆行为。

使用方法：[README](../README.md) · [混淆选型](obfuscation.md) ·
[Carakan](carakan.md) · [Presto](presto.md) · [Trident](trident.md)

## 升级说明

- 应用版本为 **v1.1.0**；Go 的 `app/core/extras` 模块路径继续使用 `/v2`，不随应用版本改变。
- Carakan 仅使用 `oh-my-hysteria/carakan/v3`，旧开发构建需双端同时更新。
  配置名和默认目标熵 4.00 不变，没有版本协商或自动回退。
- Presto、Trident 保留当前格式及单密码配置；原有配置文件位置和分享链接方案不变。

## 产物

候选产物单独位于 `build/release-v1.1.0/binaries/`：

- `oh-my-hysteria-windows-amd64.exe`
- `oh-my-hysteria-linux-amd64`
- `oh-my-hysteria-linux-arm64`
- 适用的许可文件、`QUIC-FORK.md` 与 `SHA256SUMS`

该目录不包含旧协议二进制、观测端点或实验数据。Windows 候选仅执行离线 CLI 冒烟，
Linux 候选交叉编译；协议页的既有公网结果保留原构建身份，没有改算为 v1.1.0 候选测试。

## 发布准备清单

- [x] 统一 `VERSION`、CLI 默认版本、Python 项目及 lockfile、README 容器示例。
- [x] Python **53/53**；core、extras 全模块和 app/cmd 回归；三模块 vet、全仓格式检查通过。
- [x] 构建三平台候选，Windows 离线 CLI/分享链接 **6/6** 通过，并核对交叉构建元数据。
- [x] 核对许可文件并生成 SHA256 校验清单；具体命令、结果与限制见
  [构建与验证历史](../BUILD-REPORT.md) 的 v1.1.0 准备记录。
- [ ] 审核待提交变更，提交后从确定的提交重建，再创建 tag 与 Release。

当前是发布准备，尚未创建提交、tag 或 Release。没有新增公网测试或流量消耗。
