# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 约定，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.2.0] - 2026-07-21

### Added

- 首次映射引导、目标预检与异常映射诊断；创建映射前会检查本地监听、凭证、server 策略与目标 TCP 拨号。
- `published_targets`：server 可向指定 client 发布候选服务；控制台仅展示 server 实际验证可达的目标，并支持一键填入映射。
- 管理页实时监控：上/下行速率、累计流量、趋势图、映射级速率、活跃隧道与运行计数。
- Linux systemd、macOS launchd、Windows 任务计划部署模板，以及 SSH / mTLS Nginx 远程管理指南。

### Changed

- 管理控制台改为更紧凑的运维界面，改善小屏布局、键盘操作、状态反馈与首次使用路径。
- README 提供校验安装、使用边界、受管部署和自动化入口的快速导航。

### Security

- 管理 API 仅接受 Bearer 令牌；移除 URL 查询令牌，强化配置落盘、导入事务与远程管理边界。

## [0.1.0] - 2026-07-21

### Added

- 基于 iroh（P2P / QUIC）的内网穿透：`powermap-server`（穿透端）暴露 ALPN 服务，`powermap-client`（用户端）把内网目标映射到本地端口。
- Web 管理页（:8088）：端口映射页（连接状态、流量指标、增删映射）与连接页（粘贴凭证接入、切换连接目标）。
- 凭证持久化：`node_id` + `token` 写入 `powermap-client.toml`，重启自动恢复。
- 多租户：`[[clients]]` 为每个客户配独立 token、网段/端口白名单与并发上限，支持轮换与吊销。
- 安全：token 常量时间比较、B 端目标白名单（防 DNS 重绑定 TOCTOU）、审计日志、资源上限、Web 管理页 Bearer 鉴权与可选 HTTPS。
- 可观测：A 端 Prometheus `/metrics`，B 端周期性把指标打进日志。
- 运维：优雅关闭（drain 在途隧道）、断线指数退避重连、看门狗热连接。
- Docker 部署（`Dockerfile` + `docker-compose.yml`）。

[Unreleased]: https://github.com/steven-ld/PowerMap/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/steven-ld/PowerMap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/steven-ld/PowerMap/releases/tag/v0.1.0
