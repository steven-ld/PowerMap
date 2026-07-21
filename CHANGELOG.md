# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 约定，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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

[Unreleased]: https://github.com/steven-ld/PowerMap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/steven-ld/PowerMap/releases/tag/v0.1.0
