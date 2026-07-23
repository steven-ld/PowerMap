# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 约定，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.7.0] - 2026-07-23

### Changed

- Test release for validating the managed update and release pipeline end to end.

## [0.6.0] - 2026-07-23

### Added

- 节点页新增稳定版检查与一键更新：从 GitHub Release 下载当前平台包、解析校验文件并验证 SHA-256 后，安全解包、原子替换并优雅重启。原生 macOS/Linux 可在进程内完成；Docker 与 Windows 会给出可复制的宿主机升级命令。

## [0.5.0] - 2026-07-22

### Added

- 域名映射：把完整 DNS 域名写入本机 hosts，并通过共享的 `127.0.0.1:443` HTTPS 入口按 TLS SNI 分发到远端服务。支持创建、更新、启停、恢复与状态诊断。
- 域名映射的 hosts 标记管理、并发协作锁、SNI 首包回放和连接限流；映射异常会保留可诊断状态，不会阻断普通端口映射启动。

### Changed

- 管理 API 当前不启用 `web_token` 鉴权。旧配置字段继续保留并可读写，供未来版本启用时兼容；Docker 与 root 启动不再要求或生成管理 token。
- 控制台移除管理 token 的输入、轮换与会话状态控件；管理页可直接操作。

### Compatibility

- 既有 `access.web_token` 配置会被保留，但不参与当前版本的启动校验或 API 行为。
- 域名映射只支持 macOS/Linux，仍要求以管理员身份运行，以便维护系统 hosts 文件和本机 443 监听。

## [0.4.0] - 2026-07-22

### Added

- UDP 隧道：映射新增 `udp` 模式，本地绑定 UDP socket，数据报经隧道由 expose 能力拨 UDP 目标；适用于 DNS、WireGuard、游戏服务器等无连接协议。access 端按来源地址维护会话并在空闲 60 秒后回收。
- HTTP 反向代理网关：映射新增 `http` 模式，单个本地端口按请求 `Host` 头分流到多个内网后端（`routes` 路由表，最多 32 条，空 `host_match` 为兜底后端）。
- 反向映射：把本机 access 侧服务暴露给 expose 所在内网。复用同一条 QUIC 连接的双向流，expose 在内网监听、把连接交回 access 拨本地目标。**默认全部拒绝**：access 需显式启用并列出允许回拨的网段与端口才放行（`reverse_enabled` + `reverse_allow_networks` + `reverse_allow_ports`）；expose 用 `[[expose.clients]]` 下的 `reverse` 声明内网监听地址。
- `Mapping` 新增 `mode` 与 `routes` 字段；旧配置省略时按 `tcp` 处理，向后兼容。

- 映射命名：`Mapping` 新增可选 `name` 字段（旧配置默认为空，向后兼容）。列表以名称为主标识、本地地址降为副信息，搜索同时覆盖名称。
- 一键启用/停用全部映射（`POST /api/mappings/toggle-all`）：逐条重建把手，单条失败不影响其余并计入返回；列表头按钮随当前状态在“全部停用/全部启用”间切换。
- 映射列表排序（异常优先/名称/本地地址/流量，选择持久化）；端口映射标签页新增异常映射计数徽章，切换到其他标签也能看到有几条映射异常。
- 导入合并模式（`POST /api/import?mode=merge`）：只叠加新增、按本地地址更新同名，保留导入未提及的现有映射；导入时可选择“覆盖”或“合并”。
- 连接时长：`/api/status` 暴露 `connected_since`，连接状态卡显示当前连接已保持时长。
- 连接质量趋势：连接状态卡以迷你趋势图展示往返延迟（RTT）历史，断线以缺口体现，便于看出链路抖动。
- 断线桌面通知（可选开启）：连接断开/恢复且页面不可见时发系统通知，与页内提示互补。
- 就地编辑映射（`PUT /api/mappings/{id}`）：仅改目标时复用原监听、不中断已建隧道；改本地地址时先绑新址再停旧址。管理页新增编辑模式与每行“复制本地地址”。
- 连接从“已连接”跌为断开时提醒一次；标签页隐藏时暂停轮询、重新可见时立即刷新。
- 映射启用/停用（`POST /api/mappings/{id}/toggle`）：停用释放本地端口并 drain 在途连接、保留配置可随时再启用；`Mapping` 新增持久化 `enabled` 字段，旧配置默认启用。
- 连接级明细：`/api/stats` 每条映射附活跃连接列表（来源、时长、上/下行字节）；管理页可展开映射查看“哪条连接在忙”。
- 事件页支持关键字搜索与导出为 JSON（按当前筛选导出，便于留存排查证据）。
- 每条映射的迷你流量趋势图，历史留存于浏览器本地存储，刷新后不断档。
- 命令面板（`⌘/Ctrl+K`）与键盘快捷键（`N` 新建、`R` 刷新、`1/2/3` 切页、`?` 帮助）。
- 可选轮询间隔（2/5/10 秒或手动）与暂停开关；映射列表支持以某条为模板克隆新建。

### Changed

- 发布物、安装脚本、systemd、launchd、Windows 任务计划与 Docker 统一为单个 `powermap` 可执行文件；直接启动后按 `powermap.toml` 中的 `[expose]`、`[access]` 运行相应能力。
- 管理控制台重组为概览、端口映射、节点和事件四个页面。节点页默认进入“远端节点”以连接其他设备；概览显示当前连接的对端 IP，映射创建默认 TCP，UDP / HTTP 作为高级选项。
- 控制台视觉系统更新为冷灰画布、白色卡片和 `#3370FF` 主蓝；浏览器标题不再注入状态 emoji，favicon 更新为蓝色节点网络标识。

### Compatibility

- 首次启动时，如未存在 `powermap.toml`，会自动读取 `powermap-server.toml` 与 `powermap-client.toml`，合并并写入统一配置；只有新配置成功落盘后才删除旧文件。
- 旧映射未填写 `mode` 时继续按 TCP 运行；旧的单租户 `token` 继续兼容并规范化为 `default` 客户。
- 新 Release 不再提供 `powermap-server` 与 `powermap-client`。需要回退到旧二进制前，请备份 `powermap.toml`、`powermap.key` 与 `powermap.credential.json`，并保留原始 role 配置副本。

### Security

- 管理页新增“清除访问令牌”入口，随时抹除本页内存中的 web_token；覆盖已配置凭证前二次确认，避免误操作断连。

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

[Unreleased]: https://github.com/steven-ld/PowerMap/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/steven-ld/PowerMap/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/steven-ld/PowerMap/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/steven-ld/PowerMap/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/steven-ld/PowerMap/compare/v0.3.0...v0.4.0
[0.2.0]: https://github.com/steven-ld/PowerMap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/steven-ld/PowerMap/releases/tag/v0.1.0
