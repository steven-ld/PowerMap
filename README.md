# PowerMap

<div align="center">

<img src="assets/powermap-logo.svg" alt="PowerMap" width="360" />

**把内网服务安全地带回本地。无需公网 IP、VPN 或路由器配置。**

[![CI](https://github.com/steven-ld/PowerMap/actions/workflows/ci.yml/badge.svg)](https://github.com/steven-ld/PowerMap/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/steven-ld/PowerMap?display_name=tag&sort=semver)](https://github.com/steven-ld/PowerMap/releases)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-3366f0.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-dc8a4d.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)

[官网](https://powermap.ga666666.com) · **简体中文** · [English](README.en.md) · [下载](https://github.com/steven-ld/PowerMap/releases) · [贡献](CONTRIBUTING.md)

</div>

PowerMap 是基于 [iroh](https://iroh.computer) 和 QUIC 的点对点内网访问工具。它让两台机器优先直连，必要时通过加密中继回退，把内网服务映射为家中电脑上的本地端口。

```text
redis-cli ──> 127.0.0.1:6379 ──> PowerMap ──> 192.168.1.101:6379
             家中电脑             加密 P2P 隧道       内网服务
```

## 导航

- [一分钟安装](#一分钟安装)
- [三分钟跑通](#三分钟跑通)
- [适用边界](#适用边界)
- [部署与远程管理](#部署)
- [安全模型](#安全模型)
- [配置参考](#配置参考)
- [排错](#排错)

## 一分钟安装

macOS / Linux 可以使用安装脚本下载**已校验**的最新 Release；默认安装到 `~/.local/bin`。执行前可先查看脚本内容。

```bash
curl -fsSLO https://raw.githubusercontent.com/steven-ld/PowerMap/main/scripts/install.sh
sh install.sh
```

Windows（PowerShell）:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/steven-ld/PowerMap/main/scripts/install.ps1 -OutFile install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

安装脚本会下载 Release 的 SHA-256 文件并在安装前校验归档。需要固定版本时使用 `sh install.sh v0.1.0`，或设置 `POWERMAP_VERSION`。也可继续使用下方的手动下载和源码构建方式。

## 适用边界

| 你需要的 | PowerMap 的做法 |
|---|---|
| 不开公网端口 | 内网侧只主动连出，不监听可扫描的入站端口 |
| 不维护 VPN | 两端通过 iroh 自动 NAT 打洞；直连失败时才经中继 |
| 不改变现有工具 | 服务映射为 `127.0.0.1:端口`，继续使用浏览器、CLI、IDE 或数据库 GUI |
| 不把安全交给默认设置 | QUIC + rustls 加密、目标白名单、独立 token、审计日志和资源上限 |

> PowerMap 适合远程访问你有权限管理的内网服务。它不是公网暴露工具，也不是替代组织级 VPN 的身份与网络策略系统。

| 适合 | 不适合 |
|---|---|
| 家里、办公室或实验室的 Redis、数据库、Web 管理页、IDE 调试端口 | 对外发布网站或 API |
| 没有公网 IP、无法修改路由器、但两端都能访问互联网 | 需要组织级 SSO、设备准入和全网路由的企业 VPN 场景 |
| 希望让既有工具继续连 `127.0.0.1` | 不应由你管理或无权限访问的网络与服务 |

## 三分钟跑通

### 1. 下载或构建

从 [Releases](https://github.com/steven-ld/PowerMap/releases) 下载对应平台的预编译包。以 macOS Apple Silicon 为例：

```bash
VERSION=v0.1.0
TARGET=aarch64-apple-darwin   # Intel: x86_64-apple-darwin；Linux: x86_64/aarch64-unknown-linux-gnu
BASE=https://github.com/steven-ld/PowerMap/releases/download/$VERSION

curl -LO $BASE/powermap-$TARGET.tar.gz
curl -LO $BASE/powermap-$TARGET.sha256
shasum -a 256 -c powermap-$TARGET.sha256   # 校验完整性
tar xzf powermap-$TARGET.tar.gz
```

解包得到 `powermap-server` 与 `powermap-client` 两个可执行文件。Windows 用户下载 `powermap-x86_64-pc-windows-msvc.zip`。

也可以自行构建（需要 Rust 1.85+）：

```bash
git clone https://github.com/steven-ld/PowerMap.git
cd PowerMap
cargo build --release
```

构建产物为 `target/release/powermap-server` 和 `target/release/powermap-client`。

### 2. 在内网设备启动 server

```bash
./powermap-server
```

首次启动会生成以下文件：

| 文件 | 用途 |
|---|---|
| `powermap-server.key` | 持久化节点身份，保持 node id 稳定 |
| `powermap-server.toml` | server 配置和访问控制 |
| `powermap-server.credential.json` | 交给 client 的连接凭证 |

把 `powermap-server.credential.json` 安全地传给家中电脑。它包含访问内网的凭证，不要提交到 Git、聊天群或日志。

> 首次启动只是为了生成身份和凭证。长期运行前，请编辑 `powermap-server.toml`，至少限制 `allow_networks` 与 `allow_ports`；为控制台自动带出服务时，再配置 `published_targets`。完整示例见 [server 配置与多租户](#server-配置与多租户)。

### 3. 在家中电脑启动 client 并创建映射

```bash
./powermap-client --credential /path/to/powermap-server.credential.json
```

打开 <http://127.0.0.1:8088>，在“端口映射”中创建：

```text
本地监听：127.0.0.1:6379
目标服务：192.168.1.101:6379
```

看到“目标验证通过”后再保存映射。若 server 配置了 `published_targets`，控制台会在连接完成后自动显示已验证的对端 IP 和服务端口，点击即可填入表单。

之后照常使用服务：

```bash
redis-cli -h 127.0.0.1 -p 6379
```

也可以通过 API 添加映射：

```bash
curl -X POST http://127.0.0.1:8088/api/mappings \
  -H 'Content-Type: application/json' \
  -d '{"local":"127.0.0.1:6379","host":"192.168.1.101","port":6379}'
```

**成功标准**：管理页显示“已连接”（直连或经中继均可），映射状态保持“监听中/已活动”，且本地命令可以通过 `127.0.0.1:端口` 访问目标服务。

## 架构

```mermaid
flowchart LR
    U["本地工具<br/>redis-cli / browser / IDE"] --> L["127.0.0.1:6379"]
    L --> A["powermap-client<br/>家中电脑"]
    A <-->|"iroh P2P · QUIC + rustls<br/>优先直连，失败回退中继"| B["powermap-server<br/>内网设备"]
    B --> S["内网服务<br/>192.168.1.101:6379"]
```

- **client（A）**：监听本地端口，提供管理页，维护到 server 的加密连接。
- **server（B）**：验证凭证与目标白名单后，在所在内网拨号目标服务。
- **中继**：仅在无法直连时转发密文，无法读取隧道内容。

每一条本地 TCP 连接都在已建立的 QUIC 连接上复用双向流。连接断开时，client 会通过看门狗与指数退避恢复连接。

## 界面

管理页默认仅绑定本地回环，实时显示连接状态、传输路径（P2P 直连 / 经中继）与流量指标，并支持浅色 / 深色主题。

| 端口映射 | 连接设置 |
|---|---|
| ![端口映射页面（浅色）](assets/screenshots/light-mappings.png) | ![连接设置页面（浅色）](assets/screenshots/light-connection.png) |
| ![端口映射页面（深色）](assets/screenshots/dark-mappings.png) | ![连接设置页面（深色）](assets/screenshots/dark-connection.png) |

## 部署

### Docker：推荐只部署 server

server 适合部署在内网设备或盒子中。`--network host` 通常能提高 NAT 打洞成功率。

```bash
docker build -t powermap .

docker run -d --name powermap-server --network host \
  -v "$PWD/data:/data" \
  -e RUST_LOG=info \
  powermap powermap-server --config /data/powermap-server.toml
```

或使用 Compose：

```bash
docker compose up -d --build
```

client 建议原生运行：映射的本地端口位于 client 所在网络命名空间，放入 Docker 会额外增加逐端口发布的管理成本。

### 受管服务与安全远程管理

Linux systemd、macOS launchd 与 Windows Task Scheduler 模板，以及保持管理页回环监听的 SSH / mTLS Nginx 远程管理方案，见 [deployment/README.md](deployment/README.md)。这些模板会保存配置和映射状态，并在异常退出后重启；不会把管理页直接暴露到公网。

| 目标 | 推荐入口 |
|---|---|
| 个人电脑临时访问 | 直接运行 `powermap-client`，使用本地管理页 |
| 长期运行的内网设备 | [受管部署模板](deployment/README.md) |
| 远程查看本地管理页 | SSH 隧道；只有确有需要时才部署 mTLS 网关 |
| 自动化创建映射 | `POST /api/mappings`，并设置 Bearer `web_token` |

### 支持的平台

Release 提供 Linux x86_64 / aarch64、macOS Intel / Apple Silicon 与 Windows x86_64 的预编译包，并附带 SHA-256 校验文件。

## 安全模型

| 控制项 | 说明 |
|---|---|
| 访问凭证 | `node_id + token` 是访问入口。像密码一样保存 `credential.json`。 |
| 端到端加密 | iroh 的 QUIC + rustls 加密所有链路；中继只见密文。 |
| 目标白名单 | server 可用 CIDR 和端口限制可拨号目标，并避免 DNS 重绑定绕过。 |
| 多租户 | `[[clients]]` 为每个使用者配置独立 token、白名单、并发上限，可单独吊销。 |
| 审计与资源限制 | 每次拨号可记录 JSON 审计日志；并发流、映射数、连接数与拨号超时均有限制。 |
| 管理 API 鉴权 | 设置 `web_token` 后，只接受 `Authorization: Bearer <token>`；不接受 URL 查询参数，避免令牌进入历史记录、代理与访问日志。 |

**不要将管理页直接暴露到公网。** 如果将 `web_bind` 改为 `0.0.0.0`，请设置 `web_token`，启用 TLS，并在反向代理或防火墙层限制访问来源。

## 运维

client 暴露 Prometheus 指标和健康检查：

```bash
curl http://127.0.0.1:8088/metrics
curl http://127.0.0.1:8088/api/health
```

指标包含隧道、握手、拒绝、拨号失败、重连和收发字节。`/metrics` 与 `/api/health` 不要求管理页 token，仅输出聚合数据；若监听到非本地地址，请在网络层限制抓取来源。

## 配置参考

默认配置目录：Linux 为 `~/.config/powermap/`，macOS 为 `~/Library/Application Support/powermap/`。使用 `--config` 指定其他路径；命令行参数优先于配置文件。

<details>
<summary><strong>client 配置</strong></summary>

```toml
node_id = "a5d40b0a8d24..."
token = "991fd0a3..."
web_bind = "127.0.0.1:8088"
web_token = ""
web_tls_cert = ""
web_tls_key = ""
max_mappings = 256
max_conns_per_mapping = 512

[[mappings]]
local = "127.0.0.1:6379"
host = "192.168.1.101"
port = 6379
```

`web_token` 为空表示管理页不鉴权；仅适用于默认本地监听。配置它后，管理 API 只能通过 `Authorization: Bearer <token>` 访问，不能使用 `?token=`。网页会在当前页面内存中临时保留手动输入的管理令牌，刷新页面后需要重新输入。非回环 `web_bind` 未设置 token、只设置一侧 TLS 文件、或只设置 `node_id`/`token` 时，client 会拒绝启动并指出配置项。`max_conns_per_mapping = 0` 表示不限制。
</details>

<details>
<summary><strong>server 配置与多租户</strong></summary>

```toml
identity = "powermap-server.key"
max_streams_per_conn = 256
dial_timeout_secs = 10
audit_log = "/var/log/powermap/audit.jsonl"

[[clients]]
id = "alice"
token = "alice-token-..."
allow_networks = ["192.168.1.0/24"]
allow_ports = [6379, 5432]
max_streams = 32
published_targets = [
  { host = "192.168.1.101", port = 6379, label = "Redis 主库" },
  { host = "192.168.1.102", port = 5432, label = "PostgreSQL" },
]

[[clients]]
id = "bob"
token = "bob-token-..."
allow_networks = ["10.0.0.0/8"]
revoked = true
```

顶层 `token` 也可用于单租户部署；它会兼容地映射为 `default` 客户，并在启动日志中明确提示，无需立刻迁移到 `[[clients]]`。`published_targets` 是显式分享给该 client 的 IP/端口候选；连接成功后，控制台会由 server 实际拨号检查，只显示当前可用的服务并支持一键填入。它不放宽白名单，端口必须仍在 `allow_ports` 中。为避免策略被静默覆盖，server 会拒绝无效 CIDR、端口 `0`、空或重复的客户 id/token。变更 `[[clients]]`、白名单、推荐目标或吊销状态后需要重启 server，并重新分发凭证文件。

单租户把同一段 `published_targets = [...]` 写在顶层；多租户则写在对应的 `[[clients]]` 下，并在分发给该客户的凭证 JSON 中保留 `published_targets` 字段。控制台的“刷新”只重新检测这些明确发布的地址，不会扫描整个内网。
</details>

## 排错

| 现象 | 处理方式 |
|---|---|
| 无法连接或被 server 拒绝 | 核对 client 使用的 `node_id` 与 `token` 是否来自该 server 的凭证文件。 |
| 本地端口绑定失败 | 端口已被占用；更换端口，或删除已有的同名映射。 |
| 中继连接超时 | 网络或中继可能短暂波动；iroh 会尝试切换中继，稍候重试。 |
| 修改配置后没有生效 | 配置在启动时读取。运行期映射请通过管理页或 API 维护；改 server 白名单或 `published_targets` 后重启 server，并重新分发凭证。 |

## 开发与贡献

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI 会在每个 push 和 PR 上运行相同检查。提交 Issue 或 PR 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请不要公开提交 Issue，而应私下联系维护者。

## License

PowerMap 采用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双许可，你可以任选其一。
