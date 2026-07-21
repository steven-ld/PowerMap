# PowerMap

<div align="center">

![PowerMap](https://img.shields.io/badge/PowerMap-P2P%20Tunnel-3370ff?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-green?style=for-the-badge)
![Rust](https://img.shields.io/badge/Rust-1.85+-orange?style=for-the-badge&logo=rust&logoColor=white)
![iroh](https://img.shields.io/badge/Built%20on-iroh-black?style=for-the-badge)

基于 [iroh](https://iroh.computer)（P2P / QUIC）的内网穿透工具。两台机器打洞直连或经中继转发，把**内网设备上的服务映射到你家里的电脑**——不用公网 IP、不用 VPN、不用改路由器。

[![CI](https://github.com/steven-ld/PowerMap/actions/workflows/ci.yml/badge.svg)](https://github.com/steven-ld/PowerMap/actions/workflows/ci.yml)
[![Release](https://github.com/steven-ld/PowerMap/actions/workflows/release.yml/badge.svg)](https://github.com/steven-ld/PowerMap/actions/workflows/release.yml)

**简体中文** • [English](README.en.md)

</div>

---

## 💡 设计理念

PowerMap 想解决一个很具体的痛点：**人在家里，服务在内网**。不想为此买公网 IP、搭 VPN、开路由器端口。于是有了这几条原则：

### 1. 零公网暴露

内网侧（穿透端）**不监听任何入站端口**，只主动连出到 iroh 中继网络。没有可被扫描的攻击面，防火墙后、NAT 后、宿舍网都能用。

### 2. 端到端加密

全程 QUIC + rustls 加密，凭证是唯一的访问入口。中继只转发密文，看不到内容。

### 3. 开箱即用

下载二进制，内网侧一跑生成凭证，家里侧粘贴凭证，Web 页点几下就通了。无数据库、无中心服务器、无账号注册。

### 4. 生产级可控

目标白名单（CIDR + 端口）、多租户独立 token、审计日志、资源上限、优雅关闭——不是玩具，是能长期挂着跑的工具。

---

## ✨ 特性

- **P2P 直连** —— iroh 自动打洞，多数网络下直连，打不通自动回退中继
- **零入站端口** —— 内网侧不暴露任何监听端口，无攻击面
- **Web 管理页** —— 两页式界面：端口映射 + 连接管理，实时流量指标
- **端到端加密** —— 全程 QUIC + rustls，中继不可见明文
- **目标白名单** —— CIDR 网段 + 端口双重限制，防 DNS 重绑定（TOCTOU）
- **多租户** —— 每个客户独立 token / 白名单 / 并发上限，可单独轮换、吊销
- **审计日志** —— 每次拨号（放行/拒绝/超时/失败）落一行 JSON
- **虚拟 IP 映射** —— 把多台内网设备映射到不同本地回环地址
- **Prometheus 指标** —— `/metrics` 端点，隧道/流量/重连全覆盖
- **自动重连** —— 后台看门狗 + 指数退避，断线 ~15s 内察觉并恢复
- **凭证持久化** —— 一次接入，重启自动恢复
- **HTTPS 管理页** —— 可选 TLS，复用 iroh 的 ring 后端，无额外 C 依赖
- **跨平台** —— Linux / macOS / Windows 预编译二进制
- **Docker Ready** —— 内网侧完美适配容器部署

---

## 🏗️ 架构

```
     内网侧（公司 / 宿舍 / 现场）                     家里侧
 ┌──────────────────────────────┐            ┌──────────────────────────────┐
 │  powermap-server（穿透端 B）  │            │  powermap-client（用户端 A）  │
 │                              │    iroh    │                              │
 │   ALPN 服务(中继) ◀──────────┼── P2P ─────┼──▶ Web 管理页 :8088          │
 │        │                     │  打洞/中继  │                              │
 │        │ 内网拨号            │            │   本地 127.0.0.1:6379         │
 │        ▼                     │            │   访问它 = 访问内网服务        │
 │  192.168.1.101:6379 等服务    │            │                              │
 └──────────────────────────────┘            └──────────────────────────────┘
```

| 端 | 部署位置 | 作用 |
|---|---|---|
| **powermap-server**（穿透端 **B**） | 内网设备上 | 用 iroh 暴露一个 ALPN 服务，生成凭证；按客户端请求在内网拨号目标并双向转发 |
| **powermap-client**（用户端 **A**） | 家里电脑 | 输入凭证，提供 Web 管理页，把本地端口映射到内网目标 |

内网设备上装了 **B**，家里的 **A** 就能访问**同内网任意设备**——比如把内网 `192.168.1.101:6379` 映射到本地 `127.0.0.1:6379`，由 B 去代访问那台机器。

---

## 🚀 快速开始

### 前置要求

- 预编译二进制：无（下载即用）
- 本地编译：Rust ≥ 1.85（`cargo --version`）

### 方式一：预编译二进制（推荐）

到 [Releases](https://github.com/steven-ld/PowerMap/releases) 下载对应平台压缩包，解压即得 `powermap-server`、`powermap-client` 两个二进制。每个包旁附 `.sha256` 校验文件。

| 平台 | 目标三元组 |
|---|---|
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux aarch64 | `aarch64-unknown-linux-gnu` |
| macOS x86_64（Intel） | `x86_64-apple-darwin` |
| macOS aarch64（Apple Silicon） | `aarch64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

### 方式二：本地编译

```bash
git clone https://github.com/steven-ld/PowerMap.git
cd PowerMap
cargo build --release
# 产物：target/release/powermap-server、target/release/powermap-client
```

<details>
<summary>国内网络拉不到 crates.io？换 rsproxy 源</summary>

在 `~/.cargo/config.toml` 里加：

```toml
[source.crates-io]
replace-with = "rsproxy-sparse"
[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
```
</details>

### 三步跑通

**第 1 步 · 内网设备上启动穿透端 B**

```bash
./powermap-server
```

首次运行在配置目录生成三个文件：

| 文件 | 说明 |
|---|---|
| `powermap-server.key` | 节点身份（**持久化，保证 node id 稳定**） |
| `powermap-server.toml` | 配置（含随机生成的 token） |
| `powermap-server.credential.json` | **凭证，交给家里侧 A** |

之后每次启动复用同一份配置，node id 和 token 都不变，A 端**无需重新拿凭证**。

**第 2 步 · 家里电脑上启动用户端 A**

```bash
./powermap-client
```

启动即打开 <http://127.0.0.1:8088> ，Web 管理页分**两页**：

- **端口映射**（主页）：连接状态、流量指标、添加与管理映射
- **连接**：粘贴凭证接入

进 **连接** 页，把 B 生成的 `powermap-server.credential.json` 整段粘进「凭证 JSON」框（或分栏填 `node_id` 与 `token`），点「接入 / 更新」——凭证写入 `powermap-client.toml`，**重启自动恢复**。

<details>
<summary>也可以用 CLI 首次注入凭证（效果等同网页填写）</summary>

```bash
./powermap-client --credential /path/to/powermap-server.credential.json
```
</details>

**第 3 步 · 添加映射**

回 **端口映射** 页填表，或用 API：

```bash
# 本地 6379 → 内网 192.168.1.101:6379
curl -X POST http://127.0.0.1:8088/api/mappings \
  -H 'Content-Type: application/json' \
  -d '{"local":"127.0.0.1:6379","host":"192.168.1.101","port":6379}'

# 虚拟 IP：本地 127.0.0.2:6379 → 另一台内网设备
curl -X POST http://127.0.0.1:8088/api/mappings \
  -H 'Content-Type: application/json' \
  -d '{"local":"127.0.0.2:6379","host":"192.168.1.101","port":6379}'

curl http://127.0.0.1:8088/api/mappings                       # 列表
curl -X DELETE http://127.0.0.1:8088/api/mappings/127.0.0.1%3A6379
```

搞定。`redis-cli -h 127.0.0.1 -p 6379` 就连到了内网的 Redis。

---

## 🐳 Docker 部署

镜像同时包含两个二进制，用 `command` 选择端。**穿透端 B 是 Docker 部署的理想对象**——跑在内网盒子上，不暴露任何入站端口。

```bash
docker build -t powermap .

# powermap-server：挂载 ./data 持久化身份与配置；host 网络提升打洞成功率
docker run -d --name powermap-server --network host \
  -v "$PWD/data:/data" \
  -e RUST_LOG=info \
  powermap powermap-server --config /data/powermap-server.toml

# 取出凭证给家里侧 A
cat data/powermap-server.credential.json
```

或用 Compose：

```bash
docker compose up -d --build
```

> ⚠️ **用户端 A 建议原生运行，别放进 Docker**：A 映射的本地端口在容器**内**，要从宿主机访问得逐个 `-p` 发布，很麻烦。A 跑在家里电脑本机最省事。

---

## ⚙️ 配置

两端各自一份 TOML，默认在 `<系统配置目录>/powermap/`（Linux `~/.config/powermap/`，macOS `~/Library/Application Support/powermap/`），用 `--config` 覆盖。命令行参数（`--help`）优先级高于配置文件。

### `powermap-client.toml`（用户端 A）

```toml
node_id = "a5d40b0a8d24..."    # B 的 EndpointId
token = "991fd0a3..."          # B 生成的访问令牌
web_bind = "127.0.0.1:8088"
web_token = ""                 # Web 管理页访问令牌；留空不鉴权
web_tls_cert = ""              # TLS 证书路径（PEM）
web_tls_key = ""               # TLS 私钥路径（PEM）
max_mappings = 256             # 最大映射条数上限
max_conns_per_mapping = 512    # 单条映射的最大并发连接数（0 = 不限）

[[mappings]]
local = "127.0.0.1:6379"
host = "192.168.1.101"
port = 6379
```

| 字段 | 说明 | 默认 |
|---|---|---|
| `node_id` | B 的 EndpointId | - |
| `token` | B 生成的访问令牌 | - |
| `web_bind` | Web 管理页监听地址 | `127.0.0.1:8088` |
| `web_token` | 管理页访问令牌，留空不鉴权（绑 `0.0.0.0` 远程管理时**务必设置**） | `""` |
| `web_tls_cert` / `web_tls_key` | 两者同时非空则启用 HTTPS | `""` |
| `max_mappings` | 最大映射条数，防止无限添加耗尽本地端口 | `256` |
| `max_conns_per_mapping` | 单条映射的最大并发连接数（0 = 不限） | `512` |

### `powermap-server.toml`（穿透端 B · 单租户）

```toml
identity = "powermap-server.key"   # 相对于本配置文件所在目录
token = "991fd0a3..."              # 留空且无 clients 时首次随机生成并回填
allow_networks = []                # 允许拨号的目标网段（CIDR），留空 = 允许全部
allow_ports = []                   # 允许拨号的目标端口，留空 = 允许全部
max_streams_per_conn = 256         # 单连接上的最大并发隧道数（0 = 不限）
dial_timeout_secs = 10             # 内网拨号超时（秒）
audit_log = ""                     # 审计日志文件路径；留空则只输出到 tracing
```

### `powermap-server.toml`（穿透端 B · 多租户）

用 `[[clients]]` 给每个客户独立 token 与白名单，可单独轮换 / 吊销：

```toml
identity = "powermap-server.key"
max_streams_per_conn = 256
dial_timeout_secs = 10
audit_log = "/var/log/powermap/audit.jsonl"

[[clients]]
id = "alice"                       # 客户标识，用于审计日志与指标标签（非机密）
token = "alice-token-..."
allow_networks = ["192.168.1.0/24"]
allow_ports = [6379, 5432]
max_streams = 32                   # 该客户的最大并发隧道数（0 = 不限）

[[clients]]
id = "bob"
token = "bob-token-..."
allow_networks = ["10.0.0.0/8"]
revoked = true                     # 吊销：保留在配置留痕，但拒绝接入
```

> 顶层单 `token` 会被归一化为一个 id 为 `default` 的客户，可与 `[[clients]]` 并存——旧配置无需改动即可继续用。轮换或吊销客户后需**重启 B** 生效。

---

## 🔐 安全

| 机制 | 说明 |
|---|---|
| **访问凭证** | `token` 是唯一入口，常量时间比较防计时侧信道。拿到 `node_id + token` 就能让 B 在其内网拨号——请像密码一样保管 `credential.json` |
| **端到端加密** | 全程 QUIC + rustls（iroh 内置），中继只转发密文 |
| **目标白名单** | `allow_networks`（CIDR）+ `allow_ports` 限定可拨号范围。B **一次性解析主机名并只对通过白名单的 IP 直接拨号**，杜绝 DNS 重绑定（TOCTOU）绕过 |
| **多租户隔离** | `[[clients]]` 给不同使用者发独立 token，各自绑定白名单与并发上限；`revoked = true` 单独吊销 |
| **审计日志** | 每次拨号（放行 / 拒绝 / 超时 / 失败）落一行 JSON，含时间戳、客户 id、目标、结果 |
| **资源上限** | `max_streams_per_conn`、每客户 `max_streams`、`dial_timeout_secs`，及 A 端 `max_mappings` / `max_conns_per_mapping`，防止耗尽资源 |
| **管理页鉴权** | 设了 `web_token` 后所有 API 需 `Authorization: Bearer <token>` 或 `?token=`；绑 `0.0.0.0` 远程管理时务必设置 |
| **管理页 HTTPS** | 同时配 `web_tls_cert` + `web_tls_key` 即启用 TLS |

---

## 📊 可观测与运维

**Prometheus 指标** —— A 端 `/metrics`，文本格式直接抓取：

```bash
curl http://127.0.0.1:8088/metrics
```

暴露隧道计数（打开 / 活跃 / 失败）、握手与目标拒绝数、超限、拨号失败 / 超时、重连次数、收发字节数等。`/metrics` 与 `/api/health` **免鉴权**（只暴露聚合计数，不含机密）；绑 `0.0.0.0` 时如需限制来源请在反代层做。B 端不暴露入站端口，改为**周期性（60s）把指标打进 tracing 日志**。

**优雅关闭** —— A 收到 `SIGINT` / `SIGTERM` 后停止接受新连接，通过 `CancellationToken` **drain 在途隧道**再退出；运行期 `DELETE` 一条映射也会主动断开该映射下的在途连接。

---

## 🔬 工作原理

1. B 用 iroh 绑定节点身份、注册到 N0 中继网络，对外暴露 ALPN `/powermap/tcp/0`。
2. A 只凭 B 的 `node_id`，iroh 通过中继 + DNS 发现 B 并打洞（多数直连，打不通走中继）。
3. 每条映射 = A 上的一个 TCP 监听。每个进来的连接，A **复用同一条到 B 的 iroh 连接**开一条 QUIC 双向流（QUIC 天然多路复用），握手头带 `{token, host, port}`。
4. B 校验 token、按白名单校验目标，在内网拨号 `host:port`，之后双向透传 TCP，支持**半关闭**（HTTP keep-alive 等协议正常工作）。
5. A 后台**看门狗**保持热连接，断线按指数退避（1→30s + 抖动）主动重连；两端 QUIC 参数为 5s keepalive + 15s 空闲超时，对端失联 ~15s 内察觉。

> QUIC 传输参数已调优：单连接并发双向流上限提到 1024，放大流量窗口，配合 64KB 转发缓冲，支撑高并发映射下的吞吐。

---

## 🩺 排错

| 现象 | 处理 |
|---|---|
| A 连不上 / `B 拒绝` | 确认 `node_id`、`token` 与 B 一致（看 `powermap-server.credential.json`） |
| `Failed to connect to relay server: timeout` | N0 中继偶发抖动，iroh 会自动切换中继（如 `euc1` → `aps1`），首条隧道多等几秒或重试一次（A 已内置一次重连重试） |
| 绑定本地端口失败 | 端口被占用；换端口，或检查是否已有同名映射 |
| 配置改了不生效 | 配置只在启动时读入；运行期增删映射走 Web/API（自动回写）。改 B 端 `[[clients]]` 需**重启 B** |
| 不想让 `/metrics` 对外可见 | 它免鉴权（只有聚合计数）；绑 `0.0.0.0` 时在反代层限制抓取来源 |

---

## 🧭 局限

- 凭证只携带 `node_id`，连接依赖 iroh 的中继 / DNS 发现。极端 NAT 下若发现不畅，可考虑改为携带完整 `EndpointAddr`（含中继 URL + 直连地址）。
- A 端每个本地 TCP 连接复用共享 iroh 连接开流；连接断开会懒重连，但已建立的隧道会随之中断，需客户端重连。

---

## 🛠️ 开发

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

CI（[`ci.yml`](.github/workflows/ci.yml)）在每次 push / PR 跑 fmt + clippy（`-D warnings`）+ test。想参与贡献请看 [CONTRIBUTING.md](CONTRIBUTING.md)。

### 发布

推送形如 `v1.2.3` 的 tag 触发 [`release.yml`](.github/workflows/release.yml)，为全部 5 个平台交叉编译并把压缩包 + 校验和上传到对应的 GitHub Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

---

## 📄 许可证

本项目采用 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 双许可，任选其一。

除非你明确声明，否则你有意提交进本项目的任何贡献（按 Apache-2.0 定义）都将以上述双许可授权，无附加条款。
