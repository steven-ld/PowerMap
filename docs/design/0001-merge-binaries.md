# 设计文档 0001：合并 server / client 为单一 binary

- 状态：草案（待评审）
- 目标版本：v0.4.0（分阶段落地，可跨版本）
- 背景 issue：反向映射 / UDP / HTTP 网关加入后，server 与 client 的角色边界已模糊
- 前置：配置运行期类型与校验已收敛（`Allowlist` 共享管道 + `validate_allowlist`，见 `tunnel.rs` / `config.rs`）

## 1. 动机

现在有两个 binary：

| binary | 代码量 | 角色 | 特征 |
| --- | --- | --- | --- |
| `powermap-server` | ~599 行 | 内网侧 B | 被动。iroh ALPN 暴露服务，收连接后按白名单拨内网。不开入站端口。有稳定身份 + 多租户 token。 |
| `powermap-client` | ~3128 行 | 家里侧 A | 主动。Web 控制台 + 本地监听（TCP/UDP/HTTP 网关），复用一条 iroh 连接开多流。看门狗重连。 |

两者共享核心库：`config` / `proto` / `signal` / `tunnel` / `metrics`。差异只在 `src/bin/` 那层的装配与生命周期。

**边界模糊的根源**：反向映射让「谁主动、谁被动」不再等同于「谁是 server、谁是 client」——

- 正向：A 主动连 B，B 在内网拨号。
- 反向：B 在内网监听，收到连接后经隧道让 **A** 拨 A 自己一侧的目标。发起方变成了 B，拨号方变成了 A。

于是「装 server 还是 client」这个问题本身就站不住了：一个节点到底扮演什么角色，取决于它的配置和用法，而不是它是哪个可执行文件。

**目标**：收敛为单一 binary `powermap`。节点行为由配置决定，用户不再需要关心装哪个。

## 2. 术语：不再用 server / client

「server / client」正是要消除的概念。本设计用两个**能力（role）**来描述一个节点能做什么，一个节点可以同时具备两种：

- **expose（暴露方，原 B）**：把自己所在网络里的服务暴露出去。发布 iroh ALPN 服务，接受入站隧道，按白名单在本地网络拨号。有稳定身份、多租户 token、正向白名单。
- **access（接入方，原 A）**：接入别人暴露的网络。带 Web 控制台，本地起监听（TCP/UDP/HTTP 网关）把流量隧道到某个 expose 节点。有看门狗、指标、反向白名单。

反向映射在这套术语下是自然的：一个 access 节点可以开启「接受某 expose 节点发起的反向连接」，此时它按自己的**反向白名单（deny-all）**回拨自己一侧目标。

## 3. 安全边界（不可动摇的约束）

> 正向白名单空集 = 放行全部（allow-all）；反向白名单空集 = 全部拒绝（deny-all）。这两套相反的语义必须始终显式、互不干扰，不得因为共用代码而被意外统一。

这条约束在代码里已经落地并要在合并后**继续保持**：

- `tunnel::Allowlist`（私有）：只做 CIDR 解析、成员判断、DNS 安全解析，**不含任何空集语义**。
- `tunnel::TargetPolicy`（正向）：包裹 `Allowlist`，`resolve_allowed` 里 `nets_empty()` → 放行全部。
- `tunnel::ReversePolicy`（反向）：包裹 `Allowlist`，`resolve_allowed` 里 `ports_empty() || nets_empty()` → 一律拒绝。
- `config::validate_allowlist`：只校验格式（CIDR 可解析、端口非 0），正反向共用且安全。

**合并如何强化（而非削弱）这条边界**：合并后，

- 正向白名单永远只出现在 **expose 角色**的配置里（`[expose]` 下每个 client）。
- 反向白名单永远只出现在 **access 角色**的配置里（`[access]` 下的 `reverse_*`）。

两套白名单绑定在不同角色、不同配置段，物理上就分开了。**红线**：合并配置结构时，绝不允许抽出一个「通用 allowlist 配置结构」让 expose 的正向白名单和 access 的反向白名单复用同一个类型——那会给「用错空集语义」开口子。底层 `validate_allowlist`（纯格式）可以共用；承载语义的外层类型必须各自独立命名。

## 4. 配置模型

### 4.1 目标形态（统一 TOML）

一个配置文件，两个可选段。**只出现一个段 = 只扮演该角色；两个都出现 = 同时扮演。**

```toml
# 我把自己网络里的服务暴露出去（原 server）
[expose]
identity = "powermap.key"
max_streams_per_conn = 256
dial_timeout_secs = 10
audit_log = ""

[[expose.clients]]
id = "alice"
token = "…"
allow_networks = ["10.0.0.0/8"]   # 正向：留空 = 放行全部
allow_ports = [6379, 443]
  [[expose.clients.reverse]]       # 我为这个客户开的反向监听
  listen = "0.0.0.0:9000"
  target_host = "…"                # 由对端 access 节点回拨其一侧
  target_port = 22

# 我接入别人暴露的网络（原 client）
[access]
node_id = "…"
token = "…"
web_bind = "127.0.0.1:8088"
web_token = ""
reverse_enabled = false
reverse_allow_networks = []        # 反向：留空 = 全部拒绝
reverse_allow_ports = []

[[access.mappings]]
local = "127.0.0.1:6379"
host  = "10.0.0.5"
port  = 6379
mode  = "tcp"
```

对应的运行期类型：

```rust
pub struct Config {
    pub expose: Option<ExposeConfig>,   // 原 BConfig（去掉重复的全局项）
    pub access: Option<AccessConfig>,   // 原 AConfig
}
```

`ExposeConfig` / `AccessConfig` 基本就是现在的 `BConfig` / `AConfig` 换个名字搬进来。字段、`#[serde(default)]`、校验逻辑全部保留，因此正反向白名单的字段名与语义原地不动。

### 4.2 向后兼容

必须让现有部署零改动继续跑。三条路径都要覆盖：

1. **旧配置文件路径**：仍读 `powermap-server.toml` / `powermap-client.toml`。加载器规则：
   - 给定 `--config path`：按新格式 `Config` 解析；若解析出的 `expose`/`access` 均为空但文件非空，回退尝试按旧 `BConfig` / `AConfig` 解析（靠 `--role` 或文件名启发）。
   - 未给 `--config`：依次探测 `powermap.toml`（新）→ `powermap-server.toml` / `powermap-client.toml`（旧）。
2. **旧 TOML 内容**：旧文件顶层就是 `BConfig`/`AConfig` 字段（无 `[expose]`/`[access]` 包裹）。提供 `Config::from_legacy_b(BConfig)` / `from_legacy_a(AConfig)` 适配，把旧结构塞进对应段。**不自动改写用户文件**，只在内存里适配 + 打一条 deprecation 日志。
3. **迁移命令**：`powermap migrate --config old.toml --out powermap.toml` 生成新格式，供用户显式升级。

旧的多租户折叠逻辑（顶层 token → id="default"）原样保留在 `ExposeConfig` 里。

### 4.3 空配置的默认行为（安全默认）

合并后一个全新、空的配置该怎么办？——**默认只启用 access（Web 控制台），expose 必须显式开启。**

理由是安全对齐：access 只在本地监听、只主动连出，风险低；expose 会接受入站连接并在你的网络里拨号，属于「把内网暴露出去」，绝不能被静默打开。所以：

- 空配置 / 只有 `[access]`：启动 Web 控制台（可无凭证，等网页粘贴），行为等同现在的 client。
- 有 `[expose]`：启动暴露服务；首次运行生成 identity + 默认 token 并回写（等同现在的 server 首次行为）。
- 两段都有：并发启动两个角色（见 §5.3）。

## 5. 运行期架构

### 5.1 把角色逻辑下沉到库

现在生命周期逻辑困在 `src/bin/*.rs` 里，无法组合。合并的第一步是把它们抽成库函数：

```rust
// src/access.rs —— 原 client.rs 的 main 主体
pub async fn run(cfg: AccessConfig, shutdown: CancellationToken) -> Result<()>;

// src/expose.rs —— 原 server.rs 的 main 主体
pub async fn run(cfg: ExposeConfig, shutdown: CancellationToken) -> Result<()>;
```

- `access::run`：装配 `Link` / `AppState` / 看门狗 / 反向驱动 / axum web server，跑到 `shutdown` 触发。
- `expose::run`：装配 endpoint / `ClientRegistry` / `TunnelHandler` / iroh `Router`，跑到 `shutdown` 触发。
- 两者都接收一个外部 `CancellationToken`，把「监听信号」从角色逻辑里剥离出去，交给统一入口，这样两个角色能共享同一个关闭信号。

这一步是**纯搬迁 + 参数化关闭信号**，不改任何行为，现有全部单测 / 集成测试必须继续通过。是整个合并里风险最低、收益最大的一步（先把 3700 行拆干净，后面才好组合）。

### 5.2 统一入口

```rust
// src/bin/powermap.rs（或 src/main.rs）
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Config::load(&args)?;      // 含 §4.2 兼容加载
    cfg.validate()?;

    let shutdown = CancellationToken::new();
    spawn_signal_watcher(shutdown.clone());   // SIGINT/SIGTERM → cancel

    let mut tasks = Vec::new();
    if let Some(e) = cfg.expose { tasks.push(spawn(expose::run(e, shutdown.clone()))); }
    if let Some(a) = cfg.access { tasks.push(spawn(access::run(a, shutdown.clone()))); }
    if tasks.is_empty() { /* 空配置 → 起 access 默认控制台，见 §4.3 */ }

    join_all(tasks).await;   // 任一角色 panic/退出都要传播
    Ok(())
}
```

### 5.3 两角色共存

一个节点同时 expose + access 是合法组合（例如：既把家里网络暴露给公司，又通过公司节点访问公司内网）。要点：

- 两个角色各自持有独立的 iroh endpoint（expose 需要稳定 identity；access 用临时身份即可），互不干扰。
- 正向策略（expose）与反向策略（access）是两套独立对象，天然分离（§3）。
- 指标：两角色共用一个 `Metrics` 实例，`/metrics` 端点按 `role="expose"|"access"` 标签区分计数（见 §8 决策 2）。
- 关闭：共享 `CancellationToken`，access 先 drain 在途隧道再停 HTTP，expose 停 iroh router，互不阻塞。

### 5.4 CLI

主模式是配置驱动。为改善首次体验，保留少量便捷子命令：

```
powermap                      # 角色由配置决定（主模式）
powermap --config <path>      # 指定配置
powermap expose               # 便捷：脚手架/强制启用 expose（首次生成配置）
powermap access               # 便捷：脚手架/强制启用 access
powermap migrate --out <p>    # 旧配置 → 新格式
```

`expose` / `access` 子命令不是常态运行所必需，只是让「我想暴露服务」这类意图能一句话起步。

## 6. 兼容与迁移

- **binary 名**：新增 `powermap`。旧的 `powermap-server` / `powermap-client` 保留一个发布周期作为**薄 shim**——各自加载自己的旧配置文件、以对应角色调用 `expose::run` / `access::run`，并打 deprecation 提示。下一个大版本移除。
- **配置文件**：旧文件继续可读（§4.2）。不强制迁移，提供 `migrate` 命令。
- **凭证格式**：`tunnel::Credential`（node_id + token + published_targets）不变，A/B 之间的握手协议（`proto`）完全不动。合并是进程组织层面的事，不触碰线上协议。
- **文档**：README / README.en / CHANGELOG 更新为「单 binary + 两角色」叙事，附旧→新迁移小节。

## 7. 分阶段落地

按风险从低到高，每阶段独立可发布、可回滚：

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| **P0（已完成）** | 配置运行期类型 + 校验收敛（`Allowlist` 管道 / `validate_allowlist`） | 正反向策略测试通过 |
| **P1** | 角色逻辑下沉到 `src/access.rs` / `src/expose.rs`，接收外部 `CancellationToken`；旧 binary 改为薄 shim 调用之 | 零行为变更；全部现有测试通过；两个旧 binary 照常工作 |
| **P2** | 统一 `Config` 类型 + `powermap` 入口 + 统一 TOML + 兼容加载器 + `migrate` 命令 | 旧配置文件零改动可跑；新配置可跑；两角色可共存；新增兼容加载 / 迁移测试 |
| **P3** | 文档全面改写；旧 binary 标记 deprecated（保留一版）；Web 控制台增加 expose 角色的只读展示（可选） | 迁移指南完整；deprecation 日志到位 |
| **P4（未来）** | 移除旧 binary shim | — |

P1 是承重墙：先把代码拆干净、证明行为不变，再谈组合。P2 才引入格式变更（有兼容层兜底）。

## 8. 已定决策

先前的四个待决问题现已敲定，作为动手依据：

1. **术语采用 `expose` / `access`。**
   - `expose`（暴露方，原 server）：把自己所在网络的服务暴露出去，接受入站连接、在本网络内拨号。
   - `access`（接入方，原 client）：接入某个 expose 节点、把其网络的服务映射到本地；同时是反向映射里「回拨自己一侧目标」的一方。
   - 淘汰 server / client：反向映射已让「谁主动」与「谁是 server」错位，用能力（暴露 / 接入）命名比用部署位置命名更贴合实际。备选 `provide`/`consume`、`host`/`connect` 不采用——`host` 与主机名概念冲突，`provide/consume` 不如 expose/access 直指「暴露网络」这一安全语义。
   - 影响面：新配置段名 `[expose]` / `[access]`、CLI 子命令 `powermap expose|access`、文档叙事、Metrics `role` 标签值。

2. **两角色共存时用单个 `Metrics` 实例 + `role` 标签。** 一个 `/metrics` 端点，计数按 `role="expose"|"access"` 区分。避免两份独立 `Metrics` 带来的端点/聚合复杂度；标签方案与 Prometheus 惯例一致。仅 access 角色开 HTTP，故 `/metrics` 端点始终由 access 侧提供；纯 expose 节点沿用现状（指标周期性打日志，不开入站端口）。

3. **expose 角色的 Web 展示推迟到 P3，且只读。** P2 不动控制台，expose 继续纯日志（与现在的 server 一致）。P3 再在控制台加一块**只读**的 expose 状态（在线客户、反向监听），不引入对 expose 的写操作——写操作会扩大 Web 面的攻击面，与「expose 必须显式、保守」的默认相悖。

4. **共存时 access 与 expose 各持独立 iroh endpoint 身份。** expose 需要稳定 identity（node_id 要长期发给对端），access 用临时身份即可。两者独立，语义清晰，也避免「暴露方身份」与「接入方身份」被同一密钥耦合。

## 9. 非目标

- 不改 A↔B 的线上协议（`proto`）。
- 不改正向 / 反向白名单的空集语义（§3 红线）。
- 不在本设计内做「自动双向发现 / 无需交换凭证」之类的新能力——那是独立特性。
