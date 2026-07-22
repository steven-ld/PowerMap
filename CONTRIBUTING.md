# 贡献指南 / Contributing

感谢你对 PowerMap 的关注！欢迎 issue、PR 和讨论。
Thanks for your interest in PowerMap! Issues, PRs and discussions are welcome.

## 开发环境 / Development setup

需要 Rust 1.85+（`edition = "2024"`）。

```bash
git clone https://github.com/steven-ld/PowerMap.git
cd PowerMap
cargo build
```

> 国内网络若拉不到 crates.io，可在 `~/.cargo/config.toml` 里换成 rsproxy 源（见 README）。

## 提交前自检 / Before you commit

CI 会在每次 push / PR 上运行 fmt + clippy(`-D warnings`) + test。请在本地先跑一遍，保持绿色：

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

一条命令跑全部：

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test
```

## 提交规范 / Commit & PR

- 提交信息用祈使句、说清「做了什么、为什么」，推荐 [Conventional Commits](https://www.conventionalcommits.org/)（`feat:`、`fix:`、`docs:` …），但不强制。
- 一个 PR 聚焦一件事，改动尽量小而完整。
- 涉及行为/协议/配置变更时，请同步更新 `README.md`（及 `README.en.md`）。
- 新功能或修 bug 尽量带上测试。

## 报告问题 / Reporting issues

提 issue 时请附上：

- 复现步骤、期望与实际行为；
- 版本（`powermap --version` / 对应 commit 或 release tag）、操作系统；
- 相关日志（`RUST_LOG=debug`），**请先脱敏**——不要粘贴 `token`、`node_id`、`credential.json` 等机密。

## 安全问题 / Security

发现安全漏洞请**不要**公开提 issue，先私下联系维护者（见仓库主页联系方式）。
Please report security vulnerabilities privately rather than in a public issue.

## 许可 / License

本项目采用 MIT 或 Apache-2.0 双许可。提交贡献即表示你同意你的贡献在同样的双许可下发布。
Unless you state otherwise, any contribution you submit is dual-licensed under MIT OR Apache-2.0.
