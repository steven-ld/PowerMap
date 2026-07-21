# ---- 构建阶段：编译两个二进制 ----
FROM rust:1-bookworm AS builder
WORKDIR /app

# 先只拷贝 Cargo.toml 并用桩代码构建一次，把 iroh 等依赖缓存到独立层，
# 之后改动源码不会重新编译依赖。
COPY Cargo.toml ./
RUN mkdir -p src/bin src/web && \
    printf 'pub mod config;\npub mod metrics;\npub mod proto;\npub mod signal;\npub mod tunnel;\n' > src/lib.rs && \
    : > src/config.rs && : > src/metrics.rs && : > src/proto.rs && \
    : > src/signal.rs && : > src/tunnel.rs && \
    printf 'fn main(){}\n' > src/bin/server.rs && \
    printf 'fn main(){}\n' > src/bin/client.rs && \
    : > src/web/index.html && \
    cargo build --release

# 拷贝真正的源码并编译（依赖已缓存，只编译本项目）
COPY src ./src
RUN touch src/lib.rs src/bin/server.rs src/bin/client.rs && \
    cargo build --release

# ---- 运行阶段：精简镜像（glibc 版本与构建端对齐） ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/powermap-client /usr/local/bin/powermap-client
COPY --from=builder /app/target/release/powermap-server /usr/local/bin/powermap-server
# 默认入口打印帮助；用 `command: ["powermap-server"]` 或 `docker run powermap powermap-server` 选择端
ENTRYPOINT ["sh", "-c", "exec \"$@\"", "--"]
CMD ["powermap-server", "--help"]
