# 受管部署与升级

PowerMap 只有一个 `powermap` 二进制和一份 `powermap.toml`。运行时按配置中的
`[expose]`、`[access]` 决定能力；两段同时存在时同一进程同时运行两种能力。

## Linux: systemd

```bash
sudo install -d -m 0700 /etc/powermap /var/lib/powermap /var/log/powermap
sudo install -m 0755 powermap /usr/local/bin/powermap
sudo install -m 0644 deployment/systemd/powermap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now powermap
sudo journalctl -u powermap -f
```

该 systemd 模板以 root 运行，仅用于让域名映射原子更新 `/etc/hosts` 并绑定回环
端口 `443`。**root 运行 access 能力时必须**先在 `/etc/powermap/powermap.toml` 设置
高强度 `web_token`；即使 `web_bind` 是回环地址，令牌为空也会使服务在启动阶段失败，
避免以 root 身份提供未鉴权的映射、凭证和配置管理 API。保持配置文件权限为 `0600`。
多个域名共享 `127.0.0.1:443`，按客户端 TLS SNI 分流；不发送 SNI 的旧客户端不能使用
此功能。

PowerMap 编辑 hosts 时会持有 `/etc/.hosts.powermap.lock`，在读取、修改和原子替换期间
串行化多个 PowerMap 进程，避免它们互相覆盖条目。这是协作式锁：不使用该锁的外部 hosts
编辑器仍可能与 PowerMap 并发写入；在同一主机上应协调此类写入。

首次在内网设备直接运行 `powermap`，会创建 `powermap.toml`、`powermap.key`
与 `powermap.credential.json`。把凭证安全传给接入设备；接入设备也直接运行
`powermap`，再在本地控制台粘贴凭证即可。

升级时，安装脚本会覆盖二进制但保留配置、身份、映射和凭证。对 systemd 服务使用：

```bash
POWERMAP_RESTART_SERVICE=1 sh install.sh
```

该命令在下载并校验 Release 后自动重启已启用的 `powermap.service`。

## macOS 与 Windows

macOS 可把统一 LaunchAgent 安装为开机常驻：

```bash
sudo install -m 0755 powermap /usr/local/bin/powermap
mkdir -p "$HOME/Library/Logs/PowerMap" "$HOME/Library/LaunchAgents"
sed "s|/Users/REPLACE_ME|$HOME|g" deployment/launchd/com.powermap.plist > "$HOME/Library/LaunchAgents/com.powermap.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.powermap.plist"
```

Windows 安装后注册一个统一计划任务：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
powershell -ExecutionPolicy Bypass -File deployment/windows/register-scheduled-task.ps1 -StartNow
```

首次使用直接运行 `powermap`；控制台会同时显示本机节点与远端节点。Windows 更新已有计划任务时在安装命令加入 `-RestartTask`；安装后会自动重启名为 `PowerMap` 的任务。

## 远程管理

默认管理页仅监听 `127.0.0.1:8088`。远程查看时优先 SSH 隧道：

```bash
ssh -N -L 8088:127.0.0.1:8088 admin@powermap-host
```

必须经 HTTPS 发布时，使用 [Nginx 模板](nginx/powermap-admin.conf)，并同时设置
`web_token`、mTLS 和来源 CIDR 限制。不要直接把管理端口暴露到公网。
