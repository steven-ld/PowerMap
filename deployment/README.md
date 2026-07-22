# 受管部署与升级

PowerMap 只有一个 `powermap` 二进制和一份 `powermap.toml`。运行时按配置中的
`[expose]`、`[access]` 决定能力；两段同时存在时同一进程同时运行两种能力。

## Linux: systemd

```bash
sudo useradd --system --home /var/lib/powermap --shell /usr/sbin/nologin powermap
sudo install -d -m 0750 -o powermap -g powermap /etc/powermap /var/lib/powermap /var/log/powermap
sudo install -m 0755 powermap /usr/local/bin/powermap
sudo install -m 0644 deployment/systemd/powermap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now powermap
sudo journalctl -u powermap -f
```

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
