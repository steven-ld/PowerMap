# 受管部署与远程管理

这些模板将 PowerMap 作为长期运行的本地进程管理。它们不改变运行时默认值：client 管理页仍只监听 `127.0.0.1:8088`，映射也应使用本地回环地址。首次在隔离环境验证后再交给服务管理器。

## Linux: systemd

以下示例以 `powermap` 这个无登录系统用户运行，并把配置、身份和凭证限制在该用户与 root 可读的目录中。将已校验的 Release 二进制安装到 `/usr/local/bin` 后执行：

```bash
sudo useradd --system --home /var/lib/powermap --shell /usr/sbin/nologin powermap
sudo install -d -m 0750 -o powermap -g powermap /etc/powermap /var/lib/powermap /var/log/powermap
sudo install -m 0755 powermap-server powermap-client /usr/local/bin/
sudo install -m 0644 deployment/systemd/powermap-server.service deployment/systemd/powermap-client.service /etc/systemd/system/
sudo systemctl daemon-reload
```

在内网机器启用 server：

```bash
sudo systemctl enable --now powermap-server
sudo journalctl -u powermap-server -f
```

首次启动会在 `/etc/powermap/` 创建配置、身份和 `powermap-server.credential.json`。仅通过安全渠道把凭证交给 client 所在机器。client 可先用 `--credential` 写入其配置，随后交给 systemd：

```bash
sudo -u powermap /usr/local/bin/powermap-client \
  --config /etc/powermap/powermap-client.toml \
  --credential /secure/path/powermap-server.credential.json
sudo systemctl enable --now powermap-client
sudo journalctl -u powermap-client -f
```

服务使用 `Restart=on-failure`，PowerMap 在收到 `SIGTERM` 时会先收尾已有隧道。升级时先停止对应服务，替换并校验二进制，然后重启：

```bash
sudo systemctl stop powermap-client
sudo install -m 0755 powermap-client /usr/local/bin/powermap-client
sudo systemctl start powermap-client
sudo systemctl status powermap-client --no-pager
```

配置位于 `/etc/powermap/`，所以替换二进制不会丢失映射或身份。回滚只需安装上一个已经校验的二进制并重启服务。

## macOS: launchd

这两个模板是当前登录用户的 LaunchAgent，适合个人电脑和常驻的内网 Mac。先把二进制放在 `/usr/local/bin`，并把模板中的 `/Users/REPLACE_ME/` 改成当前实际用户目录；launchd 不会展开 `~`。

```bash
sudo install -m 0755 powermap-server powermap-client /usr/local/bin/
mkdir -p "$HOME/Library/Logs/PowerMap" "$HOME/Library/LaunchAgents"
sed "s|/Users/REPLACE_ME|$HOME|g" deployment/launchd/com.powermap.client.plist \
  > "$HOME/Library/LaunchAgents/com.powermap.client.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.powermap.client.plist"
launchctl kickstart -k "gui/$(id -u)/com.powermap.client"
tail -f "$HOME/Library/Logs/PowerMap/powermap-client.log"
```

server 同理使用 `com.powermap.server.plist`。默认配置目录为 `~/Library/Application Support/powermap/`。升级后使用 `launchctl kickstart -k gui/$(id -u)/com.powermap.client` 重启；卸载使用 `launchctl bootout gui/$(id -u)/com.powermap.client`。若需要在没有用户登录时运行 server，请由管理员把模板改为 LaunchDaemon，并显式指定专用用户、配置目录和日志目录。

## Windows: Task Scheduler

先运行 Release 安装脚本，再注册当前用户的登录任务。任务在异常退出后最多重试三次，日志写入 `%LOCALAPPDATA%\PowerMap\logs`。可选的 `-ConfigPath` 让部署位置明确；默认使用 `%APPDATA%\powermap\powermap-<role>.toml`。

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
powershell -ExecutionPolicy Bypass -File deployment/windows/register-scheduled-task.ps1 -Role client -StartNow
Get-ScheduledTask -TaskName PowerMap-client
Get-Content "$env:LOCALAPPDATA\PowerMap\logs\powermap-client.log" -Wait
```

在内网机器注册 server 时把 `-Role client` 换成 `-Role server`。更新二进制后执行 `Start-ScheduledTask -TaskName PowerMap-client`；删除任务使用 `Unregister-ScheduledTask -TaskName PowerMap-client -Confirm:$false`。

## 远程管理

首选 SSH 隧道，它不增加任何公开的 HTTP 入口。保持 client 的 `web_bind = "127.0.0.1:8088"`，然后在管理员电脑运行：

```bash
ssh -N -L 8088:127.0.0.1:8088 admin@client-host
```

之后访问本机的 `http://127.0.0.1:8088`。

必须使用 HTTPS 网关时，使用 [Nginx 模板](nginx/powermap-admin.conf) 并**仍然**保持 PowerMap 监听在 `127.0.0.1:8088`。该模板要求：

1. 在 client 配置中生成强随机 `web_token`，例如 `openssl rand -hex 32`，并重启 client。
2. 将可信 CA 签发的站点证书和只发给管理员的客户端证书配置到 Nginx。
3. 将示例 `server_name`、证书路径与 `allow 203.0.113.0/24` 改为实际值；不要使用 `allow all`。
4. 执行 `sudo nginx -t && sudo systemctl reload nginx`。

网关要求 mTLS 和来源 CIDR 两层限制，并把 PowerMap 的 `/metrics` 与 `/api/health` 返回 404，因为这两个端点不要求 `web_token`。管理页仍会要求输入 `web_token`，令牌只在浏览器当前页面内存中保存。模板关闭该虚拟主机访问日志，避免包括被拒绝的旧 `?token=` 请求在内的查询字符串落盘。

部署后应验证：公网地址无法直接到达 `:8088`；无客户端证书的 HTTPS 请求失败；有证书但没有 `web_token` 的管理 API 返回 401；远程 `/metrics` 与 `/api/health` 返回 404。不要把 client 的管理端口直接发布到互联网。
