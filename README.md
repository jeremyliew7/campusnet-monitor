# 校园网连接助手（Windows 测试版）

这个本地工具定期检测网站的 HTTPS 首页，并在网站异常时帮助对照 DNS 和候选 IPv4 地址。适合先在少量可信电脑上试用；不同校园网、代理和浏览器的结果可能不同。

**当前验证边界：**网站检测、候选扫描以及隔离测试文件中的 hosts 添加和撤销已验证。Windows 管理员授权测试被取消，真实系统 hosts 写入尚未完成端到端验证；在补足这项验证及多电脑测试前，请勿用于同学电脑的正式修复。

## 使用

1. 在 Windows 10/11 64 位电脑上运行 `CampusNetMonitor.exe`。不需要单独安装 Python；系统需要自带 `curl.exe` 和 PowerShell 的 `Resolve-DnsName`。
2. 窗口打开时，默认每轮结束后等待 60 秒再检测。可调整间隔、暂停、手动刷新，也可添加 HTTPS 首页域名。
3. 选中网站后点击“检查可修复地址”。软件会查询本机默认 DNS；Google 搜索和 Google 学术还会将 `google.com` 的解析结果作为候选，逐个对目标域名验证证书和首页响应。也可以手动输入公网 IPv4。
4. 只有候选地址在 3 次测试中至少 2 次收到 HTTP 2xx/3xx 响应，才可查看应用方案。地址和变更范围显示出来后，用户确认并完成 Windows 管理员授权；写入前会重新测试地址、检查 hosts 未被其他程序修改。
5. 如该域名已有其他工具或用户维护的 hosts 记录，本软件会拒绝覆盖。选中网站可撤销本软件自己的记录；不会替换整个 hosts 文件。

## 如何理解结果

- “有响应 HTTP 200”表示本次 HTTPS 首页请求收到 200，不证明登录、搜索、对话、视频或页面全部资源正常。重定向、403、404、429 等单独显示。
- 检测使用不经过显式 HTTP 代理的请求；VPN/TUN 或校园网中间设备仍可能影响路径，结果可能与浏览器不同。
- 系统默认 DNS 的候选查询不使用 hosts；公共 DNS 查询默认关闭。若用户主动勾选 Google 公共 DNS，所检测的域名会发送给 Google。
- 候选地址不是永久地址；换网络或以后失效时应重新检测。能连接首页也不保证应用全部功能可用。
- 此版本只支持公网 IPv4 的 hosts 候选。不读取账号、密码或浏览器 Cookie，不设置开机启动、不主动上传日志，不更改系统 DNS、IPv6 或代理。
- `auth.openai.com`、`challenges.cloudflare.com`、`accounts.google.com` 不提供固定操作；登录和验证码域名保留动态解析。
- 默认网站是 Google 搜索、Google 学术、ChatGPT、GitHub、Hugging Face、arXiv；可添加自定义域名。

## 文件和权限

- 用户设置和修改前的 hosts 备份存放在 `%LOCALAPPDATA%\CampusNetMonitor`。备份可能包含原有 hosts 记录，请不要随意公开。
- 日常检测无需管理员权限。仅在用户确认 hosts 变更时，Windows 会请求管理员授权。软件只管理标记为 `CampusNet Monitor` 的独立区域；如果原 hosts 随后被其他程序更改，应用会拒绝按旧方案写入。
- 修改后会尝试刷新 Windows DNS 缓存。浏览器仍可能缓存旧结果，需要重新打开页面。若只想撤销某个条目，请使用“撤销本软件的记录”，不要用旧备份覆盖后来新增的其他内容。
- 本测试版没有代码签名，Windows SmartScreen 或安全软件可能提示未知发布者。请先在可信电脑上小范围测试，再决定是否分发；不要要求同学关闭安全软件或跳过他们不理解的警告。

## 开发与验证

源码只使用 Python 标准库及系统 `curl.exe`；打包使用 PyInstaller。运行源码前需要 Python 3.11+ 和 Tkinter：

```powershell
python campusnet.py
python -m unittest -v test_campusnet
```

测试覆盖候选 IP 格式、外部 hosts 冲突、文件变化保护、复测失败时拒绝写入，以及在隔离测试文件内添加和撤销记录。真实网站检测与独立浏览器使用仍应在目标电脑上验证。
