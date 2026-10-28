"""Local-only website probes and narrow, byte-preserving hosts changes."""
from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

BEGIN = b"# >>> CampusNet Monitor >>>"
END = b"# <<< CampusNet Monitor <<<"
PROTECTED_HOSTS = {"auth.openai.com", "challenges.cloudflare.com", "accounts.google.com"}
DNS_TIMEOUT = 12
PROBE_TIMEOUT = 8
DEFAULT_SITES = [
    {"name": "Google 搜索", "host": "www.google.com"},
    {"name": "Google 学术", "host": "scholar.google.com"},
    {"name": "ChatGPT", "host": "chatgpt.com"},
    {"name": "GitHub", "host": "github.com"},
    {"name": "Hugging Face", "host": "huggingface.co"},
    {"name": "arXiv", "host": "arxiv.org"},
]


def normalize_host(value: str) -> str:
    value = value.strip()
    if "://" in value:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() != "https" or parsed.username or parsed.password:
            raise ValueError("请输入 HTTPS 网站，不支持用户名、密码或其他协议。")
        if parsed.port not in (None, 443) or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("请输入网站域名或 HTTPS 首页地址，不包含路径、参数或端口。")
        value = parsed.hostname or ""
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("域名格式不正确。") from exc
    if len(host) > 253 or "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise ValueError("请输入有效的网站域名，例如 example.com。")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split(".")):
        raise ValueError("域名格式不正确。")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("请输入域名，不要直接输入 IP 地址。")


def public_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("请输入有效的 IPv4 地址。") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise ValueError("修复候选必须是公网 IPv4 地址。")
    return str(address)


def hosts_path() -> Path:
    if os.name != "nt":
        raise RuntimeError("当前版本仅支持 Windows。")
    return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mappings(data: bytes) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        for alias in parts[1:]:
            name = alias.rstrip(".").lower()
            if name in found and found[name] != parts[0]:
                raise ValueError(f"hosts 中存在重复映射：{name}")
            found[name] = parts[0]
    return found


def split_own_block(data: bytes) -> tuple[bytes, bytes]:
    lines = data.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    if not starts and not ends:
        return data, b""
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError("本软件的 hosts 标记异常，请先检查原文件。")
    a, b = starts[0], ends[0] + 1
    return b"".join(lines[:a] + lines[b:]), b"".join(lines[a:b])


def host_state(data: bytes, host: str) -> dict:
    host = normalize_host(host)
    outside, block = split_own_block(data)
    outside_map, own_map = _mappings(outside), _mappings(block)
    return {"external": outside_map.get(host), "own": own_map.get(host)}


def render_hosts(data: bytes, host: str, address: str | None) -> tuple[bytes, dict]:
    host = normalize_host(host)
    if address is not None and host in PROTECTED_HOSTS:
        raise ValueError("此认证或验证域名保留动态解析，本软件不会固定地址。")
    outside, block = split_own_block(data)
    external = _mappings(outside)
    if host in external:
        raise ValueError("该域名已有其他工具或用户维护的 hosts 记录，本软件不会覆盖。")
    # Refuse to discard edits or comments made inside our generated block.
    if block:
        for line in block.splitlines()[1:-1]:
            fields = line.split()
            if len(fields) != 2 or line.lstrip().startswith(b"#"):
                raise ValueError("本软件的管理区被手动修改，请先检查原文件。")
    own = _mappings(block)
    previous = own.get(host)
    if address is None:
        if host not in own:
            raise ValueError("该域名没有由本软件添加的记录。")
        del own[host]
    else:
        own[host] = public_ipv4(address)
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    generated = b""
    if own:
        generated = newline.join([BEGIN] + [f"{ip} {name}".encode("ascii") for name, ip in sorted(own.items())] + [END]) + newline
    if block:
        after = data.replace(block, generated, 1)
    elif generated:
        after = data + (newline if data and not data.endswith(b"\n") else b"") + generated
    else:
        after = data
    return after, {"host": host, "before": previous, "after": address, "changed": after != data}


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


def curl_path() -> str:
    if os.name == "nt":
        native = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"
        if native.is_file():
            return str(native)
    result = shutil.which("curl")
    if not result:
        raise RuntimeError("未找到 curl。请使用带有系统 curl 的 Windows 10/11。")
    return result


def probe(host: str, ip: str | None = None, timeout: int = PROBE_TIMEOUT) -> dict:
    host = normalize_host(host)
    args = [curl_path(), "--disable", "--silent", "--show-error", "--output", os.devnull,
            "--connect-timeout", "4", "--max-time", str(timeout), "--noproxy", "*",
            "--user-agent", "CampusNetMonitor/0.1", "--write-out",
            "%{http_code}|%{remote_ip}|%{time_connect}|%{time_appconnect}|%{time_total}"]
    if ip:
        args += ["-4", "--resolve", f"{host}:443:{public_ipv4(ip)}"]
    args += [f"https://{host}/"]
    try:
        process = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 4,
                                 creationflags=_creation_flags())
    except subprocess.TimeoutExpired:
        return {"state": "timeout", "status": "连接超时", "http": 0, "ip": "", "exit": 28, "tcp": 0.0}
    fields = process.stdout.strip().split("|")
    try:
        code = int(fields[0])
        remote = fields[1]
        tcp, tls, total = (float(x) for x in fields[2:5])
    except (IndexError, ValueError):
        code, remote, tcp, tls, total = 0, "", 0.0, 0.0, 0.0
    exit_code = process.returncode
    if exit_code == 6:
        state, status = "dns", "DNS 解析失败"
    elif exit_code == 28:
        state, status = "timeout", "连接超时" if tcp == 0 else "连接后超时"
    elif exit_code == 7:
        state, status = "connect", "连接失败"
    elif exit_code in (35, 60, 77):
        state, status = "tls", "证书或安全连接异常"
    elif exit_code:
        state, status = "error", f"连接失败（错误 {exit_code}）"
    elif 200 <= code < 300:
        state, status = "ok", f"有响应 HTTP {code}"
    elif 300 <= code < 400:
        state, status = "redirect", f"跳转 HTTP {code}"
    elif code in (401, 403, 429):
        state, status = "limited", f"受限 HTTP {code}"
    elif code == 404:
        state, status = "limited", "首页路径 HTTP 404"
    else:
        state, status = "limited", f"响应 HTTP {code}"
    return {"state": state, "status": status, "http": code, "ip": remote,
            "exit": exit_code, "tcp": tcp, "tls": tls, "total": total}


def dns_candidates(host: str) -> tuple[list[str], str]:
    host = normalize_host(host)
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return [], "系统 DNS 查询不可用"
    # normalize_host restricts the inserted string to safe ASCII domain characters.
    script = (f"$ErrorActionPreference='Stop'; $a=@(Resolve-DnsName -Name '{host}' "
              "-Type A -DnsOnly -NoHostsFile -QuickTimeout | "
              "Where-Object { $_.Type -eq 'A' -and $_.Section -eq 'Answer' } | "
              "Select-Object -ExpandProperty IPAddress); ConvertTo-Json -InputObject $a -Compress")
    try:
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, timeout=DNS_TIMEOUT,
                                creationflags=_creation_flags())
        if result.returncode != 0:
            return [], "系统 DNS 未返回 IPv4 地址"
        parsed = json.loads(result.stdout.strip() or "[]")
        raw = parsed if isinstance(parsed, list) else [parsed]
        values = []
        for item in raw:
            try:
                address = public_ipv4(str(item))
                if address not in values:
                    values.append(address)
            except ValueError:
                pass
        return values, "系统默认 DNS（不读取 hosts）"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return [], "系统 DNS 查询失败或超时"


def public_dns_candidates(host: str) -> tuple[list[str], str]:
    host = normalize_host(host)
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": host, "type": "A"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=6) as response:
            obj = json.loads(response.read(65536).decode("utf-8"))
        values = []
        for row in obj.get("Answer", []):
            if row.get("type") == 1:
                try:
                    value = public_ipv4(str(row.get("data", "")))
                    if value not in values:
                        values.append(value)
                except ValueError:
                    pass
        return values, "Google 公共 DNS（已向其发送域名）"
    except (OSError, ValueError, json.JSONDecodeError):
        return [], "Google 公共 DNS 查询失败"


def scan(host: str, manual: str = "", include_public: bool = False, cancelled=None) -> tuple[list[dict], list[str]]:
    host = normalize_host(host)
    cancelled = cancelled or (lambda: False)
    addresses, notes = {}, []
    normal, note = dns_candidates(host)
    notes.append(note)
    if cancelled():
        return [], notes
    for ip in normal:
        addresses.setdefault(ip, []).append("系统 DNS")
    if host in {"www.google.com", "scholar.google.com"}:
        extras, note = dns_candidates("google.com")
        notes.append("Google 候选来源：" + note)
        for ip in extras:
            addresses.setdefault(ip, []).append("google.com DNS")
    try:
        state = host_state(hosts_path().read_bytes(), host)
        for kind in ("own", "external"):
            if state[kind]:
                try:
                    addresses.setdefault(public_ipv4(state[kind]), []).append("当前 hosts")
                except ValueError:
                    pass
    except (OSError, ValueError):
        notes.append("无法读取现有 hosts")
    if manual.strip():
        addresses.setdefault(public_ipv4(manual), []).append("手动输入")
    if include_public and not cancelled():
        public, note = public_dns_candidates(host)
        notes.append(note)
        for ip in public:
            addresses.setdefault(ip, []).append("Google 公共 DNS")
    # Put a manually requested or currently active address ahead of a long DNS answer.
    def priority(row: tuple[str, list[str]]) -> tuple:
        sources = row[1]
        return ("手动输入" not in sources, "当前 hosts" not in sources,
                "google.com DNS" not in sources, "Google 公共 DNS" not in sources, row[0])
    items = sorted(addresses.items(), key=priority)[:8]

    def check(row: tuple[str, list[str]]) -> dict:
        ip, sources = row
        samples = []
        for _ in range(3):
            if cancelled():
                break
            samples.append(probe(host, ip))
        usable = sum(s["exit"] == 0 and 200 <= s["http"] < 400 for s in samples)
        reached = sum(s["exit"] == 0 and s["http"] > 0 for s in samples)
        return {"ip": ip, "sources": sources, "usable": usable, "reached": reached, "samples": samples}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(check, items))
    return results, notes


def apply_hosts(host: str, address: str | None, expected_hash: str, created: int) -> bool:
    host = normalize_host(host)
    if address is not None and host in PROTECTED_HOSTS:
        raise ValueError("此认证或验证域名保留动态解析，本软件不会固定地址。")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("无效的文件校验值。")
    if not 0 <= time.time() - int(created) <= 900:
        raise ValueError("修复方案已过期，请重新检测。")
    if address is not None:
        address = public_ipv4(address)
        samples = [probe(host, address) for _ in range(3)]
        if sum(s["exit"] == 0 and 200 <= s["http"] < 400 for s in samples) < 2:
            raise ValueError("地址复测未通过，未修改 hosts。")
    path = hosts_path()
    # Lock the actual file while rechecking its bytes; do not replace its ACL.
    with path.open("r+b") as stream:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            before = stream.read()
            if sha256(before) != expected_hash:
                raise ValueError("hosts 已发生变化，请重新生成方案。")
            after, change = render_hosts(before, host, address)
            if not change["changed"]:
                raise ValueError("记录没有变化。")
            try:
                stream.seek(0)
                stream.write(after)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
            except OSError:
                stream.seek(0)
                stream.write(before)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
                raise
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
    if os.name == "nt":
        try:
            result = subprocess.run([str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ipconfig.exe"), "/flushdns"],
                                    capture_output=True, timeout=10, creationflags=_creation_flags(), check=False)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False
    return True
