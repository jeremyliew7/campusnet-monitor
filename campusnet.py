"""CampusNet Monitor: a local Windows website connectivity helper."""
from __future__ import annotations

import concurrent.futures
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import uuid
import webbrowser

import campusnet_core as core

APP_NAME = "校园网连接助手"


def data_dir() -> Path:
    override = os.environ.get("CAMPUS_NET_DATA_DIR")
    base = Path(override) if override else Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "CampusNetMonitor"
    base.mkdir(parents=True, exist_ok=True)
    return base


def read_settings() -> dict:
    path = data_dir() / "settings.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        custom = []
        seen = {site["host"] for site in core.DEFAULT_SITES}
        for item in data.get("custom", []):
            host = core.normalize_host(str(item.get("host", "")))
            if host not in seen:
                custom.append({"name": str(item.get("name", host))[:60], "host": host})
                seen.add(host)
        interval = int(data.get("interval", 60))
        return {"custom": custom, "interval": interval if interval in (30, 60, 120, 300) else 60}
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return {"custom": [], "interval": 60}


def save_settings(settings: dict) -> None:
    path = data_dir() / "settings.json"
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temp.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def backup_hosts(data: bytes) -> Path:
    folder = data_dir() / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (time.strftime("hosts-%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8] + ".bak")
    with path.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    if core.sha256(path.read_bytes()) != core.sha256(data):
        raise OSError("备份校验失败，未继续修改。")
    return path


def elevated_main(args: list[str]) -> int:
    if os.name != "nt" or len(args) != 5:
        return 10
    operation, host, address, expected_hash, created = args
    if operation not in {"set", "remove"}:
        return 10
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return 11
    try:
        flushed = core.apply_hosts(host, None if operation == "remove" else address, expected_hash, int(created))
        return 0 if flushed else 17
    except ValueError as exc:
        text = str(exc)
        if "复测" in text:
            return 12
        if "变化" in text or "过期" in text:
            return 13
        if "其他工具" in text or "管理区" in text:
            return 14
        return 15
    except Exception:
        return 16


def run_elevated(args: list[str]) -> int:
    if os.name != "nt":
        raise OSError("当前版本仅支持 Windows。")

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

    launch_args = ["--elevated"] + args
    if not getattr(sys, "frozen", False):
        launch_args.insert(0, str(Path(__file__).resolve()))
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFO)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    info = SHELLEXECUTEINFO()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = sys.executable
    info.lpParameters = subprocess.list2cmdline(launch_args)
    info.nShow = 0
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:
            raise OSError("已取消 Windows 管理员授权。")
        raise OSError(f"无法启动管理员操作（Windows 错误 {error}）。")
    if not info.hProcess:
        raise OSError("无法获取管理员操作状态。")
    return int(info.hProcess)


class CandidateDialog:
    def __init__(self, app: "Application", site: dict):
        self.app, self.site = app, site
        self.window = tk.Toplevel(app.root)
        self.window.title(f"检查可修复地址 · {site['name']}")
        self.window.geometry("790x520")
        self.window.minsize(680, 440)
        self.window.transient(app.root)
        self.results: list[dict] = []
        self.busy = False
        self.cancelled = threading.Event()
        box = ttk.Frame(self.window, padding=18)
        box.pack(fill="both", expand=True)
        ttk.Label(box, text=f"检查 {site['host']} 的候选地址", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(box, text="每个地址独立验证域名证书并请求首页 3 次；最多测试 8 个地址。", wraplength=740).pack(anchor="w", pady=(6, 12))
        controls = ttk.Frame(box)
        controls.pack(fill="x")
        ttk.Label(controls, text="补充 IPv4（可选）").pack(side="left")
        self.manual = tk.StringVar()
        ttk.Entry(controls, textvariable=self.manual, width=20).pack(side="left", padx=8)
        self.public = tk.BooleanVar(value=False)
        ttk.Checkbutton(box, text="同时查询 Google 公共 DNS（会向 Google 发送此域名）", variable=self.public).pack(anchor="w", pady=8)
        table_frame = ttk.Frame(box)
        self.table = ttk.Treeview(table_frame, columns=("ip", "source", "result"), show="headings", height=9)
        for key, text, width in [("ip", "IPv4 地址", 150), ("source", "地址来源", 220), ("result", "验证结果", 270)]:
            self.table.heading(key, text=text)
            self.table.column(key, width=width, stretch=True)
        self.note = tk.StringVar(value="点击“开始检测”。这一步不会修改系统设置。")
        actions = ttk.Frame(box)
        actions.pack(side="bottom", fill="x", pady=(8, 0))
        self.scan_button = ttk.Button(actions, text="开始检测", command=self.start_scan)
        self.scan_button.pack(side="left")
        ttk.Button(actions, text="查看并应用选中地址", command=self.prepare).pack(side="left", padx=8)
        ttk.Button(actions, text="关闭", command=self.close).pack(side="right")
        ttk.Label(box, textvariable=self.note, wraplength=740).pack(side="bottom", anchor="w", fill="x", pady=8)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(side="left", fill="both", expand=True)
        table_frame.pack(fill="both", expand=True)
        self.window.protocol("WM_DELETE_WINDOW", self.close)

    def close(self) -> None:
        self.cancelled.set()
        self.window.destroy()

    def start_scan(self) -> None:
        if self.busy:
            return
        manual = self.manual.get().strip()
        if manual:
            try:
                core.public_ipv4(manual)
            except ValueError as exc:
                messagebox.showerror(APP_NAME, str(exc), parent=self.window)
                return
        self.busy = True
        self.scan_button.configure(state="disabled")
        self.note.set("正在查询并逐个验证，请稍候……")
        self.table.delete(*self.table.get_children())
        include_public = self.public.get()

        def work():
            try:
                rows, notes = core.scan(self.site["host"], manual, include_public,
                                        lambda: self.cancelled.is_set() or self.app.stop_event.is_set())
                self.app.dispatch(lambda: self.finish(rows, notes))
            except Exception as exc:
                text = str(exc)
                self.app.dispatch(lambda: self.failed(text))
        threading.Thread(target=work, daemon=True).start()

    def finish(self, rows: list[dict], notes: list[str]) -> None:
        if not self.window.winfo_exists():
            return
        self.busy = False
        self.scan_button.configure(state="normal")
        self.results = rows
        for index, row in enumerate(rows):
            result = f"可连接 {row['usable']}/3" if row["usable"] >= 2 else f"未通过；收到响应 {row['reached']}/3"
            self.table.insert("", "end", iid=str(index), values=(row["ip"], "、".join(row["sources"]), result))
        self.note.set(("；".join(notes) + "。") if rows else "未找到可测试的公网 IPv4；hosts 不一定能解决此问题。")

    def failed(self, text: str) -> None:
        if not self.window.winfo_exists():
            return
        self.busy = False
        self.scan_button.configure(state="normal")
        self.note.set("检测未完成：" + text)

    def prepare(self) -> None:
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo(APP_NAME, "请先选择一个候选地址。", parent=self.window)
            return
        row = self.results[int(selected[0])]
        if row["usable"] < 2:
            messagebox.showwarning(APP_NAME, "该地址未达到至少 2/3 次 HTTPS 首页响应，不提供应用。", parent=self.window)
            return
        self.app.prepare_change(self.site["host"], row["ip"], parent=self.window)


class Application:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = read_settings()
        self.sites = [dict(s) for s in core.DEFAULT_SITES] + self.settings["custom"]
        self.refreshing = False
        self.running = True
        self.stop_event = threading.Event()
        self.schedule_id = None
        self.progress = tk.StringVar(value="准备检测")
        self.interval = tk.StringVar(value=str(self.settings["interval"]))
        self.create_ui()
        self.root.after(200, self.refresh)

    def create_ui(self) -> None:
        self.root.title(APP_NAME + " · 测试版")
        self.root.geometry("1050x690")
        self.root.minsize(820, 570)
        self.root.configure(bg="#f2f5f9")
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#f2f5f9")
        style.configure("TLabel", background="#f2f5f9", foreground="#1f2937", font=("Microsoft YaHei UI", 10))
        style.configure("Heading.TLabel", font=("Microsoft YaHei UI", 16, "bold"), foreground="#102d50")
        style.configure("Sub.TLabel", foreground="#64748b", font=("Microsoft YaHei UI", 9))
        style.configure("TButton", font=("Microsoft YaHei UI", 10), padding=(12, 7))
        style.configure("Treeview", font=("Microsoft YaHei UI", 10), rowheight=34, background="white", fieldbackground="white")
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 10, "bold"), padding=6)
        body = ttk.Frame(self.root, padding=20)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=APP_NAME, style="Heading.TLabel").pack(anchor="w")
        ttk.Label(body, text="持续查看网站连接，异常时对照候选地址。", style="Sub.TLabel").pack(anchor="w", pady=(3, 12))
        toolbar = ttk.Frame(body)
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Button(toolbar, text="立即刷新", command=self.refresh).pack(side="left")
        self.pause_button = ttk.Button(toolbar, text="暂停自动刷新", command=self.toggle)
        self.pause_button.pack(side="left", padx=(8, 0))
        ttk.Label(toolbar, text="刷新间隔（秒）").pack(side="left", padx=(20, 6))
        combo = ttk.Combobox(toolbar, textvariable=self.interval, values=("30", "60", "120", "300"), state="readonly", width=6)
        combo.pack(side="left")
        combo.bind("<<ComboboxSelected>>", self.change_interval)
        ttk.Label(toolbar, textvariable=self.progress, style="Sub.TLabel").pack(side="right")
        table_frame = ttk.Frame(body)
        self.table = ttk.Treeview(table_frame, columns=("site", "domain", "status", "detail", "time"), show="headings", height=10, selectmode="browse")
        for key, text, width, stretch in [("site", "网站", 150, True), ("domain", "域名", 210, True),
                                          ("status", "连接状态", 165, True), ("detail", "本次地址 / 说明", 250, True),
                                          ("time", "更新时间", 100, False)]:
            self.table.heading(key, text=text)
            self.table.column(key, width=width, stretch=stretch, anchor="w")
        self.table.tag_configure("ok", foreground="#166534")
        self.table.tag_configure("limited", foreground="#9a6700")
        self.table.tag_configure("error", foreground="#b42318")
        self.table.tag_configure("waiting", foreground="#64748b")
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(side="left", fill="both", expand=True)
        table_frame.pack(fill="both", expand=True)
        self.table.bind("<Double-1>", lambda _event: self.open_site())
        actions = ttk.Frame(body)
        actions.pack(fill="x", pady=(12, 8))
        ttk.Button(actions, text="检查可修复地址", command=self.find_candidates).pack(side="left")
        ttk.Button(actions, text="打开网站", command=self.open_site).pack(side="left", padx=8)
        ttk.Button(actions, text="添加网站", command=self.add_site).pack(side="left")
        ttk.Button(actions, text="删除自定义网站", command=self.remove_site).pack(side="left", padx=8)
        ttk.Button(actions, text="撤销本软件的记录", command=self.remove_mapping).pack(side="right")
        ttk.Label(body, text="检测方式：不使用显式代理的 HTTPS 首页请求；VPN/TUN 仍可能影响路径。",
                  style="Sub.TLabel", wraplength=950).pack(anchor="w", pady=(6, 0))
        ttk.Label(body, text="HTTP 响应不等于登录、搜索或全部功能正常。只在窗口打开时刷新，不会自动修改 hosts。",
                  style="Sub.TLabel", wraplength=950).pack(anchor="w", pady=(4, 0))
        self.rebuild()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def dispatch(self, callback) -> None:
        try:
            if self.root.winfo_exists():
                self.root.after(0, callback)
        except (RuntimeError, tk.TclError):
            pass

    def rebuild(self) -> None:
        self.table.delete(*self.table.get_children())
        for site in self.sites:
            self.table.insert("", "end", iid=site["host"], values=(site["name"], site["host"], "等待检测", "—", "—"), tags=("waiting",))

    def selected(self) -> dict | None:
        selection = self.table.selection()
        if not selection:
            messagebox.showinfo(APP_NAME, "请先选择一个网站。", parent=self.root)
            return None
        return next((s for s in self.sites if s["host"] == selection[0]), None)

    def refresh(self) -> None:
        if self.refreshing:
            return
        if self.schedule_id:
            self.root.after_cancel(self.schedule_id)
            self.schedule_id = None
        self.refreshing = True
        sites = list(self.sites)
        self.progress.set(f"检测中 0/{len(sites)}")

        def work():
            done = 0
            def check(site):
                if self.stop_event.is_set():
                    return {"state": "error", "status": "已停止", "ip": ""}
                return core.probe(site["host"])
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                pending = {pool.submit(check, site): site for site in sites}
                for future in concurrent.futures.as_completed(pending):
                    site = pending[future]
                    try:
                        result = future.result()
                    except Exception:
                        result = {"state": "error", "status": "检测未完成", "ip": ""}
                    done += 1
                    count = done
                    self.dispatch(lambda s=site, r=result, c=count: self.update_result(s, r, c, len(sites)))
            self.dispatch(self.finish_refresh)
        threading.Thread(target=work, daemon=True).start()

    def update_result(self, site: dict, result: dict, count: int, total: int) -> None:
        host = site["host"]
        if self.table.exists(host):
            state = result["state"]
            tag = "ok" if state == "ok" else ("limited" if state in {"redirect", "limited"} else "error")
            self.table.item(host, values=(site["name"], host, result["status"], result.get("ip") or "—", time.strftime("%H:%M:%S")), tags=(tag,))
        self.progress.set(f"检测中 {count}/{total}")

    def finish_refresh(self) -> None:
        self.refreshing = False
        self.progress.set("上次完成 " + time.strftime("%H:%M:%S"))
        if self.running:
            self.schedule_id = self.root.after(int(self.interval.get()) * 1000, self.refresh)

    def toggle(self) -> None:
        self.running = not self.running
        self.pause_button.configure(text="暂停自动刷新" if self.running else "继续自动刷新")
        if not self.running and self.schedule_id:
            self.root.after_cancel(self.schedule_id)
            self.schedule_id = None
        elif self.running and not self.refreshing:
            self.refresh()

    def change_interval(self, _event=None) -> None:
        self.settings["interval"] = int(self.interval.get())
        try:
            save_settings(self.settings)
        except OSError as exc:
            messagebox.showwarning(APP_NAME, "无法保存设置：" + str(exc), parent=self.root)
        if self.running and not self.refreshing:
            if self.schedule_id:
                self.root.after_cancel(self.schedule_id)
            self.schedule_id = self.root.after(int(self.interval.get()) * 1000, self.refresh)

    def add_site(self) -> None:
        value = simpledialog.askstring(APP_NAME, "请输入网站域名或 HTTPS 首页地址：", parent=self.root)
        if not value:
            return
        try:
            host = core.normalize_host(value)
            if any(s["host"] == host for s in self.sites):
                raise ValueError("这个网站已在列表中。")
            site = {"name": host, "host": host}
            new_settings = {**self.settings, "custom": self.settings["custom"] + [site]}
            save_settings(new_settings)
            self.settings = new_settings
            self.sites.append(site)
            self.table.insert("", "end", iid=host, values=(host, host, "等待检测", "—", "—"), tags=("waiting",))
            if not self.refreshing:
                self.refresh()
        except (ValueError, OSError) as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.root)

    def remove_site(self) -> None:
        site = self.selected()
        if not site:
            return
        if site["host"] in {s["host"] for s in core.DEFAULT_SITES}:
            messagebox.showinfo(APP_NAME, "默认网站不能在此删除。", parent=self.root)
            return
        if not messagebox.askyesno(APP_NAME, f"从列表中删除 {site['host']}？\n这不会修改 hosts。", parent=self.root):
            return
        self.settings["custom"] = [s for s in self.settings["custom"] if s["host"] != site["host"]]
        try:
            save_settings(self.settings)
        except OSError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=self.root)
            return
        self.sites = [s for s in self.sites if s["host"] != site["host"]]
        self.table.delete(site["host"])

    def open_site(self) -> None:
        site = self.selected()
        if site:
            webbrowser.open("https://" + site["host"] + "/")

    def find_candidates(self) -> None:
        site = self.selected()
        if site:
            CandidateDialog(self, site)

    def remove_mapping(self) -> None:
        site = self.selected()
        if site:
            self.prepare_change(site["host"], None, parent=self.root)

    def prepare_change(self, host: str, address: str | None, parent) -> None:
        if os.name != "nt":
            messagebox.showerror(APP_NAME, "当前版本仅支持 Windows。", parent=parent)
            return
        try:
            before = core.hosts_path().read_bytes()
            _after, change = core.render_hosts(before, host, address)
            if not change["changed"]:
                raise ValueError("这个地址已经生效，无需修改。")
            previous = change["before"] or "无本软件记录"
            replacement = address or "移除本软件记录，恢复正常解析"
            prompt = (f"即将修改 {host}：\n\n原记录：{previous}\n新记录：{replacement}\n\n"
                      "只修改本软件管理区，会先备份当前 hosts。Windows 将请求管理员授权。\n"
                      "连接响应不代表登录或全部功能正常。是否继续？")
            if not messagebox.askyesno(APP_NAME, prompt, parent=parent):
                return
            backup = backup_hosts(before)
            operation = "set" if address else "remove"
            handle = run_elevated([operation, host, address or "-", core.sha256(before), str(int(time.time()))])
            self.progress.set("等待管理员操作及复测……")
            self.poll_elevated(handle, host, address, backup, time.monotonic())
        except (OSError, ValueError) as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=parent)

    def poll_elevated(self, handle: int, host: str, address: str | None, backup: Path, started: float) -> None:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        status = kernel.WaitForSingleObject(wintypes.HANDLE(handle), 0)
        if status == 0x102 and time.monotonic() - started < 120:
            self.root.after(800, lambda: self.poll_elevated(handle, host, address, backup, started))
            return
        if status == 0x102:
            self.progress.set("管理员操作仍未结束，请稍后检查 hosts")
            kernel.CloseHandle(wintypes.HANDLE(handle))
            return
        code = wintypes.DWORD()
        kernel.GetExitCodeProcess(wintypes.HANDLE(handle), ctypes.byref(code))
        kernel.CloseHandle(wintypes.HANDLE(handle))
        if code.value in (0, 17):
            try:
                state = core.host_state(core.hosts_path().read_bytes(), host)
                if state["own"] != address:
                    raise ValueError("写入后的记录与预期不一致。")
            except (OSError, ValueError) as exc:
                messagebox.showwarning(APP_NAME, "操作已结束，但复核失败：" + str(exc), parent=self.root)
                return
            warning = "\nDNS 缓存未确认刷新，请手动刷新或重新打开浏览器。" if code.value == 17 else ""
            messagebox.showinfo(APP_NAME, f"已更新 {host}。\n请在浏览器中验证实际功能。{warning}\n\n备份：{backup}", parent=self.root)
            self.progress.set("修改完成，等待浏览器验证")
            if not self.refreshing:
                self.refresh()
        else:
            reasons = {10: "参数无效", 11: "没有管理员权限", 12: "地址复测未通过", 13: "hosts 已变化或方案已过期",
                       14: "现有记录冲突或管理区被修改", 15: "方案无效", 16: "读写操作失败"}
            messagebox.showerror(APP_NAME, f"没有确认完成修改：{reasons.get(code.value, '操作失败')}。\n备份：{backup}", parent=self.root)
            self.progress.set("修改未完成")

    def close(self) -> None:
        self.running = False
        self.stop_event.set()
        self.root.destroy()


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--elevated":
        return elevated_main(sys.argv[2:])
    root = tk.Tk()
    Application(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
