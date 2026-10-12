"""Chrome headless + 手写 CDP 客户端 —— 截图工具（无 playwright/puppeteer）。

用法：
    python _shots/cdp_shot.py <out.png> [url] [theme] [width] [height]

关键坑（血泪）：
  1. 主题存在 localStorage['shadow-agent-settings'] 的 themeMode 字段，
     不是 'shadow-agent-theme'。写错就恒为浅色。
  2. admin 会话必须走 sessionStorage['shadow-agent-sso-handoff']，
     直接写 localStorage 的 authSession 会被 boot 逻辑无条件清掉。
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import base64
import shutil

CHROME = None
for cand in [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
]:
    if os.path.exists(cand):
        CHROME = cand
        break
if not CHROME:
    raise SystemExit("Chrome not found")


class CDP:
    def __init__(self, ws_url):
        self.url = ws_url
        self.ws = None

    def connect(self):
        import socket
        import ssl
        from urllib.parse import urlparse
        u = urlparse(self.url)
        sock = socket.create_connection((u.hostname, u.port))
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += sock.recv(4096)
        self.sock = sock
        self.buf = b""
        self.msg_id = 0

    def _send_frame(self, payload: bytes):
        import struct
        header = bytearray([0x81])
        n = len(payload)
        mask = os.urandom(4)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _recv_msg(self):
        import struct
        def readn(n):
            while len(self.buf) < n:
                d = self.sock.recv(65536)
                if not d:
                    raise EOFError
                self.buf += d
            out, self.buf = self.buf[:n], self.buf[n:]
            return out
        hdr = readn(2)
        opcode = hdr[0] & 0x0F
        ln = hdr[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", readn(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", readn(8))[0]
        data = readn(ln)
        if opcode == 0x8:
            raise EOFError
        if opcode == 0x9:
            return None  # ping
        return data.decode("utf-8", "replace")

    def call(self, method, params=None, timeout=30):
        self.msg_id += 1
        mid = self.msg_id
        self._send_frame(json.dumps({"id": mid, "method": method, "params": params or {}}).encode())
        t0 = time.time()
        while time.time() - t0 < timeout:
            m = self._recv_msg()
            if m is None:
                continue
            try:
                obj = json.loads(m)
            except Exception:
                continue
            if obj.get("id") == mid:
                return obj
        raise TimeoutError(method)


def main():
    out = sys.argv[1]
    url = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3000/"
    theme = sys.argv[3] if len(sys.argv) > 3 else "light"
    W = int(sys.argv[4]) if len(sys.argv) > 4 else 1440
    H = int(sys.argv[5]) if len(sys.argv) > 5 else 900
    setup = sys.argv[6] if len(sys.argv) > 6 else ""

    port = 9223
    profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_chromeprofile")
    os.makedirs(profile, exist_ok=True)
    proc = subprocess.Popen(
        [CHROME, "--headless=new", f"--remote-debugging-port={port}",
         f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
         "--disable-gpu", "--hide-scrollbars", f"--window-size={W},{H}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        ws = None
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as r:
                    tabs = json.load(r)
                page = [t for t in tabs if t.get("type") == "page"]
                if page:
                    ws = page[0]["webSocketDebuggerUrl"]
                    break
            except Exception:
                pass
            time.sleep(0.3)
        if not ws:
            raise SystemExit("cannot reach CDP")

        c = CDP(ws)
        c.connect()
        c.call("Page.enable")
        c.call("Runtime.enable")
        c.call("Emulation.setDeviceMetricsOverride",
               {"width": W, "height": H, "deviceScaleFactor": 1, "mobile": False})

        # 关键：setup 脚本必须用 addScriptToEvaluateOnNewDocument 注册，
        # 保证它在**每一个**新 document 的最开始执行 —— 也就是在 React boot
        # 读取 sessionStorage/localStorage 之前。
        # 早先的写法是「导航 → evaluate 注入 → 再导航」，那样第二次导航会把
        # 刚写进 sessionStorage 的东西连同 document 一起换掉（且时机在 boot 之后），
        # 结果 admin 会话永远进不去、页面停在 demo 首页。
        #
        # 🔴 另一个更隐蔽的坑（实测踩到）：本函数内部会 navigate **两次**
        #    （先拿 origin 写主题、再正式导航）。setup 是「每个 document 都跑」，
        #    所以第一次导航时它写入 handoff 会被那次的 boot 立刻消费并 removeItem，
        #    等第二次导航时 handoff 已经没了 → 页面停在登录页。
        #    修法：把 setup 包一层 origin 守卫，让它在**任何 http(s) document**
        #    起始都重新写入（幂等），不再依赖「只写一次」。
        if setup:
            guarded = (
                "(function(){try{"
                "if(location.protocol==='http:'||location.protocol==='https:'){%s}"
                "}catch(e){}})()"
            ) % setup
            c.call("Page.addScriptToEvaluateOnNewDocument", {"source": guarded})

        # 主题也要预置：先导航一次拿到 origin 写 localStorage，之后 addScript 会补上主题
        c.call("Page.navigate", {"url": url})
        time.sleep(1.2)
        settings = json.dumps({"themeMode": theme})
        # 用引号安全转义，避免 python 字面量落到 JS 里出语法错误
        c.call("Runtime.evaluate", {
            "expression": (
                "localStorage.setItem('shadow-agent-settings', %s);"
                "document.documentElement.dataset.theme = %s;"
            ) % (json.dumps(settings), json.dumps(theme)),
        })
        # 把主题也纳入预置脚本，保证 reload 后仍生效（而不是依赖上一次的残留）
        c.call("Page.addScriptToEvaluateOnNewDocument", {
            "source": (
                "try{localStorage.setItem('shadow-agent-settings', %s);"
                "document.documentElement.dataset.theme = %s;}catch(e){}"
            ) % (json.dumps(settings), json.dumps(theme)),
        })
        c.call("Page.navigate", {"url": url})
        time.sleep(3.5)
        if setup:
            # 🔴 handoff 会被 boot 逻辑消费后 removeItem，所以「读不到 sessionStorage」是
            #    **正常**现象（读到才是异常）。真正的判据是控制台侧栏是否出现。
            r = c.call("Runtime.evaluate", {
                "expression": "JSON.stringify({handoffLeft: !!sessionStorage.getItem('shadow-agent-sso-handoff'),"
                              " aside: !!document.querySelector('aside nav')})"
            })
            print("setup applied:", r.get("result", {}).get("result", {}).get("value"))
            time.sleep(2.5)

        # 🔴 关键：handoff 消费后页面会做一次客户端跳转（demo → 控制台），
        #    固定 sleep 极易截到跳转中途（此时 DOM 里既没有侧栏也没有目标视图）。
        #    必须轮询等待「侧栏 nav 出现」，再截图。
        for _ in range(40):
            chk = c.call("Runtime.evaluate", {
                "expression": "!!document.querySelector('aside nav')"
            })
            if chk.get("result", {}).get("result", {}).get("value"):
                break
            time.sleep(0.5)
        else:
            print("WARN: aside nav never appeared — 可能未登录成功")
        time.sleep(1.2)

        # 可选：点击后截图（第 7 个参数 = 要点击的可见文本，逗号分隔，逐个点击）。
        # 用于进入 demo 模式 / 切到某个侧栏视图 —— 登录页之后的页面只能靠真实交互到达。
        if len(sys.argv) > 7 and sys.argv[7]:
            for label in sys.argv[7].split(","):
                label = label.strip()
                if not label:
                    continue
                js = (
                    "(() => { const t = %s;"
                    "  const els = [...document.querySelectorAll('button,a,[role=tab],[role=button]')];"
                    "  const hit = els.find(e => (e.innerText||'').trim().includes(t));"
                    "  if (hit) { hit.click(); return 'clicked:' + (hit.innerText||'').trim().slice(0,40); }"
                    "  return 'not-found:' + t; })()"
                ) % json.dumps(label)
                r = c.call("Runtime.evaluate", {"expression": js})
                print("click", label, "->", r.get("result", {}).get("result", {}).get("value"))
                time.sleep(2.0)
            time.sleep(1.5)

        # 可选：截图前滚动到指定 scrollY（第 9 个参数），等幕帘 transition 走完。
        # 第 10 个参数 = "1" 时全页截图（captureBeyondViewport），默认视口截图 ——
        # 验证 sticky 侧栏 / 滚动幕帘必须用视口截图（全页会把 fixed 元素摊平）。
        # 滚动在 probe 之前执行，probe 才能读到滚动后的幕帘状态。
        fullpage = len(sys.argv) > 10 and sys.argv[10] == "1"
        scroll_y = int(sys.argv[9]) if len(sys.argv) > 9 and sys.argv[9] else 0
        if scroll_y and not fullpage:
            c.call("Runtime.evaluate", {"expression": f"window.scrollTo(0,{scroll_y})"})
            time.sleep(1.4)  # veil opacity transition 560ms + 稳帧

        # 可选：点击完成后执行探针表达式并打印结果（第 8 个参数）。
        if len(sys.argv) > 8 and sys.argv[8]:
            pr = c.call("Runtime.evaluate", {"expression": sys.argv[8]})
            print("probe:", json.dumps(pr.get("result", {}))[:2000])

        res = c.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": fullpage})
        data = res.get("result", {}).get("data")
        if not data:
            raise SystemExit("no screenshot data: " + json.dumps(res)[:400])
        with open(out, "wb") as f:
            f.write(base64.b64decode(data))
        print("saved", out, os.path.getsize(out), "bytes")

        # 顺带把渲染后的主题报出来，便于确认没写错键
        chk = c.call("Runtime.evaluate", {
            "expression": "JSON.stringify({theme: document.documentElement.dataset.theme || 'system',"
                          "body: getComputedStyle(document.body).backgroundColor})"
        })
        print("theme check:", chk.get("result", {}).get("result", {}).get("value"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
