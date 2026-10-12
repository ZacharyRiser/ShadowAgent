"""登录/注册页「后端不可达」横幅修复的实测探针。

核心手法：
  - 复制「后端没起」的现场不必真去杀后端 —— CDP 的 Network.setBlockedURLs
    把到 :8000 的请求全拦掉，浏览器就会抛 TypeError('Failed to fetch')，
    与端口不通的表现一致，且完全可逆。
  - controlled input 必须走原生 setter + 派发 input 事件，
    直接赋 el.value React 收不到（值变了但 state 没变）。

用法: python _shots/auth_probe.py
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp_shot import CDP, CHROME  # noqa: E402

URL = "http://127.0.0.1:3000/"
BANNER_RE = "注册已关闭|无法连接后端|注册已开放|注册为邀请制|当前后端还没有管理员账号"

JS_BANNER = (
    "(() => {"
    "  const re = /%(re)s/;"
    "  const all = [...document.querySelectorAll('div')];"
    "  const cands = all.filter(e => !e.querySelector('input,button')"
    "     && e.innerText && e.innerText.trim().length > 0 && e.innerText.trim().length < 320);"
    "  const hit = cands.filter(e => re.test(e.innerText))"
    "     .sort((a,b) => a.innerText.length - b.innerText.length)[0];"
    "  if (!hit) return 'NO-BANNER';"
    "  const cs = getComputedStyle(hit);"
    "  return JSON.stringify({text: hit.innerText.trim().replace(/\\s+/g,' '),"
    "     color: cs.color, bg: cs.backgroundColor});"
    "})()"
) % {"re": BANNER_RE}

JS_CLICK_REGISTER = (
    "(() => {"
    "  const els = [...document.querySelectorAll('button')];"
    "  const hit = els.find(e => e.innerText.trim() === '注册');"
    "  if (!hit) return 'no-register-tab';"
    "  hit.click(); return 'ok';"
    "})()"
)

JS_FILL = (
    "(() => {"
    "  const setV = (el, v) => {"
    "    const d = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');"
    "    d.set.call(el, v);"
    "    el.dispatchEvent(new Event('input', {bubbles: true}));"
    "  };"
    "  const ins = [...document.querySelectorAll('input')];"
    "  const pick = (t) => ins.find(i => (i.getAttribute('type') || 'text') === t);"
    "  const byLabel = (txt) => ins.find(i => {"
    "     const lab = i.closest('label');"
    "     return lab && lab.innerText.includes(txt); });"
    "  setV(byLabel('姓名'), 'rum');"
    "  const mail = pick('email') || byLabel('邮箱');"
    "  setV(mail, 'rum@example.com');"
    "  const pwds = ins.filter(i => i.getAttribute('type') === 'password');"
    "  if (pwds.length < 2) return 'expect-2-password-inputs-got-' + pwds.length;"
    "  setV(pwds[0], 'shadow1234');"
    "  setV(pwds[1], 'shadow1234');"
    "  return 'filled:' + ins.map(i => (i.getAttribute('type')||'text')).join(',');"
    "})()"
)

JS_SUBMIT = (
    "(() => {"
    "  const els = [...document.querySelectorAll('button[type=submit],form button')];"
    "  const hit = els.find(e => e.innerText.includes('创建账号')) || els[0];"
    "  if (!hit) return 'no-submit';"
    "  hit.click();"
    "  return 'clicked:' + hit.innerText.trim().slice(0, 30) + ':disabled=' + hit.disabled;"
    "})()"
)

JS_ERR = (
    "(() => {"
    "  const e = document.querySelector('#auth-form-error');"
    "  if (!e) return 'NO-INLINE-ERROR-ELEMENT';"
    "  const cs = getComputedStyle(e);"
    "  return JSON.stringify({text: (e.innerText||'').trim().replace(/\\s+/g,' '),"
    "     role: e.getAttribute('role'), live: e.getAttribute('aria-live'),"
    "     color: cs.color, bg: cs.backgroundColor});"
    "})()"
)


def evaluate(c, expr, timeout=30):
    r = c.call("Runtime.evaluate", {"expression": expr}, timeout=timeout)
    res = r.get("result", {})
    if res.get("exceptionDetails"):
        return "JS-ERROR: " + json.dumps(res["exceptionDetails"])[:400]
    return res.get("result", {}).get("value")


def run(label, block_backend, out_png):
    port = 9225
    here = os.path.dirname(os.path.abspath(__file__))
    profile = os.path.join(here, "_chromeprofile_probe")
    os.makedirs(profile, exist_ok=True)
    proc = subprocess.Popen(
        [CHROME, "--headless=new", f"--remote-debugging-port={port}",
         f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
         "--disable-gpu", "--hide-scrollbars", "--window-size=1440,1000", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print("\n" + "=" * 70)
    print("CASE %s   (block_backend=%s)" % (label, block_backend))
    print("=" * 70)
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
        c.call("Network.enable")
        c.call("Emulation.setDeviceMetricsOverride",
               {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False})

        if block_backend:
            c.call("Network.setBlockedURLs", {"urls": ["*://127.0.0.1:8000/*",
                                                       "*://localhost:8000/*"]})

        # 每个新 document 起始就清空存储 —— demo 会话残留会让页面直接跳控制台，
        # 不清就测不到登录页（这是之前踩过的假结论来源）。
        c.call("Page.addScriptToEvaluateOnNewDocument", {
            "source": "try{localStorage.clear();sessionStorage.clear();}catch(e){}"
        })

        c.call("Page.navigate", {"url": URL})
        time.sleep(4.5)

        print("1) 切到「注册」页签:", evaluate(c, JS_CLICK_REGISTER))
        time.sleep(0.9)
        print("2) 横幅:", evaluate(c, JS_BANNER))

        print("3) 填充表单:", evaluate(c, JS_FILL))
        time.sleep(0.5)
        print("4) 提交:", evaluate(c, JS_SUBMIT))
        # 给网络往返 / 失败留时间
        time.sleep(3.0)
        print("5) 内联错误:", evaluate(c, JS_ERR))

        res = c.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
        data = res.get("result", {}).get("data")
        if data:
            with open(out_png, "wb") as f:
                f.write(base64.b64decode(data))
            print("   截图:", out_png, os.path.getsize(out_png), "bytes")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    run("A / 后端不可达", True, os.path.join(here, "_auth_unreachable.png"))
    run("B / 后端在线", False, os.path.join(here, "_auth_online.png"))
