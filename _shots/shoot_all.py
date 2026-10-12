"""批量截图驱动：逐视图 × 双主题，走 SSO handoff 注入 admin 会话。

用法：python _shots/shoot_all.py
输出：docs/screenshots/v4-{light,dark}-<view>.png
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOTS = os.path.join(ROOT, "_shots")
OUTDIR = os.path.join(ROOT, "docs", "screenshots")
PY = sys.executable

token = open(os.path.join(SHOTS, "_token.txt"), encoding="utf-8").read().strip()
expires = int(time.time()) + 3600

VIEWS = [
    ("overview", "overview", ""),
    ("gateway", "gateway", ""),
    ("metrics", "metrics", ""),
    ("logs", "logs", ""),
    ("policies", "policies", ""),
    ("rules", "rules", ""),
    ("keys", "keys", ""),
    ("orgs", "orgs", ""),
    ("settings", "settings", ""),
    ("help", "help", ""),
    # SOC 安全大屏没有独立 hash，必须点击侧栏「安全大屏」按钮进入（全屏覆盖层）
    ("soc", "overview", "安全大屏"),
]

# SSO handoff 必须是 JSON 对象文本；双重 stringify 会失效。
handoff = json.dumps({"access_token": token, "token_type": "bearer", "expires_at": expires})
SETUP = (
    "try{"
    "sessionStorage.setItem('shadow-agent-sso-handoff', %s);"
    "}catch(e){}"
) % json.dumps(handoff)


def shoot(view, hash_name, theme, out_path, clicks=""):
    url = f"http://127.0.0.1:3000/#{hash_name}"
    # 不再每次清 chrome profile。原因有二：
    #  1) 沙箱对批量删除有安全闸（>50 文件需人工确认），profile 有 1600+ 文件；
    #  2) 已无必要 —— setup 脚本现在在**每个 document** 起始都幂等重写 handoff，
    #     而 boot 逻辑中 handoff 优先级高于 localStorage 的陈旧会话
    #     （仅在无有效 handoff 时才 removeStorage(authSession) 并回落 demo）。
    #     因此复用 profile 不会再有"旧 demo 会话盖掉 handoff"的问题。
    cmd = [PY, os.path.join(SHOTS, "cdp_shot.py"), out_path, url, theme, "1440", "1400", SETUP, clicks]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    ok = os.path.exists(out_path)
    print(f"[{'OK ' if ok else 'FAIL'}] {theme:5s} {view:9s} -> {os.path.basename(out_path)}")
    if not ok:
        print((r.stdout or "")[-800:])
        print((r.stderr or "")[-800:])


if __name__ == "__main__":
    os.makedirs(OUTDIR, exist_ok=True)
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    for view, hash_name, clicks in VIEWS:
        if only and only not in (view, hash_name):
            continue
        for theme in ("light", "dark"):
            out = os.path.join(OUTDIR, f"v4-{theme}-{view}.png")
            shoot(view, hash_name, theme, out, clicks)
    print("done")
