"""给 SOC 的容器级卡片/区块加 `soc-card` 类（供浅色主题补投影层次）。

只命中同时满足三个条件的 className：
  1. 含 rounded-[var(--radius-lg)]
  2. 含 border-[color-mix(in_oklab,var(--tone-accent)_28%,transparent)]
  3. 含 bg-[var(--surface-raised)] 或 bg-[var(--surface-sunken)]
→ 排除行（radius-md）、页脚（无圆角）、进度条（无边框）等非容器元素。
"""
import io
import re
import os

FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "src",
    "app", "components", "security-dashboard.tsx",
)

PAT = re.compile(
    r'className="((?=[^"]*rounded-\[var\(--radius-lg\)\])'
    r'(?=[^"]*border-\[color-mix\(in_oklab,var\(--tone-accent\)_28%,transparent\)\])'
    r'(?=[^"]*bg-\[var\(--surface-(?:raised|sunken)\)\])[^"]*)"'
)


def main():
    s = io.open(FILE, encoding="utf-8").read()
    hits = []

    def repl(m):
        cls = m.group(1)
        if "soc-card" in cls:
            return m.group(0)
        hits.append(cls[:70])
        return 'className="soc-card ' + cls + '"'

    out = PAT.sub(repl, s)
    io.open(FILE, "w", encoding="utf-8", newline="").write(out)
    print(f"已加 soc-card 的元素数: {len(hits)}")
    for h in hits:
        print("   ", h)
    print()
    print("文件内 soc-card 出现次数:", out.count("soc-card "))


if __name__ == "__main__":
    main()
