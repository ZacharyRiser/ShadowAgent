"""把残留的 Tailwind 默认类精确映射到语义 token（像素等价）。

映射依据（globals.css 实测值 vs Tailwind 默认）：
    text-xs   12px  == --text-micro       12px   等价
    text-sm   14px  == --text-body        14px   等价
    text-lg   18px  ~= --text-subhead     17px   差 1px
    text-xl   20px  == --text-heading     20px   等价
    rounded-xl  12px == --radius-md       12px   等价
    rounded-2xl 16px == --radius-lg       16px   等价
    duration-150/200 -> --dur-fast 160ms（小元素 hover/状态，语义最贴）
    transition-all    -> 显式属性表（motion-design：只动 transform/opacity/颜色）
    裸 ease-out       -> --ease-out-quart 指数缓动（禁 Tailwind 内置缓动）

注意：`ease-[var(--ease-out-quart)]` 里的 "ease-out" 是子串，必须用
      (?<![\\w-])ease-out(?![\\w-]) 排除，否则误报。
"""
import io
import re
import glob
import os

RULES = [
    (r"\brounded-2xl\b", "rounded-[var(--radius-lg)]"),
    (r"\brounded-xl\b", "rounded-[var(--radius-md)]"),
    (r"\btext-xl\b", "text-[length:var(--text-heading)]"),
    (r"\btext-lg\b", "text-[length:var(--text-subhead)]"),
    (r"\btext-sm\b", "text-[length:var(--text-body)]"),
    (r"\btext-xs\b", "text-[length:var(--text-micro)]"),
    (r"\btransition-all\b", "transition-[color,background-color,border-color,box-shadow,transform,opacity]"),
    (r"\bduration-(?:150|200)\b", "duration-[var(--dur-fast)]"),
    (r"(?<![\w\-])ease-out(?![\w\-])", "ease-[var(--ease-out-quart)]"),
]


def main():
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend"))
    total = 0
    for f in sorted(glob.glob("src/**/*.tsx", recursive=True)):
        t = io.open(f, encoding="utf-8").read()
        orig = t
        detail = []
        for pat, rep in RULES:
            t, n = re.subn(pat, rep, t)
            if n:
                detail.append(f"{n:3d}x  {pat}  ->  {rep}")
                total += n
        if t != orig:
            io.open(f, "w", encoding="utf-8", newline="").write(t)
            print(f"### {f}")
            for d in detail:
                print("   ", d)
    print()
    print("=== 共替换", total, "处 ===")


if __name__ == "__main__":
    main()
