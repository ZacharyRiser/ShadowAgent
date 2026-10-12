"""列出前端源码里待 token 化的 Tailwind 类（只读，带行号与原文）。"""
import io
import re
import glob
import os

PATTERNS = {
    "rounded-2xl": r"\brounded-2xl\b",
    "rounded-xl": r"\brounded-xl\b",
    "text-xl": r"\btext-xl\b",
    "text-lg": r"\btext-lg\b",
    "text-sm": r"\btext-sm\b",
    "text-xs": r"\btext-xs\b",
    "transition-all": r"\btransition-all\b",
    "duration-150/200/300": r"\bduration-(?:150|200|300|500|700)\b",
    # 真正的裸 ease-out：排除 ease-[var(--ease-out-quart)] 这类 token 写法里的子串
    "裸 ease-out": r"(?<![\w\-])ease-out(?![\w\-])",
    "spring 动画": r'type:\s*["\']spring["\']',
    "ease easeOut": r'ease:\s*["\']ease(?:Out|In|InOut)["\']',
    "装饰光斑 blur": r"\bblur-(?:2xl|3xl)\b",
}


def main():
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend"))
    grand = {}
    for f in sorted(glob.glob("src/**/*.tsx", recursive=True)):
        t = io.open(f, encoding="utf-8").read()
        lines = t.split("\n")
        found = []
        for label, pat in PATTERNS.items():
            for m in re.finditer(pat, t):
                ln = t[: m.start()].count("\n") + 1
                found.append((ln, label, lines[ln - 1].strip()))
            c = len(re.findall(pat, t))
            if c:
                grand[label] = grand.get(label, 0) + c
        if found:
            print(f"### {f}  ({len(found)} 处)")
            for ln, label, src in sorted(found):
                print(f"  L{ln:5d} [{label}]")
                print(f"        {src[:150]}")
            print()
    print("=== 汇总 ===")
    for k, v in sorted(grand.items(), key=lambda x: -x[1]):
        print(f"  {v:5d}  {k}")


if __name__ == "__main__":
    main()
