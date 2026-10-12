"""审计前端源码里违反四个设计 skill 硬条款的写法（只读）。"""
import io
import re
import glob
import os

PATTERNS = [
    ("spring 弹性动画 (motion-design 禁)", r'type:\s*["\']spring["\']'),
    ("ease easeOut/easeIn (非指数缓动)", r'ease:\s*["\']ease(?:Out|In|InOut)["\']'),
    ("通用 duration-200/300/500/700", r'duration-(?:200|300|500|700)\b'),
    ("裸 ease-out (应指数缓动)", r'\bease-out\b'),
    ("rounded-xl/2xl (应 radius token)", r'rounded-(?:xl|2xl)\b'),
    ("text-xs/sm/lg/xl (应字号 token)", r'\btext-(?:xs|sm|lg|xl|2xl)\b'),
    ("装饰性 radial-gradient", r'radial-gradient'),
    ("blur-3xl 光斑", r'blur-3xl'),
    ("transition-all (应列具体属性)", r'transition-all\b'),
    ("h-9/w-9 非 4pt 阶梯", r'\b(?:h|w)-9\b'),
]


def main():
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend"))
    total = {}
    for f in sorted(glob.glob("src/**/*.tsx", recursive=True)):
        t = io.open(f, encoding="utf-8").read()
        hits = {}
        for label, pat in PATTERNS:
            n = len(re.findall(pat, t))
            if n:
                hits[label] = n
        if hits:
            print(f)
            for k, v in sorted(hits.items(), key=lambda x: -x[1]):
                print(f"    {v:4d}  {k}")
                total[k] = total.get(k, 0) + v
    print()
    print("=== 全前端汇总 ===")
    for k, v in sorted(total.items(), key=lambda x: -x[1]):
        print(f"  {v:5d}  {k}")


if __name__ == "__main__":
    main()
