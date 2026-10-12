"use client";

import { useEffect, useRef, useState } from "react";

/* 数字滚动（count-up）：挂载时从 0 滚到目标值，值变化时从当前显示值续滚。
   · SSR 安全 —— 初始态就是目标值，服务端与客户端首帧一致，无 hydration 警告；
     挂载后的动画由 rAF 驱动（setState 全部发生在 rAF 回调里，不做同步级联渲染）。
   · prefers-reduced-motion: reduce 时经一帧 rAF 直出目标值，不做动画。
   · 动画被打断（值再次变化 / 卸载）时从「当前显示值」继续，不跳变。
   · format 在渲染期调用，允许调用方决定呈现（千分位、单位、小数位）。 */

type AnimatedNumberProps = {
  value: number;
  durationMs?: number;
  format?: (value: number) => string;
  className?: string;
};

export function AnimatedNumber({
  value,
  durationMs = 900,
  format,
  className,
}: AnimatedNumberProps) {
  // 非法输入统一收敛为 0 —— 绝不让 NaN 流进 format
  const target = typeof value === "number" && Number.isFinite(value) ? value : 0;

  const [shown, setShown] = useState(target);
  const displayRef = useRef(target);
  const rafRef = useRef(0);
  const mountedRef = useRef(false);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      rafRef.current = requestAnimationFrame(() => {
        displayRef.current = target;
        setShown(target);
      });
      mountedRef.current = true;
      return;
    }

    // 首次挂载从 0 滚起（入场），之后从当前显示值续滚（更新）
    const from = mountedRef.current ? displayRef.current : 0;
    mountedRef.current = true;
    const startedAt = performance.now();

    const tick = (now: number) => {
      const t = Math.min(1, (now - startedAt) / durationMs);
      const eased = 1 - Math.pow(1 - t, 4); // ease-out-quart，与全局缓动同族
      const current = from + (target - from) * eased;
      displayRef.current = current;
      setShown(current);
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);

    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [target, durationMs]);

  return (
    <span className={className}>
      {format ? format(shown) : String(Math.round(shown))}
    </span>
  );
}
