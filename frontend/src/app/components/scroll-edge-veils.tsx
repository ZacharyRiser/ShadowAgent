"use client";
/* 滚动边缘毛玻璃幕帘：视口上下各一条 backdrop-blur 渐隐带 ——
   内容滚动掠过视口上下边缘的「交界面」时施加高斯模糊（毛玻璃幕帘），丝滑淡入淡出。
   顶帘：页面向下滚过阈值后淡入（内容正从顶边掠过）；回顶淡出。
   底帘：仍存在可滚动余量时淡入（内容正从底边涌入）；滚到底淡出。
   opacity 直写 style、rAF 合帧 —— 滚动事件高频，state 化会整页重渲染。
   insetSidebar：lg 以上避开 268px 侧栏（app shell 用），落地页无侧栏不传。 */
import { useEffect, useRef } from "react";

export function ScrollEdgeVeils({ insetSidebar = false }: { insetSidebar?: boolean }) {
  const topRef = useRef<HTMLDivElement | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let topShown: boolean | null = null;
    let bottomShown: boolean | null = null;
    let frame = 0;

    const sync = () => {
      frame = 0;
      const remaining =
        document.documentElement.scrollHeight - window.innerHeight - window.scrollY;
      const nextTop = window.scrollY > 12;
      const nextBottom = remaining > 4;
      if (nextTop !== topShown && topRef.current) {
        topShown = nextTop;
        topRef.current.style.opacity = nextTop ? "1" : "0";
      }
      if (nextBottom !== bottomShown && bottomRef.current) {
        bottomShown = nextBottom;
        bottomRef.current.style.opacity = nextBottom ? "1" : "0";
      }
    };

    const requestSync = () => {
      if (!frame) frame = requestAnimationFrame(sync);
    };

    sync();
    window.addEventListener("scroll", requestSync, { passive: true });
    window.addEventListener("resize", requestSync);
    return () => {
      if (frame) cancelAnimationFrame(frame);
      window.removeEventListener("scroll", requestSync);
      window.removeEventListener("resize", requestSync);
    };
  }, []);

  const insetClass = insetSidebar ? "scroll-veil-inset-sidebar" : "";
  return (
    <>
      <div ref={topRef} aria-hidden className={`scroll-veil scroll-veil-top ${insetClass}`} />
      <div ref={bottomRef} aria-hidden className={`scroll-veil scroll-veil-bottom ${insetClass}`} />
    </>
  );
}
