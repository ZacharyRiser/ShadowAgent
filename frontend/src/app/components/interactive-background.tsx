"use client";

import { useEffect, useRef } from "react";

/* 交互式粒子网络背景（零依赖，原生 canvas）。
   隐喻：节点 = Agent / 安全事件，连线 = 链路 —— 呼应「网关夹在应用与模型之间」。

   交互模型 v3 —— 「鼠标是这张网络里的一个引力节点」：
   · 吸附旋涡：指针周围粒子被拉向光标并带切向分量，形成绕行星群；
     拂过速度越快引力越强（pointer.speed 缩放），扫过时拖出一串尾随粒子。
   · 指针即节点：光标与附近粒子连出细线，整片星网跟着光标走；
     光标处另有一枚柔和光晕，与交互元素上的 .spot 光斑同一视觉语言。
   · 按住拖拽 = 蓄力弹弓：按下即原地冲击，按住拖出橡皮筋（带蓄力环），
     松手把 SLING_RADIUS 内的粒子沿拖拽方向定向弹射（带随机散布）。
   · 滚轮 = 全场涌动：粒子随滚动方向获得竖向速度 kick，
     指针处按节流泛出涟漪 —— 整片场都「感觉到」你在滚动页面。
   · 双击 = 幻影节点：光标处生成一个临时强引力体（3.5s 寿命，脉冲光环），
     把周围粒子织成密网后熄灭，粒子被弹簧送回各自基点。
   · 弹性回家：每颗粒子有漂移基点（home），激励消失后以弹簧+阻尼归位。

   硬性约束：
   · 颜色从语义 token 读取（--tone-accent），主题切换时跟随，不引入硬编码色板；
     token 缺失时才回落到同色相字面量（纯画布装饰，不进 CSS 层）。
   · pointer-events: none —— 不拦截任何 UI 事件；指针位置由 window 级监听获取。
   · prefers-reduced-motion: reduce 时只画一帧静止场（有纹理、无动画、无指针响应）。
   · 标签页隐藏即停 rAF；DPR 上限 2；节点数按面积摊派并有上限（O(n²) 连线可控）。 */

type FieldNode = {
  hx: number;
  hy: number;
  hvx: number;
  hvy: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
};

type Ripple = {
  x: number;
  y: number;
  age: number;
};

type Phantom = {
  x: number;
  y: number;
  age: number;
};

const LINK_DIST = 112;
const POINTER_LINK_DIST = 150;
const ATTRACT_RADIUS = 210;
const ATTRACT = 420; // 引力加速度(px/s²)，再经 falloff 与拂过速度系数缩放
const SWIRL = 0.75; // 切向分量比例 —— 绕行而非直线坠向光标
const CORE_RADIUS = 26; // 核心斥力圈：防止粒子塌缩进光标点
const CORE_PUSH = 900;
const SPRING = 3.2; // 回家弹簧(/s²)
const DAMPING = 2.6; // 速度阻尼(/s)
const MAX_SPEED = 260;
const SHOCK_RADIUS = 260;
const SHOCK_IMPULSE = 260;
const HOME_SPEED = 13; // 基点漂移速度上限(px/s)
const CHARGE_MIN_DRAG = 14; // 低于此拖距视为普通点击，不做定向弹射
const SLING_RADIUS = 300;
const SLING_MAX_IMPULSE = 340;
const WHEEL_KICK = 100; // 滚轮全场竖向 kick(px/s)
const WHEEL_RIPPLE_GAP = 120; // 滚轮涟漪节流(ms)
const PHANTOM_LIFE = 3.5; // 幻影节点寿命(s)
const PHANTOM_RADIUS = 240;
const PHANTOM_LINK_DIST = 180;
const MAX_PHANTOMS = 3;

function readToken(name: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value.startsWith("oklch(") ? value : "";
}

/* token 形如 oklch(78% 0.13 178)（无 alpha），在收括号前注入 / alpha。
   已含 alpha 的字符串不可用此函数 —— 二次注入会产出非法颜色，
   canvas 静默回退成黑色（踩过）。每次都从原始 token 现合成。 */
function withAlpha(color: string, alpha: number, fallback: string): string {
  if (!color) return fallback;
  return `${color.slice(0, -1)} / ${alpha})`;
}

export function InteractiveBackground() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let raf = 0;
    let lastTime = 0;
    let running = false;
    let accentToken = "";
    let nodes: FieldNode[] = [];
    let ripples: Ripple[] = [];
    let phantoms: Phantom[] = [];
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");

    // 画布 fixed 铺在视口上（不随文档拉伸），坐标即视口坐标 ——
    // 与指针事件的 clientX/Y 同一坐标系，滚动无需任何换算。
    // （旧实现画布 absolute 随文档增高，长页面粒子被摊薄拉长，已废弃。）
    const pointer = { cx: -1e4, cy: -1e4, x: -1e4, y: -1e4, active: false, speed: 0 };
    const charge = { active: false, startX: 0, startY: 0, x: 0, y: 0 };
    let lastPointerAt = 0;
    let lastWheelRipple = 0;
    const fallbackAccent = "oklch(70% 0.12 178)";

    const syncPointerCanvas = () => {
      pointer.x = pointer.cx;
      pointer.y = pointer.cy;
    };

    const buildField = () => {
      const count = Math.round(Math.min(140, Math.max(52, (width * height) / 15000)));
      nodes = Array.from({ length: count }, () => {
        const hx = Math.random() * width;
        const hy = Math.random() * height;
        const angle = Math.random() * Math.PI * 2;
        const speed = 3 + Math.random() * HOME_SPEED;
        return {
          hx,
          hy,
          hvx: Math.cos(angle) * speed,
          hvy: Math.sin(angle) * speed,
          x: hx,
          y: hy,
          vx: 0,
          vy: 0,
          r: 1.1 + Math.random() * 1.1,
        };
      });
    };

    const resize = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      buildField();
      if (!running) drawFrame(0.016, false);
    };

    const step = (dt: number, respondToPointer: boolean) => {
      // 停手后引力渐弱，而不是瞬间消失
      pointer.speed *= Math.exp(-5 * dt);

      for (const phantom of phantoms) phantom.age += dt;
      phantoms = phantoms.filter((phantom) => phantom.age < PHANTOM_LIFE);

      for (const node of nodes) {
        // 基点漂移；越界时基点与实体一起平移，避免弹簧把粒子横穿全屏拉走
        node.hx += node.hvx * dt;
        node.hy += node.hvy * dt;
        if (node.hx < -8) {
          node.hx += width + 16;
          node.x += width + 16;
        } else if (node.hx > width + 8) {
          node.hx -= width + 16;
          node.x -= width + 16;
        }
        if (node.hy < -8) {
          node.hy += height + 16;
          node.y += height + 16;
        } else if (node.hy > height + 8) {
          node.hy -= height + 16;
          node.y -= height + 16;
        }

        if (respondToPointer && pointer.active) {
          const dx = pointer.x - node.x;
          const dy = pointer.y - node.y;
          const d = Math.hypot(dx, dy);
          if (d < ATTRACT_RADIUS && d > 0.001) {
            const falloff = 1 - d / ATTRACT_RADIUS;
            const boost = 0.55 + Math.min(1.6, pointer.speed / 700);
            const pull = falloff * ATTRACT * boost * dt;
            const ux = dx / d;
            const uy = dy / d;
            // 指向光标的引力 + 切向分量 → 绕行旋涡
            node.vx += ux * pull - uy * pull * SWIRL;
            node.vy += uy * pull + ux * pull * SWIRL;
            if (d < CORE_RADIUS) {
              const push = (1 - d / CORE_RADIUS) * CORE_PUSH * dt;
              node.vx -= ux * push;
              node.vy -= uy * push;
            }
          }
        }

        // 幻影节点：比指针更强的第二引力体，把周围粒子织成密网
        for (const phantom of phantoms) {
          const dx = phantom.x - node.x;
          const dy = phantom.y - node.y;
          const d = Math.hypot(dx, dy);
          if (d < PHANTOM_RADIUS && d > 0.001) {
            const falloff = 1 - d / PHANTOM_RADIUS;
            const pull = falloff * ATTRACT * 1.5 * dt;
            const ux = dx / d;
            const uy = dy / d;
            node.vx += ux * pull - uy * pull * 0.5;
            node.vy += uy * pull + ux * pull * 0.5;
          }
        }

        // 弹簧回家 + 阻尼：激励消失后安静归位
        node.vx += (node.hx - node.x) * SPRING * dt;
        node.vy += (node.hy - node.y) * SPRING * dt;
        const damp = Math.exp(-DAMPING * dt);
        node.vx *= damp;
        node.vy *= damp;

        const speed = Math.hypot(node.vx, node.vy);
        if (speed > MAX_SPEED) {
          node.vx = (node.vx / speed) * MAX_SPEED;
          node.vy = (node.vy / speed) * MAX_SPEED;
        }

        node.x += node.vx * dt;
        node.y += node.vy * dt;
      }

      ripples = ripples.filter((ripple) => (ripple.age += dt) < 0.9);
    };

    const drawFrame = (dt: number, respondToPointer: boolean) => {
      ctx.clearRect(0, 0, width, height);
      const pointerLive = respondToPointer && pointer.active;

      // 光标光晕：指针是这片场里的光源
      if (pointerLive) {
        const glow = ctx.createRadialGradient(pointer.x, pointer.y, 0, pointer.x, pointer.y, 130);
        glow.addColorStop(0, withAlpha(accentToken, 0.1, fallbackAccent));
        glow.addColorStop(1, withAlpha(accentToken, 0, fallbackAccent));
        ctx.fillStyle = glow;
        ctx.fillRect(pointer.x - 130, pointer.y - 130, 260, 260);
      }

      // 粒子间连线：指针附近的链路点亮
      for (let i = 0; i < nodes.length; i += 1) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j += 1) {
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const dist = Math.hypot(dx, dy);
          if (dist >= LINK_DIST) continue;
          let alpha = (1 - dist / LINK_DIST) * 0.2;
          if (pointerLive) {
            const mx = (a.x + b.x) / 2 - pointer.x;
            const my = (a.y + b.y) / 2 - pointer.y;
            const pd = Math.hypot(mx, my);
            if (pd < ATTRACT_RADIUS) alpha *= 1 + 2.6 * (1 - pd / ATTRACT_RADIUS);
          }
          ctx.strokeStyle = withAlpha(accentToken, alpha, fallbackAccent);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      // 指针即节点：光标与附近粒子连出细线，星网跟着光标走
      if (pointerLive) {
        for (const node of nodes) {
          const d = Math.hypot(node.x - pointer.x, node.y - pointer.y);
          if (d >= POINTER_LINK_DIST) continue;
          ctx.strokeStyle = withAlpha(accentToken, (1 - d / POINTER_LINK_DIST) * 0.38, fallbackAccent);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(pointer.x, pointer.y);
          ctx.lineTo(node.x, node.y);
          ctx.stroke();
        }
      }

      // 幻影节点：脉冲光环 + 密网连线，临终前 0.8s 淡出
      for (const phantom of phantoms) {
        const fade = Math.min(1, (PHANTOM_LIFE - phantom.age) / 0.8);
        const pulse = 8 + Math.sin(phantom.age * 5) * 2.5;
        ctx.fillStyle = withAlpha(accentToken, 0.85 * fade, fallbackAccent);
        ctx.beginPath();
        ctx.arc(phantom.x, phantom.y, 3.5, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = withAlpha(accentToken, 0.3 * fade, fallbackAccent);
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(phantom.x, phantom.y, pulse, 0, Math.PI * 2);
        ctx.stroke();
        for (const node of nodes) {
          const d = Math.hypot(node.x - phantom.x, node.y - phantom.y);
          if (d >= PHANTOM_LINK_DIST) continue;
          ctx.strokeStyle = withAlpha(accentToken, (1 - d / PHANTOM_LINK_DIST) * 0.3 * fade, fallbackAccent);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(phantom.x, phantom.y);
          ctx.lineTo(node.x, node.y);
          ctx.stroke();
        }
      }

      // 蓄力橡皮筋：锚点 + 拖拽线 + 随拖距增大的蓄力环
      if (pointerLive && charge.active) {
        const len = Math.hypot(charge.x - charge.startX, charge.y - charge.startY);
        if (len > 4) {
          ctx.strokeStyle = withAlpha(accentToken, 0.32, fallbackAccent);
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(charge.startX, charge.startY);
          ctx.lineTo(charge.x, charge.y);
          ctx.stroke();
          ctx.fillStyle = withAlpha(accentToken, 0.5, fallbackAccent);
          ctx.beginPath();
          ctx.arc(charge.startX, charge.startY, 3, 0, Math.PI * 2);
          ctx.fill();
          ctx.strokeStyle = withAlpha(accentToken, 0.25, fallbackAccent);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(charge.startX, charge.startY, 6 + Math.min(38, len * 0.12), 0, Math.PI * 2);
          ctx.stroke();
        }
      }

      for (const node of nodes) {
        let alpha = 0.42 + node.r * 0.12;
        if (pointerLive) {
          const pd = Math.hypot(node.x - pointer.x, node.y - pointer.y);
          if (pd < ATTRACT_RADIUS) alpha += 0.5 * (1 - pd / ATTRACT_RADIUS);
        }
        ctx.fillStyle = withAlpha(accentToken, alpha, fallbackAccent);
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.fill();
      }

      for (const ripple of ripples) {
        const t = ripple.age / 0.9;
        ctx.strokeStyle = withAlpha(accentToken, 0.24 * (1 - t), fallbackAccent);
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(ripple.x, ripple.y, 8 + t * 220, 0, Math.PI * 2);
        ctx.stroke();
      }
    };

    const tick = (time: number) => {
      if (!running) return;
      const dt = lastTime ? Math.min(0.05, (time - lastTime) / 1000) : 0.016;
      lastTime = time;
      step(dt, true);
      drawFrame(dt, true);
      raf = requestAnimationFrame(tick);
    };

    const start = () => {
      if (running || reduced.matches) return;
      running = true;
      lastTime = 0;
      raf = requestAnimationFrame(tick);
    };

    const stop = () => {
      running = false;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
    };

    const syncMotion = () => {
      if (reduced.matches) {
        stop();
        step(0.016, false);
        drawFrame(0.016, false);
      } else {
        start();
      }
    };

    const onPointerMove = (event: PointerEvent) => {
      const now = performance.now();
      const gap = (now - lastPointerAt) / 1000;
      if (lastPointerAt && gap > 0.001) {
        const d = Math.hypot(event.clientX - pointer.cx, event.clientY - pointer.cy);
        const instant = Math.min(1500, d / gap);
        pointer.speed = pointer.speed * 0.6 + instant * 0.4;
      }
      lastPointerAt = now;
      pointer.cx = event.clientX;
      pointer.cy = event.clientY;
      syncPointerCanvas();
      pointer.active = true;
      if (charge.active) {
        charge.x = event.clientX;
        charge.y = event.clientY;
      }
    };

    const onPointerDown = (event: PointerEvent) => {
      const px = event.clientX;
      const py = event.clientY;
      charge.active = true;
      charge.startX = px;
      charge.startY = py;
      charge.x = px;
      charge.y = py;
      if (reduced.matches) return;
      ripples.push({ x: px, y: py, age: 0 });
      // 冲击波：把附近粒子向外荡开
      for (const node of nodes) {
        const dx = node.x - px;
        const dy = node.y - py;
        const d = Math.hypot(dx, dy);
        if (d >= SHOCK_RADIUS || d < 0.001) continue;
        const impulse = (1 - d / SHOCK_RADIUS) * SHOCK_IMPULSE;
        node.vx += (dx / d) * impulse;
        node.vy += (dy / d) * impulse;
      }
    };

    // 弹弓释放：拖距够长则沿拖拽方向定向弹射，否则只是普通点击（仅有按下时的径向冲击）
    const onPointerUp = (event: PointerEvent) => {
      if (!charge.active) return;
      charge.active = false;
      if (reduced.matches) return;
      const px = event.clientX;
      const py = event.clientY;
      const dx = px - charge.startX;
      const dy = py - charge.startY;
      const len = Math.hypot(dx, dy);
      if (len < CHARGE_MIN_DRAG) return;
      const power = (Math.min(len, 380) / 380) * SLING_MAX_IMPULSE;
      const ux = dx / len;
      const uy = dy / len;
      for (const node of nodes) {
        const rx = node.x - px;
        const ry = node.y - py;
        const d = Math.hypot(rx, ry);
        if (d >= SLING_RADIUS) continue;
        const falloff = 1 - d / SLING_RADIUS;
        node.vx += ux * power * falloff + (Math.random() - 0.5) * 40 * falloff;
        node.vy += uy * power * falloff + (Math.random() - 0.5) * 40 * falloff;
      }
      ripples.push({ x: px, y: py, age: 0 });
    };

    const onDoubleClick = (event: MouseEvent) => {
      if (reduced.matches) return;
      if (phantoms.length >= MAX_PHANTOMS) phantoms.shift();
      phantoms.push({ x: event.clientX, y: event.clientY, age: 0 });
    };

    const onWheel = (event: WheelEvent) => {
      if (reduced.matches) return;
      const kick = Math.max(-1, Math.min(1, event.deltaY / 500)) * WHEEL_KICK;
      for (const node of nodes) node.vy += kick;
      const now = performance.now();
      if (pointer.active && now - lastWheelRipple > WHEEL_RIPPLE_GAP) {
        lastWheelRipple = now;
        ripples.push({ x: pointer.x, y: pointer.y, age: 0 });
      }
    };

    const resetGestures = () => {
      pointer.active = false;
      pointer.speed = 0;
      charge.active = false;
    };

    const onVisibility = () => {
      if (document.hidden) stop();
      else syncMotion();
    };

    // 主题切换（data-theme 属性变化）时重读颜色 token
    const themeObserver = new MutationObserver(() => {
      accentToken = readToken("--tone-accent");
      if (!running) drawFrame(0.016, false);
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    accentToken = readToken("--tone-accent");
    resize();

    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    window.addEventListener("pointerdown", onPointerDown, { passive: true });
    window.addEventListener("pointerup", onPointerUp, { passive: true });
    window.addEventListener("pointercancel", resetGestures, { passive: true });
    window.addEventListener("dblclick", onDoubleClick, { passive: true });
    window.addEventListener("wheel", onWheel, { passive: true });
    document.documentElement.addEventListener("pointerleave", resetGestures);
    document.addEventListener("visibilitychange", onVisibility);
    reduced.addEventListener("change", syncMotion);
    syncMotion();

    return () => {
      stop();
      themeObserver.disconnect();
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("pointercancel", resetGestures);
      window.removeEventListener("dblclick", onDoubleClick);
      window.removeEventListener("wheel", onWheel);
      document.documentElement.removeEventListener("pointerleave", resetGestures);
      document.removeEventListener("visibilitychange", onVisibility);
      reduced.removeEventListener("change", syncMotion);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      className="pointer-events-none fixed inset-0 h-full w-full"
    />
  );
}
