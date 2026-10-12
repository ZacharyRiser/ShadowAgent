# ShadowAgent 页面结构与版式说明

> **本文件不是设计系统文档**，只是为"下一位接手项目的人"提供一份**页面与版式的现状说明**。
> 视觉规范依据：`impeccable` / `frontend-design` / `apple-design` / `frontend-dev`
> 四个 skill 的条款；设计决策与理由见 `.impeccable.md` 与仓库提交历史。
>
> 编写：Falcon ／ 2026-09-18
> **更新：2026-09-19**（兼容层删除 + 硬编码清零 + 台账式重构 + 全量 token 化）

---

## 1. 产品与使用者

**ShadowAgent** —— AI Agent 运行时安全网关。反向代理夹在 OpenAI 兼容客户端与上游 LLM 之间，
检测提示词注入、未授权工具调用、密钥外泄、敏感文件访问、危险命令、提权持久化。
处置：放行 / 告警 / 脱敏 / 阻断。事件进拦截日志 + SSE + Webhook。

| 角色 | 关心什么 | 界面重点 |
| --- | --- | --- |
| 安全运营（主要） | 拦截了什么、为什么拦、误报率 | 拦截日志、策略、告警 |
| 安全管理员 | 密钥治理、权限发放、证据导出 | 密钥中心、审批、证据包 |
| 运维 | 关联网关、看健康度 | 设置、运行参考 |
| 业务接入方 | 能不能调、怎么调 | 对话、验证场景 |

**误报会直接导致真实业务中断** —— 精确率优先是产品红线，视觉上表现为
"阻断状态必须一眼可辨、但整体配色不能到处是红"。

---

## 2. 主题机制

两套主题，同一份组件代码：

| 主题 | 触发 | 视觉方向 |
| --- | --- | --- |
| `dark` | `html[data-theme="dark"]`（由设置项选定，或系统偏好） | 精密仪器风：深底、亮度分层、网格底纹 |
| `light` | `html[data-theme="light"]` | 编辑风：冷调纸白、明确栏线、双层投影 |

主题由 `localStorage['shadow-agent-settings']` 的 `themeMode` 驱动，取值为
`system` / `light` / `dark`；`system` 时不写 `data-theme`，走媒体查询。

---

## 3. 实现结构（三个文件）

### `src/app/globals.css`（690 行，**六段式**）

1. **尺度层** `@theme inline` —— 字体（含中文回落链）、三档玻璃模糊、固定 rem 字阶、
   4pt 间距、区块节奏、4 档圆角、指数缓动、时长、z-index 阶梯
2. **双主题色板** —— `html[data-theme="dark"], html:not([data-theme])` + `html[data-theme="light"]`
3. **基础排版** —— `h1`–`h4`（字号/字重/负字距/行高）、`.prose-cjk`、`.tnum`
4. **滚动条**
5. **语义工具类** —— `.glass-panel`、`.btn-*`、`.chip-*`、`.skeleton`、`.tap-target`、底纹
6. **无障碍** —— `prefers-reduced-motion`、全局 `:focus-visible`

> **附：SOC 大屏的浅色适配**
> 外壳走 `bg-[var(--background)]`，**跟随主题**（浅色模式即浅色大屏）。
> 浅色主题下相邻层级亮度差极小（画布 97.5% / sunken 95.8% / raised 100%），
> 仅靠边框撑不起深度 → 容器级卡片/区块加 `soc-card` 类，由
> `html[data-theme="light"] .soc-shell .soc-card { box-shadow: var(--panel-shadow-soft) }`
> 补真实投影。深色主题不需要（靠亮度分层 + inset 高光）。
> ⚠️ **不要把该视图钉成恒定深色** —— 那只是把「不协调」换成「一块深色孤岛」。

> ⚠️ **这里曾经有第 7 段「兼容层」（340 行），已于 2026-09-19 整层删除。**
> 它当初的作用是用「同优先级 + 靠后」压过源码里约 750 处硬编码色类。
> 删除原因：**它本身是 bug 放大器** —— `.text-white{color:var(--text-primary)}` 会按源码顺序
> 压掉同元素上的 `text-[var(--accent-on-solid)]`，导致主按钮变成深底深字（对比度 ~1.9:1）。
> 现在硬编码色类已在**源码层清零**，兼容层没有存在必要。**请勿复活。**

### `src/app/page.tsx`（约 8300 行）

单文件应用，含全部视图的渲染函数。样式基础常量集中在文件头部：

| 常量 / 组件 | 用途 |
| --- | --- |
| `buttonBase` | 所有按钮共享：高度、内距、字重、focus ring、disabled |
| `inputBase` | 所有输入框/选择框共享 |
| `glassPanelClass` | 主面板（大圆角 + 边框 + 背景 + 阴影 + 玻璃模糊） |
| `glassPanelSoftClass` | 次级面板（无模糊、软边框） |
| `glassPanelMotionClass` | 面板的 hover 动效叠加层 |
| `floatingGlassMenuClass` | 浮层菜单 |
| `buttonClass(variant)` | 取 primary / secondary / ghost / danger 四套按钮皮肤 |
| `viewVariants` | 视图切换动效（入场 260ms，出场 120ms） |
| **`Ledger`** | **台账外壳**：表头 + `empty` 态 + 行容器（详见第 6 节） |
| **`ledgerRowClass`** | **台账行的公共地板**：`border-b` 分隔 + hover 底色 + 只过渡颜色 |
| **`severityChipClass()`** | 严重级 → `chip-*` 变体（只返回变体，基类由调用方拼） |
| `PanelGlow` | 面板顶部 1px 高光栏线（**仅页面级 `p-6` 刊头保留，卡片级已移除**） |

视图清单与 `VIEW_ITEMS` 常量一一对应（对话、总览、日志、策略、密钥、告警、审批、
证据、大屏、设置、帮助）。新增视图：加一条 `VIEW_ITEMS` + 一个 `renderXxx()`。

### `src/app/layout.tsx`

只做 `html` / `body` 骨架与元信息，不承载视觉。

---

## 4. 版式速查（改动前请遵守）

- **字号**：一律用 `text-[length:var(--text-*)]`。
  ⚠️ **必须带 `length:` 前缀** —— Tailwind v4 把 `text-<arbitrary>` 当「字号/颜色二选一」
  命名空间，不写前缀会按 **color** 编译（字号零生效，还会抢走同元素上的颜色声明）。
  颜色则相反：`text-[var(--text-muted)]` **不带**前缀才对。
- **字重**：标题 620–700，正文 400–500，标签 600。不要用 900。
- **间距**：`var(--space-2xs)` 4px 起，按 4/8/12/16/24/32/48/64 递进。
- **圆角**：`--radius-xs/sm/md/lg/xl` = 6/8/12/16/22。默认 `sm`（控件）或 `md`（卡片）。
- **缓动**：只用 `--ease-out-quart` / `--ease-out-quint` / `--ease-out-expo`。
  **不要用 `ease`、`ease-in-out` 或任何回弹曲线**（framer-motion 的 `type: "spring"` 同样禁用）。
- **时长**：`--dur-instant` 120ms（按压）、`--dur-fast` 160ms（hover）、
  `--dur-base` 240ms（状态变化）、`--dur-slow` 380ms（大块位移）。
- **过渡属性**：用 `transition-[color,background-color,border-color,box-shadow,transform,opacity]`，
  **不要用 `transition-all`**（会带上 width/height 等触发布局的属性）。
- **z-index**：用 `--z-dropdown/sticky/overlay/modal/toast/tooltip`，**不要写魔法数字**。
- **数据**：加 `.tnum` 类，避免数字宽度抖动。
- **中文段落**：加 `.prose-cjk` 类（行高 1.75、字距 0.02em）。

---

## 5. 台账（Ledger）模式 —— 高密度同构记录的标准做法

**凡是「N 条同构记录、每行 3~6 个字段」的列表，一律用台账，不要卡片墙。**
卡片墙会把每行包成 12px 圆角 + 描边 + 底色的盒子，是反 AI 味检查表 #4
「一模一样圆角卡片」的逐字命中，也违反 spatial-design 的「Cards Are Not Required」。

已台账化的视图：验证场景库、策略列表、自定义规则、组织列表、成员列表、
运行状态路由明细、指标带、帮助页能力域、设置页字段组。

### 写法

```tsx
<Ledger
  gridClass="grid-cols-1 sm:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_auto]"
  columns={["", "", "text-right"]}      // 逐列表头对齐类，可省
  header={["能力域 / 说明", "可用端点与凭据", "操作"]}
  empty="暂无数据"
>
  {rows.map((row) => (
    <div className={`grid ... ${ledgerRowClass}`}>...</div>
  ))}
</Ledger>
```

- **行高收益实测**：验证场景库从 92px/卡（5 张卡 + 间距）压到 **56px/行**，首屏可见条数翻倍。
- **选中态不要整行换边框 + 阴影**：改「行首绝对定位竖条 + 序号/标题变色」。
- **刻意不用 `<table>`**：行内常放 `Switch` / `GlassSelect` / 长文本，窄屏要折行，
  `grid` 比 `table` 的 colgroup 更可控。

### ⚠️ 两条硬规则

1. **骨架屏栅格必须与真实行逐格一致**（复用同一份 `gridClass` 常量）——
   否则数据到达瞬间整页跳版。历史上组织台账骨架屏第 3 格用了居中、真实行是 `justify-self-end`。
2. **窄屏里每个单元格都要显式 `col-start-N`**。只给 `row-start-N` 会被 auto-flow 丢进
   第 2 列 —— 实测风险分徽章跑到左列与类型字段**重叠**并渲染出游离字符。
   次要列用 `hidden sm:block` 折叠，避免两格抢同一个 `col-start-3`。

> ℹ️ `Ledger` 组件目前**只被 1 处使用**（帮助页）。另外几处台账是手写的
> `grid` + `ledgerRowClass`，因为它们的表头在四个维度上都有差异：
> 外壳（`glassPanelClass` vs 裸 border）、gap（`gap-x-3` vs `-4`）、
> 内距（`px-4 sm:px-5` vs `px-5`）、表头是否带 `bg-[var(--surface-sunken)]`。
> 注意 **表头 gap 必须等于行 gap**，否则列会错位。强行统一需要给 `Ledger` 加 4 个 prop
> （抽象成本超过它消除的重复），或改动 5 个视图的外观 —— 两者都不划算，故暂不统一。

---

## 6. 已知的样式债务

1. **`--accent-on-solid` 不是通用「前景色」**。它的语义是「实心强调色底上的前景色」，
   在深色主题是 `oklch(19%)` **近黑**。把它用在非强调底的元素上会出问题 ——
   实测把 Switch 滑块写成 `bg-[var(--accent-on-solid)]` 后，深色主题下是
   近黑滑块压 `oklch(24%)` 轨道，**滑块完全不可见**（浅色主题反而正常，
   所以只截一个主题必漏）。滑块用 `bg-[var(--text-primary)]`。
2. **`settings.apiBase` 只能经由 `apiBaseUrl`（已兜底）读取**，
   不得裸调 `settings.apiBase.replace(...)` / `.trim()` ——
   localStorage 缺字段会 `undefined.replace` **打挂整页**，且崩溃面会蔓延到
   事件回调 / `useEffect` / async fetcher。
3. **组件实际宽度不能用 `@container` 或 `md:` 断点判断**：同一个行组件可能同时出现在
   全宽页 / 360px 登录样例卡 / 总览侧栏三处，同视口下宽度可差 3 倍 ——
   任何视口断点都必然猜错其中一种。用**显式 `dense` prop** 由调用方声明版面。
4. **改完源码必须清 `.next/dev` 重启 dev server**：webpack 的 Tailwind 产物**不随 HMR 更新**，
   否则探针与截图读到的都是陈旧 CSS。删/改类名后要清 `.next` 全量重建。
5. **本机无 playwright/puppeteer**，视觉验证靠自建 Chrome headless + CDP 截图
   （`_shots/cdp_shot.py` 单张 / `_shots/shoot_all.py` 批量双主题）；
   另有 `_shots/audit_frontend.py`（违规写法审计）、`_shots/tokenize_remaining.py`（token 化）。
   ⚠️ 临时管理令牌写在 `_shots/_token.txt`，已在 `.gitignore` 排除 —— **不要提交**。
6. **`PanelGlow` 装饰密度**：43 处 → 8 处（只留页面级刊头）。一条青色高光线重复
   43 次就从「克制点缀」退化成「模式化装饰」。新增面板时先想想是否真需要。
7. **`--text-lg` 无精确对应 token**：`text-lg`(18px) → `--text-subhead`(17px) 差 1px。
   其余映射（`text-xs`=12=`--text-micro`、`text-sm`=14=`--text-body`、
   `text-xl`=20=`--text-heading`、`rounded-xl`=12=`--radius-md`、`rounded-2xl`=16=`--radius-lg`）
   均为像素精确。
