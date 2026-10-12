# Shadow Agent Frontend

Next.js + Tailwind CSS 管理端大屏，用于展示影子智能体的运行态势、拦截日志和策略状态。

## Run

```powershell
npm install
$env:SHADOW_AGENT_API_BASE="http://127.0.0.1:8000"
npm run dev
```

访问 `http://localhost:3000`。

## Checks

```powershell
npm test      # vitest：只测纯逻辑（邮箱形状、注册状态文案），不需要 DOM
npm run lint
npm run build
```

`npm test` 覆盖的是**构建与类型检查都抓不到的判定逻辑** —— 例如「后端连不上」曾被写成
「注册已关闭」这类谎报。为此这类逻辑被抽成纯模块（`src/app/auth-logic.ts`、
`src/app/time-utils.ts`）而不是留在 `page.tsx` 里，用例放 `src/app/__tests__/`。
刻意不装 jsdom / testing-library：组件能否渲染由截图验证，装一整套 DOM 环境只为渲一个
client component 是拿依赖换信心。新增判定分支时请同步抽成纯函数并补用例。
