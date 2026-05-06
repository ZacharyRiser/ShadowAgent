import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  FileText,
  LayoutDashboard,
  Lock,
  Network,
  Settings,
  Shield,
} from "lucide-react";

export const dynamic = "force-dynamic";

type InterceptLog = {
  id: number;
  timestamp: string;
  threat_type: string;
  action_taken: string;
  original_prompt: string;
  details: {
    request_id?: string;
    layer?: string;
    reason?: string;
    risk_score?: number;
    source_excerpt?: string;
    [key: string]: unknown;
  };
};

async function getInterceptLogs(): Promise<InterceptLog[]> {
  const apiBase = process.env.SHADOW_AGENT_API_BASE ?? "http://localhost:8000";

  try {
    const response = await fetch(`${apiBase}/api/v1/logs?limit=20`, {
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch logs: ${response.status}`);
    }

    const data = (await response.json()) as { items?: InterceptLog[] };
    return data.items ?? [];
  } catch {
    return [];
  }
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function riskTone(score = 0) {
  if (score >= 0.9) {
    return "border-red-400/40 bg-red-500/10 text-red-100";
  }

  if (score >= 0.75) {
    return "border-amber-400/40 bg-amber-500/10 text-amber-100";
  }

  return "border-emerald-400/40 bg-emerald-500/10 text-emerald-100";
}

export default async function Home() {
  const logs = await getInterceptLogs();
  const totalBlocked = logs.filter((log) => log.action_taken === "Blocked").length;
  const unauthorizedApiCalls = logs.filter(
    (log) => log.threat_type === "Unauthorized API",
  ).length;
  const promptInjections = logs.filter(
    (log) => log.threat_type === "Prompt Injection",
  ).length;

  const metrics = [
    {
      label: "总拦截次数",
      value: totalBlocked.toString(),
      icon: AlertTriangle,
      tone: "text-red-200",
    },
    {
      label: "越权调用阻断",
      value: unauthorizedApiCalls.toString(),
      icon: Lock,
      tone: "text-amber-200",
    },
    {
      label: "提示词注入攻击",
      value: promptInjections.toString(),
      icon: Activity,
      tone: "text-cyan-200",
    },
  ];

  const policySnapshot = [
    ["指令/数据解耦", "启用", "text-emerald-200"],
    ["语义意图审计", "规则引擎", "text-amber-200"],
    ["工具权限控制", "白名单", "text-emerald-200"],
    ["日志持久化", "SQLite", "text-cyan-200"],
  ];

  const navigationItems = [
    { label: "总览", icon: LayoutDashboard, active: true },
    { label: "拦截日志", icon: FileText },
    { label: "安全策略配置", icon: Settings },
  ];

  return (
    <main className="min-h-screen overflow-x-hidden bg-[#08111f] text-slate-100">
      <div className="grid min-h-screen min-w-0 grid-cols-1 lg:grid-cols-[264px_minmax(0,1fr)]">
        <aside className="border-b border-slate-800 bg-[#0b1424] px-5 py-5 lg:border-b-0 lg:border-r">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-300/30 bg-cyan-500/10">
              <Shield className="h-5 w-5 text-cyan-200" aria-hidden="true" />
            </div>
            <div>
              <div className="text-sm font-semibold text-white">Shadow Agent</div>
              <div className="text-xs text-slate-400">Runtime Security</div>
            </div>
          </div>

          <nav className="mt-8 space-y-1" aria-label="管理导航">
            {navigationItems.map((item) => (
              <a
                key={item.label}
                href="#"
                className={`flex h-10 items-center gap-3 rounded-md px-3 text-sm ${
                  item.active
                    ? "border border-cyan-300/30 bg-cyan-400/10 text-cyan-100"
                    : "text-slate-400 hover:bg-slate-800/70 hover:text-slate-100"
                }`}
              >
                <item.icon className="h-4 w-4" aria-hidden="true" />
                {item.label}
              </a>
            ))}
          </nav>

          <div className="mt-8 rounded-lg border border-slate-800 bg-slate-900/70 p-4">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-100">
              <Network className="h-4 w-4 text-emerald-300" aria-hidden="true" />
              代理层状态
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
              <span>Gateway</span>
              <span className="rounded-md border border-emerald-300/30 bg-emerald-400/10 px-2 py-1 text-emerald-100">
                Online
              </span>
            </div>
          </div>
        </aside>

        <section className="min-w-0 px-5 py-6 sm:px-8">
          <header className="flex flex-col gap-4 border-b border-slate-800 pb-6 md:flex-row md:items-end md:justify-between">
            <div>
              <p className="text-sm font-medium text-cyan-200">
                大模型运行时安全态势
              </p>
              <h1 className="mt-2 text-3xl font-semibold text-white">
                影子智能体控制台
              </h1>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300">
              <CheckCircle2 className="h-4 w-4 text-emerald-300" aria-hidden="true" />
              实时审计链路已启用
            </div>
          </header>

          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {metrics.map((metric) => (
              <div
                key={metric.label}
                className="rounded-lg border border-slate-800 bg-slate-900/80 p-5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">{metric.label}</span>
                  <metric.icon className={`h-5 w-5 ${metric.tone}`} aria-hidden="true" />
                </div>
                <div className="mt-4 font-mono text-3xl font-semibold text-white">
                  {metric.value}
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
            <section className="min-w-0 rounded-lg border border-slate-800 bg-slate-900/80">
              <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    最新拦截记录
                  </h2>
                  <p className="mt-1 text-sm text-slate-400">
                    来自后端审计数据库的最近安全事件
                  </p>
                </div>
              </div>
              <div
                className="max-w-full overflow-x-auto whitespace-nowrap"
                data-log-table-scroll
              >
                <table className="w-full min-w-[760px] border-collapse text-left text-sm">
                  <thead className="text-xs uppercase text-slate-500">
                    <tr className="border-b border-slate-800">
                      <th className="px-5 py-3 font-medium">时间</th>
                      <th className="px-5 py-3 font-medium">威胁类型</th>
                      <th className="px-5 py-3 font-medium">处置</th>
                      <th className="px-5 py-3 font-medium">风险</th>
                      <th className="px-5 py-3 font-medium">命中层</th>
                      <th className="px-5 py-3 font-medium">原始输入</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.length === 0 ? (
                      <tr>
                        <td className="px-5 py-8 text-slate-400" colSpan={6}>
                          暂无拦截记录
                        </td>
                      </tr>
                    ) : (
                      logs.map((log) => (
                        <tr
                          key={log.id}
                          className="border-b border-slate-800/80 last:border-b-0"
                        >
                          <td className="px-5 py-4 font-mono text-xs text-slate-400">
                            {formatTime(log.timestamp)}
                          </td>
                          <td className="px-5 py-4 text-slate-100">
                            {log.threat_type}
                          </td>
                          <td className="px-5 py-4">
                            <span className="rounded-md border border-red-400/30 bg-red-500/10 px-2 py-1 text-xs text-red-100">
                              {log.action_taken}
                            </span>
                          </td>
                          <td className="px-5 py-4">
                            <span
                              className={`rounded-md border px-2 py-1 font-mono text-xs ${riskTone(
                                log.details.risk_score,
                              )}`}
                            >
                              {(log.details.risk_score ?? 0).toFixed(2)}
                            </span>
                          </td>
                          <td className="px-5 py-4 font-mono text-xs text-cyan-200">
                            {log.details.layer ?? "unknown"}
                          </td>
                          <td className="max-w-[260px] truncate px-5 py-4 text-slate-300">
                            {log.original_prompt}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="rounded-lg border border-slate-800 bg-slate-900/80 p-5">
              <h2 className="text-base font-semibold text-white">策略快照</h2>
              <div className="mt-5 space-y-4">
                {policySnapshot.map(([label, value, tone]) => (
                  <div
                    key={label}
                    className="flex items-center justify-between border-b border-slate-800 pb-3 last:border-b-0 last:pb-0"
                  >
                    <span className="text-sm text-slate-400">{label}</span>
                    <span className={`text-sm font-medium ${tone}`}>{value}</span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </section>
      </div>
    </main>
  );
}
