// 网关测试台域：表单状态与检测结果类型。
// 从 page.tsx 原样搬出（前端单体拆解阶段 1），供 page 与 gateway 视图共享。

export type GatewayResult = {
  ok: boolean;
  title: string;
  message: string;
  detail?: unknown;
};

export type GatewayFormState = {
  model: string;
  prompt: string;
  externalContext: string;
  toolName: string;
  parameters: string;
  stream: boolean;
};

export const DEFAULT_GATEWAY_FORM: GatewayFormState = {
  model: "shadow-agent-simulated",
  prompt: "请总结这段外部资料，并保持原始用户意图不变。",
  externalContext: "",
  toolName: "",
  parameters: "{\n  \"requires_admin\": false\n}",
  stream: false,
};
