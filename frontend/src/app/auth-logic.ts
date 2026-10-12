/**
 * Pure auth-form logic, kept out of `page.tsx` so it can be tested.
 *
 * Both functions below exist because of a real defect class:
 *
 * * `isValidEmailInput` — registration used to accept any string and let the
 *   backend answer 400/422, so the form itself said nothing (fixed in e156ef1).
 * * `registrationHint` — the copy was a nested ternary inside the JSX, and it
 *   reported a **network failure** as the policy conclusion "注册已关闭"
 *   (fixed in eb8efcc). Deriving both the tone and the message here makes that
 *   property assertable: an unreachable backend must never be described as a
 *   decision the product made.
 *
 * A component test would need a browser and a running backend; these two are
 * plain functions, so the guard costs milliseconds.
 */

/** Mirrors the shape returned by `/api/v1/auth/bootstrap-status`. */
export type BootstrapStatus = {
  initialized: boolean;
  bootstrap_required: boolean;
  bootstrap_token_configured: boolean;
  demo_override_enabled: boolean;
  open_registration_enabled: boolean;
  invite_token_configured: boolean;
  recommended_role: string;
};

/* 注册时账号邮箱即身份，格式必须在**发出请求前**就拦住 —— 否则用户只会看到
   一个来自后端的 400/422，而表单本身毫无反馈。
   ⚠️ 只用于注册；登录不做形状拦截，以免把历史上已存在的非标准账号锁在门外。 */
const EMAIL_LOCAL_PATTERN = /^[A-Za-z0-9._%+\-]+$/;
const EMAIL_LABEL_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$/;
const EMAIL_TLD_PATTERN = /^[A-Za-z]{2,63}$/;

export function isValidEmailInput(value: string): boolean {
  const candidate = value.trim();
  if (candidate.length < 3 || candidate.length > 255) return false;
  if (candidate.split("@").length !== 2) return false;
  const [local, domain] = candidate.split("@");
  if (local.length < 1 || local.length > 64) return false;
  if (!EMAIL_LOCAL_PATTERN.test(local)) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  if (!EMAIL_TLD_PATTERN.test(labels[labels.length - 1])) return false;
  return labels.slice(0, -1).every((label) => EMAIL_LABEL_PATTERN.test(label));
}

export type RegistrationHint = {
  /** `danger` renders as an error banner; `neutral` as a plain explanatory note. */
  tone: "danger" | "neutral";
  message: string;
};

/**
 * Copy for the registration panel under every bootstrap state.
 *
 * Order matters and is the point of the function: an unreachable backend is
 * checked **first** and always wins. Deriving a policy statement from
 * `bootstrapStatus === null` is the bug this replaces — `null` means "not
 * loaded or not reachable", never "registration disabled".
 */
export function registrationHint(
  status: BootstrapStatus | null,
  bootstrapUnreachable: boolean,
  apiBaseUrl: string,
): RegistrationHint | null {
  if (bootstrapUnreachable) {
    return {
      tone: "danger",
      message: `无法连接后端服务（${apiBaseUrl}）。页面能打开不代表后端在线——请先确认后端已启动，否则登录与注册都会以「Failed to fetch」失败。`,
    };
  }

  if (!status) {
    // Loading, and not an error: say nothing rather than invent a conclusion.
    return null;
  }

  if (status.bootstrap_required) {
    if (status.bootstrap_token_configured) {
      return {
        tone: "neutral",
        message:
          "当前后端还没有管理员账号。请在注册时填写 bootstrap token，完成首个管理员初始化。",
      };
    }
    if (status.demo_override_enabled) {
      return {
        tone: "neutral",
        message:
          "当前后端还没有管理员账号，但已开启本地 demo 直通模式，可直接完成首个管理员注册。",
      };
    }
    return {
      tone: "neutral",
      message:
        "当前后端还没有管理员账号，且尚未配置 bootstrap token。请先在后端环境变量中设置 SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN。",
    };
  }

  if (status.open_registration_enabled) {
    return { tone: "neutral", message: "注册已开放，新账号将默认获得 client 角色。" };
  }
  if (status.invite_token_configured) {
    return { tone: "neutral", message: "注册为邀请制，请在下方填写管理员提供的邀请码。" };
  }
  return {
    tone: "neutral",
    message: "注册已关闭。请联系管理员获取邀请码，或由管理员签发托管 API Key。",
  };
}
