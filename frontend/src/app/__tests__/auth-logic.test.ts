/**
 * Guards the two frontend defects that no build-time check could catch.
 *
 * * `isValidEmailInput` — the case table is deliberately the **same** list the
 *   backend uses in `backend/tests/test_email_validation.py`, including the
 *   value from the original bug report (`http/l8000@qq.com`). If the two
 *   validators drift, one of the suites fails instead of the user getting a
 *   400 from a form that said nothing.
 * * `registrationHint` — the copy used to be a nested ternary inside the JSX,
 *   and it announced 「注册已关闭」 for a backend that had never answered. The
 *   property asserted here is simple: the unreachable branch wins, and a
 *   missing status produces no conclusion at all.
 */

import { describe, expect, it } from "vitest";

import { isValidEmailInput, registrationHint, type BootstrapStatus } from "../auth-logic";

const VALID_EMAILS = [
  "name@example.com",
  "a.b+tag@sub.domain.co",
  "USER@EXAMPLE.COM",
  "x_y-z%1@a-b.io",
  "a@b.cn",
  "first.last@my-company.com.cn",
  "  name@example.com  ",
];

const INVALID_EMAILS = [
  "http/l8000@qq.com", // exact value from the bug report
  "plainaddress",
  "a@b", // no TLD
  "a@b.c", // 1-char TLD
  "a@b.123", // numeric TLD
  "a@.com",
  "a@b.",
  "a@b..com",
  "a@-b.com",
  "a@b-.com",
  ".a@b.com",
  "a.@b.com",
  "a..b@c.com",
  "a@@b.com",
  "a b@c.com",
  "@b.com",
  "a@b.com/",
  "中文@qq.com",
  "",
];

describe("isValidEmailInput", () => {
  it.each(VALID_EMAILS)("accepts %s", (email) => {
    expect(isValidEmailInput(email)).toBe(true);
  });

  it.each(INVALID_EMAILS)("rejects %s", (email) => {
    expect(isValidEmailInput(email)).toBe(false);
  });

  it("enforces the same length ceilings as the backend", () => {
    expect(isValidEmailInput("a".repeat(250) + "@example.com")).toBe(false);
    expect(isValidEmailInput("a".repeat(65) + "@example.com")).toBe(false);
    expect(isValidEmailInput("a".repeat(64) + "@example.com")).toBe(true);
  });
});

function status(overrides: Partial<BootstrapStatus> = {}): BootstrapStatus {
  return {
    initialized: true,
    bootstrap_required: false,
    bootstrap_token_configured: false,
    demo_override_enabled: false,
    open_registration_enabled: false,
    invite_token_configured: false,
    recommended_role: "client",
    ...overrides,
  };
}

describe("registrationHint", () => {
  it("reports an unreachable backend as a connectivity error, not a policy", () => {
    const hint = registrationHint(status({ open_registration_enabled: true }), true, "http://localhost:8000");
    expect(hint?.tone).toBe("danger");
    expect(hint?.message).toContain("无法连接后端服务");
    expect(hint?.message).toContain("http://localhost:8000");
    expect(hint?.message).not.toContain("注册已关闭");
  });

  it("keeps the connectivity message even when a stale status says otherwise", () => {
    // Network failure is checked first on purpose: a cached status must not be
    // able to turn an outage into "registration is open".
    const hint = registrationHint(status({ open_registration_enabled: true }), true, "http://127.0.0.1:8000");
    expect(hint?.tone).toBe("danger");
  });

  it("says nothing while the status is merely unknown", () => {
    // The original defect: `bootstrapStatus === null` was read as "registration
    // is closed". null means "not loaded / not reachable", so there is no
    // conclusion to draw yet.
    expect(registrationHint(null, false, "http://localhost:8000")).toBeNull();
  });

  it("describes the three bootstrap states", () => {
    const token = registrationHint(
      status({ initialized: false, bootstrap_required: true, bootstrap_token_configured: true }),
      false,
      "http://localhost:8000",
    );
    expect(token?.message).toContain("bootstrap token");

    const demo = registrationHint(
      status({ initialized: false, bootstrap_required: true, demo_override_enabled: true }),
      false,
      "http://localhost:8000",
    );
    expect(demo?.message).toContain("demo 直通模式");

    const missing = registrationHint(
      status({ initialized: false, bootstrap_required: true }),
      false,
      "http://localhost:8000",
    );
    expect(missing?.message).toContain("SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN");
  });

  it("distinguishes open, invite-only and closed registration", () => {
    expect(
      registrationHint(status({ open_registration_enabled: true }), false, "http://localhost:8000")?.message,
    ).toContain("注册已开放");
    expect(
      registrationHint(status({ invite_token_configured: true }), false, "http://localhost:8000")?.message,
    ).toContain("邀请制");
    expect(registrationHint(status(), false, "http://localhost:8000")?.message).toContain("注册已关闭");
  });

  it("only ever says registration is closed when the backend said so", () => {
    // Cross-check: walk every state and assert the closed copy appears exactly
    // once — for the one state that actually means it.
    const states: Array<[BootstrapStatus | null, boolean]> = [
      [null, false],
      [status({ open_registration_enabled: true }), false],
      [status({ invite_token_configured: true }), false],
      [status(), false],
      [status({ initialized: false, bootstrap_required: true }), false],
      [status(), true],
    ];
    const closedCount = states.filter(([s, unreachable]) =>
      (registrationHint(s, unreachable, "http://localhost:8000")?.message ?? "").includes("注册已关闭"),
    ).length;
    expect(closedCount).toBe(1);
  });

  it("always marks the neutral states as neutral", () => {
    const hint = registrationHint(status({ open_registration_enabled: true }), false, "http://localhost:8000");
    expect(hint?.tone).toBe("neutral");
  });
});
