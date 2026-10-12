"use client";

// 组织视图：前端单体拆解阶段 1，JSX 自 page.tsx renderOrgs 逐字搬出（AST 定位，零手抄）。
// 状态与副作用仍归 page.tsx 所有（阶段 2 再归仓）；本组件纯展示 + 回调上抛。

import type { Dispatch, SetStateAction } from "react";
import { Building2, ChevronRight, Globe, Plus, RefreshCcw, Save, Shield, Trash2, Users } from "lucide-react";
import { GlassSelect } from "../components/glass-select";
import { PanelGlow, ledgerRowClass } from "../components/page-widgets";
import { buttonClass, glassPanelClass, inputBase } from "../components/ui-kit";
import type { OrgListItem, OrgMemberItem, SsoConfigItem } from "../types";

export function OrgsView({
  addOrgMember,
  createOrg,
  deleteOrgSso,
  hasAdminAccess,
  hasConsoleToken,
  loadOrgList,
  memberAddBusy,
  memberAddForm,
  memberBusyId,
  orgCreateBusy,
  orgCreateForm,
  orgCreateOpen,
  orgList,
  orgListError,
  orgListLoading,
  orgMembers,
  orgMembersLoading,
  orgSelectedId,
  orgSsoBusy,
  orgSsoConfig,
  orgSsoForm,
  orgSsoLoading,
  removeOrgMember,
  saveOrgSso,
  selectOrg,
  setMemberAddForm,
  setOrgCreateForm,
  setOrgCreateOpen,
  setOrgSsoForm,
  updateOrgMemberRole,
}: {
  addOrgMember: () => Promise<void>;
  createOrg: () => Promise<void>;
  deleteOrgSso: () => Promise<void>;
  hasAdminAccess: boolean;
  hasConsoleToken: boolean;
  loadOrgList: () => Promise<void>;
  memberAddBusy: boolean;
  memberAddForm: { email: string; role: string };
  memberBusyId: number | null;
  orgCreateBusy: boolean;
  orgCreateForm: { slug: string; name: string };
  orgCreateOpen: boolean;
  orgList: OrgListItem[];
  orgListError: string;
  orgListLoading: boolean;
  orgMembers: OrgMemberItem[];
  orgMembersLoading: boolean;
  orgSelectedId: number | null;
  orgSsoBusy: boolean;
  orgSsoConfig: SsoConfigItem | null;
  orgSsoForm: { provider_name: string; client_id: string; client_secret: string; issuer_url: string; scopes: string; default_role: string; jit_enabled: boolean; enabled: boolean };
  orgSsoLoading: boolean;
  removeOrgMember: (userId: number, email: string) => Promise<void>;
  saveOrgSso: () => Promise<void>;
  selectOrg: (orgId: number | null) => void;
  setMemberAddForm: Dispatch<SetStateAction<{ email: string; role: string }>>;
  setOrgCreateForm: Dispatch<SetStateAction<{ slug: string; name: string }>>;
  setOrgCreateOpen: Dispatch<SetStateAction<boolean>>;
  setOrgSsoForm: Dispatch<SetStateAction<{ provider_name: string; client_id: string; client_secret: string; issuer_url: string; scopes: string; default_role: string; jit_enabled: boolean; enabled: boolean }>>;
  updateOrgMemberRole: (userId: number, role: string) => Promise<void>;
}) {
{
    if (!hasAdminAccess) {
      return (
        <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
          <PanelGlow />
          <div className="relative flex items-start gap-3 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
            <Shield className="mt-0.5 h-5 w-5 shrink-0 text-[var(--tone-warning-text)]" aria-hidden />
            <span>组织管理需要管理员权限。请使用管理员账号登录，或在「设置」中配置 Admin API Key 后重试。</span>
          </div>
        </section>
      );
    }

    const selectedOrg = orgList.find((org) => org.id === orgSelectedId) ?? null;
    const canManageSelected =
      Boolean(selectedOrg) &&
      (selectedOrg?.role === "owner" || selectedOrg?.role === "admin" || !hasConsoleToken);

    return (
      <div className="space-y-5">
        <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
          <PanelGlow />
          <div className="relative flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">组织（租户）</h2>
              <p className="mt-1 text-[length:var(--text-body)] leading-6 text-[var(--text-secondary)]">
                每个组织拥有独立的日志、策略、自定义规则与托管密钥；平台管理员可见全部组织，组织管理员仅可见所属组织。
              </p>
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={() => void loadOrgList()} disabled={orgListLoading} className={buttonClass("secondary")}>
                <RefreshCcw className={`h-4 w-4 ${orgListLoading ? "animate-spin" : ""}`} aria-hidden />
                刷新
              </button>
              <button type="button" onClick={() => setOrgCreateOpen((current) => !current)} className={buttonClass("primary")}>
                <Plus className="h-4 w-4" aria-hidden />
                创建组织
              </button>
            </div>
          </div>

          {orgCreateOpen ? (
            <div className="relative mt-4 rounded-[var(--radius-lg)] border border-[var(--panel-border)] bg-[var(--surface-raised)] p-5">
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="mb-2 block text-[length:var(--text-caption)] text-[var(--text-secondary)]">组织标识（slug，仅小写字母、数字、-、_）</span>
                  <input
                    value={orgCreateForm.slug}
                    onChange={(event) => setOrgCreateForm((current) => ({ ...current, slug: event.target.value }))}
                    className={inputBase}
                    placeholder="acme"
                    autoComplete="off"
                  />
                </label>
                <label className="block">
                  <span className="mb-2 block text-[length:var(--text-caption)] text-[var(--text-secondary)]">组织名称</span>
                  <input
                    value={orgCreateForm.name}
                    onChange={(event) => setOrgCreateForm((current) => ({ ...current, name: event.target.value }))}
                    className={inputBase}
                    placeholder="Acme Inc."
                    autoComplete="off"
                  />
                </label>
              </div>
              <div className="mt-3 flex justify-end gap-2">
                <button type="button" onClick={() => setOrgCreateOpen(false)} className={buttonClass("ghost")}>
                  取消
                </button>
                <button type="button" onClick={() => void createOrg()} disabled={orgCreateBusy} className={buttonClass("primary")}>
                  {orgCreateBusy ? "创建中…" : "创建"}
                </button>
              </div>
              <p className="mt-2 text-[length:var(--text-micro)] leading-5 text-[var(--text-muted)]">
                创建组织需要平台管理员或现有组织的 owner 角色；创建者将自动成为新组织的 owner。
              </p>
            </div>
          ) : null}

          {/* 组织列表：卡片墙 → 台账。每个组织一行，选中态用行首竖条而非整行换边框。
              列：[竖条][名称+slug][角色/成员][SSO][默认] */}
          <div className="relative mt-4 overflow-hidden rounded-[var(--radius-lg)] border border-[var(--panel-border)]">
            <div className="grid grid-cols-[3px_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-[var(--panel-border)] bg-[var(--surface-sunken)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)] sm:grid-cols-[3px_minmax(0,1fr)_minmax(0,0.9fr)_auto_auto]">
              <span aria-hidden />
              <span>组织</span>
              <span className="hidden sm:block">角色 / 成员</span>
              <span className="hidden text-right sm:block">SSO</span>
              <span className="text-right">状态</span>
            </div>

            {orgListError ? (
              <div className="border-b border-[var(--divider)] px-4 py-3" role="alert">
                <p className="rounded-[var(--radius-md)] border border-[color-mix(in_oklab,var(--tone-danger)_28%,transparent)] bg-[var(--tone-danger-surface)] px-4 py-3 text-[length:var(--text-caption)] text-[var(--tone-danger-text)]">
                  组织列表加载失败：{orgListError}
                </p>
              </div>
            ) : null}

            {orgListLoading && orgList.length === 0 ? (
              /* 骨架屏而非"加载中…"文字：interaction-design 明确要求 skeleton > spinner */
              <div role="status" aria-label="组织列表加载中">
                <span className="sr-only">正在加载组织列表</span>
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} aria-hidden className="grid grid-cols-[3px_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-[var(--divider)] px-4 py-3.5 last:border-b-0 sm:grid-cols-[3px_minmax(0,1fr)_minmax(0,0.9fr)_auto_auto]">
                    <span className="skeleton h-9 w-[3px] rounded-full" />
                    <div className="flex flex-col gap-1.5">
                      <span className="skeleton h-4 w-1/3" />
                      <span className="skeleton h-3 w-1/2" />
                    </div>
                    <span className="skeleton hidden h-3.5 w-24 sm:block" />
                    <span className="skeleton hidden h-5 w-14 sm:block" />
                    <span className="skeleton h-5 w-12 justify-self-end" />
                  </div>
                ))}
              </div>
            ) : orgList.length === 0 ? (
              <p className="px-4 py-8 text-center text-[length:var(--text-body)] text-[var(--text-muted)] sm:px-5">
                还没有可见组织。点击「创建组织」建立第一个租户。
              </p>
            ) : null}

            {orgList.map((org) => {
              const selected = org.id === orgSelectedId;
              return (
                <button
                  key={org.id}
                  type="button"
                  onClick={() => selectOrg(selected ? null : org.id)}
                  aria-pressed={selected}
                  className={`relative grid w-full grid-cols-[3px_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 px-4 py-3 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--tone-accent)] sm:grid-cols-[3px_minmax(0,1fr)_minmax(0,0.9fr)_auto_auto] ${ledgerRowClass} ${
                    selected ? "bg-[var(--tone-accent-surface)]" : ""
                  }`}
                >
                  <span
                    aria-hidden
                    className={`h-9 w-[3px] self-center rounded-full transition-colors duration-[var(--dur-fast)] ${
                      selected ? "bg-[var(--accent-solid)]" : "bg-transparent"
                    }`}
                  />
                  <span className="min-w-0">
                    <span className="flex flex-wrap items-center gap-2">
                      <Building2 className={`h-4 w-4 shrink-0 ${selected ? "text-[var(--tone-accent-text)]" : "text-[var(--text-muted)]"}`} aria-hidden />
                      <span className={`truncate text-[length:var(--text-body)] font-medium ${selected ? "text-[var(--tone-accent-text)]" : "text-[var(--text-primary)]"}`}>
                        {org.name}
                      </span>
                      <span className="shrink-0 font-mono text-[length:var(--text-micro)] text-[var(--text-muted)]">{org.slug}</span>
                    </span>
                  </span>
                  {/* 移动端（3 列）只有 [竖条][组织][状态] 三格：
                      SSO 与角色两列折叠隐藏，避免与状态格争抢同一栅格单元。
                      sm: 起升到 5 列，各归其位。 */}
                  <span className="hidden truncate text-[length:var(--text-caption)] text-[var(--text-secondary)] sm:col-start-3 sm:block">
                    {org.role || "member"}
                    {typeof org.member_count === "number" ? ` · ${org.member_count} 名成员` : ""}
                  </span>
                  <span className="hidden justify-end sm:col-start-4 sm:flex">
                    {org.sso_enabled ? (
                      <span className="chip chip-success">SSO: {org.sso_provider || "已启用"}</span>
                    ) : (
                      <span className="text-[length:var(--text-micro)] text-[var(--text-muted)]">—</span>
                    )}
                  </span>
                  <span className="col-start-3 flex items-center justify-end gap-1.5 sm:col-start-5">
                    {org.is_default ? <span className="chip chip-info">默认</span> : null}
                    <ChevronRight
                      className={`h-4 w-4 shrink-0 text-[var(--text-muted)] transition-transform duration-[var(--dur-fast)] ${selected ? "rotate-90" : ""}`}
                      aria-hidden
                    />
                  </span>
                </button>
              );
            })}
          </div>
        </section>

        {selectedOrg ? (
          <div className="grid gap-5 xl:grid-cols-2">
            <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
              <PanelGlow />
              <div className="relative flex items-start justify-between gap-3">
                <div>
                  <h2 className="flex items-center gap-2 text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">
                    <Users className="h-4 w-4 text-[var(--tone-accent-text)]" aria-hidden />
                    成员管理 · {selectedOrg.name}
                  </h2>
                  <p className="mt-1 text-[length:var(--text-micro)] leading-5 text-[var(--text-muted)]">
                    添加已有控制台账号并分配组织角色（owner / admin / member）。
                  </p>
                </div>
              </div>

              {canManageSelected ? (
                <div className="relative mt-4 flex flex-col gap-2 sm:flex-row">
                  <input
                    value={memberAddForm.email}
                    onChange={(event) => setMemberAddForm((current) => ({ ...current, email: event.target.value }))}
                    className={inputBase}
                    placeholder="成员邮箱（需已注册或经 SSO 开户）"
                    aria-label="成员邮箱"
                  />
                  <div className="flex shrink-0 gap-2">
                    <div className="w-32">
                      <GlassSelect
                        value={memberAddForm.role}
                        options={[
                          { value: "member", label: "member" },
                          { value: "admin", label: "admin" },
                          { value: "owner", label: "owner" },
                        ]}
                        onChange={(value) => setMemberAddForm((current) => ({ ...current, role: value }))}
                        ariaLabel="成员角色"
                      />
                    </div>
                    <button type="button" onClick={() => void addOrgMember()} disabled={memberAddBusy} className={buttonClass("primary")}>
                      <Plus className="h-4 w-4" aria-hidden />
                      {memberAddBusy ? "添加中…" : "添加"}
                    </button>
                  </div>
                </div>
              ) : null}

              {/* 成员列表：卡片墙 → 台账。列：[头像][姓名+邮箱][平台角色][组织角色][操作] */}
              <div className="relative mt-4 overflow-hidden rounded-[var(--radius-lg)] border border-[var(--panel-border)]">
                <div className="grid grid-cols-[2rem_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-[var(--panel-border)] bg-[var(--surface-sunken)] px-4 py-2 text-[length:var(--text-micro)] font-medium uppercase tracking-[0.08em] text-[var(--text-muted)]">
                  <span aria-hidden />
                  <span>成员</span>
                  <span className="text-right">组织角色</span>
                </div>

                {orgMembersLoading ? (
                  <div role="status" aria-label="成员加载中">
                    <span className="sr-only">正在加载组织成员</span>
                    {Array.from({ length: 3 }).map((_, i) => (
                      <div key={i} aria-hidden className="grid grid-cols-[2rem_minmax(0,1fr)_auto] items-center gap-x-3 border-b border-[var(--divider)] px-4 py-3 last:border-b-0">
                        <span className="skeleton h-8 w-8 rounded-full" />
                        <div className="flex flex-col gap-1.5">
                          <span className="skeleton h-3.5 w-1/3" />
                          <span className="skeleton h-3 w-1/2" />
                        </div>
                        <span className="skeleton h-6 w-20" />
                      </div>
                    ))}
                  </div>
                ) : orgMembers.length === 0 ? (
                  <p className="px-4 py-8 text-center text-[length:var(--text-body)] text-[var(--text-muted)]">
                    还没有成员。用上方输入框按邮箱添加第一个成员。
                  </p>
                ) : null}

                {!orgMembersLoading &&
                  orgMembers.map((member) => (
                    <div
                      key={member.user_id}
                      className={`grid grid-cols-[2rem_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-2 px-4 py-3 ${ledgerRowClass}`}
                    >
                      <span
                        aria-hidden
                        className="grid h-8 w-8 place-items-center rounded-full border border-[color-mix(in_oklab,var(--tone-accent)_26%,transparent)] bg-[var(--tone-accent-surface)] font-mono text-[length:var(--text-micro)] font-semibold text-[var(--tone-accent-text)]"
                      >
                        {(member.name || member.email).trim().slice(0, 1).toUpperCase()}
                      </span>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate text-[length:var(--text-body)] font-medium text-[var(--text-primary)]">
                            {member.name || member.email}
                          </span>
                          {!member.is_active ? <span className="chip chip-danger">已停用</span> : null}
                        </div>
                        <div className="mt-0.5 truncate text-[length:var(--text-micro)] text-[var(--text-muted)]">
                          {member.email} · 平台角色 {member.platform_role}
                        </div>
                      </div>
                      {canManageSelected ? (
                        <div className="flex items-center gap-1.5">
                          <div className="w-28">
                            <GlassSelect
                              value={member.org_role}
                              options={[
                                { value: "member", label: "member" },
                                { value: "admin", label: "admin" },
                                { value: "owner", label: "owner" },
                              ]}
                              onChange={(value) => void updateOrgMemberRole(member.user_id, value)}
                              ariaLabel={`调整 ${member.email} 的组织角色`}
                            />
                          </div>
                          <button
                            type="button"
                            onClick={() => void removeOrgMember(member.user_id, member.email)}
                            disabled={memberBusyId === member.user_id}
                            className="tap-target inline-flex items-center justify-center rounded-[var(--radius-xs)] p-1.5 text-[var(--text-muted)] transition-colors duration-[var(--dur-fast)] hover:bg-[var(--tone-danger-surface)] hover:text-[var(--tone-danger-text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--tone-accent)] disabled:opacity-50"
                            aria-label={`移除成员 ${member.email}`}
                            title="移除成员"
                          >
                            <Trash2 className="h-4 w-4" aria-hidden />
                          </button>
                        </div>
                      ) : (
                        <span className="chip chip-neutral justify-self-end">{member.org_role}</span>
                      )}
                    </div>
                  ))}
              </div>
            </section>

            <section className={`${glassPanelClass} relative overflow-hidden p-6`}>
              <PanelGlow />
              <div className="relative">
                <h2 className="flex items-center gap-2 text-[length:var(--text-heading)] font-semibold text-[var(--text-primary)]">
                  <Globe className="h-4 w-4 text-[var(--tone-accent-text)]" aria-hidden />
                  OIDC 单点登录 · {selectedOrg.slug}
                </h2>
                <p className="mt-1 text-[length:var(--text-micro)] leading-5 text-[var(--text-muted)]">
                  Authorization Code + PKCE；成员在登录页输入组织标识「{selectedOrg.slug}」即可直达企业 IdP 登录。
                </p>

                {orgSsoLoading ? (
                  <p className="mt-4 text-[length:var(--text-body)] text-[var(--text-muted)]">SSO 配置加载中…</p>
                ) : !canManageSelected ? (
                  <p className="mt-4 text-[length:var(--text-body)] text-[var(--text-muted)]">需要组织 owner / admin 角色才能配置 SSO。</p>
                ) : (
                  <div className="mt-4 space-y-3">
                    <div className="flex flex-wrap items-center gap-2 text-[length:var(--text-micro)]">
                      <span
                        className={`rounded-full border px-2.5 py-0.5 ${
                          orgSsoConfig?.enabled
                            ? "border-[color-mix(in_oklab,var(--tone-success)_28%,transparent)] bg-[var(--tone-success-surface)] text-[var(--tone-success-text)]"
                            : "border-[var(--panel-border)] bg-[var(--surface-raised)] text-[var(--text-secondary)]"
                        }`}
                      >
                        {orgSsoConfig?.enabled ? "已启用" : orgSsoConfig ? "已停用" : "未配置"}
                      </span>
                      {orgSsoConfig?.client_secret_masked ? (
                        <span className="font-mono text-[var(--text-muted)]">secret {orgSsoConfig.client_secret_masked}</span>
                      ) : null}
                    </div>

                    <label className="block">
                      <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">Provider 名称（展示用）</span>
                      <input
                        value={orgSsoForm.provider_name}
                        onChange={(event) => setOrgSsoForm((current) => ({ ...current, provider_name: event.target.value }))}
                        className={inputBase}
                        placeholder="Okta / Auth0 / Entra ID"
                        autoComplete="off"
                      />
                    </label>
                    <label className="block">
                      <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">Issuer URL（支持 .well-known/openid-configuration）</span>
                      <input
                        value={orgSsoForm.issuer_url}
                        onChange={(event) => setOrgSsoForm((current) => ({ ...current, issuer_url: event.target.value }))}
                        className={inputBase}
                        placeholder="https://login.acme.com"
                        autoComplete="off"
                      />
                    </label>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <label className="block">
                        <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">Client ID</span>
                        <input
                          value={orgSsoForm.client_id}
                          onChange={(event) => setOrgSsoForm((current) => ({ ...current, client_id: event.target.value }))}
                          className={inputBase}
                          autoComplete="off"
                        />
                      </label>
                      <label className="block">
                        <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">
                          Client Secret{orgSsoConfig?.client_secret_masked ? "（留空保留原值）" : ""}
                        </span>
                        <input
                          value={orgSsoForm.client_secret}
                          onChange={(event) => setOrgSsoForm((current) => ({ ...current, client_secret: event.target.value }))}
                          className={inputBase}
                          type="password"
                          autoComplete="new-password"
                        />
                      </label>
                    </div>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <label className="block">
                        <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">Scopes</span>
                        <input
                          value={orgSsoForm.scopes}
                          onChange={(event) => setOrgSsoForm((current) => ({ ...current, scopes: event.target.value }))}
                          className={inputBase}
                          autoComplete="off"
                        />
                      </label>
                      <label className="block">
                        <span className="mb-2 block text-[length:var(--text-body)] text-[var(--text-secondary)]">SSO 新用户平台角色（JIT 开户）</span>
                        <div className="min-h-10">
                          <GlassSelect
                            value={orgSsoForm.default_role}
                            options={[
                              { value: "client", label: "client" },
                              { value: "admin", label: "admin" },
                              { value: "security_admin", label: "security_admin" },
                            ]}
                            onChange={(value) => setOrgSsoForm((current) => ({ ...current, default_role: value }))}
                            ariaLabel="SSO 新用户默认平台角色"
                          />
                        </div>
                      </label>
                    </div>
                    <div className="flex flex-wrap gap-4">
                      <label className="flex items-center gap-2 text-[length:var(--text-body)] text-[var(--text-secondary)]">
                        <input
                          type="checkbox"
                          checked={orgSsoForm.jit_enabled}
                          onChange={(event) => setOrgSsoForm((current) => ({ ...current, jit_enabled: event.target.checked }))}
                          className="h-4 w-4 rounded border-[var(--panel-border)] bg-[var(--surface-raised)]"
                        />
                        JIT 自动开户（首次 SSO 登录自动创建账号）
                      </label>
                      <label className="flex items-center gap-2 text-[length:var(--text-body)] text-[var(--text-secondary)]">
                        <input
                          type="checkbox"
                          checked={orgSsoForm.enabled}
                          onChange={(event) => setOrgSsoForm((current) => ({ ...current, enabled: event.target.checked }))}
                          className="h-4 w-4 rounded border-[var(--panel-border)] bg-[var(--surface-raised)]"
                        />
                        启用 SSO 登录
                      </label>
                    </div>

                    <div className="flex flex-wrap justify-end gap-2 pt-1">
                      {orgSsoConfig ? (
                        <button type="button" onClick={() => void deleteOrgSso()} disabled={orgSsoBusy} className={buttonClass("danger")}>
                          <Trash2 className="h-4 w-4" aria-hidden />
                          删除连接
                        </button>
                      ) : null}
                      <button type="button" onClick={() => void saveOrgSso()} disabled={orgSsoBusy} className={buttonClass("primary")}>
                        <Save className="h-4 w-4" aria-hidden />
                        {orgSsoBusy ? "保存中…" : orgSsoConfig ? "更新配置" : "保存并启用"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </section>
          </div>
        ) : null}
      </div>
    );
  }
}
