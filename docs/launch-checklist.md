# Shadow Agent 上线检查清单

发布到生产环境前的逐项确认。全部勾选前不应对外提供服务。

## 1. 密钥与配置（阻断项）

- [ ] `SHADOW_AGENT_JWT_SECRET` 已设置（≥32 字符随机值），且未写入代码库/git
- [ ] `SHADOW_AGENT_API_KEY_PEPPER` 与 JWT 密钥是不同的随机值
- [ ] `SHADOW_AGENT_ADMIN_API_KEY` / `SHADOW_AGENT_CLIENT_API_KEY` 为高强度随机值，仅存于密钥管理设施
- [ ] `SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN` 已设置；首个管理员注册后妥善销毁记录
- [ ] `SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP=false`（除非临时演示）
- [ ] `SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=false`（生产必须走真实上游）
- [ ] `SHADOW_AGENT_ALLOWED_ORIGINS` 仅包含真实控制台域名
- [ ] `.env` 文件不在镜像内（`.dockerignore` 已覆盖，构建后再核对）
- [ ] 所有默认密钥/演示密钥已轮换或删除

## 2. 部署架构

- [ ] 入口已启用 TLS（反代/负载均衡终止），HTTP 明文端口未对外暴露
- [ ] 数据库卷启用静态加密并有备份策略
- [ ] 单实例部署：容器以非 root 用户运行，healthcheck 通过
- [ ] 多实例部署：`INSTALL_REDIS=true` 构建 + `SHADOW_AGENT_REDIS_URL` 已配置，且 `/health` 返回 `"shared_state": "redis"`
- [ ] 上游 LLM 提供商的 API key 仅存在于后端环境，从未下发到前端
- [ ] Alembic 迁移在部署流程中执行（容器入口已内置）

## 3. 安全验证

- [ ] `python -m pytest tests` 全部通过（含共享态测试）
- [ ] 未授权访问 `/metrics`、`/api/v1/logs` 返回 401/403
- [ ] 注入攻击样本（直接/间接/多轮）均被 403 阻断且有拦截日志
- [ ] `GET /api/v1/semantic-status`（管理员凭证）返回 `model_loaded: true`，`mode` 与灰度决策一致（建议先 `monitor` 观察再切 `enforce`）
- [ ] `GET /api/v1/rules/dlp-status` 确认响应侧 DLP 模式符合预期（生产建议 `redact` 或 `block`，不要 `off`）
- [ ] 中文注入改写样本人工抽测（已知短板：中文泛化召回低，见 [benchmarks/injection-detection.md](benchmarks/injection-detection.md)；monitor 模式事件可作回流标注）
- [ ] 登录连续失败触发账户锁定（429）
- [ ] 停用账户后其 JWT 立即失效
- [ ] 审批单二次审批返回 409（状态机完整）
- [ ] `python tools/check_openai_compat.py` 退出码为 0（网关对标准 OpenAI 请求/工具调用为 drop-in 兼容）
- [ ] 已按业务决定 `SHADOW_AGENT_UNKNOWN_TOOL_POLICY`：默认 `deny` 为严格白名单，
      **未在策略表中的第三方工具会被拒绝**；接入真实 Agent（工具名不可穷举）时需设为 `allow`，
      此时仍由行为风险引擎拦截危险命令/敏感文件/内网目标/凭据访问
- [ ] 已用真实客户端（含 function calling 多轮）人工跑通一次工具调用闭环
- [ ] 多租户隔离抽测：A 组织管理员按 id 访问/修改 B 组织的规则、密钥、日志均返回 404；SSE 事件流仅含本组织事件
- [ ] SSO 回调校验：错误 state / 过期 state 重放被拒绝（`#error=sso_invalid_state`）；停用账号在回调时被拒绝
- [ ] 若启用 SSO：`SHADOW_AGENT_CONSOLE_URL` / `SHADOW_AGENT_PUBLIC_BASE_URL` 为生产域名，IdP 侧已注册 `{PUBLIC_BASE_URL}/api/v1/auth/sso/callback` 回调地址，JIT 默认角色与邀请策略经过评审
- [ ] 无任何测试后门/调试端点残留：`SHADOW_AGENT_DOCS_ENABLED` 保持 `false`（默认），
      `GET /docs`、`/redoc`、`/openapi.json` 均返回 404 —— **应用内已强制**，不再依赖反代屏蔽
- [ ] 已按业务决定 `SHADOW_AGENT_LOG_REDACT`：默认 `secrets` 会遮蔽凭据形状后再落库；
      若某次排查确需原文，临时切 `full`（更严）而不是 `off`
- [ ] 已确认 `SHADOW_AGENT_MAX_BODY_BYTES`（默认 2 MiB）不会截断真实业务的最大上下文；
      该值与前置反代/网关的上限**取更小者生效**，压测时的超大用例需相应调整
- [ ] 启动日志中的 `ShadowAgent posture:` 一行与预期一致（`log_redact` / `docs` / `max_body_bytes` / `upstream` /
      `upstream_retries` / `upstream_proxy_env`）
- [ ] 已按上游 SLA 决定重试与熔断参数：`SHADOW_AGENT_UPSTREAM_RETRY_MAX`（默认 2）、
      `_RETRY_BUDGET_SECONDS`（默认 90s，**整次调用的墙钟上限**）、`_CIRCUIT_THRESHOLD`（默认 5）、
      `_CIRCUIT_COOLDOWN_SECONDS`（默认 30s）。默认只重试连接期错误与 429；
      `_RETRY_UNSAFE=true` 会重试读超时/5xx，**可能重复计费与重复执行工具调用**，上线前需书面确认
- [ ] `SHADOW_AGENT_UPSTREAM_TRUST_ENV` 保持 `false`（默认）—— 上游流量含 prompt 与模型输出，
      不应静默走环境里的 `HTTP(S)_PROXY`；确需代理出网时显式置 `true` 并记录原因
- [ ] **依赖漏洞已清零（两侧均已实测满足）**：后端 `pip-audit -r backend/requirements.txt --strict`
      退出码为 0（2026-09-26 实测通过）；前端 2026-09-27 刷新后 OSV 复核全量锁文件
      （437 包）与生产树（58 包）均零公告，CI `npm audit --audit-level=high` 已转阻断。
      复跑方式：`python frontend/tools/osv_npm_audit.py --prod-only`

## 4. 可观测性与运维

- [ ] Prometheus 已抓取 `/metrics`（管理员凭证），告警规则覆盖 5xx 比率、延迟 P99、限流触发量
- [ ] 日志外送集中系统（审计防篡改）
- [ ] **网关进程的 stdout/stderr 必须被持续消费（阻断项）**：日志 sink 写不进去时，
  管道缓冲区写满（Windows 实测约 4KB）会让写入方**永久阻塞**。日志已默认交给后台
  `QueueListener` 线程（`app/logging_setup.py`），所以**被卡住的是那条线程、不再是事件循环**
  —— 请求不会挂起，但队列会填满并开始丢日志。禁止用「无人读取的管道」启动：`subprocess.PIPE`
  无读线程、supervisor/journald 停止读取、重定向到已写满的磁盘、NSSM 等包装器丢弃输出等。
  ⚠️ 这只把故障从「静默停摆」降级成「静默丢日志」，判断依据从「服务没响应」变成
  **`shadow_agent_log_dropped_total` 非零**（见下一条）。
- [ ] **日志丢弃已纳入监控（阻断项）**：`shadow_agent_log_dropped_total` **任何非零值即告警**
  —— 它表示后台 sink 跟不上日志速率（或 sink 被阻塞），记录正在被丢弃。
  `shadow_agent_log_queue_depth` 持续上升是更早的预警信号。解耦只在
  `shadow_agent_log_async_enabled == 1` 时生效；若该值为 `0`（部署方显式设了
  `SHADOW_AGENT_LOG_ASYNC=0`），则回到同步写，上一条的「静默停摆」风险重新成立。
- [ ] **数据外发边界已决策并留档（阻断项）**：`/metrics` 的
  `shadow_agent_remote_fallback_enabled` 必须为 `0`（默认、出厂配置）。
  若确要开启远程兜底（`SHADOW_AGENT_REMOTE_FALLBACK_MODE`），必须先把四件事写进部署文档：
  (1) **哪些数据会出网**（仅语义层灰带样本，且默认经 `redact_text` 脱敏 + 截断 1500 字符）；
  (2) **发给谁**（`..._ALLOWED_HOSTS` 白名单，空 = 通道关闭；非 loopback 强制 https）；
  (3) **谁批准了这次外发**（本项目「零网络调用」是卖点，开启即改变产品语义）；
  (4) **超时预算**（`..._TIMEOUT_MS`，默认 1500ms，跑在请求路径上）。
  另需监控 `shadow_agent_remote_fallback_total{outcome="error"}`：非零增长说明在付延迟却没拿到判定。
  ⚠️ 该通道**一律绕过 `HTTP_PROXY`**（`ProxyHandler({})`）——把安全判定流量交给无人配置过的代理
  正是本产品要防的静默外发。
- [ ] 日志保留期已按 [gdpr.md](compliance/gdpr.md) 第 5 节决策并设置 `SHADOW_AGENT_*_RETENTION_DAYS` 环境变量（内置自动清理，默认拦截/告警/重放 180 天、审计 365 天）
- [ ] `/metrics` 中 `shadow_agent_retention_purged_rows_total` 已纳入监控（首次大额清理属预期行为）
- [ ] **数据库连接池饱和已纳入监控（阻断项）**：`shadow_agent_db_pool_timeout_total`
  **任何非零值即告警** —— 它表示有请求在等连接时耗尽了 `pool_timeout`，也就是网关发生了停顿。
  `shadow_agent_db_pool_connections{state="in_use"}` 与 `shadow_agent_db_pool_capacity`
  接近（>80%）时应提前扩容。**池上限必须大于峰值并发连接需求**（进程内实测：c=8 峰值 7 条、
  c=32 峰值 23 条；持有时长 8–24ms，与 handler 的 ~2ms CPU 时间无关）。
  历史教训：该指标此前**完全不存在**，池饱和时网关静默停摆（零字节返回、无 5xx、无日志），
  排查耗时一整轮会话，最终靠 `faulthandler` 抓栈才发现。
- [ ] 备份恢复演练至少完成一次
- [ ] Redis 故障时的 fail-open 降级行为已纳入应急预案（限流退化为单实例）

## 5. 合规

- [ ] 面向欧盟：GDPR 数据映射与告知文本完成（见 [gdpr.md](compliance/gdpr.md)）
- [ ] 面向中国境内：等保定级备案与自查表完成（见 [mlps-2.0.md](compliance/mlps-2.0.md)）
- [ ] 与上游 LLM 提供商签署数据处理协议
- [ ] 工具拦截策略（黑名单/工具权限）已按业务场景评审

## 6. 性能验收

**绝对 rps 不是通过/不通过的门槛。** 同代码在同一台机器上背靠背复测差异 ≤10%，
但**跨会话（机器负载不同）实测差 13–20%**：2026-09-20 较早一次测得
health 841 / chat 294 / injection 152 / analyze 357 / logs 499 rps，
当日晚些时候用**同一份代码**（含 `git archive HEAD` 提取的纯提交版本）复测得下表数值；
`HEAD` 与工作树逐场景差异为 +3.0% / −2.3% / +4.5% / +3.4% / +13.2%（`logs` 一项落在
会话内噪声带内，见下），**未提交改动不构成性能回退**。因此下表的用途是**量级参考**，
验收以下面的相对判据为准，上线前必须在目标硬件上重测。

测量条件（缺任意一项，测得的数字无效）：

- `c=8`、每场景 15s；服务端 `stdout/stderr` 必须被消费（`DEVNULL` 或读线程）
- **两个限流变量都要抬高**：`SHADOW_AGENT_RATE_LIMIT_PER_MINUTE`
  **和** `SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE`（后者默认 20/min，只作用于
  `/api/v1/logs`；漏设会让 `logs` 场景测到 429 而不是吞吐，且不会报错）
- `SHADOW_AGENT_UPSTREAM_BASE_URL=" "`：dotenv 不覆盖已存在的环境变量，
  而 `backend/.env` 指向真实上游；漏设会让 `chat` 场景真的外发并返回 502
- loopback 目标须忽略环境代理（`perf/load_test.py` 已内建）

| 场景 | 实测区间 rps | p50 | p95 | 说明 |
| --- | ---: | ---: | ---: | --- |
| GET /health | 728–732 | 9.3 | 15–16 | 无认证、无 DB 写 |
| POST /chat/completions（放行） | 251 | 29.5–30.0 | 41.5–41.9 | 全检测引擎 |
| POST /chat/completions（阻断） | 134–144 | 44–49 | 109–112 | 含拦截日志写入 |
| POST /analyze | 285–314 | 24–26 | 34–39 | 无写 |
| GET /api/v1/logs（管理员） | 464–498 | 11 | 39–45 | 独立限流，见上 |
| mixed（9 场景 × c=8 = 72 worker） | 145–166 | 289–319 | 1218–1388 | **不与单场景行可比**，见下 |

两次运行合计 31,410 / 32,213 请求、**0 个 5xx**，压测后 `/health` 均为 200。

验收判据（相对，与硬件无关）：

- 阻断路径 p95 不劣化放行路径 3 倍以上（当前 109–112ms vs 41.5–41.9ms ≈ **2.6–2.7×**，通过）
- 语义检测层 p95 < 33ms（层内预算，与端到端请求延迟是两码事）
- 0 个 5xx，且压测后 `/health` 正常

⚠️ **`mixed` 行不与单场景行可比** —— 它展开成 9 个场景 × `--concurrency`，
即 `c=8` 时是 **72 路并发**，而单场景行只有 8 路。实测（同服务、同载荷，只改客户端
连接上限）：

| 客户端连接上限 | mixed rps | p50 | p95 |
| ---: | ---: | ---: | ---: |
| 12（旧 harness：按 `concurrency` 而非 worker 总数 sizing） | 238.9 | 185.4ms | 879ms |
| 76（修复后：按 72 worker sizing） | 156.5 | 302.4ms | 1250ms |

即：**提高 offer 并发反而使吞吐从 239 降到 157 rps**，属超出饱和点后的争用塌陷，
不是排队等待。此前记录在案的 `mixed` 281 rps / p50 234ms 是**客户端连接饥饿**造成的
假值（72 worker 只有 12 条连接），已作废；该场景「p50 高于任一单场景 p99」不再是
待查缺陷，而是**跨场景混合负载本身的属性**。

⚠️ **连接池已修复**（见 `backend/database.py::_pool_kwargs`）：SQLAlchemy 默认 QueuePool
上限 15，`pool.checkout()` 同步跑在事件循环上，而 `c=32` 时**连接需求峰值实测 23 条**
（SQLAlchemy 池 `checkout`/`checkin` 事件埋点；`c=8` 峰值仅 7）→ 需求顶穿上限后循环被钉死。
关键点：同步 `checkout()` 使「缺连接」不是**排队**而是**停摆** —— 循环一卡，在飞的请求就无法
完成、无法归还连接，形成正反馈。（修前 `chat` `c=32` 为 4.8 rps + 32 × 30s 客户端超时，
连接持有 p95 = 30,046ms；修后 246 rps、0 错、持有 p95 51ms。）
修复方式为 `pool_size=20` / `max_overflow=40` / `pool_timeout` 30s→5s。
**内存型 SQLite 必须跳过该 sizing**（`SingletonThreadPool` 会拒绝这些参数）。

**容量规划**：池上限必须 **> 峰值并发连接需求**（本例 23）。实测连接持有 8.3ms@c=8 /
24.3ms@c=32 —— **不等于 handler 的 ~2ms CPU 时间**（差额是 DB 往返 + 预检 ping + 提交），
所以「handler 很快 ⇒ 连接池够用」是错误推理。移植到 PostgreSQL / 多 worker 时必须重测峰值，
**不要照抄 20+40**。

生产环境用 `backend/perf/load_test.py` 重测并记录到运维文档（注意其 docstring 中的
stdout 消费与限流/上游三条要求，否则测得的数字无效）。

**自动门禁（相对判据，硬件无关）**：`cd backend && python tools/perf_gate.py`
（exit 0 通过 / 1 判据失败 / 2 无法运行）。两档：

- **档 1 并发压力**：`chat` @ `c=32`（**必须超过池上限才压得到上限**——原缺陷在 c=8 完全不显形）
- **档 2 相对延迟形状**：5 个单场景 @ `c=8`（不含 `mixed`，它是 72 路并发，不可比）

判据：无 5xx、无客户端超时(599)、阻断路径 p95 不劣化放行路径 4 倍以上、压测后 `/health`
仍在服务（无静默停摆）、**连接池未饿死任何请求**（`shadow_agent_db_pool_timeout_total == 0`）。
已验证：旧配置（`SHADOW_AGENT_DB_POOL_SIZE=5 SHADOW_AGENT_DB_MAX_OVERFLOW=10`，即缺陷当时的 15 条）
下门禁**失败**，默认配置下**通过**。

该门禁已接进 CI 的 `perf-gate` job，但**只在手动触发（`workflow_dispatch`）时运行** ——
判据是相对的、硬件无关，但共享 runner 仍然是测延迟比值的噪声环境，而**第一天就红掉的门禁
只会训练人忽略它**。改动请求路径 / 连接池 / `app/middleware` 之后，从 Actions 页手动跑一次。
（`backend/tests/test_ci_gates.py` 守着「它仍在 CI 里」与「仍是手动触发」两条。）


## 7. 发布后迭代

- 跟踪 `requirements*.txt` 安全更新（建议每月一次依赖审计）
- **依赖自动更新已配置**：`.github/dependabot.yml` —— pip（`/backend`）与 npm（`/frontend`）
  每周一 09:00 Asia/Shanghai、github-actions 每月；minor/patch 按生态分组成单个 PR，major 不进组；
  `next` / `eslint-config-next` / `react` / `react-dom` 被显式忽略，因为它们是**成组精确锁定**的，
  必须一起动并人工验证。⚠️ **安全更新（security updates）还需在仓库 Settings 里单独开启** ——
  配置文件管不到那一项。
- **前端判定逻辑有单元测试守护**：`frontend` 的 `vitest` 套件在 CI 的 Lint 与 Build 之间跑
  `npm test`（邮箱形状、注册状态文案等分支逻辑）。新增此类判定必须抽成纯函数并补用例，
  否则形成无人守的空白 —— `next build` + `tsc` 不会因为「把网络故障写成策略结论」而变红。
- 拦截规则误报/漏报反馈渠道已建立
- 版本发布走 CI 全绿后发布
