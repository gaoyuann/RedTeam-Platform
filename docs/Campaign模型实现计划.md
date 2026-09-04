# Campaign 攻击战役模型 — 完整实现计划

> 日期：2026-08-19
> 目标：将攻击测试3类编排从"playbook过滤标签"提升为"攻击战役"一等公民

---

## 一、数据模型

### 1.1 新增表

```sql
-- ── 攻击战役 ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaigns (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id     TEXT    NOT NULL UNIQUE,           -- 唯一标识 camp_xxxx
  name            TEXT    NOT NULL,                  -- 战役名称
  description     TEXT,                               -- 战役描述
  target          TEXT,                               -- 主目标（IP/网段/主机名）
  status          TEXT    NOT NULL DEFAULT 'draft'
                  CHECK (status IN ('draft','running','paused','completed','failed','aborted')),
  created_by      TEXT    REFERENCES users(username),
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_campaigns_status    ON campaigns(status);
CREATE INDEX IF NOT EXISTS idx_campaigns_created_by ON campaigns(created_by);

-- ── 战役阶段 ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaign_phases (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  phase_id        TEXT    NOT NULL UNIQUE,           -- 唯一标识 phase_xxxx
  campaign_id     TEXT    NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
  phase_type      TEXT    NOT NULL
                  CHECK (phase_type IN ('data-exfiltration','tampering-deception','device-control')),
  display_name    TEXT,                               -- 阶段显示名（中文）
  order_index     INTEGER NOT NULL DEFAULT 0,         -- 推荐执行顺序 0=最先
  status          TEXT    NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','completed','skipped','failed')),
  summary         TEXT,                               -- 阶段结果摘要（JSON）
  config          TEXT,                               -- 阶段配置（JSON: auto_advance, required 等）
  started_at      TEXT,
  completed_at    TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_phases_campaign   ON campaign_phases(campaign_id);
CREATE INDEX IF NOT EXISTS idx_phases_type       ON campaign_phases(phase_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_phases_campaign_type ON campaign_phases(campaign_id, phase_type);

-- ── 阶段-Playbook编排 ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaign_playbooks (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id     TEXT    NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
  phase_id        TEXT    NOT NULL REFERENCES campaign_phases(phase_id) ON DELETE CASCADE,
  playbook_id     TEXT    NOT NULL REFERENCES playbooks(playbook_id),
  execution_order INTEGER NOT NULL DEFAULT 0,         -- 阶段内执行顺序
  execution_mode  TEXT    NOT NULL DEFAULT 'sequential'
                  CHECK (execution_mode IN ('sequential','parallel','conditional')),
  run_id          TEXT,                               -- 关联的执行记录ID
  status          TEXT    NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','completed','skipped','failed')),
  target_override TEXT,                               -- 阶段级目标覆盖（可选）
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cp_campaign  ON campaign_playbooks(campaign_id);
CREATE INDEX IF NOT EXISTS idx_cp_phase     ON campaign_playbooks(phase_id);
CREATE INDEX IF NOT EXISTS idx_cp_playbook  ON campaign_playbooks(playbook_id);

-- ── 阶段产物（跨阶段数据传递） ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaign_artifacts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id     TEXT    NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
  phase_id        TEXT    NOT NULL REFERENCES campaign_phases(phase_id),
  artifact_type   TEXT    NOT NULL,                   -- credential / ip_list / file_hash / access_token / custom
  artifact_key    TEXT    NOT NULL,                   -- 键名（如 "cracked_hashes", "discovered_ips"）
  artifact_value  TEXT    NOT NULL,                   -- 值（JSON字符串）
  source_run_id   TEXT,                               -- 来源执行记录
  created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_artifacts_campaign ON campaign_artifacts(campaign_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_phase    ON campaign_artifacts(phase_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type     ON campaign_artifacts(artifact_type);
```

### 1.2 数据关系图

```
campaigns (1) ──→ (N) campaign_phases (1) ──→ (N) campaign_playbooks
     │                    │                           │
     │                    │                           └──→ playbooks (已有)
     │                    │
     │                    └──→ (N) campaign_artifacts
     │                              ↑
     └──→ (N) campaign_artifacts ───┘  (跨阶段传递)
```

---

## 二、后端 API

### 2.1 新增路由文件 `backend/src/routes/campaigns.js`

#### Campaign CRUD

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/api/campaigns` | campaign:read | 列表（支持 ?status= 过滤） |
| GET | `/api/campaigns/:id` | campaign:read | 详情（含 phases + playbooks + artifacts） |
| POST | `/api/campaigns` | campaign:write | 创建战役（自动创建3个阶段） |
| PUT | `/api/campaigns/:id` | campaign:write | 更新战役（name/description/target） |
| DELETE | `/api/campaigns/:id` | campaign:write | 删除战役（CASCADE 删除 phases/playbooks/artifacts） |

#### Phase 管理

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/api/campaigns/:id/phases` | campaign:read | 获取3个阶段 |
| PUT | `/api/campaigns/:id/phases/:phaseId` | campaign:write | 更新阶段（config/display_name） |
| PUT | `/api/campaigns/:id/phases/:phaseId/skip` | campaign:write | 跳过某阶段 |

#### Playbook 编排

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| POST | `/api/campaigns/:id/phases/:phaseId/playbooks` | campaign:write | 添加 playbook 到阶段 |
| DELETE | `/api/campaigns/:id/phases/:phaseId/playbooks/:cpId` | campaign:write | 从阶段移除 playbook |
| PUT | `/api/campaigns/:id/phases/:phaseId/playbooks/reorder` | campaign:write | 重排阶段内 playbook 顺序 |

#### 战役执行

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| POST | `/api/campaigns/:id/start` | campaign:write | 启动战役（按阶段顺序执行） |
| POST | `/api/campaigns/:id/pause` | campaign:write | 暂停战役 |
| POST | `/api/campaigns/:id/resume` | campaign:write | 恢复战役 |
| POST | `/api/campaigns/:id/abort` | campaign:write | 终止战役 |

#### 产物管理

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/api/campaigns/:id/artifacts` | campaign:read | 获取所有产物 |
| GET | `/api/campaigns/:id/artifacts?phase_id=&type=` | campaign:read | 按阶段/类型过滤 |
| POST | `/api/campaigns/:id/artifacts` | campaign:write | 手动添加产物 |
| DELETE | `/api/campaigns/:id/artifacts/:artifactId` | campaign:write | 删除产物 |

#### 战役报告

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| GET | `/api/campaigns/:id/report` | campaign:read | 生成战役汇总报告 |

### 2.2 RBAC 扩展

在 `config/rbac.js` 新增 `campaign` 路由组：

```javascript
'campaign': { read: ['admin', 'teacher', 'operator', 'viewer', 'student'],
              write: ['admin', 'teacher', 'operator', 'student'] },
```

### 2.3 战役执行引擎 `backend/src/services/campaignEngine.js`

核心逻辑：

```
startCampaign(campaignId):
  1. 校验状态 (draft → running)
  2. 按 order_index 排序获取 phases
  3. 对每个 phase:
     a. 检查前置条件（是否有前置阶段的产物）
     b. 更新 phase status = running
     c. 按 execution_order 遍历 campaign_playbooks:
        - sequential: 逐个执行，前一个完成再执行下一个
        - parallel: 并行执行所有
        - conditional: 检查条件表达式决定是否执行
     d. 收集 evidence → 提取 artifacts → 写入 campaign_artifacts
     e. 更新 phase status = completed
     f. 检查 auto_advance 配置，决定是否自动进入下一阶段
  4. 所有 phase 完成 → campaign status = completed
  5. 生成 campaign report
```

**阶段间产物传递机制**：

- 阶段执行完成后，从 evidence_records 中提取关键产物
- 产物类型：credential（凭据）、ip_list（发现IP）、file_hash（文件哈希）、access_token（访问令牌）
- 下一阶段执行时，将前置阶段的产物注入为 playbook 变量（`{{artifact.credential}}`、`{{artifact.ip_list}}`）

### 2.4 迁移脚本 `backend/src/db/migrations/012_add_campaign_tables.js`

---

## 三、前端

### 3.1 新增 CampaignPage

替换 ExecutionPage 中的3个 RadioButton 区域，CampaignPage 作为"漏洞攻击测试"模块的主页面。

#### 页面结构

```
┌─────────────────────────────────────────────────────────────────────┐
│  攻击战役管理                                                        │
├─────────────────────────────────────────────────────────────────────┤
│  [＋ 新建战役]  [刷新]                                               │
├──────────┬──────────────────────────────────────────────────────────┤
│ 战役列表  │  战役详情                                                  │
│          │                                                            │
│ ▸ 战役A  │  名称: XXX        目标: 192.168.1.0/24                    │
│   运行中  │  状态: 运行中     创建: 2026-08-19                        │
│ ▸ 战役B  │                                                            │
│   已完成  │  ┌──────────────────────────────────────────────────────┐ │
│ ▸ 战役C  │  │ ① 数据抵近窃取  ──→ ② 信息篡改欺骗 ──→ ③ 关键设备夺控 │ │
│   草稿   │  │    ✅ 已完成         🔄 运行中          ⬜ 待执行       │ │
│          │  └──────────────────────────────────────────────────────┘ │
│          │                                                            │
│          │  ── 当前阶段: 信息篡改欺骗 ──────────────────────────────  │
│          │                                                            │
│          │  Playbook编排:                                             │
│          │  ┌────┬──────────────────────┬────────┬──────┐           │
│          │  │ 顺序│ Playbook             │ 模式    │ 状态 │           │
│          │  ├────┼──────────────────────┼────────┼──────┤           │
│          │  │ 1  │ DNS欺骗攻击          │ 串行    │ ✅   │           │
│          │  │ 2  │ 会话劫持攻击         │ 串行    │ 🔄   │           │
│          │  │ 3  │ DVWA文件篡改         │ 并行    │ ⬜   │           │
│          │  └────┴──────────────────────┴────────┴──────┘           │
│          │  [＋ 添加Playbook]  [移除]  [重排]                        │
│          │                                                            │
│          │  ── 阶段产物 ──────────────────────────────────────────── │
│          │  类型: credential   键: cracked_hashes   值: [3条]        │
│          │  类型: ip_list      键: discovered_ips   值: [5条]        │
│          │                                                            │
│          │  [▶ 启动战役]  [⏸ 暂停]  [⏹ 终止]  [查看报告]            │
└──────────┴──────────────────────────────────────────────────────────┘
```

### 3.2 新建战役对话框

```
┌─────────────────────────────────────┐
│  新建攻击战役                         │
├─────────────────────────────────────┤
│  名称*: [________________]          │
│  描述:  [________________]          │
│  目标*: [192.168.1.0/24___]        │
│                                     │
│  阶段配置:                           │
│  ☑ ① 数据抵近窃取 (默认勾选)        │
│  ☑ ② 信息篡改欺骗 (默认勾选)        │
│  ☑ ③ 关键设备夺控 (默认勾选)        │
│                                     │
│  自动推进: ☑ 阶段完成后自动进入下一阶段│
│                                     │
│         [取消]    [创建]             │
└─────────────────────────────────────┘
```

### 3.3 阶段进度可视化

使用 QStepIndicator（自定义 QWidget）展示3阶段进度：

```
  ① 数据窃取 ────→ ② 信息篡改 ────→ ③ 设备夺控
     ✅                🔄               ⬜
   已完成             运行中           待执行
```

- 每个阶段节点可点击切换到该阶段的详情
- 箭头表示推荐推进方向
- 阶段间有虚线连接，表示"松耦合"——可以跳过或乱序

### 3.4 文件清单

| 文件 | 说明 |
|------|------|
| `frontend/src/pages/CampaignPage.h` | 头文件 |
| `frontend/src/pages/CampaignPage.cpp` | 主页面实现 |
| `frontend/src/pages/PhasePanel.h` | 阶段面板组件 |
| `frontend/src/pages/PhasePanel.cpp` | 阶段面板（playbook编排 + 产物展示） |
| `frontend/src/pages/StepIndicator.h` | 3阶段进度指示器 |
| `frontend/src/pages/StepIndicator.cpp` | 可视化步骤条 |

### 3.5 MainWindow 集成

将"漏洞攻击测试"模块的页面从 ExecutionPage 改为 CampaignPage（或 CampaignPage 内嵌 ExecutionPage 作为执行引擎）。

---

## 四、安全 Harness

> 从软件安全角度出发，覆盖输入验证、权限控制、注入防护、审计追踪、数据隔离、速率限制六大维度。

### 4.1 输入验证（Input Validation）

**原则**：所有外部输入（HTTP body/query/params）在进入业务逻辑前必须经过校验。

| 风险点 | 防护措施 | 实现位置 |
|--------|---------|---------|
| Campaign name/description | 长度限制（name≤200, desc≤2000），禁止HTML/JS标签 | `campaigns.js` 路由层 |
| Target字段 | 严格IP/CIDR/主机名正则校验，**禁止内网保留地址作为外部目标**（防SSRF） | `campaigns.js` + 工具函数 `validateTarget()` |
| phase_type | CHECK约束 + 代码层白名单校验 | DB schema + 路由层 |
| execution_mode | CHECK约束 + 代码层白名单 | DB schema + 路由层 |
| artifact_value | JSON格式校验 + 大小限制（≤64KB） | 路由层 |
| playbook_id | 外键约束 + 存在性校验 | DB + 路由层 |

**Target校验函数**：

```javascript
function validateTarget(target) {
  if (!target || target.length > 256) return false;
  // 禁止协议前缀（防SSRF）
  if (/^(https?|ftp|file|data):/i.test(target)) return false;
  // 允许: IP, CIDR, 主机名
  const ipCidr = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const hostname = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return ipCidr.test(target) || hostname.test(target);
}
```

### 4.2 权限控制（Authorization）

**原则**：最小权限 + 纵深防御。

| 层级 | 措施 |
|------|------|
| 路由层 | RBAC守卫 `rbacGuard('campaign')`，控制读写权限 |
| 业务层 | 创建者校验：只有创建者或admin可以修改/删除/启动自己的战役 |
| 数据层 | 查询自动注入 `created_by` 过滤（非admin只能看自己的战役） |
| 阶段执行 | operator/student可执行但不能修改战役配置 |
| 产物访问 | 产物包含敏感数据（凭据），需 campaign:read 权限 + 创建者校验 |

**业务层权限检查**：

```javascript
// 只有创建者或admin可以操作战役
function canModifyCampaign(req, campaign) {
  return req.user.role === 'admin' || req.user.sub === campaign.created_by;
}
```

### 4.3 注入防护（Injection Prevention）

| 风险 | 防护 |
|------|------|
| SQL注入 | 所有查询使用 better-sqlite3 的 `prepare().run()/get()/all()` 参数化查询，**禁止字符串拼接SQL** |
| 命令注入 | playbook的args_template通过 `{{variable}}` 模板变量注入，**禁止直接拼接用户输入到shell命令**；变量值经过shellescape处理 |
| JSON注入 | artifact_value 使用 `JSON.parse()` 严格校验，序列化用 `JSON.stringify()` |
| 路径遍历 | campaign_id/phase_id 使用 UUID v4 格式，不基于用户输入构造文件路径 |

**模板变量安全替换**：

```javascript
// 安全替换 {{artifact.xxx}} 模板变量
function safeTemplateReplace(template, artifacts) {
  return template.replace(/\{\{(\w[\w.]*)\}\}/g, (match, key) => {
    const value = artifacts[key];
    if (value === undefined) return match; // 未定义变量保持原样
    // 对shell参数进行转义
    return String(value).replace(/[^\w\-.,:/@]/g, '\\$&');
  });
}
```

### 4.4 审计追踪（Audit Trail）

**原则**：所有关键操作必须留痕，不可篡改。

| 操作 | 审计内容 |
|------|---------|
| 创建战役 | who, when, campaign_id, name, target |
| 启动/暂停/终止战役 | who, when, campaign_id, 前后状态 |
| 添加/移除playbook | who, when, campaign_id, phase_id, playbook_id |
| 阶段状态变更 | who, when, campaign_id, phase_id, 前后状态 |
| 产物创建/删除 | who, when, campaign_id, artifact_type, artifact_key |
| 权限校验失败 | who, when, 尝试的操作, 被拒绝的原因 |

**实现**：复用现有 `audit_log` 表，type 字段使用 `campaign_*` 前缀：

```javascript
db.prepare(`INSERT INTO audit_log (type, execution_id, user_role, target, timestamp, reasons)
  VALUES (?, ?, ?, ?, datetime('now'), ?)`).run(
    'campaign_start', campaign.campaign_id, req.user.role, campaign.target, JSON.stringify({from: 'draft', to: 'running'})
  );
```

### 4.5 数据隔离与敏感数据处理

| 风险 | 防护 |
|------|------|
| 凭据泄露 | `campaign_artifacts` 中 `artifact_type='credential'` 的值在API返回时**脱敏**（只显示前4位+***） |
| 跨战役数据泄露 | 查询强制注入 `campaign_id` 过滤，禁止跨战役访问产物 |
| 并发冲突 | SQLite WAL模式 + 乐观锁（updated_at检查），防止并发修改 |
| 级联删除 | 删除战役时 CASCADE 删除所有关联数据，不留孤儿记录 |

**凭据脱敏**：

```javascript
function sanitizeArtifact(artifact) {
  if (artifact.artifact_type === 'credential') {
    try {
      const val = JSON.parse(artifact.artifact_value);
      // 对密码/哈希字段脱敏
      if (val.password) val.password = val.password.slice(0, 4) + '****';
      if (val.hash) val.hash = val.hash.slice(0, 8) + '****';
      artifact.artifact_value = JSON.stringify(val);
      artifact._sanitized = true;
    } catch {}
  }
  return artifact;
}
```

### 4.6 速率限制与资源保护

| 风险 | 防护 |
|------|------|
| 战役创建滥用 | 每用户最多同时 10 个非终态战役（draft/running/paused） |
| 并发执行过多 | 同时运行的战役最多 3 个（全局限制） |
| 产物存储膨胀 | 每战役最多 500 个产物，每个 artifact_value ≤ 64KB |
| API调用频率 | 复用现有 rate limiter，campaign 路由组 30次/分钟 |

**并发限制检查**：

```javascript
function checkCampaignLimits(db, username) {
  // 每用户最多10个活跃战役
  const userActive = db.prepare(
    "SELECT COUNT(*) AS n FROM campaigns WHERE created_by = ? AND status IN ('draft','running','paused')"
  ).get(username).n;
  if (userActive >= 10) throw new Error('活跃战役数量已达上限(10)');

  // 全局最多3个运行中战役
  const globalRunning = db.prepare(
    "SELECT COUNT(*) AS n FROM campaigns WHERE status = 'running'"
  ).get().n;
  if (globalRunning >= 3) throw new Error('运行中战役数量已达上限(3)');
}
```

### 4.7 安全检查清单（Security Checklist）

实现时逐项确认：

- [ ] 所有路由有 RBAC 守卫
- [ ] 所有用户输入经过 validateTarget / 长度校验 / 类型校验
- [ ] 无字符串拼接SQL，全部参数化查询
- [ ] playbook args_template 变量替换经过 shell 转义
- [ ] campaign_id/phase_id 使用 UUID，不基于用户输入
- [ ] 创建者权限校验（非admin不能操作他人战役）
- [ ] 凭据类产物 API 返回时脱敏
- [ ] 关键操作写入 audit_log
- [ ] 并发限制检查（每用户10 / 全局3）
- [ ] 产物大小限制（64KB / 500条）
- [ ] 删除操作 CASCADE 清理关联数据
- [ ] 阶段状态机校验（不允许非法状态转换）
- [ ] 战役状态机校验（draft→running→paused/completed/failed/aborted）

---

## 五、实施步骤

### Step 1: 数据库迁移

- 新建 `012_add_campaign_tables.js`
- 4张表：campaigns, campaign_phases, campaign_playbooks, campaign_artifacts
- RBAC 扩展：config/rbac.js 新增 'campaign' 路由组

### Step 2: 后端 API

- 新建 `routes/campaigns.js`：CRUD + Phase管理 + Playbook编排 + 产物管理
- 新建 `services/campaignEngine.js`：战役执行引擎（阶段调度 + 产物传递）
- `server.js` 注册路由：`/api/campaigns` + rbacGuard('campaign')
- 输入校验函数：validateTarget, validateCampaignInput
- 审计日志：所有关键操作写入 audit_log

### Step 3: 前端组件

- 新建 `CampaignPage.h/.cpp`：战役列表 + 详情 + 创建对话框
- 新建 `PhasePanel.h/.cpp`：阶段面板（playbook编排表 + 产物列表）
- 新建 `StepIndicator.h/.cpp`：3阶段进度可视化
- `MainWindow.cpp`：模块5页面从 ExecutionPage 切换为 CampaignPage
- `CMakeLists.txt`：新增源文件

### Step 4: 战役执行引擎

- `campaignEngine.js`：startCampaign / pauseCampaign / resumeCampaign / abortCampaign
- 阶段调度：按 order_index 顺序执行，支持 auto_advance
- 产物提取：从 evidence_records 提取 credential / ip_list / file_hash
- 产物注入：将前置阶段产物作为模板变量注入后续 playbook
- WebSocket 通知：阶段状态变更实时推送

### Step 5: 测试与验证

- 手动测试：创建战役 → 添加playbook → 启动 → 查看阶段进度 → 查看产物 → 查看报告
- 安全测试：越权访问、注入尝试、并发限制、凭据脱敏验证
- 集成测试：与现有 ExecutionPage / runs API 的兼容性

---

## 六、与现有系统的兼容

| 现有功能 | 兼容方案 |
|---------|---------|
| ExecutionPage 单次执行 | 保留，作为"快速执行"入口；CampaignPage 是"编排执行"入口 |
| runs API | Campaign 复用 runs API 执行 playbook，run_id 记录在 campaign_playbooks |
| evidence_records | Campaign 从 evidence 提取产物，不修改 evidence 结构 |
| WebSocket 通知 | 扩展事件类型：campaign_started / phase_completed / campaign_completed |
| RBAC | 新增 'campaign' 路由组，不影响现有权限 |
| playbook baseline_group | 保留，Campaign 创建时自动按 baseline_group 推荐 playbook |
