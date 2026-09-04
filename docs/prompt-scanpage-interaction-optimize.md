# ScanPage 交互优化 — 实施提示词

## 背景

当前 ScanPage 右侧面板的推荐预案和 AI 生成预案的交互存在以下问题：

1. **点击推荐预案行直接跳转到 ExecutionPage** — 用户只是想查看推荐预案的详情，却被迫跳转离开扫描页面。应改为：点击推荐行仅选中该行（高亮），不跳转；需要跳转时通过专门的"前往执行→"按钮触发。
2. **AI 生成预案后立即保存到预案库** — 用户无法在保存前预览 AI 生成的战术手册内容。应改为：生成后先在界面展示预览（步骤列表+描述），用户确认后才保存并跳转执行。
3. **"前往执行→"按钮语义不清** — 当前只有一个 `m_viewGenBtn`，既用于 AI 生成预案也用于推荐预案，但推荐预案没有独立的"前往执行"入口。

## 需修改的文件

- `frontend/src/pages/ScanPage.h`
- `frontend/src/pages/ScanPage.cpp`

## 修改1：推荐预案表格 — 点击行仅选中，不跳转

### 当前行为
```cpp
void ScanPage::onRecommendationClicked(int row, int) {
  auto *item = m_recTable->item(row, 0);
  if (!item) return;
  QString pbId = item->data(Qt::UserRole).toString();
  if (pbId.isEmpty()) return;
  emit playbookNavigateRequested(pbId, m_currentTarget);  // ← 直接跳转
}
```

### 改为
点击推荐行仅选中该行（高亮），保存选中的 playbookId 到成员变量 `m_selectedRecPlaybookId`，并在推荐表格下方显示"前往执行「xxx」→"按钮。

**具体实现**：

1. **ScanPage.h** 新增：
   ```cpp
   QString m_selectedRecPlaybookId;   // 当前选中的推荐预案ID
   QString m_selectedRecPlaybookName; // 当前选中的推荐预案名称
   QPushButton *m_recExecBtn;         // 推荐预案的"前往执行→"按钮
   ```

2. **ScanPage.cpp setupUI()** 中：
   - 在推荐表格下方（`m_recTable` 之后、`m_genBtn` 之前）新增一行布局：
     ```cpp
     auto *recExecH = new QHBoxLayout;
     m_recExecBtn = new QPushButton("前往执行 →");
     m_recExecBtn->setVisible(false);
     m_recExecBtn->setProperty("primary", true);
     recExecH->addWidget(m_recExecBtn);
     recExecH->addStretch();
     right->addLayout(recExecH);
     connect(m_recExecBtn, &QPushButton::clicked, this, &ScanPage::onRecExecClicked);
     ```

3. **ScanPage.cpp onRecommendationClicked()** 改为：
   ```cpp
   void ScanPage::onRecommendationClicked(int row, int) {
     auto *item = m_recTable->item(row, 0);
     if (!item) return;
     QString pbId = item->data(Qt::UserRole).toString();
     if (pbId.isEmpty()) return;
     // 仅选中，不跳转
     m_selectedRecPlaybookId = pbId;
     m_selectedRecPlaybookName = item->text();
     // 显示"前往执行"按钮
     m_recExecBtn->setVisible(true);
     m_recExecBtn->setText(QString("前往执行「%1」→").arg(m_selectedRecPlaybookName.left(20)));
   }
   ```

4. **ScanPage.cpp 新增 onRecExecClicked()**：
   ```cpp
   void ScanPage::onRecExecClicked() {
     if (m_selectedRecPlaybookId.isEmpty()) return;
     emit playbookNavigateRequested(m_selectedRecPlaybookId, m_currentTarget);
   }
   ```
   需在 ScanPage.h 的 private slots 中声明 `void onRecExecClicked();`

5. **ScanPage.cpp clearDetailPanel()** 中清空推荐选中状态：
   ```cpp
   m_selectedRecPlaybookId.clear();
   m_selectedRecPlaybookName.clear();
   m_recExecBtn->setVisible(false);
   ```

6. **ScanPage.cpp onTaskClicked()** 中，切换任务时也清空推荐选中：
   在 `m_viewGenBtn->setVisible(false);` 附近添加：
   ```cpp
   m_selectedRecPlaybookId.clear();
   m_selectedRecPlaybookName.clear();
   m_recExecBtn->setVisible(false);
   ```

## 修改2：AI 生成预案 — 先预览再保存

### 当前行为
1. 点击"AI 生成预案" → 调用后端 `/api/scan-tasks/{id}/generate-playbook`
2. 后端**立即**生成并保存到数据库，返回 `playbook_id`、`name`、`steps_count`
3. 前端显示"✓ 已生成: xxx (N步) — 已添加到预案库" + "前往执行→"按钮

### 改为
1. 点击"AI 生成预案" → 调用后端（后端行为不变，仍然生成并保存）
2. 生成成功后，**不再显示"已添加到预案库"**，改为在右侧面板展开一个**AI预案预览区**，显示：
   - 预案名称 + 步骤数
   - 步骤列表（从 `/api/playbooks/{playbookId}` 获取详情）
   - "前往执行→"按钮（跳转到 ExecutionPage）
3. 预览区替代原来的单行状态提示，让用户能看到 AI 生成的完整战术手册

**具体实现**：

1. **ScanPage.h** 新增：
   ```cpp
   // AI 生成预案预览区
   QWidget *m_genPreviewWidget;      // 预览区容器（可整体显示/隐藏）
   QLabel *m_genPreviewTitle;        // "AI 生成预案: xxx (N步)"
   QTableWidget *m_genStepTable;     // 步骤预览表格
   QPushButton *m_genExecBtn;        // "前往执行→"按钮
   ```

2. **ScanPage.cpp setupUI()** 中，在 `m_genBtn` 所在行之后，新增预览区：
   ```cpp
   // ── AI 生成预案预览区（初始隐藏）──────────────────────
   m_genPreviewWidget = new QWidget;
   auto *genPreviewLayout = new QVBoxLayout(m_genPreviewWidget);
   genPreviewLayout->setContentsMargins(0, 0, 0, 0);

   m_genPreviewTitle = new QLabel;
   m_genPreviewTitle->setStyleSheet(Theme::SectionStyle);
   genPreviewLayout->addWidget(m_genPreviewTitle);

   m_genStepTable = new QTableWidget(0, 4);
   m_genStepTable->setHorizontalHeaderLabels({"步骤", "工具", "目标参数", "描述"});
   m_genStepTable->setAlternatingRowColors(true);
   m_genStepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
   m_genStepTable->setSortingEnabled(false);
   m_genStepTable->horizontalHeader()->setStretchLastSection(true);
   m_genStepTable->setContextMenuPolicy(Qt::CustomContextMenu);
   genPreviewLayout->addWidget(m_genStepTable);

   auto *genExecH = new QHBoxLayout;
   m_genExecBtn = new QPushButton("前往执行 →");
   m_genExecBtn->setProperty("primary", true);
   genExecH->addWidget(m_genExecBtn);
   genExecH->addStretch();
   genPreviewLayout->addLayout(genExecH);
   connect(m_genExecBtn, &QPushButton::clicked, this, &ScanPage::onGenExecClicked);

   m_genPreviewWidget->setVisible(false);
   right->addWidget(m_genPreviewWidget);

   // 步骤表格右键菜单
   connect(m_genStepTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
     auto *item = m_genStepTable->itemAt(pos);
     if (!item) return;
     QMenu menu;
     menu.addAction("复制单元格内容", [item]() { QApplication::clipboard()->setText(item->text()); });
     menu.exec(m_genStepTable->viewport()->mapToGlobal(pos));
   });
   ```

3. **ScanPage.cpp onGeneratePlaybook()** 成功回调改为：
   ```cpp
   if (res["status"].toString() == "ok") {
     auto data = res["data"].toObject();
     QString pbId = data["playbook_id"].toString();
     QString pbName = data["name"].toString();
     int steps = data["steps_count"].toInt();

     m_lastGeneratedId = pbId;

     // 显示预览区标题
     m_genPreviewTitle->setText(QString("AI 生成预案: %1 (%2步)").arg(pbName).arg(steps));
     m_genExecBtn->setText(QString("前往执行「%1」→").arg(pbName.left(20)));

     // 加载 Playbook 详情并渲染步骤表格
     m_api->get("/api/playbooks/" + pbId, 5000, [this](const QJsonObject &pbRes) {
       if (pbRes["status"].toString() != "ok") return;
       auto pb = pbRes["data"].toObject();
      auto stepsArr = pb["steps"].toArray();
       m_genStepTable->setRowCount(stepsArr.size());
       for (int i = 0; i < stepsArr.size(); i++) {
         auto s = stepsArr[i].toObject();
         int stepNum = s["step_index"].toInt(i + 1);
         m_genStepTable->setItem(i, 0, new QTableWidgetItem(QString("Step %1").arg(stepNum)));
         m_genStepTable->setItem(i, 1, new QTableWidgetItem(s["tool_id"].toString()));
         QStringList args;
         auto at = s["args_template"];
         if (at.isString()) {
           QJsonArray argsArr = QJsonDocument::fromJson(at.toString().toUtf8()).array();
           for (const auto &v : argsArr) args << v.toVariant().toString();
         } else if (at.isArray()) {
           for (const auto &v : at.toArray()) args << v.toVariant().toString();
         }
         m_genStepTable->setItem(i, 2, new QTableWidgetItem(args.join(" ")));
         m_genStepTable->setItem(i, 3, new QTableWidgetItem(s["description"].toString()));
       }
       m_genStepTable->resizeColumnsToContents();
       m_genStepTable->horizontalHeader()->setStretchLastSection(true);
     });

     // 显示预览区
     m_genPreviewWidget->setVisible(true);

     // 隐藏旧的 m_viewGenBtn（不再需要，预览区有自己的执行按钮）
     m_viewGenBtn->setVisible(false);

     loadRecommendations(m_selectedTaskId);
   }
   ```

4. **ScanPage.cpp 新增 onGenExecClicked()**：
   ```cpp
   void ScanPage::onGenExecClicked() {
     if (m_lastGeneratedId.isEmpty()) return;
     emit playbookNavigateRequested(m_lastGeneratedId, m_currentTarget);
   }
   ```
   需在 ScanPage.h 的 private slots 中声明 `void onGenExecClicked();`

5. **ScanPage.cpp clearDetailPanel()** 中隐藏预览区：
   ```cpp
   m_genPreviewWidget->setVisible(false);
   m_genStepTable->setRowCount(0);
   ```

6. **ScanPage.cpp onTaskClicked()** 中，切换任务时隐藏预览区：
   在 `m_viewGenBtn->setVisible(false);` 附近添加：
   ```cpp
   m_genPreviewWidget->setVisible(false);
   m_genStepTable->setRowCount(0);
   ```

7. **clearDetailPanel() 84行附近**，在 `m_lastGeneratedId.clear();` 附近添加：
   ```cpp
   m_genPreviewWidget->setVisible(false);
   m_genStepTable->setRowCount(0);
   ```

## 修改3：移除旧的 m_viewGenBtn

现在"前往执行→"功能分别由 `m_recExecBtn`（推荐预案）和 `m_genExecBtn`（AI生成预案）承担，`m_viewGenBtn` 不再需要。

1. **ScanPage.h** 移除：
   ```cpp
   QPushButton *m_viewGenBtn;
   ```

2. **ScanPage.cpp setupUI()** 移除 `m_viewGenBtn` 的创建和连接：
   ```cpp
   // 移除：
   m_viewGenBtn = new QPushButton("前往执行 →");
   m_viewGenBtn->setVisible(false);
   m_viewGenBtn->setProperty("primary", true);
   bottomH->addWidget(m_viewGenBtn);
   connect(m_viewGenBtn, &QPushButton::clicked, this, &ScanPage::onViewGeneratedPlaybook);
   ```

3. **ScanPage.h** 移除 `onViewGeneratedPlaybook()` slot 声明

4. **ScanPage.cpp** 移除 `onViewGeneratedPlaybook()` 方法实现

5. **ScanPage.cpp** 所有引用 `m_viewGenBtn` 的地方改为使用新的按钮或直接移除：
   - `clearDetailPanel()` 中的 `m_viewGenBtn->setVisible(false);` → 移除
   - `onTaskClicked()` 中的 `m_viewGenBtn->setVisible(false);` → 移除
   - `onGeneratePlaybook()` 中的 `m_viewGenBtn->setVisible(false);` → 移除（已在修改2中处理）

## 修改4：onGeneratePlaybook 不再自动触发

### 当前行为
`onTaskClicked()` 中，扫描完成后自动调用 `onGeneratePlaybook()`：
```cpp
if (status == "COMPLETED" && structured) {
  m_genBtn->setEnabled(true);
  m_reexecBtn->setVisible(false);
  loadRecommendations(id);
  onGeneratePlaybook();  // ← 自动触发
}
```

### 改为
不再自动触发 AI 生成。用户需要手动点击"AI 生成预案"按钮。推荐预案表格仍然自动加载（因为它是后端匹配的，不需要 LLM 调用，速度快）。

```cpp
if (status == "COMPLETED" && structured) {
  m_genBtn->setEnabled(true);
  m_reexecBtn->setVisible(false);
  loadRecommendations(id);
  // 不再自动触发 onGeneratePlaybook()
}
```

同样，`onPollStatus()` 中扫描完成后的逻辑也要移除 `onGeneratePlaybook()` 调用：
```cpp
if (status == "COMPLETED" && structured) {
  m_genBtn->setEnabled(true);
  m_reexecBtn->setVisible(false);
  loadRecommendations(m_selectedTaskId);
  // 移除: onGeneratePlaybook();
}
```

## 实施顺序

1. ScanPage.h — 新增成员（m_selectedRecPlaybookId/Name, m_recExecBtn, m_genPreviewWidget/Title/StepTable/ExecBtn），移除 m_viewGenBtn 和 onViewGeneratedPlaybook
2. ScanPage.cpp setupUI() — 新增推荐执行按钮 + AI预览区，移除 m_viewGenBtn
3. ScanPage.cpp onRecommendationClicked() — 改为仅选中不跳转
4. ScanPage.cpp 新增 onRecExecClicked() / onGenExecClicked()
5. ScanPage.cpp onGeneratePlaybook() — 改为显示预览区而非单行提示
6. ScanPage.cpp onTaskClicked() — 移除自动触发 onGeneratePlaybook()
7. ScanPage.cpp onPollStatus() — 移除自动触发 onGeneratePlaybook()
8. ScanPage.cpp clearDetailPanel() — 清空新增状态，隐藏预览区
9. 移除 m_viewGenBtn 和 onViewGeneratedPlaybook 的所有残留引用
10. 编译测试

## 验收标准

1. 点击推荐预案行 → 仅高亮选中该行，不跳转；推荐表格下方出现"前往执行「xxx」→"按钮
2. 点击"前往执行「xxx'→"按钮 → 跳转到 ExecutionPage 快速执行Tab，Playbook已选中+目标IP已填入
3. 点击"AI 生成预案"按钮 → 显示加载状态 → 生成完成后在右侧面板展开预览区，显示步骤列表
4. 预览区内有"前往执行→"按钮 → 点击跳转到 ExecutionPage
5. 扫描完成后不再自动触发 AI 生成，需用户手动点击
6. 切换扫描任务或清空详情时，推荐选中状态和 AI 预览区正确重置
7. m_viewGenBtn 和 onViewGeneratedPlaybook 已完全移除
8. 编译通过，无回归问题

## 交互流程图

```
扫描完成
  │
  ├─ 自动加载推荐预案表格
  │    │
  │    ├─ 点击推荐行 → 仅选中高亮 + 显示"前往执行→"按钮
  │    │
  │    └─ 点击"前往执行→" → 跳转 ExecutionPage
  │
  └─ 手动点击"AI 生成预案"
       │
       ├─ 生成中...（按钮禁用+文字变化）
       │
       └─ 生成成功 → 展开预览区
            │
            ├─ 显示: 预案名称 + 步骤数
            ├─ 显示: 步骤表格（步骤/工具/参数/描述）
            │
            └─ 点击"前往执行→" → 跳转 ExecutionPage
```
