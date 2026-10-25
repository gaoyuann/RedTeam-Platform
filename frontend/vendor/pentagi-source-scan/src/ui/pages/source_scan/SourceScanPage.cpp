#include "SourceScanPage.h"
#include "config/ConfigManager.h"
#include "services/source_scan/SourceScanService.h"
#include "services/source_scan/SourceScanStore.h"
#include <QAbstractItemView>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStackedWidget>
#include <QStyle>
#include <QSyntaxHighlighter>
#include <QTableWidget>
#include <QTextBlock>
#include <QTextBrowser>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>

namespace {
QString timeText(const QString &value) {
    const auto d = QDateTime::fromString(value, Qt::ISODateWithMs);
    return d.isValid() ? d.toLocalTime().toString("MM-dd HH:mm:ss") : QStringLiteral("尚未刷新");
}
QString severityText(const QString &s) {
    if (s == "critical")
        return QStringLiteral("严重");
    if (s == "high")
        return QStringLiteral("高危");
    if (s == "medium")
        return QStringLiteral("中危");
    if (s == "low")
        return QStringLiteral("低危");
    return QStringLiteral("信息");
}
QColor severityColor(const QString &s) {
    if (s == "critical" || s == "high")
        return QColor("#b91c1c");
    if (s == "medium")
        return QColor("#b45309");
    return QColor("#2563eb");
}
void configureTable(QTableWidget *table, const QStringList &headers) {
    table->setColumnCount(headers.size());
    table->setHorizontalHeaderLabels(headers);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setStretchLastSection(true);
    table->setWordWrap(false);
    table->setShowGrid(false);
}
QString pageStyle() {
    return QStringLiteral(
        "QWidget { color:#172033; } QDialog { background:#f3f6fb; }"
        "QLabel[heading=true] { font-size:22px; font-weight:700; }"
        "QPushButton { background:#eef3fb; border:1px solid #c7d5ea; border-radius:7px; padding:8px 14px; }"
        "QPushButton:hover { background:#d9e8ff; } QPushButton:disabled { color:#94a3b8; }"
        "QPushButton[primary=true] { background:#2563eb; color:white; }"
        "QLineEdit,QComboBox,QPlainTextEdit,QTextBrowser,QTreeWidget,QTableWidget { background:white; "
        "border:1px solid #dbe3ef; border-radius:8px; }"
        "QHeaderView::section { background:#eef3fb; padding:8px; border:none; font-weight:600; }"
        "QSplitter::handle { background:#dbe3ef; } QTableWidget::item { padding:6px; }");
}
class SourceHighlighter : public QSyntaxHighlighter {
  public:
    explicit SourceHighlighter(QTextDocument *doc) : QSyntaxHighlighter(doc) {}

  protected:
    void highlightBlock(const QString &text) override {
        const QRegularExpression words(
            QStringLiteral("\\b(alignas|auto|bool|break|case|catch|char|class|const|constexpr|continue|"
                           "default|delete|do|double|else|enum|explicit|extern|false|float|for|friend|if|"
                           "inline|int|long|namespace|new|noexcept|nullptr|operator|private|protected|public|"
                           "return|short|signed|sizeof|static|struct|switch|template|this|throw|true|try|"
                           "typedef|typename|union|unsigned|using|virtual|void|volatile|while)\\b"));
        auto matches = words.globalMatch(text);
        while (matches.hasNext()) {
            auto m = matches.next();
            setFormat(m.capturedStart(), m.capturedLength(), QColor("#7c3aed"));
        }
        const QRegularExpression strings(QStringLiteral("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'"));
        matches = strings.globalMatch(text);
        while (matches.hasNext()) {
            auto m = matches.next();
            setFormat(m.capturedStart(), m.capturedLength(), QColor("#047857"));
        }
        if (text.trimmed().startsWith('#'))
            setFormat(0, text.size(), QColor("#0369a1"));
        setCurrentBlockState(0);
        int start = previousBlockState() == 1 ? 0 : text.indexOf("/*");
        while (start >= 0) {
            const int end = text.indexOf("*/", start + 2);
            const int count = end < 0 ? text.size() - start : end - start + 2;
            setFormat(start, count, QColor("#64748b"));
            if (end < 0) {
                setCurrentBlockState(1);
                break;
            }
            start = text.indexOf("/*", start + count);
        }
        const int comment = text.indexOf("//");
        if (comment >= 0)
            setFormat(comment, text.size() - comment, QColor("#64748b"));
    }
};
class CodeEditor;
class LineNumbers : public QWidget {
  public:
    explicit LineNumbers(CodeEditor *editor);

  protected:
    void paintEvent(QPaintEvent *) override;

  private:
    CodeEditor *m_editor;
};
class CodeEditor : public QPlainTextEdit {
  public:
    explicit CodeEditor(QWidget *parent) : QPlainTextEdit(parent), m_gutter(new LineNumbers(this)) {
        setReadOnly(true);
        setLineWrapMode(QPlainTextEdit::NoWrap);
        setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        new SourceHighlighter(document());
        connect(this, &QPlainTextEdit::blockCountChanged, this, [this]() { margin(); });
        connect(this, &QPlainTextEdit::updateRequest, this, [this](const QRect &r, int dy) {
            if (dy)
                m_gutter->scroll(0, dy);
            else
                m_gutter->update(0, r.y(), m_gutter->width(), r.height());
        });
        margin();
    }
    void drawNumbers(QPaintEvent *) {
        QPainter p(m_gutter);
        p.fillRect(m_gutter->rect(), QColor("#f1f5f9"));
        p.setPen(QColor("#64748b"));
        p.setFont(font());
        QTextBlock block = firstVisibleBlock();
        int number = block.blockNumber();
        int top = qRound(blockBoundingGeometry(block).translated(contentOffset()).top());
        while (block.isValid() && top <= m_gutter->height()) {
            const int height = qRound(blockBoundingRect(block).height());
            if (block.isVisible() && top + height >= 0)
                p.drawText(0, top, m_gutter->width() - 8, fontMetrics().height(), Qt::AlignRight,
                           QString::number(number + 1));
            top += height;
            block = block.next();
            ++number;
        }
    }

  protected:
    void resizeEvent(QResizeEvent *e) override {
        QPlainTextEdit::resizeEvent(e);
        margin();
    }

  private:
    void margin() {
        int digits = 1;
        for (int n = qMax(1, blockCount()); n >= 10; n /= 10)
            ++digits;
        const int width = 16 + fontMetrics().horizontalAdvance('9') * digits;
        setViewportMargins(width, 0, 0, 0);
        m_gutter->setGeometry(contentsRect().left(), contentsRect().top(), width, contentsRect().height());
        m_gutter->update();
    }
    LineNumbers *m_gutter;
};
LineNumbers::LineNumbers(CodeEditor *editor) : QWidget(editor), m_editor(editor) {}
void LineNumbers::paintEvent(QPaintEvent *e) {
    m_editor->drawNumbers(e);
}
} // namespace

SourceScanPage::SourceScanPage(ConfigManager *config, QWidget *parent)
    : QWidget(parent), m_config(config), m_service(new SourceScanService(config->configDirPath(), this)) {
    setObjectName(QStringLiteral("sourceScanPage"));
    setStyleSheet(pageStyle());
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(8);
    auto *top = new QHBoxLayout;
    auto *title = new QLabel(QStringLiteral("源码扫描"), this);
    title->setProperty("heading", true);
    top->addWidget(title);
    top->addStretch();
    m_newScan = new QPushButton(QStringLiteral("+ 新建源码扫描"), this);
    m_newScan->setProperty("primary", true);
    top->addWidget(m_newScan);
    layout->addLayout(top);
    auto *description = new QLabel(
        QStringLiteral(
            "选择 .cpp / .h 文件或目录进行静态审计，保留扫描时的源码快照，点击漏洞可定位代码。"),
        this);
    description->setWordWrap(true);
    layout->addWidget(description);
    auto *filters = new QHBoxLayout;
    m_search = new QLineEdit(this);
    m_search->setPlaceholderText(QStringLiteral("搜索任务名称、路径或 Flow ID"));
    filters->addWidget(m_search, 1);
    m_state = new QComboBox(this);
    m_state->addItem(QStringLiteral("全部状态"), QString());
    for (const QString &s :
         QStringList{"prepared", "creating", "uploading", "uncertain", "running", "completed", "failed"}) {
        SourceScanTask t;
        t.status = s;
        m_state->addItem(SourceScan::statusText(t), s);
    }
    filters->addWidget(m_state);
    auto *reloadButton = new QPushButton(QStringLiteral("刷新本地列表"), this);
    filters->addWidget(reloadButton);
    layout->addLayout(filters);
    m_tasks = new QTableWidget(this);
    m_tasks->setObjectName(QStringLiteral("sourceScanTasks"));
    configureTable(m_tasks, {QStringLiteral("任务名称"), QStringLiteral("源码路径"), QStringLiteral("状态"),
                             QStringLiteral("漏洞"), QStringLiteral("Flow"), QStringLiteral("最近更新")});
    m_tasks->setColumnWidth(0, 210);
    m_tasks->setColumnWidth(1, 300);
    m_tasks->setColumnWidth(2, 175);
    m_tasks->setColumnWidth(3, 65);
    m_tasks->setMaximumHeight(145);
    layout->addWidget(m_tasks);
    m_notice =
        new QLabel(QStringLiteral("选择任务后在下方查看源码；点击文件切换内容，点击漏洞定位对应文件及代码行。"), this);
    m_notice->setWordWrap(true);
    m_notice->setTextFormat(Qt::PlainText);
    layout->addWidget(m_notice);
    m_workspace = new QStackedWidget(this);
    m_workspace->setObjectName(QStringLiteral("sourceScanWorkspace"));
    auto *empty = new QLabel(QStringLiteral("选择上方扫描任务，查看文件树、源码与漏洞结果。"), m_workspace);
    empty->setAlignment(Qt::AlignCenter);
    m_workspace->addWidget(empty);
    layout->addWidget(m_workspace, 1);
    connect(m_newScan, &QPushButton::clicked, this, &SourceScanPage::newScan);
    connect(reloadButton, &QPushButton::clicked, this, &SourceScanPage::reload);
    connect(m_search, &QLineEdit::textChanged, this, &SourceScanPage::filterTasks);
    connect(m_state, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this]() { filterTasks(); });
    connect(m_tasks, &QTableWidget::cellClicked, this, [this](int row, int) {
        if (auto *item = m_tasks->item(row, 0))
            openTask(item->data(Qt::UserRole).toString());
    });
    connect(m_service, &SourceScanService::taskCreated, this, [this](const QString &id) {
        reload();
        openTask(id);
    });
    connect(m_service, &SourceScanService::changed, this, [this](const QString &) { reload(); });
    connect(m_service, &SourceScanService::progress, this,
            [this](const QString &, const QString &message) { m_notice->setText(message); });
    connect(m_service, &SourceScanService::finished, this, [this](const QString &, const QString &error) {
        m_newScan->setEnabled(true);
        reload();
        m_notice->setText(error.isEmpty() ? QStringLiteral("源码扫描操作完成；结果已保存。") : error);
    });
    reload();
}
void SourceScanPage::showEvent(QShowEvent *e) {
    QWidget::showEvent(e);
    reload();
}
void SourceScanPage::reload() {
    SourceScanStore store(m_config->configDirPath());
    QString error;
    if (!store.open(&error)) {
        m_notice->setText(error);
        return;
    }
    const auto tasks = store.tasks(&error);
    if (!error.isEmpty()) {
        m_notice->setText(error);
        return;
    }
    const QSignalBlocker block(m_tasks);
    m_tasks->setRowCount(tasks.size());
    int row = 0;
    for (const auto &task : tasks) {
        const int count = store.findings(task.id, &error).size();
        const QStringList values{
            task.name,   task.selectedPaths.join("; "), SourceScan::statusText(task), QString::number(count),
            task.flowId, timeText(task.updatedAt)};
        for (int col = 0; col < values.size(); ++col) {
            auto *item = new QTableWidgetItem(values[col]);
            item->setToolTip(col == 2 ? task.error : values[col]);
            m_tasks->setItem(row, col, item);
        }
        m_tasks->item(row, 0)->setData(Qt::UserRole, task.id);
        m_tasks->item(row, 2)->setData(Qt::UserRole, task.status);
        ++row;
    }
    m_newScan->setEnabled(!m_service->busy());
    if (!error.isEmpty())
        m_notice->setText(error);
    filterTasks();
    if (m_workspace->count() == 1 && !tasks.isEmpty())
        openTask(tasks.first().id);
}
void SourceScanPage::filterTasks() {
    for (int row = 0; row < m_tasks->rowCount(); ++row) {
        QString text;
        for (int c = 0; c < m_tasks->columnCount(); ++c)
            text += m_tasks->item(row, c)->text() + " ";
        m_tasks->setRowHidden(row, !text.contains(m_search->text(), Qt::CaseInsensitive) ||
                                       (!m_state->currentData().toString().isEmpty() &&
                                        m_tasks->item(row, 2)->data(Qt::UserRole) != m_state->currentData()));
    }
}
void SourceScanPage::openTask(const QString &id) {
    if (m_windows.value(id)) {
        m_workspace->setCurrentWidget(m_windows[id]);
        return;
    }
    auto *window = new PentagiSourceScanDetailDialog(m_config, m_service, id, this);
    m_windows.insert(id, window);
    window->setWindowFlags(Qt::Widget);
    window->setMinimumSize(0, 360);
    m_workspace->addWidget(window);
    m_workspace->setCurrentWidget(window);
}
void SourceScanPage::newScan() {
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("新建源码扫描"));
    dialog.resize(680, 450);
    dialog.setStyleSheet(pageStyle());
    auto *layout = new QVBoxLayout(&dialog);
    auto *form = new QFormLayout;
    auto *name = new QLineEdit(
        QStringLiteral("源码扫描 %1").arg(QDateTime::currentDateTime().toString("MM-dd HH:mm")), &dialog);
    name->setMaxLength(120);
    form->addRow(QStringLiteral("任务名称"), name);
    layout->addLayout(form);
    layout->addWidget(new QLabel(QStringLiteral("扫描路径（每行一个，可直接输入或使用选择器）："), &dialog));
    auto *paths = new QPlainTextEdit(&dialog);
    paths->setPlaceholderText(QStringLiteral("/home/user/project\n/home/user/example.cpp"));
    layout->addWidget(paths, 1);
    auto *pick = new QHBoxLayout;
    auto *folder = new QPushButton(QStringLiteral("选择文件夹…"), &dialog);
    auto *file = new QPushButton(QStringLiteral("选择 .cpp/.h 文件…"), &dialog);
    pick->addWidget(folder);
    pick->addWidget(file);
    pick->addStretch();
    layout->addLayout(pick);
    const auto append = [paths](const QStringList &selected) {
        QStringList lines = paths->toPlainText().split('\n', QString::SkipEmptyParts);
        for (const auto &s : selected)
            if (!lines.contains(s))
                lines << s;
        paths->setPlainText(lines.join('\n'));
    };
    connect(folder, &QPushButton::clicked, &dialog, [&dialog, append]() {
        const QString dir = QFileDialog::getExistingDirectory(&dialog, QStringLiteral("选择源码目录"));
        if (!dir.isEmpty())
            append({dir});
    });
    connect(file, &QPushButton::clicked, &dialog, [&dialog, append]() {
        append(QFileDialog::getOpenFileNames(&dialog, QStringLiteral("选择源码文件"), QString(),
                                             QStringLiteral("C++ 源码 (*.cpp *.h *.CPP *.H)")));
    });
    auto *warning = new QLabel(
        QStringLiteral(
            "目录递归收集 .cpp/.h（包含隐藏目录）。仅支持 UTF-8；最多 4096 文件、合计 16 MiB、单文件 2 "
            "MiB。\n源码内容会发送到已配置的 PentAGI 服务，本地保存快照；不编译、不执行、不利用漏洞。"),
        &dialog);
    warning->setWordWrap(true);
    layout->addWidget(warning);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Ok, &dialog);
    buttons->button(QDialogButtonBox::Ok)->setText(QStringLiteral("确认发送并开始扫描"));
    buttons->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&]() {
        if (name->text().trimmed().isEmpty() || paths->toPlainText().trimmed().isEmpty()) {
            QMessageBox::warning(&dialog, QStringLiteral("信息不完整"),
                                 QStringLiteral("请填写任务名称和至少一个路径。"));
            return;
        }
        dialog.accept();
    });
    if (dialog.exec() != QDialog::Accepted)
        return;
    const auto config = m_config->currentConfig();
    if (config.pentagi.graphqlUrl.trimmed().isEmpty()) {
        m_notice->setText(QStringLiteral("请先在设置中配置 PentAGI 接口。"));
        return;
    }
    QStringList selected;
    for (const auto &s : paths->toPlainText().split('\n', QString::SkipEmptyParts))
        if (!s.trimmed().isEmpty())
            selected << s.trimmed();
    if (m_service->start(config, name->text(), selected)) {
        m_newScan->setEnabled(false);
        m_notice->setText(QStringLiteral("正在验证并保存源码快照……"));
    }
}

PentagiSourceScanDetailDialog::PentagiSourceScanDetailDialog(ConfigManager *config, SourceScanService *service,
                                               const QString &id, QWidget *parent)
    : QDialog(parent), m_config(config), m_service(service), m_id(id) {
    setObjectName(QStringLiteral("sourceScanDetail"));
    setWindowTitle(QStringLiteral("源码扫描详情"));
    setWindowFlags(windowFlags() | Qt::WindowMinMaxButtonsHint);
    resize(1460, 880);
    setMinimumSize(1050, 620);
    setStyleSheet(pageStyle());
    auto *layout = new QVBoxLayout(this);
    auto *top = new QHBoxLayout;
    m_heading = new QLabel(this);
    m_heading->setTextFormat(Qt::PlainText);
    m_heading->setWordWrap(true);
    m_heading->setProperty("heading", true);
    top->addWidget(m_heading, 1);
    m_countdown = new QLabel(this);
    top->addWidget(m_countdown);
    m_refresh = new QPushButton(QStringLiteral("刷新当前结果"), this);
    m_refresh->setObjectName(QStringLiteral("sourceScanRefresh"));
    top->addWidget(m_refresh);
    layout->addLayout(top);
    m_summary = new QLabel(this);
    m_summary->setTextFormat(Qt::PlainText);
    m_summary->setWordWrap(true);
    layout->addWidget(m_summary);
    auto *split = new QSplitter(Qt::Horizontal, this);
    split->setObjectName(QStringLiteral("sourceScanThreePanes"));
    split->setChildrenCollapsible(false);
    m_tree = new QTreeWidget(split);
    m_tree->setObjectName(QStringLiteral("sourceScanFileTree"));
    m_tree->setHeaderLabel(QStringLiteral("文件树 · 扫描时快照"));
    m_tree->setMinimumWidth(160);
    m_tree->setUniformRowHeights(true);
    auto *middle = new QWidget(split);
    auto *center = new QVBoxLayout(middle);
    center->setContentsMargins(0, 0, 0, 0);
    m_sourceLabel = new QLabel(QStringLiteral("请选择源码文件"), middle);
    m_sourceLabel->setTextFormat(Qt::PlainText);
    m_sourceLabel->setWordWrap(true);
    center->addWidget(m_sourceLabel);
    m_code = new CodeEditor(middle);
    m_code->setObjectName(QStringLiteral("sourceScanCode"));
    center->addWidget(m_code, 1);
    auto *right = new QWidget(split);
    right->setMinimumWidth(280);
    auto *rl = new QVBoxLayout(right);
    rl->setContentsMargins(0, 0, 0, 0);
    auto *filter = new QHBoxLayout;
    filter->addWidget(new QLabel(QStringLiteral("漏洞结果"), right));
    filter->addStretch();
    m_severity = new QComboBox(right);
    m_severity->setMinimumContentsLength(9);
    m_severity->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_severity->addItem(QStringLiteral("全部严重度"), QString());
    for (const auto &s : QStringList{"critical", "high", "medium", "low", "info"})
        m_severity->addItem(severityText(s), s);
    filter->addWidget(m_severity);
    rl->addLayout(filter);
    auto *vertical = new QSplitter(Qt::Vertical, right);
    vertical->setChildrenCollapsible(false);
    m_results = new QTableWidget(vertical);
    m_results->setObjectName(QStringLiteral("sourceScanFindings"));
    configureTable(m_results, {QStringLiteral("级别"), QStringLiteral("漏洞 / 位置")});
    m_results->setColumnWidth(0, 65);
    m_details = new QTextBrowser(vertical);
    m_details->setOpenExternalLinks(false);
    m_details->setObjectName(QStringLiteral("sourceScanFindingDetail"));
    vertical->setStretchFactor(0, 3);
    vertical->setStretchFactor(1, 2);
    vertical->setSizes({360, 220});
    rl->addWidget(vertical, 1);
    split->setStretchFactor(0, 0);
    split->setStretchFactor(1, 3);
    split->setStretchFactor(2, 2);
    split->setSizes({200, 700, 390});
    split->setHandleWidth(6);
    layout->addWidget(split, 1);
    m_notice = new QLabel(this);
    m_notice->setObjectName(QStringLiteral("sourceScanStatus"));
    m_notice->setTextFormat(Qt::PlainText);
    m_notice->setWordWrap(true);
    layout->addWidget(m_notice);
    connect(m_tree, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem *item, int) {
        const QString path = item->data(0, Qt::UserRole).toString();
        if (!path.isEmpty())
            showFile(path);
    });
    connect(m_tree, &QTreeWidget::currentItemChanged, this,
            [this](QTreeWidgetItem *item, QTreeWidgetItem *) {
        if (!item) return;
        const QString path = item->data(0, Qt::UserRole).toString();
        if (!path.isEmpty() && path != m_currentPath) showFile(path);
    });
    connect(m_results, &QTableWidget::cellClicked, this, [this](int row, int) { showFinding(row); });
    connect(m_refresh, &QPushButton::clicked, this, &PentagiSourceScanDetailDialog::refresh);
    connect(m_severity, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            [this]() { updateFindings(); });
    connect(service, &SourceScanService::changed, this, [this](const QString &id) {
        if (id == m_id)
            reload();
        m_refresh->setEnabled(!m_service->busy() && !m_task.endpoint.startsWith(QStringLiteral("mock://")));
    });
    connect(service, &SourceScanService::progress, this, [this](const QString &id, const QString &message) {
        if (id == m_id)
            m_notice->setText(message);
    });
    connect(service, &SourceScanService::finished, this, [this](const QString &id, const QString &error) {
        m_refresh->setEnabled(true);
        if (id == m_id) {
            m_remaining = 300;
            reload();
            if (!error.isEmpty())
                m_notice->setText(error);
        }
    });
    auto *timer = new QTimer(this);
    timer->setObjectName(QStringLiteral("sourceScanAutoRefresh"));
    timer->setInterval(1000);
    connect(timer, &QTimer::timeout, this, &PentagiSourceScanDetailDialog::tick);
    timer->start();
    reload();
    m_countdown->setText(m_task.endpoint.startsWith(QStringLiteral("mock://"))
                             ? QStringLiteral("Mock 演示 · 不连接后端")
                             : SourceScan::terminal(m_task.flowStatus) && m_task.assistantState == "idle"
                             ? QStringLiteral("任务已结束 · 可手动刷新")
                             : QStringLiteral("下次刷新 5:00"));
}
void PentagiSourceScanDetailDialog::reject() {
    if (isWindow()) QDialog::reject();
}
void PentagiSourceScanDetailDialog::reload() {
    SourceScanStore store(m_config->configDirPath());
    QString error;
    if (!store.open(&error)) {
        m_notice->setText(error);
        return;
    }
    const auto task = store.task(m_id, &error);
    if (task.id.isEmpty()) {
        m_notice->setText(error);
        return;
    }
    m_task = task;
    const bool initialFiles = m_files.isEmpty();
    m_heading->setText(QStringLiteral("%1 · %2").arg(task.name, SourceScan::statusText(task)));
    if (m_files.isEmpty()) {
        m_files = store.files(m_id, &error);
        QMap<QString, QTreeWidgetItem *> nodes;
        for (const auto &file : m_files) {
            QString prefix;
            QTreeWidgetItem *parent = nullptr;
            const auto pieces = file.path.split('/');
            for (int i = 0; i < pieces.size(); ++i) {
                if (!prefix.isEmpty())
                    prefix += '/';
                prefix += pieces[i];
                QTreeWidgetItem *node = nodes.value(prefix);
                if (!node) {
                    node = parent ? new QTreeWidgetItem(parent) : new QTreeWidgetItem(m_tree);
                    node->setText(0, pieces[i]);
                    node->setIcon(0, style()->standardIcon(i == pieces.size() - 1 ? QStyle::SP_FileIcon
                                                                                  : QStyle::SP_DirIcon));
                    nodes.insert(prefix, node);
                }
                parent = node;
                if (i == pieces.size() - 1) {
                    node->setData(0, Qt::UserRole, file.path);
                    node->setToolTip(0, file.originalPath);
                    m_fileItems.insert(file.path, node);
                }
            }
        }
        m_tree->expandToDepth(1);
        if (!m_files.isEmpty())
            showFile(m_files.first().path);
    }
    m_findings = store.findings(m_id, &error);
    const QStringList order{"critical", "high", "medium", "low", "info"};
    std::sort(m_findings.begin(), m_findings.end(),
              [order](const SourceScanFinding &a, const SourceScanFinding &b) {
                  if (a.severity != b.severity)
                      return order.indexOf(a.severity) < order.indexOf(b.severity);
                  if (a.path != b.path)
                      return a.path < b.path;
                  return a.line < b.line;
              });
    m_summary->setText(
        QStringLiteral(
            "Flow：%1  |  源码：%2 文件  |  已发现：%3 项  |  "
            "最近成功刷新：%4\n查看的是创建任务时的源码快照，不受原文件后续修改影响；AI 结果需要人工复核。")
            .arg(task.flowId.isEmpty() ? QStringLiteral("正在创建 / 待确认") : task.flowId)
            .arg(m_files.size())
            .arg(m_findings.size())
            .arg(timeText(task.lastRefresh)));
    m_notice->setText(
        error.isEmpty()
            ? (task.error.isEmpty()
                   ? QStringLiteral("自动刷新和手动刷新复用同一 Assistant；已有结果不会因请求失败清空。")
                   : task.error)
            : error);
    updateFindings();
    const bool mock = task.endpoint.startsWith(QStringLiteral("mock://"));
    m_refresh->setEnabled(!m_service->busy() && !mock);
    if (mock) {
        m_summary->setText(QStringLiteral("Mock 离线演示  |  示例源码：%1 文件  |  示例问题：%2 项  |  未执行真实扫描")
            .arg(m_files.size()).arg(m_findings.size()));
        m_countdown->setText(QStringLiteral("Mock 演示 · 不连接后端"));
        if (initialFiles && m_results->rowCount() > 0) {
            m_results->selectRow(0);
            showFinding(0);
        }
    }
}
void PentagiSourceScanDetailDialog::refresh() {
    if (m_task.endpoint.startsWith(QStringLiteral("mock://"))) return;
    if (m_service->busy())
        return;
    if (m_service->refresh(m_config->currentConfig(), m_id)) {
        m_refresh->setEnabled(false);
        m_notice->setText(QStringLiteral("刷新中：正在核对 Flow 和专用 Assistant……"));
    }
}
void PentagiSourceScanDetailDialog::tick() {
    if (m_task.endpoint.startsWith(QStringLiteral("mock://"))) {
        m_countdown->setText(QStringLiteral("Mock 演示 · 不连接后端"));
        return;
    }
    if (m_service->busy()) {
        m_countdown->setText(QStringLiteral("请求处理中"));
        return;
    }
    if (SourceScan::terminal(m_task.flowStatus) && m_task.assistantState == "idle") {
        m_countdown->setText(QStringLiteral("任务已结束 · 可手动刷新"));
        return;
    }
    if (m_task.status == "uncertain" || m_task.createPending) {
        m_countdown->setText(QStringLiteral("结果待确认 · 请手动刷新"));
        return;
    }
    if (!isVisible())
        return;
    --m_remaining;
    if (m_remaining <= 0) {
        m_remaining = 300;
        refresh();
    }
    m_countdown->setText(
        QStringLiteral("下次刷新 %1:%2").arg(m_remaining / 60).arg(m_remaining % 60, 2, 10, QChar('0')));
}
void PentagiSourceScanDetailDialog::showFile(const QString &path, int line, int endLine) {
    const auto it =
        std::find_if(m_files.begin(), m_files.end(), [&](const SourceScanFile &f) { return f.path == path; });
    if (it == m_files.end())
        return;
    if (m_currentPath != path) {
        m_code->setPlainText(it->content);
        m_currentPath = path;
    }
    m_sourceLabel->setText(path + QStringLiteral("  [只读快照]"));
    QList<QTextEdit::ExtraSelection> highlights;
    if (line > 0) {
        const int limit = qMin(endLine < line ? line : endLine, line + 500);
        for (int n = line; n <= limit; ++n) {
            QTextEdit::ExtraSelection s;
            s.cursor = QTextCursor(m_code->document()->findBlockByNumber(n - 1));
            s.format.setBackground(QColor("#fef3c7"));
            s.format.setProperty(QTextFormat::FullWidthSelection, true);
            highlights << s;
        }
        m_code->setTextCursor(QTextCursor(m_code->document()->findBlockByNumber(line - 1)));
        m_code->centerCursor();
    }
    m_code->setExtraSelections(highlights);
    if (auto *item = m_fileItems.value(path)) {
        m_tree->setCurrentItem(item);
        m_tree->scrollToItem(item);
    }
}
void PentagiSourceScanDetailDialog::updateFindings() {
    const QString selected =
        m_results->currentRow() >= 0
            ? m_results->item(m_results->currentRow(), 0)->data(Qt::UserRole + 1).toString()
            : QString();
    m_results->setRowCount(0);
    int restore = -1;
    for (int i = 0; i < m_findings.size(); ++i) {
        const auto &f = m_findings[i];
        if (!m_severity->currentData().toString().isEmpty() &&
            m_severity->currentData().toString() != f.severity)
            continue;
        const int row = m_results->rowCount();
        m_results->insertRow(row);
        auto *risk = new QTableWidgetItem(severityText(f.severity));
        risk->setForeground(severityColor(f.severity));
        risk->setData(Qt::UserRole, i);
        risk->setData(Qt::UserRole + 1, f.key);
        m_results->setItem(row, 0, risk);
        auto *title = new QTableWidgetItem(QStringLiteral("%1 — %2:%3").arg(f.title, f.path).arg(f.line));
        title->setToolTip(title->text());
        m_results->setItem(row, 1, title);
        if (f.key == selected)
            restore = row;
    }
    if (restore >= 0) {
        m_results->selectRow(restore);
        showFinding(restore);
    } else if (m_results->rowCount() == 0)
        m_details->setPlainText(
            QStringLiteral("暂无符合条件的已确认漏洞。审计进行中或解析失败不代表源码安全。"));
    else
        m_details->setPlainText(QStringLiteral("点击漏洞查看证据、说明和修复建议，并定位到对应源码。"));
}
void PentagiSourceScanDetailDialog::showFinding(int row) {
    if (row < 0 || row >= m_results->rowCount())
        return;
    const int index = m_results->item(row, 0)->data(Qt::UserRole).toInt();
    if (index < 0 || index >= m_findings.size())
        return;
    const auto &f = m_findings[index];
    m_details->setPlainText(
        QStringLiteral("%1  [%2]\n%3:%4-%5\n%6\n\n说明\n%7\n\n源码证据\n%8\n\n修复建议\n%9\n\n此为 AI "
                       "整理的审计结果，请人工复核。")
            .arg(f.title, severityText(f.severity), f.path)
            .arg(f.line)
            .arg(f.endLine)
            .arg(f.cwe, f.description, f.evidence, f.recommendation));
    showFile(f.path, f.line, f.endLine);
}
