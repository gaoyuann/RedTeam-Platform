#include "ModuleRibbon.h"
#include <QFrame>
#include <QButtonGroup>
#include <QSignalBlocker>
#include <QFontMetrics>
#include <QVariant>
#include <QHBoxLayout>
#include <QIcon>
#include <QScrollArea>
#include <QStackedWidget>
#include <QToolButton>
#include <QVBoxLayout>

QStringList ModuleRibbon::moduleNames()
{
    return {QStringLiteral("网络拓扑绘制"), QStringLiteral("脆弱性扫描"),
        QStringLiteral("漏洞利用想定与预案"), QStringLiteral("漏洞攻击测试"),
        QStringLiteral("测试评估"), QStringLiteral("测试资源部署配置"), QStringLiteral("系统管理")};
}

const QVector<RibbonFeature> &ModuleRibbon::features()
{
    static const QVector<RibbonFeature> values{
        {"topology.discover", "网络拓扑探测", "拓扑发现", "search", 0},
        {"topology.edit", "网络拓扑编辑", "拓扑编绘", "settings", 0},
        {"topology.display", "网络拓扑展示", "拓扑视图", "topology", 0},
        {"topology.annotate", "网络拓扑信息标注", "信息标注", "reports", 0},
        {"scans.system", "系统漏洞扫描", "漏洞检测", "search", 1},
        {"scans.web", "Web漏洞扫描", "漏洞检测", "search", 1},
        {"scans.ports", "端口扫描", "服务检测", "topology", 1},
        {"scans.passwords", "弱口令扫描", "服务检测", "settings", 1},
        {"scans.backdoor", "后门探测", "威胁检测", "search", 1, false},
        {"plans.scenario", "漏洞利用想定", "想定规划", "analysis", 2},
        {"plans.task", "漏洞利用预案", "预案编排", "tasks", 2},
        {"plans.library", "漏洞利用战术手册", "战术知识", "library", 2},
        {"attacks.data", "数据抵近窃取攻击测试", "数据与信息", "tasks", 3},
        {"attacks.tampering", "信息篡改欺骗攻击测试", "数据与信息", "tasks", 3},
        {"attacks.control", "关键设备夺控攻击测试", "设备与网络", "tasks", 3},
        {"attacks.disruption", "跨网致瘫攻击测试", "设备与网络", "topology", 3, false},
        {"attacks.wireless", "无线攻击测试", "无线环境", "topology", 3, false},
        {"evaluation.results", "测试结果与评估", "任务评估", "reports", 4},
        {"evaluation.capture", "网络数据捕获", "网络证据", "topology", 4},
        {"evaluation.analysis", "网络数据分析", "网络证据", "analysis", 4},
        {"evaluation.perception", "安全态势感知", "安全态势", "dashboard", 4, false},
        {"evaluation.situation", "安全态势分析", "安全态势", "analysis", 4, false},
        {"evaluation.display", "安全态势展示", "安全态势", "dashboard", 4, false},
        {"resources.discovery", "资产探测", "目标资源", "search", 5},
        {"resources.hexstrike", "HexStrike部署配置", "执行环境", "settings", 5, false},
        {"resources.runtime", "虚拟环境部署配置", "执行环境", "settings", 5, true, true},
        {"resources.llm", "大语言模型LLM部署配置", "智能服务", "analysis", 5, true, true},
        {"resources.labs", "测试靶场部署配置", "测试支撑", "topology", 5, true, true},
        {"resources.tools", "测试工具部署配置", "测试支撑", "settings", 5, true, true},
        {"system.tasks", "任务管理", "任务与账户", "tasks", 6},
        {"system.users", "用户管理", "任务与账户", "user", 6, true, true},
        {"system.permissions", "权限管理", "任务与账户", "settings", 6, true, true},
        {"system.license", "加密锁校验", "运行许可", "settings", 6, true, true},
        {"system.generate-report", "测试报告自动智能生成", "报告中心", "reports", 6},
        {"system.reports", "测试报告管理", "报告中心", "reports", 6}
    };
    return values;
}

const RibbonFeature *ModuleRibbon::feature(const QString &id)
{
    for (const auto &entry : features()) if (entry.id == id) return &entry;
    return nullptr;
}

ModuleRibbon::ModuleRibbon(bool administrator, QWidget *parent)
    : QWidget(parent), m_administrator(administrator), m_pages(new QStackedWidget(this)), m_selection(new QButtonGroup(this))
{
    setObjectName(QStringLiteral("moduleRibbon"));
    setAttribute(Qt::WA_StyledBackground, true);
    setStyleSheet(QStringLiteral(
        "QWidget#moduleRibbon { background:#ffffff; border-bottom:1px solid #dbe3ef; }"
        "QToolButton { color:#334b6b; border:1px solid transparent; border-radius:6px;"
        " padding:3px 9px; font-size:13px; font-weight:400; background:transparent; }"
        "QToolButton:hover { background:#f1f5ff; border-color:#dce6fa; }"
        "QToolButton:checked { color:#245fd6; background:#edf3ff; border-color:#cdddfb; }"
        "QToolButton:disabled { color:#a8b2c2; background:transparent; border-color:transparent; }"));
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->addWidget(m_pages);
    setFixedHeight(42);
    m_selection->setExclusive(true);
    for (int module = 0; module < moduleNames().size(); ++module) {
        auto *scroll = new QScrollArea(m_pages);
        scroll->setObjectName(QStringLiteral("ribbonScroll%1").arg(module));
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll->setStyleSheet(QStringLiteral(
            "QScrollBar:horizontal { height:4px; background:#f1f5fb; margin:0; }"
            "QScrollBar::handle:horizontal { background:#c7d3e4; border-radius:2px; min-width:24px; }"
            "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }"));
        auto *content = new QWidget(scroll);
        QPalette palette = content->palette();
        palette.setColor(QPalette::Window, Qt::white);
        content->setPalette(palette);
        content->setAutoFillBackground(true);
        scroll->viewport()->setPalette(palette);
        auto *groups = new QHBoxLayout(content);
        groups->setContentsMargins(10, 4, 10, 4);
        groups->setSpacing(8);
        QStringList groupNames;
        for (const auto &entry : features())
            if (entry.module == module && !groupNames.contains(entry.group)) groupNames << entry.group;
        for (const auto &name : groupNames) {
            auto *group = new QWidget(content);
            auto *vertical = new QVBoxLayout(group);
            vertical->setContentsMargins(0, 0, 4, 0);
            vertical->setSpacing(2);
            auto *commands = new QHBoxLayout;
            commands->setSpacing(4);
            for (const auto &entry : features()) {
                if (entry.module != module || entry.group != name) continue;
                auto *button = new QToolButton(group);
                button->setObjectName(QStringLiteral("ribbon.%1").arg(entry.id));
                button->setProperty("featureId", entry.id);
                button->setText(entry.title);
                button->setAccessibleName(entry.title);
                button->setIcon(QIcon(QStringLiteral(":/icons/shell/%1.svg").arg(entry.icon)));
                button->setIconSize(QSize(14, 14));
                button->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
                button->setCheckable(true);
                QFont commandFont = button->font(); commandFont.setPixelSize(13);
                commandFont.setWeight(QFont::Normal); button->setFont(commandFont);
                button->ensurePolished();
                button->setFixedWidth(qMax(72, button->sizeHint().width()));
                button->setFixedHeight(30);
                m_selection->addButton(button);
                button->setEnabled(canOpen(entry.id));
                button->setToolTip(!entry.implemented ? entry.title + QStringLiteral(" · 暂未实现")
                    : entry.adminOnly && !administrator ? entry.title + QStringLiteral(" · 仅管理员可用") : entry.title);
                if (button->isEnabled()) connect(button, &QToolButton::clicked, this, [this, id = entry.id]() {
                    if (canOpen(id)) emit featureRequested(id);
                });
                commands->addWidget(button);
                m_buttons << button;
            }
            vertical->addLayout(commands);
            groups->addWidget(group);
            auto *line = new QFrame(content);
            line->setFrameShape(QFrame::VLine);
            line->setStyleSheet(QStringLiteral("color:#e1e7f1;"));
            groups->addWidget(line);
        }
        groups->addStretch();
        scroll->setWidget(content);
        m_pages->addWidget(scroll);
    }
}

bool ModuleRibbon::canOpen(const QString &id) const
{
    const auto *entry = feature(id);
    return entry && entry->implemented && (!entry->adminOnly || m_administrator);
}

void ModuleRibbon::setModule(int module)
{
    if (module >= 0 && module < m_pages->count()) m_pages->setCurrentIndex(module);
}

void ModuleRibbon::setActiveFeature(const QString &id)
{
    const auto *entry = feature(id);
    if (entry) setModule(entry->module);
    m_selection->setExclusive(false);
    for (auto *button : m_buttons) {
        const QSignalBlocker blocker(button);
        button->setChecked(button->property("featureId").toString() == id && canOpen(id));
    }
    m_selection->setExclusive(true);
}
