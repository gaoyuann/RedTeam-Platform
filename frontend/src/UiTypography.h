#pragma once
#include <QFont>
#include <QFontDatabase>
#include <QStringList>

namespace Theme {

constexpr int BodyFontPixels = 14;
constexpr int TopologyFontPixels = 13;

// Resolve an installed Chinese sans-serif family instead of inheriting a
// desktop's serif default. Explicit monospace fonts in code views stay local.
inline QFont uiFont()
{
    const QStringList installed = QFontDatabase().families(QFontDatabase::SimplifiedChinese);
    const QStringList preferred{
        QStringLiteral("Noto Sans CJK SC"), QStringLiteral("Source Han Sans SC"),
        QStringLiteral("Source Han Sans CN"), QStringLiteral("思源黑体"),
        QStringLiteral("Microsoft YaHei UI"), QStringLiteral("Microsoft YaHei"),
        QStringLiteral("微软雅黑"), QStringLiteral("PingFang SC"),
        QStringLiteral("WenQuanYi Micro Hei"), QStringLiteral("WenQuanYi Zen Hei")
    };
    QFont font(QStringLiteral("sans-serif"));
    for (const auto &family : preferred) {
        if (!installed.contains(family, Qt::CaseInsensitive)) continue;
        font.setFamily(family);
        break;
    }
    font.setStyleHint(QFont::SansSerif);
    font.setStyleStrategy(QFont::PreferAntialias);
    font.setPixelSize(BodyFontPixels);
    font.setWeight(QFont::Normal);
    return font;
}

// Keep graph labels independent of the surrounding control typography.
// Explicit page fonts (including accessibility overrides) still take precedence.
inline QFont topologyFont(QFont base)
{
    if (base.pixelSize() == BodyFontPixels) base.setPixelSize(TopologyFontPixels);
    return base;
}

} // namespace Theme
