#pragma once
#include <QCoreApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QJsonArray>
#include <QJsonObject>

namespace Theme {

inline void enableHighDpiScaling()
{
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
#endif
}

inline QJsonObject displayScalingInfo()
{
    QJsonArray screens;
    for (auto *screen : QGuiApplication::screens()) {
        const auto geometry = screen->geometry();
        screens.append(QJsonObject{{"width", geometry.width()}, {"height", geometry.height()},
            {"devicePixelRatio", screen->devicePixelRatio()}, {"logicalDpi", screen->logicalDotsPerInch()}});
    }
    return {{"platform", QGuiApplication::platformName()}, {"screens", screens}};
}

} // namespace Theme
