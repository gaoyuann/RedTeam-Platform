#pragma once
#include <QCoreApplication>
#include <QGuiApplication>
#include <QScreen>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSysInfo>
#include <cmath>

namespace Theme {

inline void enableHighDpiScaling()
{
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QCoreApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
#endif
}

inline bool hasExplicitDisplayScaling(const QProcessEnvironment &environment)
{
    for (const auto &key : {"QT_SCALE_FACTOR", "QT_SCREEN_SCALE_FACTORS", "QT_FONT_DPI",
                           "QT_ENABLE_HIGHDPI_SCALING", "QT_AUTO_SCREEN_SCALE_FACTOR", "QT_DEVICE_PIXEL_RATIO"})
        if (environment.contains(QString::fromLatin1(key))) return true;
    return false;
}

inline qreal missingDisplayScale(qreal hostScale, qreal qtScale, int screenCount)
{
    // Multi-monitor layouts need per-monitor mapping; never guess a global scale.
    if (screenCount != 1 || !std::isfinite(hostScale) || !std::isfinite(qtScale)
        || hostScale < 1 || hostScale > 4 || qtScale < 0.5 || qtScale > 4
        || hostScale <= qtScale + 0.05) return 1;
    return qMin(qreal(4), hostScale / qtScale);
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

inline QByteArray readDisplayProbe(QProcess &process, const QString &program, const QStringList &arguments)
{
    process.setProcessChannelMode(QProcess::SeparateChannels);
    process.start(program, arguments);
    if (!process.waitForFinished(4000)) {
        process.kill();
        process.waitForFinished(200);
        return {};
    }
    return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0
        ? process.readAllStandardOutput().trimmed() : QByteArray();
}

// Some WSLg sessions expose a 200% Windows monitor to X11 as 96 DPI / DPR 1.
// Correct only that missing scale, locally to this process, before QApplication.
inline void applyWslDisplayScaling(const QString &executable)
{
#ifdef Q_OS_LINUX
    const auto environment = QProcessEnvironment::systemEnvironment();
    const auto platform = environment.value(QStringLiteral("QT_QPA_PLATFORM"));
    if (hasExplicitDisplayScaling(environment)
        || (!platform.isEmpty() && platform != QStringLiteral("xcb") && platform != QStringLiteral("wayland"))
        || !QSysInfo::kernelVersion().contains(QStringLiteral("microsoft"), Qt::CaseInsensitive)
        || !QDir(QStringLiteral("/mnt/wslg")).exists()) return;
    const QString powershell = QStringLiteral("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe");
    if (!QFileInfo::exists(powershell)) return;
    const QString script = QStringLiteral(
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
        "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; "
        "public class RedTeamDisplay { "
        "[DllImport(\"user32.dll\")] public static extern IntPtr MonitorFromPoint(long point, uint flags); "
        "[DllImport(\"user32.dll\")] public static extern int GetSystemMetrics(int index); "
        "[DllImport(\"shcore.dll\")] public static extern int GetScaleFactorForMonitor(IntPtr monitor, out int scale); }'; "
        "$scaleValue=0; $result=[RedTeamDisplay]::GetScaleFactorForMonitor("
        "[RedTeamDisplay]::MonitorFromPoint(0,1),[ref]$scaleValue); "
        "if ($result -eq 0) { @{percent=$scaleValue;count=[RedTeamDisplay]::GetSystemMetrics(80)} | ConvertTo-Json -Compress }");
    QByteArray utf16;
    for (const auto character : script) {
        utf16.append(char(character.unicode() & 0xff));
        utf16.append(char(character.unicode() >> 8));
    }
    QProcess hostProbe;
    const auto host = QJsonDocument::fromJson(readDisplayProbe(hostProbe, powershell,
        {QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"), QStringLiteral("-EncodedCommand"),
         QString::fromLatin1(utf16.toBase64())})).object();
    if (host.value("count").toInt() != 1 || host.value("percent").toDouble() <= 100) return;
    // A short-lived Qt-only probe accounts for scaling already supplied by WSLg.
    // Its diagnostic path never constructs login, backend or task components.
    QProcess qtProbe;
    const auto screens = QJsonDocument::fromJson(readDisplayProbe(qtProbe, executable,
        {QStringLiteral("--display-info-raw")})).object().value("screens").toArray();
    if (screens.size() != 1) return;
    const auto factor = missingDisplayScale(host.value("percent").toDouble() / 100,
        screens.first().toObject().value("devicePixelRatio").toDouble(), screens.size());
    if (factor > 1.01) qputenv("QT_SCALE_FACTOR", QByteArray::number(factor, 'f', 4));
#else
    Q_UNUSED(executable)
#endif
}

} // namespace Theme
