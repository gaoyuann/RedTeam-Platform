#include "ReportFileActions.h"

#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>

QString ReportFileActions::findWpsExecutable()
{
  const auto executable = [](const QString &path) {
    const QFileInfo info(path);
    return info.isFile() && info.isExecutable();
  };
  const QString configured = QString::fromUtf8(qgetenv("WPS_PATH"));
  if (!configured.isEmpty() && executable(configured)) return configured;

  const QStringList candidates{
    "/usr/bin/wps-office",
    "/opt/apps/cn.wps.wps-office-pro/files/wps-office/office6/wps",
    "/opt/wps-office/office6/wps",
    "/usr/local/bin/wps",
    "/usr/bin/wps"
  };
  for (const auto &path : candidates) if (executable(path)) return path;
  for (const auto &name : {QStringLiteral("wps-office"), QStringLiteral("wps")}) {
    const QString path = QStandardPaths::findExecutable(name);
    if (!path.isEmpty()) return path;
  }
  return {};
}

ReportFileActions::OpenResult ReportFileActions::openInWps(const QString &filePath)
{
  const QString executable = findWpsExecutable();
  if (!executable.isEmpty()) {
    if (QProcess::startDetached(executable, {filePath})) return {OpenStatus::Started, {}, {}};
    return {OpenStatus::Failed, QStringLiteral("启动失败"),
      QStringLiteral("无法启动 WPS，报告已保存至：\n%1\n请手动打开文件。").arg(filePath)};
  }

  // Preserve WSL default-file opening without sending a dynamic path through cmd.exe.
  const QString explorer = QStringLiteral("/mnt/c/Windows/explorer.exe");
  const QString distribution = QString::fromUtf8(qgetenv("WSL_DISTRO_NAME"));
  if (!distribution.isEmpty() && QFileInfo::exists(explorer)) {
    const QString absolute = QFileInfo(filePath).absoluteFilePath();
    const auto drive = QRegularExpression("^/mnt/([a-zA-Z])(/.*)$").match(absolute);
    QString windowsPath = drive.hasMatch()
        ? drive.captured(1).toUpper() + ":" + drive.captured(2)
        : QStringLiteral("\\\\wsl.localhost\\") + distribution + absolute;
    windowsPath.replace('/', '\\');
    if (QProcess::startDetached(explorer, {windowsPath}))
      return {OpenStatus::Started, {}, {}};
  }
  return {OpenStatus::NotFound, QStringLiteral("未找到 WPS"),
    QStringLiteral("未检测到 WPS Office，报告已保存至：\n%1\n请手动打开文件。\n"
                   "可设置环境变量 WPS_PATH 指向 WPS 可执行文件路径。").arg(filePath)};
}
