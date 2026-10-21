#pragma once

#include <QString>

namespace ReportFileActions {

enum class OpenStatus { Started, NotFound, Failed };

struct OpenResult {
  OpenStatus status;
  QString title;
  QString message;
};

QString findWpsExecutable();
OpenResult openInWps(const QString &filePath);

} // namespace ReportFileActions
