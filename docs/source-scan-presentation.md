# 源码扫描结果呈现

详情页沿用 pentagi-v3 的 `src/ui/pages/source_scan/SourceScanPage.cpp` 交互：左侧文件树、中间只读源码、右侧全部发现及详情。代码编辑器的行号栏和 C/C++ 高亮复用原版实现，Qt 技术栈不变。任务提交仍使用本项目的远端源码 URL 接口。

## 数据与联动

- 文件树主要来自任务接口的 `source_files` 快照元数据，文件总数只统计快照。
- `/work/src/` 是远端快照根目录；仅去掉这个明确前缀后与报告相对路径匹配，任务 ID 始终参与键值。其他绝对路径不会按 basename 猜测匹配。
- 报告引用但没有快照的文件置于“待核对 · 未匹配源码”，不生成虚构代码。
- 选择文件只切换代码，不缩小右侧发现列表。严重度筛选作用于整个任务。
- 点击发现选择对应文件，调用已有只读 source-file 接口加载内容并核对 SHA-256 元数据，定位和高亮行范围。未匹配或越界位置明确标注待核对。
- 刷新保留所选发现。异步源码请求通过序号和文件键防止旧响应覆盖新选择。
- 原始报告与依据放在右侧标签页，代码区保持固定；报告预览上限 64000 字符并显示截断提示。
- 扫描发现仍是待复核记录；浏览页面不会创建或执行验证任务。原有显式测试准备入口保留。

## 验证

```sh
cmake --build build --target PentagiSourceHostChecks RedTeam-SourceScanDetailChecks -j2
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 build/frontend/RedTeam-SourceScanDetailChecks
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1.5 build/frontend/RedTeam-SourceScanDetailChecks
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=2 build/frontend/RedTeam-SourceScanDetailChecks
QT_QPA_PLATFORM=offscreen build/frontend/PentagiSourceHostChecks
```

单元/交互检查使用确定性接口样例；真实结果截图另通过现有后端只读接口加载 Flow15 已保存结果。截图使用修改后的 Qt 组件离屏渲染，不代表已发布或已部署新前端。
