# 字号与小窗口显示修复

## 当前桌面缩放修复

2026-11-01 实机确认：用户运行的是最新程序，Windows 主屏为 200% 缩放；WSLg 的 X11 显示器却按约 96 DPI、DPR 1 暴露 2520×1680 像素。Windows 的逻辑桌面为 1260×840。即使正文为 14px，整个应用也仍按未缩放像素绘制。这是本轮整套界面显小的实际原因。

应用在构建 `QApplication` 前启用 Qt 5 的 High DPI 缩放及高分辨率图标，并允许 125%／150% 等比例。WSLg 单屏环境下，使用 Windows `GetScaleFactorForMonitor` 读取主屏缩放，再通过独立的 Qt 诊断进程读取已生效的 DPR，只补足缺失部分。例如主屏 200%、Qt 已为 200% 时保持原值，不再放大。显式的 `QT_SCALE_FACTOR`、`QT_SCREEN_SCALE_FACTORS`、`QT_FONT_DPI` 和 DPI 启用／关闭环境变量优先，不覆盖用户设置。

补偿仅影响应用进程，不修改 Windows、Linux 桌面、WSLg 或其他软件配置。普通 Linux／Windows 不运行 WSL 适配。宿主查询超时、无可用 Windows 互操作、结果无效或多屏无法对应时不猜测全局比例；多屏跟随由 Qt 原生 DPI 支持处理。当前只在启动时补偿 WSLg 信息缺失，跨屏移动与运行中修改 Windows 缩放仍需后续验证。

诊断入口不会创建登录、后端连接或任务页面：

```sh
./build/frontend/RedTeam-Platform --display-info-raw
./build/frontend/RedTeam-Platform --display-info
```

实测修复前约 DPR 1.001、逻辑 2517×1678；补偿后 DPR 2.00005、逻辑 1260×840，与 Windows 对齐。`QT_SCALE_FACTOR=1.5` 仍使用约 1.5 倍，`QT_ENABLE_HIGHDPI_SCALING=0` 仍使用 1 倍。保留 14px 正文、13px 紧凑操作、15px 主导航及已经修复的模块职责。

改动文件：`frontend/src/UiDisplayScaling.h`（新增）、`frontend/src/main.cpp`、`frontend/CMakeLists.txt` 和 `frontend/test/batch16_context_checks.cpp`。官方原理参考 [Qt 5 High DPI](https://doc.qt.io/archives/qt-5.15/highdpi.html) 与 [GetScaleFactorForMonitor](https://learn.microsoft.com/en-us/windows/win32/api/shellscalingapi/nf-shellscalingapi-getscalefactorformonitor)。

本轮构建应用和 Batch16Checks 通过。补偿计算与环境覆盖包含于 2 倍缩放紧凑专项，39 项通过；2 倍首页专项 27 项通过；2 倍扫描／拓扑与证据正文专项 92 项通过。另在本机真实 X11／WSLg 桌面、不设置 `QT_SCALE_FACTOR` 的情况下运行隔离首页交互，27 项通过，并检查实际 Qt 截图（`build/ui-dpi-20261101/home.png`、`home-wide.png`）。仅使用隔离任务样例，未启动真实业务扫描。

完整界面回归 `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 ./build/frontend/RedTeam-Platform-Batch16Checks` 为 1388 项通过。启动诊断、真实桌面首页和隔离测试验证完成，保留原断言及超时设置。

## 原因与调整

默认字体原为 13 磅、中等字重，按钮、输入框、表头和页签普遍指定 17–18 像素。高 DPI 下这些尺寸随系统缩放放大，配合较大的导航留白和执行摘要的高度压缩，会造成文字拥挤、卡片标题裁切及操作区域显示不全。

当前默认字体为 14 个逻辑像素、正常字重；表格、输入和弹窗正文为 14 像素，紧凑操作为 13 像素，页面页签为 14 像素，模块导航为 15 像素。拓扑画布默认文字单独保持 13 像素，显示时继续随画布缩放。保留系统 DPI 缩放和中文无衬线字体选择，不修改用户显示设置。浅色、深色样式同步调整。

长任务文字仅在绘制时省略，原始文本、提示和可访问性信息保留；操作按钮保持可见。导航减少多余留白，使最小 1024 像素窗口可完整显示七个模块名称。

指标卡标题与附注允许换行，卡片布局维持最小内容高度。执行页增加整页滚动，并为摘要及记录区保留最小高度，小窗口通过滚动查看完整内容。摘要仍可折叠，长摘要保留内部滚动。

## 文件

- 字体与样式：`frontend/src/UiTypography.h`、`AppStyle.h`、`StyleDark.h`、`Theme.h`、`widgets/WorkbenchTabs.h`。
- 导航和任务栏：`frontend/src/MainWindow.cpp`、`widgets/ModuleRibbon.cpp`、新增 `widgets/ElidedLabel.h`。
- 执行摘要：`frontend/src/widgets/MetricCard.h`、`pages/TaskExecutionPanel.cpp`。
- 回归：`frontend/test/batch16_context_checks.cpp`。

## 验证

使用现有 CMake 目录与 Qt 配置：

```sh
cmake --build build --target RedTeam-Platform-Batch16Checks RedTeam-Platform -j 4
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 REDTEAM_COMPACT_ONLY=1 ./build/frontend/RedTeam-Platform-Batch16Checks
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1.5 REDTEAM_COMPACT_ONLY=1 ./build/frontend/RedTeam-Platform-Batch16Checks
QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=2 REDTEAM_COMPACT_ONLY=1 ./build/frontend/RedTeam-Platform-Batch16Checks
QT_QPA_PLATFORM=offscreen ./build/frontend/RedTeam-Platform-Batch16Checks
```

三档缩放各 32 项专项检查通过，并人工核对任务栏及执行摘要顶部、底部截图。检查覆盖最小窗口宽度下的全部模块文字、长任务名、操作按钮、卡片标题和数值、短窗口的滚动可达性。离屏验证不代替实际 Windows 显示环境验收；本次不修改正在运行的客户端进程或后台数据。

最终结果：客户端及测试程序构建成功，完整界面回归 1265 项检查全部通过；三档缩放专项各 32 项全部通过。


## 导航与正文层级（2026-11-01）

以拓扑节点文字的阅读密度为参照，默认正文和常用输入、按钮、表格、提示统一为 13 个逻辑像素、正常或中等字重；页面 Tab 为 14 像素，主模块为 15 像素。主模块同时在局部样式中明确字号，避免全局列表样式覆盖字体设置。扫描页、任务表单和方案说明中遗留的 16–18 像素正文同步收小，保留独立页面标题与统计数值的层级。浅色、深色通用控件保持一致。

子功能按钮使用完整单行名称，文字 13 像素、正常字重，图标 16 像素；按钮高 40 像素、整栏高 52 像素，收紧分组间距。窄窗口仍可水平滚动到全部入口，功能名称、顺序和路由保持。拓扑节点使用相同的默认字体，画布缩放仍按原逻辑生效。

本轮涉及共享字体与浅／深色样式（`UiTypography.h`、`AppStyle.h`、`StyleDark.h`、`Theme.h`）、主窗口和子功能栏（`MainWindow.cpp`、`widgets/ModuleRibbon.cpp`），以及拓扑、扫描、任务表单、方案、执行和结果页的局部文字（`pages/TopologyPage.cpp`、`ScanPage.cpp`、`FlowPage.cpp`、`TaskPlanPage.cpp`、`TaskExecutionPanel.cpp`、`TaskResultsPanel.cpp`）。回归文件为 `frontend/test/batch16_context_checks.cpp`。

首次完整回归命令 `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 ./build/frontend/RedTeam-Platform-Batch16Checks` 在“窄窗口长文本增加行高”检查失败。实际截图与诊断确认宽、窄行高均为 51 像素：缩小字体后，原样例的任务名称和 URL 在窄窗口只需两行，宽窗口的两行时间戳也已撑到同样高度，文字没有裁切。已有用例改用更长的多级 URL，保留窄窗口必须增加行高、放宽窗口必须恢复行高及字段完整可见的全部断言。

本轮验证结果：

- `cmake --build build --target RedTeam-Platform RedTeam-Platform-Batch16Checks -j 4`：通过。
- `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=<1 / 1.5 / 2> REDTEAM_COMPACT_ONLY=1 ./build/frontend/RedTeam-Platform-Batch16Checks`：三档各 60 项通过。
- `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=<1 / 1.5> REDTEAM_SCAN_PRESENTATION_ONLY=1 REDTEAM_SCAN_SCREENSHOT_DIR=<临时截图目录> ./build/frontend/RedTeam-Platform-Batch16Checks`：两档各 116 项通过。
- `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1.5 REDTEAM_RIBBON_REVIEW_ONLY=1 REDTEAM_RIBBON_SCREENSHOT_DIR=<临时截图目录> ./build/frontend/RedTeam-Platform-Batch16Checks`：597 项通过。
- `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 TASK_IDENTITY_CAPTURE_DIR=<临时截图目录> ./build/frontend/RedTeam-Platform-Batch16Checks`：完整回归 1314 项通过，长文本窄窗口增高与宽窗口恢复断言通过。

人工核对 100% 和 150% 的实际 Qt 拓扑截图及宽、窄任务列表截图。截图与接口均为隔离样例；尚未验证用户正在使用的部署客户端。本地预览位于 `build/ui-typography-20261101/`，不提交构建产物，不重启运行中的客户端。


## 按“源主机”的实际显示大小修正

用户反馈上一轮 13 像素控件仍大于拓扑卡片的“源主机”。核对发现正在运行的确实是上一轮新构建，不能归因于没有重启。拓扑节点会随 `QGraphicsView` 的适应画布缩放，按钮和表单不会；把两者设为同一个字号并不能得到同样的屏幕字形大小。

本轮将正文、输入框、表格、操作按钮和子功能改为 10 个逻辑像素；页面页签为 12 像素，主模块维持 15 像素。拓扑文字从默认 UI 字号中分离，默认继续用 13 像素，避免参照物也跟着缩小。显式指定的页面字体仍受支持，节点尺寸仍按实际文字边界测量。连线文字和间距计算使用同一画布字体。常规按钮高 30 像素，子功能按钮高 30 像素、整栏高 42 像素，输入和表格内边距同步收紧。

补充“属性编辑＋选中源主机＋画布”实际 Qt 截图，沿用原显示专项的模拟接口，不读真实任务和凭据。相同窗口与 150% 缩放下，节点均为 13 像素，画布缩放均为 0.943；字段字体由 13 像素降为 10 像素。预览保存在 `build/ui-typography-20261101/properties-before.png` 与 `properties-after.png`。前文 13 像素正文及 52 像素功能区的记录为上一轮状态。

本轮验证：

- 主程序及 `RedTeam-Platform-Batch16Checks` 使用原构建目录编译通过。
- `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 ./build/frontend/RedTeam-Platform-Batch16Checks`：完整回归 1310 项通过。
- `REDTEAM_SCAN_PRESENTATION_ONLY=1` 配合 `QT_SCALE_FACTOR=1 / 1.5` 和截图目录：两档各 89 项通过，包含展开属性编辑、选中“源主机”的截图。
- `REDTEAM_COMPACT_ONLY=1` 配合 `QT_SCALE_FACTOR=1.5 / 2`：两档各 32 项通过。
- `cmake --build build/topology-ui -j 4` 和 `ctest --test-dir build/topology-ui --output-on-failure`：构建及 1/1 冒烟检查通过，包含显式 9/12/16/24 磅字体的节点边界与遮挡验证。

完成前重新核对本地运行进程，可执行文件与本次磁盘构建一致。预览截图仍使用隔离样例，不代表真实扫描结果。


## 可读性恢复（当前生效）

上一轮把局部导航的紧凑需求扩大为全局 10px，导致表格、表单及“发现详情与证据”弹窗过小。现将默认字体和阅读内容恢复为 14px，按钮及子功能为 13px，页面 Tab 为 14px，顶部模块和“首页”为 15px。继续保留紧凑留白、首页简化、模块各自负责内容和重复流程页签隐藏；没有恢复大流程卡片或大字号、厚留白导航。拓扑节点默认继续用独立的 13px。首页正文同步使用 14px。

共享浅／深色样式、各任务页残留的 10px 局部样式及默认字体一起调整，防止只改全局但弹窗或页面仍被旧样式覆盖。显示专项补充实际打开只读证据弹窗，检查扫描结果和证据正文均至少 14px，并保存弹窗截图。

本轮验证：应用、Batch16Checks 和 DashboardChecks 均使用原 CMake 目录编译通过；`REDTEAM_SCAN_PRESENTATION_ONLY=1` 在 1 / 1.5 缩放下各 92 项通过，包含实际证据弹窗字体断言与截图；`REDTEAM_COMPACT_ONLY=1` 在 2 倍缩放下 32 项通过；`ctest --test-dir build -R '^ui-dashboard$' --output-on-failure` 为 1/1 通过。实际截图在 `build/ui-readable-20261101/`，均来自隔离样例，不作为真实扫描证据。

完整命令 `QT_QPA_PLATFORM=offscreen QT_SCALE_FACTOR=1 ./build/frontend/RedTeam-Platform-Batch16Checks` 为 1388 项通过。完成前只读核对发现当前客户端进程仍使用上一构建，须重新打开才能加载恢复字号；未主动关闭用户窗口。
