# 拓扑显示完整性

本次调整参考 pentagi-v3 的列表、详情与画布分工，保留现有 Qt Widgets、拓扑模型和接口。

- 节点名称、角色和服务说明按实际字体换行，卡片根据文字实际边界计算高度，不使用省略号截掉名称。地址独立显示。
- 后端生成坐标和旧归档坐标继续使用；卡片测量完成后，在视图中避让重叠节点，并为连接标签保留间距。避让不改写归档中的已有坐标，显式拖动继续按原流程标记待保存。
- “适应画布”完整容纳节点及文字，最多使用原始比例，避免少量节点被过度放大。自动适应状态下调整窗口、展开侧栏或显示节点操作会重新适应；用户主动缩放后保留手动比例。
- 扫描记录、节点与连线、信息按钮可再次点击收起对应侧栏。没有选择具体主机时收起扫描及验证操作区。
- 画布标题保持简短，完整汇总说明放在信息页和悬停提示。资产清单切回拓扑时，节点、连线和服务统计从当前文档重新计算，不恢复过期缓存。

修改涉及 `TopologyPage.cpp/.h`；源码任务列表和视图选择的配套调整见 [源码扫描结果呈现](source-scan-presentation.md)。测试位于 `frontend/tests/topology/TopologySmoke.cpp`、`frontend/test/pentagi_source_host_checks.cpp` 和 `frontend/test/scan_presentation_checks.h`。

验证使用隔离的模拟数据和 Qt 离屏渲染，包含旧坐标碰撞、三个节点、长中文名称、9/12/16/24 磅字号、重复渲染、文档坐标保持、侧栏切换、窗口变化、手动缩放和整窗显示检查。未运行真实扫描或部署远端客户端。

```sh
cmake --build build --target RedTeam-Platform RedTeam-Platform-Batch16Checks PentagiSourceHostChecks -j 4
cmake --build build/topology-ui -j 4
ctest --test-dir build/topology-ui --output-on-failure
ctest --test-dir build -R '^(ui-context-|pentagi-source-host$)' --output-on-failure -j 1
```

可用 `REDTEAM_SCAN_PRESENTATION_ONLY=1` 单独运行包含源码页和拓扑页的显示检查，`REDTEAM_SCAN_SCREENSHOT_DIR` 可将完整应用窗口截图写入指定目录。截图使用模拟数据，不作为真实扫描证据或部署证明。


## 本地验证结果（2026-10-31）

- 主程序、完整 UI 回归目标、源码任务交互目标和拓扑冒烟目标编译通过。
- `ctest --test-dir build/topology-ui --output-on-failure`：1/1 通过。
- `ctest --test-dir build -R '^(ui-context-|pentagi-source-host$)' --output-on-failure -j 1`：4/4 通过，包含 100%、125%、150% 缩放的完整 UI 回归。
- 带整窗截图的显示专项共 81 项检查通过，截图在临时目录，不提交。
- 首次使用 `-j 3` 跑完整 UI 回归时，125% 和 150% 在 120 秒上限超时；100% 通过，超时前无断言失败。串行重跑全部通过，推断与并行负载和整套用例耗时有关，未单独定位资源瓶颈。

| 修改文件 | 内容 |
| --- | --- |
| `frontend/src/pages/PentagiSourceScanHost.cpp` | 源码列表、创建弹窗、完整状态与时间、刷新选择保持 |
| `frontend/src/pages/ScanPage.cpp` | 视图选择框按内容宽度靠左显示 |
| `frontend/src/pages/TopologyPage.cpp/.h` | 完整节点文字、避让、适应画布、侧栏和当前统计 |
| `frontend/test/pentagi_source_host_checks.cpp` | 新建交互、时间、控件边界和刷新选择回归 |
| `frontend/tests/topology/TopologySmoke.cpp` | 字号、碰撞、完整文字与坐标保持回归 |
| `frontend/test/scan_presentation_checks.h` | 源码与拓扑的完整窗口显示回归与截图 |
| `docs/source-scan-presentation.md`、本文档 | 页面结构、行为和验证说明 |
