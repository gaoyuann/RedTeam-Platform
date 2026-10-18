# 拓扑节点属性编辑消失修复

## 问题与原因

点击拓扑节点时，属性编辑短暂出现，鼠标松开后消失。原实现每次鼠标释放都执行位置更新并排队重建场景，即使节点没有移动。重建时 `QGraphicsScene::clear()` 发出选择变化信号，清空当前节点 ID 和属性表单；后续选择同步受保护，不会重新填充表单。

节点、连线列表重建同样可能发出临时取消选择信号。应用属性后排队的回调还会重新选择此前编辑的对象，覆盖用户刚切换到的新对象。

## 修复

- 记录鼠标按下时的节点位置，仅实际移动后才更新位置和重绘。
- 重建场景和列表时屏蔽临时选择信号；场景重建后恢复当前选中对象。
- 排队的重绘采用执行时的当前选择，避免切回旧节点或旧连线。
- 用户主动取消选择仍正常返回概览。

修改生产文件为 `frontend/src/pages/TopologyPage.cpp`；测试修改为 `frontend/tests/topology/TopologySmoke.cpp` 和该目录的 `CMakeLists.txt`，增加 Qt Test 依赖用于实际鼠标事件回归。

## 本地验证（2026-10-13）

新增鼠标回归在修复前通过 `ctest --test-dir build/topology-ui --output-on-failure` 复现“鼠标释放后属性消失”断言失败；该次失败退出还发生段错误，未独立定位其析构原因。修复后同一测试正常通过并退出。

以下命令使用已有 WSL / Qt5 / CMake 构建目录，均通过：

```sh
cmake --build build/topology-ui -j2
ctest --test-dir build/topology-ui --output-on-failure
cmake --build build --target RedTeam-Platform -j2
git diff --check
```

拓扑冒烟测试覆盖鼠标点击不标记修改或重建场景、拖动后位置及属性保持、节点和连线属性应用、未应用修改随节点切换保存、文档重建后的选择保持、主动取消选择，以及已有布局和字号回归。构建保留已有 Qt 弃用警告。

本次为本地离屏交互验证和编译；没有部署服务器或云笔电，也没有连接真实后端或扫描目标。
