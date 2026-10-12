# 加密锁校验使用与部署说明

## 功能入口与实现

入口为 **系统管理 → 加密锁校验**。

对应实现：

- `frontend/src/services/dongle/DongleService.*`：动态加载 ROCKEY ARM SDK，枚举、注册、校验、销毁、读写策略。
- `frontend/src/pages/DongleVerificationPage.*`：设备管理页面与确认交互。
- `frontend/src/main.cpp`：登录前校验。
- `frontend/src/MainWindow.cpp`、`SimpleMainWindow.cpp`：每 5 秒复核，失败锁定界面，恢复后返回原页面。
- `third_party/rockey/`：随程序分发的厂商库；构建后复制到可执行文件旁。

## 使用

1. 将 ROCKEY ARM 插入运行 Qt 客户端的电脑，打开加密锁校验页，点击刷新设备。
2. 选中设备，执行注册校验并确认。写入并回读校验成功、策略保存成功后才启用本机校验。
3. 校验当前设备只读取设备，不写入。注册后的启动校验及心跳也只读设备。
4. 启用策略时必须能校验通过已绑定的设备。运行时拔出设备会锁屏，操作系统重新识别设备后，下一个心跳（约 5 秒内）恢复。WSL 需要先恢复 USB 转发，单纯插回 Windows 不代表 WSL 已经可见。
5. 在设备仍连接、界面可访问时可关闭校验策略，设备记录会保留。
6. 销毁只清除选中设备的本平台注册区域，并回读确认。销毁当前绑定设备会先保存停用策略，保存失败不擦除设备；设备擦除失败时策略保持停用，可刷新后重试或重新启用。销毁其他设备不会清除当前绑定。

策略使用 `QStandardPaths::AppConfigLocation/dongle.json`，通常为
`~/.config/RedTeam-Platform/dongle.json`（以当前程序的组织/应用名称及 `XDG_CONFIG_HOME` 为准）。它属于当前操作系统用户，而非服务器或整个机器共享配置。
保存失败时界面重新读取磁盘策略，并保留错误提示。

## 与 PentAGI 的关系

沿用源项目的 ROCKEY ARM 数据区协议：偏移 3840、长度 256 字节。
本项目记录标记为 `REDTEAM-LOCK-V1`，包含版本、HID、PID 指纹和 SHA-256 校验；与 `PENTAGI-LOCK-V1` 不互认。
二者占用同一保留区域，不能在同一设备上同时保留两种注册记录。覆盖其他应用记录需要额外确认，销毁不会清除其他应用的记录。
SHA-256 用于一致性检查，并非厂商签名或不可伪造的挑战应答；当前实现继承源项目的本地客户端校验模式，并不为后端 HTTP API 增加授权限制。

## SDK 与 Linux 部署

现有厂商库支持 Linux ARM64（aarch64）、x86/x86_64，以及 Windows x86/x64。按程序构建架构选择库，不以其他架构的库兜底。
可执行文件位于 `bin/` 时，SDK 放在安装根目录的 `third_party/rockey/<架构>/`。

- 完整 Linux 打包脚本将 SDK 和 `scripts/70-rockey-arm.rules` 带入分发包，缺失目标 SDK 时打包失败。
- ARM64 厂商库已从用户提供的 `ROCKEY-ARM_SDK_LINUX.rar` 接入，原包为 `ARM64_Rockey-ARM_SDK_LINUX_V2.00_20260415.tar.gz`。文件保持厂商原名：`third_party/rockey/linux-aarch64/libRockeyARM.so.1.0`，不得改名为旧版 `.so.0.3`。
- CMake、客户端加载器、ARM64 专用打包和通用 Linux 打包均使用上述路径。ARM64 专用打包会先校验 ELF 架构，缺库或架构错误时停止；源码同步需包含 `third_party/rockey/`，在云笔电重新构建即可复制到程序旁。
- 此 ARM64 库依赖系统的 `libc.so.6`、`ld-linux-aarch64.so.1`，所需 GLIBC 符号版本为 2.17。当前开发机为 x86_64，已完成 ELF/接口静态核验；ARM64 动态加载及 USB 实机验收需在云笔电执行。库来源与校验值见 `third_party/rockey/linux-aarch64/README.md`。
- Linux 桌面设备权限可由部署管理员安装规则：

```sh
sudo install -m 0644 scripts/70-rockey-arm.rules /etc/udev/rules.d/70-rockey-arm.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
```

重新插拔设备后以普通桌面用户运行程序。WSL 环境还需让 USB 设备可被对应 Linux 环境访问。

## 验证

```sh
cmake -S . -B build
cmake --build build -j 4
cmake -S frontend/tests/dongle -B build/dongle-tests
cmake --build build/dongle-tests -j 4
ctest --test-dir build/dongle-tests --output-on-failure
bash -n scripts/package-linux.sh scripts/package-client-arm64.sh
```

测试依赖 Qt5 Test 和 Python 3，使用独立目录的模拟 SDK，覆盖设备身份核对、跨应用数据保护、SDK 读写错误及回读、记录篡改、策略格式、注册取消、单次注册写入、多设备销毁及保存失败保护。
窗口测试运行真实的管理员和普通用户窗口，各执行两轮断开锁屏和恢复原页面，测试配置使用临时目录，不修改真实策略或 USB 设备。
此外检查缺少 SDK 时的行为、三种 Linux SDK 的 ELF 架构，以及两个打包脚本的 ARM64 库复制和缺库/错架构保护。打包测试使用替身程序与架构探测结果，仅验证打包流程，不执行 ARM64 程序。
模拟库仅在 `build/dongle-tests/` 中生成，不进入主程序构建或分发包。
模拟测试不能替代真实设备验收。发布前需在目标操作系统和 CPU 架构上验证注册、启动校验及拔插锁屏恢复。

### 本次验证结果（2026-10-12）

- WSL Ubuntu 22.04 / x86_64：完整 Qt 客户端构建通过，8 组 CTest 测试通过，两个打包脚本语法检查通过。
- 新增回归测试先复现了管理员恢复后仍停留锁定页、销毁缺少回读、策略保存失败仍擦除设备的问题；修复后通过。
- ARM64 SDK 完成来源哈希、ELF、导出接口与依赖静态核验；本次没有执行云笔电 ARM64 实机测试。

### 云笔电实机验收

1. 合并后更新代码并在 ARM64 云笔电重新构建，确认程序旁有 `third_party/rockey/linux-aarch64/libRockeyARM.so.1.0`；只更新后端服务器无法更新客户端 SDK。
2. 将加密狗接入运行客户端的云笔电系统（如果通过远程桌面，需提供 USB 重定向）。安装上面的 udev 规则后重新插拔，在系统管理页刷新，确认可枚举设备。
3. 注册并校验成功后重启客户端，插着设备应通过启动校验；不插设备应阻止进入。此步骤会写入注册记录，遇到其他应用数据应确认是否允许覆盖。
4. 登录后分别验证管理员和普通用户窗口：拔出后锁屏，插回且系统识别后恢复原页面，连续测试两次。
5. 保持设备连接，停用策略后重启，无设备也应能进入。需要清除注册时再执行销毁，确认设备不再通过校验、绑定策略已停用。
