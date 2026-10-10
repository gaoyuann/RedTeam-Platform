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
4. 启用策略时必须能校验通过已绑定的设备。运行时拔出设备会锁屏，重新插入后最多约 5 秒恢复。
5. 在设备仍连接、界面可访问时可关闭校验策略，设备记录会保留。
6. 销毁只清除选中设备的本平台注册区域。销毁当前绑定设备会同时停用策略；销毁其他设备不会清除当前绑定。

策略使用 `QStandardPaths::AppConfigLocation/dongle.json`，通常为
`~/.config/RedTeam/RedTeam-Platform/dongle.json`。它属于当前操作系统用户，而非服务器或整个机器共享配置。
保存失败时界面重新读取磁盘策略，并保留错误提示。

## 与 PentAGI 的关系

沿用源项目的 ROCKEY ARM 数据区协议：偏移 3840、长度 256 字节。
本项目记录标记为 `REDTEAM-LOCK-V1`，包含版本、HID、PID 指纹和 SHA-256 校验；与 `PENTAGI-LOCK-V1` 不互认。
二者占用同一保留区域，不能在同一设备上同时保留两种注册记录。覆盖其他应用记录需要额外确认，销毁不会清除其他应用的记录。
SHA-256 用于一致性检查，并非厂商签名或不可伪造的挑战应答；当前实现继承源项目的本地客户端校验模式，并不为后端 HTTP API 增加授权限制。

## SDK 与 Linux 部署

现有厂商库支持 Linux x86/x86_64、Windows x86/x64。按程序构建架构选择库，不以其他架构的库兜底。
可执行文件位于 `bin/` 时，SDK 放在安装根目录的 `third_party/rockey/<架构>/`。

- 完整 Linux 打包脚本将 SDK 和 `scripts/70-rockey-arm.rules` 带入分发包，缺失目标 SDK 时打包失败。
- ARM64 客户端脚本仅在存在 `third_party/rockey/linux-aarch64/libRockeyARM.so.0.3` 时复制该库，否则明确警告加密锁校验不可用。仓库当前没有该库，需向厂商获取对应架构 SDK。
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

测试依赖 Qt5 Test，使用独立目录的模拟 SDK，覆盖设备身份核对、跨应用数据保护、SDK 错误传播、策略格式、拔插复核、单次注册写入、多设备销毁及保存失败提示。
模拟库仅在 `build/dongle-tests/` 中生成，不进入主程序构建或分发包。
模拟测试不能替代真实设备验收。发布前需在目标操作系统和 CPU 架构上验证注册、启动校验及拔插锁屏恢复。
