# Codex 远程运维配置手册

这份文档给操作电脑上的 Codex 使用。操作电脑不需要变成云笔电，也不需要运行 Qt 客户端；它通过 SSH 连接服务器和云笔电，负责检查版本、更新代码、获取日志和核对部署结果。

当前示例：服务器 192.168.1.103、目录 /opt/RedTeam-Platform；云笔电 192.168.1.112、用户 user4、目录 /home/user4/RedTeam-Platform。新环境必须替换这些值。不要把密码、私钥、令牌、.env 或数据库写进仓库和脚本。

## 给另一台 Codex 的任务提示

请读取 AGENTS.md 和 docs/Codex异机配置手册.md。你运行在操作电脑上，不要把操作电脑配置成云笔电，也不要在本机启动 Qt 客户端。通过 redteam-server 和 redteam-laptop 两个 SSH 别名，只执行远程检查、代码更新和日志读取。先汇报两端 SSH、版本、服务状态和工作区状态；发现远端未提交修改、运行中任务或 SSH 未授权时先停止并报告。服务器更新后先确认健康，再让云笔电同步和本机构建。执行日志要区分：服务器数据库和后端日志是任务执行事实，云笔电日志主要是客户端、更新器和连接错误。

## 1. 操作电脑 SSH 配置

在操作电脑的 ~/.ssh/config 配置两个别名。管理员把操作电脑公钥加入两台设备各自账号的 authorized_keys，并核对主机指纹。

    Host redteam-server
        HostName <SERVER_HOST>
        User <SERVER_SSH_USER>
        IdentityFile ~/.ssh/redteam_ops_ed25519
        IdentitiesOnly yes
        BatchMode yes
        ConnectTimeout 10
        StrictHostKeyChecking yes

    Host redteam-laptop
        HostName <LAPTOP_HOST>
        User <LAPTOP_USER>
        IdentityFile ~/.ssh/redteam_ops_ed25519
        IdentitiesOnly yes
        BatchMode yes
        ConnectTimeout 10
        StrictHostKeyChecking yes

连通性检查：

    ssh redteam-server 'hostname; git -C /opt/RedTeam-Platform rev-parse --short HEAD'
    ssh redteam-laptop 'hostname; git -C /home/user4/RedTeam-Platform rev-parse --short HEAD'
    ssh redteam-server 'curl -fsS http://127.0.0.1:3002/api/health'

## 2. 更新前只读盘点

    ssh redteam-server 'git -C /opt/RedTeam-Platform status --short; git -C /opt/RedTeam-Platform branch --show-current; sudo systemctl is-active redteam-backend.service redteam-autoupdate.service'
    ssh redteam-laptop 'git -C /home/user4/RedTeam-Platform status --short; git -C /home/user4/RedTeam-Platform branch --show-current; systemctl --user is-active redteam-autoupdate.service redteam-client.service || true'

服务器更新器会在运行中任务、未提交 tracked 文件、非快进更新或路径冲突时拒绝部署。不得使用 git reset --hard、git clean 或删除数据库绕过保护。

## 3. 更新服务器代码

开发机先提交并推送远程 main，服务器自动更新器负责拉取、预检查、备份、迁移、健康检查和失败回滚。先确认远程提交和实际更新器：

    ssh redteam-server 'git -C /opt/RedTeam-Platform fetch --no-tags origin main; git -C /opt/RedTeam-Platform rev-parse HEAD; git -C /opt/RedTeam-Platform rev-parse origin/main'
    ssh redteam-server 'sudo systemctl cat redteam-autoupdate.service'

只有在明确授权且 ExecStart 指向仓库脚本时，才执行一次检查：

    ssh redteam-server 'cd /opt/RedTeam-Platform && ROLE=server PROJECT_DIR=/opt/RedTeam-Platform BRANCH=main bash scripts/auto-update-platform.sh --once'

若服务调用 /usr/local/lib/redteam/auto-update-platform.sh，不要用操作电脑的未提交脚本覆盖它，应按服务器安装方式审核更新。更新后核对：

    ssh redteam-server 'sudo systemctl is-active redteam-backend.service; curl -fsS http://127.0.0.1:3002/api/health; git -C /opt/RedTeam-Platform rev-parse HEAD'

## 4. 更新云笔电代码

首选让云笔电已有 auto-update-client.sh 通过 REDTEAM_SYNC_SOURCE 从服务器同步前端源码，在云笔电本机 ARM64 构建并切换客户端。操作电脑只观察：

    ssh redteam-laptop 'systemctl --user status redteam-autoupdate.service redteam-client.service --no-pager'
    ssh redteam-laptop 'tail -n 100 /home/user4/RedTeam-Platform/update.log'
    ssh redteam-laptop 'git -C /home/user4/RedTeam-Platform rev-parse HEAD; cat /home/user4/RedTeam-Platform/.client-update/deployed 2>/dev/null || true; sha256sum /home/user4/RedTeam-Platform/build/frontend/RedTeam-Platform'

明确授权时才手动触发：

    ssh redteam-laptop 'cd /home/user4/RedTeam-Platform && UPDATE_ONCE=1 bash scripts/auto-update-client.sh'
    ssh redteam-laptop 'cd /home/user4/RedTeam-Platform && bash scripts/update-client.sh'

不要在操作电脑上编译后把 x86 二进制复制到 ARM64 云笔电；用户正在操作时不要强制杀掉前端进程。

## 5. 获取云笔电日志

云笔电更新器日志是 /home/user4/RedTeam-Platform/update.log；用户级日志来自 redteam-autoupdate.service 和 redteam-client.service。实际任务执行事实主要在服务器后端、SQLite 和服务器 systemd 日志中。

    mkdir -p /tmp/redteam-remote-logs
    ssh redteam-laptop 'tail -n 500 /home/user4/RedTeam-Platform/update.log' > /tmp/redteam-remote-logs/laptop-update.log
    ssh redteam-laptop 'journalctl --user -u redteam-autoupdate.service -n 500 --no-pager' > /tmp/redteam-remote-logs/laptop-autoupdate.log
    ssh redteam-laptop 'journalctl --user -u redteam-client.service -n 500 --no-pager' > /tmp/redteam-remote-logs/laptop-client.log
    scp redteam-laptop:/home/user4/RedTeam-Platform/update.log /tmp/redteam-remote-logs/laptop-update-full.log

实时跟踪：

    ssh redteam-laptop 'tail -F /home/user4/RedTeam-Platform/update.log'

## 6. 获取服务器实际执行日志

    ssh redteam-server 'sudo journalctl -u redteam-backend.service -n 500 --no-pager'
    ssh redteam-server 'sudo journalctl -u redteam-backend.service --since "1 hour ago" --no-pager'
    ssh redteam-server 'sudo journalctl -u redteam-autoupdate.service -n 200 --no-pager'

需要任务记录时，通过平台 API 或只读 SQLite 副本查询，不要在生产库写入。可在服务器执行只读备份后用 scp 带回；不要把完整生产数据库复制到共享位置。

## 7. 停止条件

标准顺序：提交并推送代码；服务器只读盘点；服务器更新和健康检查；云笔电自动同步或本机编译；采集云笔电日志和服务器执行日志；核对版本与服务状态。

遇到远端未提交修改、活动扫描或攻击、SSH 指纹变化、健康检查失败、云笔电正在操作或日志含未脱敏凭据时停止。采集后对账号、令牌、Cookie、内网凭据和靶场响应脱敏。

这份手册描述的是操作电脑远程管理两端，不会把操作电脑变成云笔电，也不会自动发布操作电脑的未提交代码。
