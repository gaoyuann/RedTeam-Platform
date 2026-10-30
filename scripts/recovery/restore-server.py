#!/usr/bin/env python3
"""Restore 12-RedTeam-Platform; no installation unless --apply is supplied."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

APP = Path('/opt/RedTeam-Platform')
NODE = Path('/home/aistation/.nvm/versions/node/v20.18.0/bin/node')
UNIT = Path('/etc/systemd/system/redteam-backend.service')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(argv, **kwargs):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    require(result.returncode == 0, '命令失败：' + str(argv[0]) + '（输出可能含配置，未直接展示）')
    return result.stdout


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def inside(root, name):
    p = PurePosixPath(name)
    require(not p.is_absolute() and '..' not in p.parts, '归档/清单包含不安全路径')
    target = root.joinpath(*p.parts)
    require(os.path.commonpath([str(target.resolve()), str(root.resolve())]) == str(root.resolve()), '路径越出恢复目录')
    return target


def verify(backup, main=True):
    if main:
        require((backup / 'COMPLETE').is_file(), '缺少 COMPLETE')
    require(not (backup / 'INCOMPLETE').exists(), '备份尚未完成')
    require(not any(backup.rglob('*.partial')), '发现未完成的传输文件')
    manifest = backup / 'SHA256SUMS'
    require(manifest.is_file(), '缺少 SHA256SUMS')
    verified = set()
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        expected, name = line.split(None, 1)
        name = name.lstrip('*')
        require(len(expected) == 64, '校验清单格式错误')
        f = inside(backup, name)
        require(f.is_file() and digest(f) == expected, '备份校验失败：' + name)
        verified.add(name[2:] if name.startswith('./') else name)
    if main:
        for name in ['platform-worktree', 'sqlite-online-snapshots', 'node-runtime',
                     'project-runtime-config', 'project-images']:
            require('server/' + name + '.tar.gz' in verified, '必要归档未纳入校验清单：' + name)
        require('metadata/server-node-runtime.json' in verified, 'Node 元数据未纳入校验清单')
    else:
        require('install.sh' in verified, 'CScan 安装脚本未纳入清单')
    print('备份校验通过：', backup.name, len(verified), '项', flush=True)


def extract(archive, destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(hasattr(tarfile, 'data_filter'), '需要安全解压支持（推荐 Ubuntu 24.04 / Python 3.12）')
    links = []
    with tarfile.open(archive) as t:
        for member in t:
            path = inside(destination, member.name)
            if member.issym():
                # Some distro backports interpret symlink targets relative to
                # archive root instead of the link's parent. Validate explicitly
                # and install links last, so extraction never follows them.
                require(not os.path.isabs(member.linkname), '拒绝绝对符号链接')
                target = (path.parent / member.linkname).resolve()
                require(os.path.commonpath([str(target), str(destination.resolve())]) == str(destination.resolve()),
                        '符号链接越出暂存目录')
                links.append((path, member.linkname))
                continue
            t.extract(member, destination, filter='data')
    for path, target in links:
        inside(destination, str(path.relative_to(destination)))
        resolved = (path.parent / target).resolve()
        require(os.path.commonpath([str(resolved), str(destination.resolve())]) == str(destination.resolve()),
                '符号链接链越出暂存目录')
        require(not os.path.lexists(path), '符号链接与已有文件冲突')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


def preflight():
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            '只能在 x86_64 Linux 服务器恢复，不能在 .200 ARM64 存储机执行 --apply')
    require(os.geteuid() == 0, '请用 sudo bash install.sh --apply 执行恢复')
    require(hasattr(tarfile, 'data_filter'), '需要带安全解压支持的 Python')
    try:
        account = pwd.getpwnam('aistation')
    except KeyError:
        raise RuntimeError('请先创建 aistation 用户，保留 /home/aistation 路径')
    require(account.pw_dir == '/home/aistation', 'aistation 用户主目录与备份不一致')
    for path in [APP, UNIT, Path(str(UNIT) + '.d')]:
        require(not os.path.lexists(path), '目标已存在，拒绝覆盖：' + str(path))
    for name in ['redteam-backend', 'redteam-autoupdate']:
        r = subprocess.run(['systemctl', 'is-active', name], capture_output=True)
        require(r.stdout.strip() not in [b'active', b'activating', b'deactivating'], '请先核查已有服务：' + name)
    with socket.socket() as sock:
        sock.bind(('0.0.0.0', 3002))
    run(['docker', 'info'])
    run(['docker', 'compose', 'version'])
    run(['runuser', '-u', 'aistation', '--', 'docker', 'info'])
    require(shutil.disk_usage('/opt').free > 4 * 1024**3, '/opt 至少需要 4 GiB 可用空间')
    require(shutil.disk_usage('/var/tmp').free > 2 * 1024**3, '/var/tmp 至少需要 2 GiB 可用空间')
    return account


def stage_backup(backup, stage):
    for name in ['platform-worktree', 'sqlite-online-snapshots', 'node-runtime', 'project-runtime-config']:
        extract(backup / 'server' / (name + '.tar.gz'), stage / name)
    source = stage / 'platform-worktree/opt/RedTeam-Platform'
    require(source.is_dir() and not source.is_symlink(), '项目归档布局不匹配')
    snapshots = stage / 'sqlite-online-snapshots'
    require((snapshots / 'opt/RedTeam-Platform/data/redteam.db').is_file(), '缺少主库一致性副本')
    for db in snapshots.rglob('*.db'):
        relative = db.relative_to(snapshots)
        require(relative.parts[:2] == ('opt', 'RedTeam-Platform'), 'SQLite 路径不属于本项目')
        with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True) as conn:
            require(conn.execute('PRAGMA integrity_check').fetchall() == [('ok',)], '数据库完整性失败')
        target = inside(stage / 'platform-worktree', str(relative))
        target.parent.mkdir(parents=True, exist_ok=True)
        for suffix in ['-wal', '-shm']:
            sidecar = Path(str(target) + suffix)
            if sidecar.exists():
                sidecar.unlink()
        shutil.copy2(db, target)
    runtime = json.loads((backup / 'metadata/server-node-runtime.json').read_text())
    require(runtime['service_executable'] == str(NODE), 'Node 路径改变，请重新核对脚本')
    saved_node = stage / 'node-runtime' / str(NODE).lstrip('/')
    require(digest(saved_node) == runtime['sha256'], 'Node 摘要不匹配')
    saved_unit = stage / 'project-runtime-config/etc/systemd/system/redteam-backend.service'
    unit_text = saved_unit.read_text()
    for field in ['User=aistation', 'Group=aistation', 'WorkingDirectory=/opt/RedTeam-Platform/backend',
                  'EnvironmentFile=/opt/RedTeam-Platform/.env', 'ExecStart=' + str(NODE) + ' src/server.js']:
        require(field in unit_text.splitlines(), '服务单元发生变化，停止自动恢复')
    require((source / '.env').is_file(), '备份缺少后端配置')
    return source, saved_node, saved_unit, runtime


def restore(backup, with_cscan):
    account = preflight()
    cscan = backup.parent / '13-CScan-20261029'
    if with_cscan:
        require((cscan / 'install.sh').is_file(), '请一并复制同级 13-CScan-20261029 目录')
        verify(cscan, main=False)
        require(not Path('/home/aistation/apps/cscan-agent').exists(), 'CScan 已存在，请核查后省略 --with-cscan')
        names = run(['docker', 'ps', '-a', '--format', '{{.Names}}']).decode().splitlines()
        volumes = run(['docker', 'volume', 'ls', '--format', '{{.Name}}']).decode().splitlines()
        require(not any(n.startswith('cscan-') for n in names + volumes), '发现已有 CScan 容器或卷，拒绝重复恢复')
    stage = Path(tempfile.mkdtemp(prefix='redteam-restore-', dir='/var/tmp'))
    os.chmod(stage, 0o700)
    print('恢复暂存与失败排查目录：', stage, flush=True)
    source, saved_node, saved_unit, runtime = stage_backup(backup, stage)
    require(run([str(saved_node), '--version']).decode().strip() == runtime['version'], 'Node 无法在新系统运行')
    run([str(saved_node), '-e', "const D=require('better-sqlite3'); new D(':memory:').close(); require('bcrypt');"], cwd=source / 'backend')
    if os.path.lexists(NODE):
        require(NODE.is_file() and not NODE.is_symlink() and digest(NODE) == runtime['sha256'], '已有 Node 与备份不同，拒绝覆盖')
    print('暂存、数据库和运行库检查通过，开始安装。', flush=True)
    if with_cscan:
        subprocess.run(['bash', 'install.sh'], cwd=cscan, check=True)
    require(not os.path.lexists(APP) and not os.path.lexists(UNIT), '恢复期间出现目标路径冲突')
    APP.mkdir(mode=0o700)
    shutil.copytree(source, APP, dirs_exist_ok=True, symlinks=True)
    for root, dirs, files in os.walk(APP, followlinks=False):
        os.chown(root, account.pw_uid, account.pw_gid)
        for name in dirs + files:
            os.chown(Path(root) / name, account.pw_uid, account.pw_gid, follow_symlinks=False)
    os.chmod(APP / '.env', 0o600)
    if not NODE.exists():
        NODE.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(saved_node, NODE)
        os.chmod(NODE, 0o755)
    run(['docker', 'load', '--input', str(backup / 'server/project-images.tar.gz')])
    with UNIT.open('xb') as f:
        f.write(saved_unit.read_bytes())
    os.chmod(UNIT, 0o644)
    run(['systemctl', 'daemon-reload'])
    try:
        run(['systemctl', 'start', 'redteam-backend.service'])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        healthy = False
        for _ in range(30):
            try:
                with opener.open('http://127.0.0.1:3002/api/health', timeout=2) as response:
                    healthy = json.load(response).get('status') == 'ok'
                if healthy:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        require(healthy, '健康检查失败；请查看 journalctl -u redteam-backend.service')
        run(['systemctl', 'enable', 'redteam-backend.service'])
    except Exception:
        subprocess.run(['systemctl', 'stop', 'redteam-backend.service'], capture_output=True)
        raise
    print('主后端已恢复，健康检查通过，已设为开机启动。')
    print('请在云笔电验收健康接口、登录、历史报告和扫描。')
    print('CScan：' + ('已调用独立安装脚本；历史 worker 未自动恢复。' if with_cscan else '未恢复，代码扫描依赖其独立恢复结果。'))
    print('Cloudflare、SSH、自动更新及网络设置未覆盖；原配置保留在备份中。')
    print('暂存目录保留供排查；未完成真实服务器全栈恢复演练。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--apply', action='store_true', help='恢复到当前服务器；默认只校验')
    parser.add_argument('--with-cscan', action='store_true', help='调用同级13号恢复脚本（不恢复worker）')
    args = parser.parse_args()
    backup = args.backup.resolve()
    verify(backup)
    if args.apply:
        restore(backup, args.with_cscan)
    else:
        print('只完成备份校验。新服务器恢复：sudo bash install.sh --apply --with-cscan')
        print('若CScan已恢复且验收通过，省略 --with-cscan。')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('恢复停止：' + str(error), file=sys.stderr)
        print('保留已写入文件和恢复的CScan，核查后继续，勿强制覆盖。', file=sys.stderr)
        sys.exit(1)
