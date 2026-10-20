# Read-only source collection. This exact program runs locally or over SSH.
import os, sys, json, base64, stat
root = os.path.realpath(base64.b64decode(sys.argv[1]).decode("utf-8"))
if root == "/" or not os.path.isdir(root):
    raise ValueError("source root must be an existing project directory")
subdir = sys.argv[3] if len(sys.argv) > 3 else ""
base = root
for part in subdir.split("/") if subdir else []:
    if part in ("", ".", "..") or "\\" in part:
        raise ValueError("invalid source subdirectory")
    root = os.path.join(root, part)
    if os.path.islink(root):
        raise ValueError("symlink directory excluded")
root = os.path.realpath(root)
if os.path.commonpath([base, root]) != base or not os.path.isdir(root):
    raise ValueError("source directory outside configured root")
extensions = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
excluded = {".git", "node_modules", "vendor", "build", "dist", ".cache"}
files, skipped = [], []
compilation = None
total, visited = 0, 0
def walk_error(error):
    skipped.append({"path": os.path.relpath(error.filename, root), "reason": "directory unreadable"})
for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
    for d in dirs:
        if d not in excluded and os.path.islink(os.path.join(directory, d)):
            skipped.append({"path": os.path.relpath(os.path.join(directory, d), root), "reason": "symlink directory excluded"})
    dirs[:] = sorted(d for d in dirs if d not in excluded and not os.path.islink(os.path.join(directory, d)))
    for name in sorted(names):
        visited += 1
        if visited > 20000:
            skipped.append({"path": ".", "reason": "directory entry limit reached; traversal stopped"})
            break
        if os.path.splitext(name)[1].lower() not in extensions:
            continue
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, root).replace(os.sep, "/")
        if len(files) >= 500:
            skipped.append({"path": relative, "reason": "file count limit"})
            continue
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("not a regular file")
                # Check after opening as well, preventing a symlink-directory race.
                opened = os.path.realpath("/proc/self/fd/" + str(stream.fileno()))
                if os.path.commonpath([root, opened]) != root:
                    raise ValueError("outside source root")
                data = stream.read(512 * 1024 + 1)
            if len(data) > 512 * 1024 or total + len(data) > 8 * 1024 * 1024:
                raise ValueError("source size limit")
            text = data.decode("utf-8-sig")
            if "\0" in text:
                raise ValueError("binary source")
            files.append({"path": relative, "content": text})
            total += len(data)
        except (OSError, ValueError, UnicodeError) as error:
            skipped.append({"path": relative, "reason": str(error)})
    if visited > 20000:
        break
if len(sys.argv) > 2 and sys.argv[2]:
    try:
        relative = sys.argv[2]
        if relative.startswith('/') or any(p in ('', '.', '..') for p in relative.split('/')):
            raise ValueError('invalid compilation database path')
        path = os.path.join(root, relative)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            opened = os.path.realpath('/proc/self/fd/' + str(stream.fileno()))
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.path.commonpath([root, opened]) != root:
                raise ValueError('compilation database outside source root')
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError('compilation database size limit')
        compilation = {'content': data.decode('utf-8-sig')}
    except (OSError, ValueError, UnicodeError):
        compilation = {'error': '指定编译数据库无法读取、超限或不在项目内'}
print(json.dumps({"files": files, "skipped": skipped, "bytes": total, "compilation": compilation}, ensure_ascii=True))
