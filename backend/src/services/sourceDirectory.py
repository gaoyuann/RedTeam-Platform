import os, sys, json
root = os.path.realpath(sys.argv[1])
relative = sys.argv[2]
parts = relative.split("/") if relative else []
if root == "/" or any(p in ("", ".", "..") for p in parts):
    raise ValueError("invalid directory")
current = root
for part in parts:
    current = os.path.join(current, part)
    if os.path.islink(current):
        raise ValueError("symlink directory excluded")
directory = os.path.realpath(current)
if os.path.commonpath([root, directory]) != root or not os.path.isdir(directory):
    raise ValueError("directory outside configured root")
entries = []
truncated = False
with os.scandir(directory) as iterator:
    for entry in iterator:
        if entry.is_dir(follow_symlinks=False):
            if any(ord(c) < 32 for c in entry.name) or "\\" in entry.name:
                continue
            if len(entries) >= 500:
                truncated = True
                break
            entries.append({"name": entry.name, "directory": True,
                            "path": "/".join(parts + [entry.name])})
entries.sort(key=lambda item: item["name"])
print(json.dumps({"path": relative, "display_path": directory,
                  "parent": "/".join(parts[:-1]) if parts else None,
                  "entries": entries, "truncated": truncated}))
