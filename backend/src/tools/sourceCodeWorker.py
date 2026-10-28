"""Fixed container protocol. Never imported or executed in the backend process."""
import json
import os
import re
import shutil
import resource
import subprocess
import sys
import tempfile

LIMIT = 32768
TOOL_PATH = "/usr/local/bin:/usr/bin:/bin"


def limits(file_limit):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))


def execute(command, data, timeout, directory, file_limit=1024 * 1024):
    env = {"PATH": TOOL_PATH, "HOME": directory, "LANG": "C.UTF-8",
           "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1", "UBSAN_OPTIONS": "halt_on_error=1"}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                   cwd=directory, env=env, preexec_fn=lambda: limits(file_limit))
        timed_out = False
        try:
            process.communicate(data.encode("utf-8"), timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.communicate()
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(LIMIT + 1), err.read(LIMIT + 1)
        return {"started": True, "exit_code": process.returncode, "timed_out": timed_out,
                "truncated": len(stdout) > LIMIT or len(stderr) > LIMIT,
                "stdout": stdout[:LIMIT].decode("utf-8", errors="replace"),
                "stderr": stderr[:LIMIT].decode("utf-8", errors="replace")}


def main():
    raw = sys.stdin.buffer.read(262145)
    if len(raw) > 262144:
        raise ValueError("artifact too large")
    value = json.loads(raw)
    files, execution, phase = value["files"], value["execution"], value["phase"]
    if value["mode"] != "local_simulation" or phase not in ("baseline", "probe") or not 1 <= len(files) <= 4:
        raise ValueError("unsupported execution")
    with tempfile.TemporaryDirectory(prefix="rt-code-") as directory:
        names = set()
        for file in files:
            name = file["filename"]
            if not re.fullmatch(r"[\w-]+\.(py|c|cpp|h|hpp)", name, re.ASCII) or name in names:
                raise ValueError("invalid filename")
            names.add(name)
            with open(os.path.join(directory, name), "x", encoding="utf-8") as handle:
                handle.write(file["source"])
        entry, language = execution["entrypoint"], execution["language"]
        if entry not in names or language not in ("python", "c", "cpp"):
            raise ValueError("invalid entrypoint")
        diagnostics = execution.get("diagnostics", "none" if language == "python" else "asan_ubsan")
        if diagnostics not in ("none", "asan_ubsan") or language == "python" and diagnostics != "none":
            raise ValueError("unsupported diagnostics")
        compilation = {"ok": True, "exit_code": 0, "stdout": "", "stderr": "", "timed_out": False, "truncated": False}
        if language != "python":
            # No model-provided flags, shell, packages or linker commands.
            sources = sorted(name for name in names if name.endswith(".c" if language == "c" else ".cpp"))
            binary = "gcc" if language == "c" else "g++"
            compiler = shutil.which(binary, path=TOOL_PATH)
            if not compiler:
                compilation.update(ok=False, exit_code=127, stderr="现有工具镜像缺少 " + binary + "，本次未运行验证程序；不会安装依赖或更换镜像")
            else:
                flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if diagnostics == "asan_ubsan" else []
                compilation = execute([compiler, "-O0", "-g", *flags, *sources, "-o", "./repro"], "", 25, directory, 16 * 1024 * 1024)
                compilation["ok"] = compilation["exit_code"] == 0 and not compilation["timed_out"] and not compilation["truncated"]
        compilation["diagnostics"] = diagnostics
        run = {"started": False, "exit_code": -1, "stdout": "", "stderr": "", "timed_out": False, "truncated": False}
        if compilation["ok"]:
            command = ["python3", "-I", "-B", "./" + entry] if language == "python" else ["./repro"]
            case = execution[phase]
            run = execute(command + case["args"], case["stdin"], 10, directory)
        result = {"format": "local-code-observation-v1", "mode": "local_simulation",
                  "artifact_id": value["artifact_id"], "artifact_hash": value["artifact_hash"], "phase": phase,
                  "language": language, "entrypoint": entry, "compile": compilation, "run": run,
                  "complete": compilation["ok"] and run["started"] and not run["timed_out"] and not run["truncated"]}
        print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
