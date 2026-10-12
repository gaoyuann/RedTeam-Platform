"""Check ARM64 SDK packaging paths/preflight; does not execute ARM64 binaries."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
SDK = Path("third_party/rockey/linux-aarch64/libRockeyARM.so.1.0")


class PackagingTests(unittest.TestCase):
    def test_arm64_sdk_bundling_and_preflight(self):
        for script, bundle in (
            ("package-client-arm64.sh", "RedTeam-Platform-Client-ARM64"),
            ("package-linux.sh", "RedTeam-Platform"),
        ):
            for case in ("valid", "missing", "wrong-architecture"):
                with self.subTest(script=script, case=case), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    for path in ("scripts", "cmake", "build/frontend", "backend/src", "stubs", str(SDK.parent)):
                        (root / path).mkdir(parents=True, exist_ok=True)
                    for name in (script, "70-rockey-arm.rules", "start.sh", "start-client.sh"):
                        shutil.copy2(REPO / "scripts" / name, root / "scripts" / name)
                    shutil.copy2(REPO / "cmake/ValidateRockeySdk.cmake", root / "cmake")
                    (root / "backend/package.json").write_text("{}")
                    # Placeholder is only copied, never run; host/Qt discovery is controlled.
                    binary = root / "build/frontend/RedTeam-Platform"
                    binary.write_text("#!/bin/sh\nexit 0\n")
                    binary.chmod(0o755)
                    for name, body in {"uname": "echo aarch64", "qmake": "echo /nonexistent-dongle-test", "ldd": "exit 0", "ldconfig": "exit 0", "strip": "exit 0"}.items():
                        stub = root / "stubs" / name
                        stub.write_text("#!/bin/sh\n" + body + "\n")
                        stub.chmod(0o755)
                    if case != "missing":
                        source = REPO / (SDK if case == "valid" else Path("third_party/rockey/linux-x86_64/libRockeyARM.so.0.3"))
                        shutil.copy2(source, root / SDK)
                    destination = root / "dist" / bundle
                    destination.mkdir(parents=True)
                    sentinel = destination / "existing-bundle"
                    sentinel.write_text("preserve on preflight failure")
                    env = dict(os.environ, PATH=str(root / "stubs") + os.pathsep + os.environ["PATH"])
                    result = subprocess.run(["bash", str(root / "scripts" / script)], env=env, capture_output=True, text=True, timeout=30)
                    if case == "valid":
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual((destination / SDK).read_bytes(), (REPO / SDK).read_bytes())
                        self.assertEqual((destination / "scripts/70-rockey-arm.rules").read_bytes(), (REPO / "scripts/70-rockey-arm.rules").read_bytes())
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertTrue(sentinel.exists(), "Preflight must not remove the existing bundle")
                        self.assertIn("Missing ROCKEY SDK" if case == "missing" else "not a linux-aarch64 ELF", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
