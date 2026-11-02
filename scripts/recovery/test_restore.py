"""Safety regressions for the standalone recovery script (no server changes)."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recovery', Path(__file__).with_name('restore-server.py'))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def test_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ['../escape', '/etc/escape']:
                with self.assertRaises(RuntimeError):
                    recovery.inside(Path(d), name)

    def test_links_and_archive_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for index, (name, link) in enumerate([('../escape', None), ('evil', '/etc'), ('evil', '../../etc')]):
                archive = root / ('bad%d.tar.gz' % index)
                with tarfile.open(archive, 'w:gz') as t:
                    m = tarfile.TarInfo(name)
                    if link:
                        m.type, m.linkname = tarfile.SYMTYPE, link
                    t.addfile(m)
                with self.assertRaises((RuntimeError, tarfile.FilterError)):
                    recovery.extract(archive, root / ('out%d' % index))

    def test_npm_relative_symlink_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / 'good.tar.gz'
            with tarfile.open(archive, 'w:gz') as t:
                link = tarfile.TarInfo('modules/.bin/tool')
                link.type, link.linkname = tarfile.SYMTYPE, '../tool/cli.js'
                t.addfile(link)
                f = tarfile.TarInfo('modules/tool/cli.js')
                f.size = 2
                t.addfile(f, io.BytesIO(b'ok'))
            recovery.extract(archive, root / 'out')
            self.assertEqual((root / 'out/modules/.bin/tool').read_bytes(), b'ok')
            self.assertTrue((root / 'out/modules/.bin/tool').is_symlink())

    def test_existing_app_rejected_before_commands(self):
        with tempfile.TemporaryDirectory() as d, \
             patch.object(recovery, 'APP', Path(d)), \
             patch.object(recovery.platform, 'system', return_value='Linux'), \
             patch.object(recovery.platform, 'machine', return_value='x86_64'), \
             patch.object(recovery.os, 'geteuid', return_value=0), \
             patch.object(recovery.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_dir='/home/aistation')), \
             patch.object(recovery, 'run') as command:
            with self.assertRaisesRegex(RuntimeError, '拒绝覆盖'):
                recovery.preflight()
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
