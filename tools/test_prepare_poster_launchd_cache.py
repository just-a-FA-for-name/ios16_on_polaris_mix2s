import copy
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from prepare_poster_launchd_cache import JOB_LIMIT, main, prepare


JOB_PATH = '/Library/LaunchDaemons/com.polaris.poster-maintenance.plist'
JOB = {
    'Label': 'com.polaris.poster-maintenance',
    'ProgramArguments': ['/usr/libexec/polaris-poster-maintenance', '--register-gradient-once'],
    'UserName': 'root',
    'RunAtLoad': True,
    'LaunchOnlyOnce': True,
    'ProcessType': 'Background',
}


def encode(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)


def fixture():
    return {
        'VersionNumber': 7,
        'LaunchDaemons': {'/System/example.plist': {
            'Label': 'test.example', '_PanicOnCrash': True, 'ProgramArguments': ['/example']}},
        'AppExtensions': {'/test.appex': {'_infoPlist': {'CFBundleIdentifier': 'test.extension'}}},
        'SystemLibraryTreeState': b'opaque tree state',
        'AppRemovalServices': {'test.removal': {'preserve': True}},
        'Symlinks': {'test': '/original'},
    }


class PosterLaunchdCacheTests(unittest.TestCase):
    def test_only_exact_job_is_added_and_other_data_is_unchanged(self):
        before = fixture()
        source = encode(before)
        patched, report = prepare(source, plistlib.dumps(JOB))
        after = plistlib.loads(patched)
        self.assertEqual(after['LaunchDaemons'].pop(JOB_PATH), JOB)
        self.assertEqual(after, before)
        self.assertEqual(source, encode(before))
        self.assertTrue(report['changed'])
        self.assertEqual((report['jobs_before'], report['jobs_after']), (1, 2))

    def test_existing_exact_job_is_byte_identical(self):
        before = fixture()
        before['LaunchDaemons'][JOB_PATH] = JOB
        source = encode(before)
        patched, report = prepare(source, plistlib.dumps(JOB))
        self.assertEqual(patched, source)
        self.assertFalse(report['changed'])

    def test_different_existing_job_is_not_overwritten(self):
        before = fixture()
        before['LaunchDaemons'][JOB_PATH] = {'Label': 'test.other'}
        with self.assertRaises(ValueError):
            prepare(encode(before), plistlib.dumps(JOB))

    def test_duplicate_label_at_another_path_is_rejected(self):
        before = fixture()
        before['LaunchDaemons']['/different.plist'] = JOB
        with self.assertRaises(ValueError):
            prepare(encode(before), plistlib.dumps(JOB))

    def test_job_cannot_add_arguments_services_privileges_or_restart(self):
        changes = (
            ('ProgramArguments', ['/bin/other']),
            ('UserName', 'mobile'),
            ('KeepAlive', True),
            ('MachServices', {'test': True}),
            ('EnvironmentVariables', {'INJECTION': 'value'}),
            ('RunAtLoad', False),
            ('RunAtLoad', 1),
        )
        for key, value in changes:
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(JOB)
                bad[key] = value
                with self.assertRaises(ValueError):
                    prepare(encode(fixture()), plistlib.dumps(bad))

    def test_malformed_and_wrong_schema_are_rejected(self):
        malformed = (
            b'bplist00',
            plistlib.dumps(fixture()),
            encode([]),
            encode({'LaunchDaemons': {}}),
            encode(dict(fixture(), LaunchDaemons=[])),
            encode(dict(fixture(), LaunchDaemons={'test': []})),
            encode(dict(fixture(), AppExtensions=[])),
        )
        for source in malformed:
            with self.subTest(source=source[:12]):
                with self.assertRaises(ValueError):
                    prepare(source, plistlib.dumps(JOB))

    def test_cli_preserves_original_and_refuses_existing_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, job, output = root / 'cache.plist', root / 'job.plist', root / 'prepared'
            data = encode(fixture())
            source.write_bytes(data)
            job.write_bytes(plistlib.dumps(JOB))
            args = ['prepare', str(source), str(job), str(output)]
            with patch('sys.argv', args), patch('builtins.print'):
                main()
                self.assertEqual(source.read_bytes(), data)
                self.assertEqual((output / 'original-launchd.plist').read_bytes(), data)
                before = {p.name: p.read_bytes() for p in output.iterdir()}
                with self.assertRaises(FileExistsError):
                    main()
                self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, before)

    def test_unsupported_or_wrongly_typed_cache_versions_are_rejected(self):
        for version in (0, 1, 6, 8, True, 7.0, '7'):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    prepare(encode(dict(fixture(), VersionNumber=version)), plistlib.dumps(JOB))

    def test_oversized_job_fails_before_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, job, output = root / 'cache.plist', root / 'job.plist', root / 'prepared'
            source.write_bytes(encode(fixture()))
            job.write_bytes(b'x' * (JOB_LIMIT + 1))
            with patch('sys.argv', ['prepare', str(source), str(job), str(output)]):
                with self.assertRaises(ValueError):
                    main()
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
