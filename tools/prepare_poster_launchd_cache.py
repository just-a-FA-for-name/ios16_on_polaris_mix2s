import argparse
import copy
import hashlib
import json
from pathlib import Path
import plistlib

JOB_PATH = '/Library/LaunchDaemons/com.polaris.poster-maintenance.plist'
JOB = {
    'Label': 'com.polaris.poster-maintenance',
    'ProgramArguments': ['/usr/libexec/polaris-poster-maintenance', '--register-gradient-once'],
    'UserName': 'root',
    'RunAtLoad': True,
    'LaunchOnlyOnce': True,
    'ProcessType': 'Background',
}
CACHE_LIMIT = 8 * 1024 * 1024
JOB_LIMIT = 4096


def canonical(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True)


def decode(data, limit, binary=False):
    if not isinstance(data, bytes) or not data or len(data) > limit:
        raise ValueError('Invalid plist input size')
    if binary and not data.startswith(b'bplist00'):
        raise ValueError('Expected a binary launchd cache')
    try:
        return plistlib.loads(data)
    except (ValueError, TypeError, OverflowError, IndexError):
        raise ValueError('Malformed plist input') from None


def prepare(source, job_source):
    cache = decode(source, CACHE_LIMIT, binary=True)
    job = decode(job_source, JOB_LIMIT)
    if not isinstance(job, dict) or canonical(job) != canonical(JOB):
        raise ValueError('Only the exact scoped maintenance job is permitted')
    if not isinstance(cache, dict) or not {
            'VersionNumber', 'LaunchDaemons', 'AppExtensions'}.issubset(cache):
        raise ValueError('Unsupported launchd cache schema')
    if type(cache['VersionNumber']) is not int or cache['VersionNumber'] != 7:
        raise ValueError('Only the verified version 7 launchd cache is supported')
    jobs = cache['LaunchDaemons']
    if not isinstance(jobs, dict) or not isinstance(cache['AppExtensions'], dict):
        raise ValueError('Unsupported daemon or extension table')
    if any(not isinstance(path, str) or not isinstance(value, dict)
           for path, value in jobs.items()):
        raise ValueError('Malformed existing daemon table')
    matching = [path for path, value in jobs.items() if value.get('Label') == JOB['Label']]
    if any(path != JOB_PATH for path in matching):
        raise ValueError('Maintenance label already exists at another path')
    changed = JOB_PATH not in jobs
    if not changed and canonical(jobs[JOB_PATH]) != canonical(JOB):
        raise ValueError('Existing maintenance path has different contents')
    patched = source
    if changed:
        updated = copy.deepcopy(cache)
        updated['LaunchDaemons'][JOB_PATH] = job
        patched = canonical(updated)
        checked = plistlib.loads(patched)
        if canonical(checked['LaunchDaemons'].pop(JOB_PATH)) != canonical(JOB):
            raise ValueError('New job did not survive serialization')
        if canonical(checked) != canonical(cache):
            raise ValueError('Unrelated cache contents changed')
    if len(patched) > CACHE_LIMIT:
        raise ValueError('Prepared cache exceeds size limit')
    return patched, {
        'format_version': 1,
        'changed': changed,
        'job_path': JOB_PATH,
        'jobs_before': len(jobs),
        'jobs_after': len(jobs) + int(changed),
        'extensions_preserved': len(cache['AppExtensions']),
        'original_sha256': hashlib.sha256(source).hexdigest(),
        'prepared_sha256': hashlib.sha256(patched).hexdigest(),
        'job_sha256': hashlib.sha256(job_source).hexdigest(),
        'original_bytes': len(source),
        'prepared_bytes': len(patched),
        'deployment': 'OFFLINE ONLY; replacing the live cache requires separate approval',
    }


def read_bounded(path, limit):
    with path.open('rb') as file:
        return file.read(limit + 1)


def main():
    parser = argparse.ArgumentParser(description='Prepare one scoped launchd cache entry without device access')
    parser.add_argument('cache', type=Path)
    parser.add_argument('job', type=Path)
    parser.add_argument('output_directory', type=Path)
    args = parser.parse_args()
    source = read_bounded(args.cache, CACHE_LIMIT)
    patched, report = prepare(source, read_bounded(args.job, JOB_LIMIT))
    args.output_directory.mkdir()
    for name, data in (
        ('original-launchd.plist', source),
        ('launchd-with-poster-maintenance.plist', patched),
        ('manifest.json', json.dumps(report, indent=2).encode('utf-8')),
    ):
        with (args.output_directory / name).open('xb') as file:
            file.write(data)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
