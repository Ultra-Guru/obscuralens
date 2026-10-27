"""scheduled_check.py tests: fully offline, fake trackers, real state files.

The script is what GitHub Actions runs daily, so its exit codes and step
outputs are a contract. These tests pin that contract down:

- exit 0 = no changes, exit 1 = changes, exit 2 = usage error, exit 3 = every
  lookup failed;
- a failing tracker is reported as an error, never mistaken for a change;
- GITHUB_OUTPUT receives changes/change_count/error_count/status/done, and
  ``done`` is only written when the run actually finishes;
- --markdown renders a ready-to-post issue body with the real diff in it.
"""

import json
from pathlib import Path

import pytest

import scripts.scheduled_check as scheduled_check
from obscuralens.watchlist import flatten
from scripts.scheduled_check import main


class FakeTracker:
    """Tracker double returning a canned info dict per target."""

    instances = []

    def __init__(self):
        self.calls = []
        FakeTracker.instances.append(self)

    def track(self, target):
        self.calls.append(target)
        info = dict(FakeTracker.results.get(target, {}))
        return {'success': True, 'info': info}


class ExplodingTracker:
    def __init__(self):
        raise RuntimeError('upstream is down')


@pytest.fixture()
def clean_fake_tracker():
    FakeTracker.instances = []
    FakeTracker.results = {}
    FakeTracker.fail_all = False
    return FakeTracker


@pytest.fixture()
def script_env(tmp_env, monkeypatch, clean_fake_tracker):
    """Wire the script's kind detection and tracker table onto the fake."""
    monkeypatch.setattr(scheduled_check, 'detect_kind', lambda value: 'ip')
    monkeypatch.setattr(scheduled_check, 'TRACKERS', {'ip': clean_fake_tracker})

    targets = tmp_env / 'watch_targets.txt'
    targets.write_text('# watched targets\n8.8.8.8\n1.1.1.1\n', encoding='utf-8')
    return {
        'targets': str(targets),
        'state': str(tmp_env / '.watch-state.json'),
        'report': str(tmp_env / 'watch-report.json'),
        'markdown': str(tmp_env / 'watch-changes.md'),
        'tracker': clean_fake_tracker,
        'tmp_env': tmp_env,
    }


def run_script(env, extra=None, with_outputs=False):
    """Invoke main() with the standard arguments plus *extra*."""
    args = ['--targets', env['targets'], '--state', env['state'],
            '--report', env['report']]
    if extra:
        args.extend(extra)
    return main(args)


def write_state(env, fields_by_target):
    """Persist snapshots the way the script does: flatten()-encoded values."""
    payload = {target: {'kind': 'ip', 'fields': flatten({'info': fields})}
               for target, fields in fields_by_target.items()}
    Path(env['state']).write_text(json.dumps(payload), encoding='utf-8')


def read_outputs(monkeypatch, tmp_path):
    """Point GITHUB_OUTPUT at a temp file and return the parsed outputs."""
    out = tmp_path / 'outputs.txt'
    monkeypatch.setenv('GITHUB_OUTPUT', str(out))
    return out


# ---------------------------------------------------------------------------
# Exit codes and the meaning of a run
# ---------------------------------------------------------------------------

def test_first_run_is_not_a_change(script_env):
    write_state(script_env, {})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {'country': 'AU'}}
    assert run_script(script_env) == 0
    report = json.loads(Path(script_env['report']).read_text(encoding='utf-8'))
    assert report['change_count'] == 0
    assert report['results'][0]['first_run'] is True


def test_no_changes_exits_zero(script_env):
    fields = {'8.8.8.8': {'country': 'US'}, '1.1.1.1': {'country': 'AU'}}
    write_state(script_env, fields)
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {'country': 'AU'}}
    assert run_script(script_env) == 0


def test_changed_field_exits_one(script_env):
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'NL'},
                                     '1.1.1.1': {'country': 'AU'}}
    assert run_script(script_env) == 1
    report = json.loads(Path(script_env['report']).read_text(encoding='utf-8'))
    assert report['change_count'] == 1
    changed = report['changes'][0]
    assert changed['target'] == '8.8.8.8'
    assert changed['changed'] == {'country': {'from': 'US', 'to': 'NL'}}


def test_removed_and_added_fields(script_env):
    write_state(script_env, {'8.8.8.8': {'country': 'US', 'org': 'Google'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {}}
    assert run_script(script_env) == 1
    report = json.loads(Path(script_env['report']).read_text(encoding='utf-8'))
    changed = report['changes'][0]
    assert changed['removed'] == {'org': '"Google"'}  # flattened values are JSON-encoded


def test_missing_targets_file_is_usage_error(script_env):
    assert main(['--targets', 'nope.txt', '--state', script_env['state']]) == 2


def test_empty_targets_file_is_usage_error(script_env):
    Path(script_env['targets']).write_text('# nothing but comments\n',
                                           encoding='utf-8')
    assert run_script(script_env) == 2


def test_every_target_failed_is_infra_error(script_env, monkeypatch):
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    monkeypatch.setattr(scheduled_check, 'TRACKERS', {'ip': ExplodingTracker})
    assert run_script(script_env) == 3
    report = json.loads(Path(script_env['report']).read_text(encoding='utf-8'))
    assert report['error_count'] == 2
    assert report['changes'] == []
    assert report['errors'][0]['error'].startswith('RuntimeError')


def test_one_failing_target_is_not_a_change(script_env, monkeypatch):
    """A single dead source must neither fail the run nor open an issue."""
    write_state(script_env, {'8.8.8.8': {'country': 'US'},
                             '1.1.1.1': {'country': 'AU'}})

    class HalfBroken:
        def __init__(self):
            self.seen = 0

        def track(self, target):
            if target == '8.8.8.8':
                raise ConnectionError('timeout')
            self.seen += 1
            return {'success': True, 'info': {'country': 'AU'}}

    half = HalfBroken()
    monkeypatch.setattr(scheduled_check, 'TRACKERS', {'ip': lambda: half})
    assert run_script(script_env) == 0
    report = json.loads(Path(script_env['report']).read_text(encoding='utf-8'))
    assert report['error_count'] == 1
    assert report['change_count'] == 0
    # the failed target keeps its previous snapshot instead of losing state
    state = json.loads(Path(script_env['state']).read_text(encoding='utf-8'))
    assert state['8.8.8.8']['fields'] == flatten({'info': {'country': 'US'}})


# ---------------------------------------------------------------------------
# GitHub Actions step outputs
# ---------------------------------------------------------------------------

def test_outputs_report_changes(script_env, monkeypatch, tmp_path):
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'DE'},
                                     '1.1.1.1': {}}
    out = read_outputs(monkeypatch, tmp_path)
    assert run_script(script_env) == 1

    outputs = dict(line.split('=', 1) for line in
                   out.read_text(encoding='utf-8').splitlines())
    assert outputs['changes'] == 'true'
    assert outputs['change_count'] == '1'
    assert outputs['error_count'] == '0'
    assert outputs['status'] == 'changes'
    assert outputs['done'] == 'true'
    assert '8.8.8.8' in outputs['summary']


def test_outputs_report_clean_run(script_env, monkeypatch, tmp_path):
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {}}
    out = read_outputs(monkeypatch, tmp_path)
    assert run_script(script_env) == 0

    outputs = dict(line.split('=', 1) for line in
                   out.read_text(encoding='utf-8').splitlines())
    assert outputs['changes'] == 'false'
    assert outputs['status'] == 'ok'
    assert outputs['done'] == 'true'


def test_outputs_all_failed_reports_error(script_env, monkeypatch, tmp_path):
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    monkeypatch.setattr(scheduled_check, 'TRACKERS', {'ip': ExplodingTracker})
    out = read_outputs(monkeypatch, tmp_path)
    assert run_script(script_env) == 3

    outputs = dict(line.split('=', 1) for line in
                   out.read_text(encoding='utf-8').splitlines())
    assert outputs['changes'] == 'false'
    assert outputs['status'] == 'error'
    assert outputs['done'] == 'true'


def test_no_outputs_without_github_output(script_env, monkeypatch):
    monkeypatch.delenv('GITHUB_OUTPUT', raising=False)
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {}}
    assert run_script(script_env) == 0


# ---------------------------------------------------------------------------
# Markdown issue body
# ---------------------------------------------------------------------------

def test_markdown_written_only_on_changes(script_env):
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {}}
    run_script(script_env, extra=['--markdown', script_env['markdown']])
    assert not Path(script_env['markdown']).exists()

    script_env['tracker'].results = {'8.8.8.8': {'country': 'FR'},
                                     '1.1.1.1': {}}
    assert run_script(script_env, extra=['--markdown',
                                         script_env['markdown']]) == 1
    body = Path(script_env['markdown']).read_text(encoding='utf-8')
    assert '`8.8.8.8`' in body
    assert '| Field | Change | Old | New |' in body
    assert '`country`' in body
    assert 'US' in body and 'FR' in body


def test_markdown_renders_added_removed_changed_and_errors(script_env,
                                                            monkeypatch):
    write_state(script_env, {'8.8.8.8': {'country': 'US', 'org': 'Google'}})

    class Broken:
        def track(self, target):
            if target == '1.1.1.1':
                raise ValueError('boom')
            return {'success': True,
                    'info': {'country': 'US', 'asn': '15169'}}

    monkeypatch.setattr(scheduled_check, 'TRACKERS',
                        {'ip': lambda: Broken()})
    assert run_script(script_env, extra=['--markdown',
                                         script_env['markdown']]) == 1
    body = Path(script_env['markdown']).read_text(encoding='utf-8')
    assert '| added' in body or 'added |' in body
    assert '`asn`' in body          # added field
    assert '`org`' in body          # removed field
    assert 'Failed lookups' in body
    assert 'boom' in body


def test_markdown_escapes_pipe_characters(script_env):
    write_state(script_env, {'8.8.8.8': {'isp': 'old'}})
    script_env['tracker'].results = {'8.8.8.8': {'isp': 'a|b|c'},
                                     '1.1.1.1': {}}
    run_script(script_env, extra=['--markdown', script_env['markdown']])
    body = Path(script_env['markdown']).read_text(encoding='utf-8')
    # a raw pipe would break the table layout in the rendered issue
    assert 'a\\|b\\|c' in body


# ---------------------------------------------------------------------------
# Extra knobs
# ---------------------------------------------------------------------------

def test_ignore_keys_suppresses_noisy_fields(script_env):
    write_state(script_env, {'8.8.8.8': {'country': 'US', 'rank': '1'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US', 'rank': '7'},
                                     '1.1.1.1': {}}
    rc = run_script(script_env, extra=['--ignore-keys', 'rank'])
    assert rc == 0
    report = json.loads(Path(script_env['report']).read_text(encoding='utf-8'))
    assert report['change_count'] == 0
    # the ignored key is still snapshotted, just not diffed
    state = json.loads(Path(script_env['state']).read_text(encoding='utf-8'))
    assert state['8.8.8.8']['fields']['rank'] == flatten({'info': {'rank': '7'}})['rank']


def test_state_file_survives_invalid_json(script_env):
    Path(script_env['state']).write_text('{not json', encoding='utf-8')
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {}}
    assert run_script(script_env) == 0


def test_volatile_fields_cannot_trigger_changes(script_env):
    """VOLATILE_KEYS filtering happens inside flatten(); keep it that way."""
    from obscuralens.watchlist import VOLATILE_KEYS

    write_state(script_env, {'8.8.8.8': {'response_time': '120',
                                         'expires_in_days': '10'}})
    script_env['tracker'].results = {
        '8.8.8.8': {'response_time': '999', 'expires_in_days': '9',
                    'country': 'US'},
        '1.1.1.1': {}}
    assert run_script(script_env) == 0
    assert 'response_time' in VOLATILE_KEYS


def test_webhook_posted_only_on_changes(script_env, monkeypatch):
    import requests

    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append((url, json))
        return None

    monkeypatch.setattr(requests, 'post', fake_post)
    write_state(script_env, {'8.8.8.8': {'country': 'US'}})
    script_env['tracker'].results = {'8.8.8.8': {'country': 'US'},
                                     '1.1.1.1': {}}
    run_script(script_env, extra=['--webhook', 'https://hook.test/x'])
    assert calls == []

    script_env['tracker'].results = {'8.8.8.8': {'country': 'CH'},
                                     '1.1.1.1': {}}
    run_script(script_env, extra=['--webhook', 'https://hook.test/x'])
    assert len(calls) == 1
    assert calls[0][0] == 'https://hook.test/x'
    assert calls[0][1]['change_count'] == 1

