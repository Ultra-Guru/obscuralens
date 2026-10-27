#!/usr/bin/env python3
"""
Scheduled watchlist check for cron, Task Scheduler or GitHub Actions.

Reads targets from a file, looks each one up, compares the flatten()-ed result
against a JSON state file and reports what changed. Snapshot state persists in
the state file between runs (which is what makes diffing work off a workstation).

Usage:
    python scripts/scheduled_check.py --targets watch_targets.txt \
        --state .watch-state.json --report watch-report.json \
        [--markdown watch-changes.md] [--webhook https://example/hook] \
        [--ignore-keys last_seen,ttl]

Exit codes are deliberately unambiguous so automation can act on the *meaning*
of a run, not just "something went non-zero":

    0  no changes detected
    1  changes detected
    2  usage / configuration error (bad arguments, missing or empty targets)
    3  infrastructure error - every target failed, nothing was checked

A single failing target does not fail the run (exit 3): it is recorded in the
report as an ``errors`` entry and counted in ``error_count`` so the workflow can
surface it without pretending a lookup failure is a watchlist change.

GitHub Actions integration: when the ``GITHUB_OUTPUT`` environment variable is
set (a path), the script also appends machine-readable step outputs -

    done=<true|false>         set to true only when the run finished cleanly
    changes=<true|false>      whether real changes were detected
    change_count=<int>        number of changed targets
    error_count=<int>         number of targets that could not be checked
    summary=<one line>        human-readable result line

``done`` is written last of all, so a crash mid-run leaves it unset and callers
can tell "ran and reported" apart from "did not finish". ``--markdown`` renders
the same diff as a ready-to-post GitHub issue body.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from obscuralens.investigate import detect_kind  # noqa: E402
from obscuralens.trackers import (  # noqa: E402
    DomainTracker,
    EmailTracker,
    IPTracker,
    PhoneTracker,
    UsernameTracker,
)
from obscuralens.watchlist import diff_snapshots, flatten  # noqa: E402

TRACKERS = {
    'ip': IPTracker,
    'phone': PhoneTracker,
    'username': UsernameTracker,
    'email': EmailTracker,
    'domain': DomainTracker,
}

#: How much of a field value is rendered into the Markdown report.
_VALUE_PREVIEW = 160


def read_targets(path: str):
    """Read one target per line; blank lines and # comments are ignored."""
    targets = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        value = line.split('#', 1)[0].strip()
        if value:
            targets.append(value)
    return targets


def _github_output(key: str, value) -> None:
    """Append ``key=value`` to the $GITHUB_OUTPUT file when it is defined."""
    path = os.environ.get('GITHUB_OUTPUT')
    if not path:
        return
    try:
        with open(path, 'a', encoding='utf-8') as handle:
            handle.write(f'{key}={value}\n')
    except OSError as exc:  # never let telemetry break the check itself
        print(f'warning: could not write {key!r} to GITHUB_OUTPUT: {exc}',
              file=sys.stderr)


def _decode(value: str):
    """Best-effort JSON decode of a flattened field value for display."""
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _preview(value) -> str:
    """Render a field value as a short, single-line Markdown-safe preview."""
    decoded = _decode(value)
    text = decoded if isinstance(decoded, str) else json.dumps(
        decoded, sort_keys=True, default=str)
    # a raw pipe or newline would break the Markdown table layout
    text = text.replace('|', '\\|').replace('\r', ' ').replace('\n', ' ')
    if len(text) > _VALUE_PREVIEW:
        text = text[:_VALUE_PREVIEW] + '…'
    return text


def render_markdown(report: dict) -> str:
    """
    Render a watch report as a ready-to-post GitHub issue body.

    Only changed targets are rendered; the surrounding text explains what a
    change means here so a reader never has to leave the issue to understand
    the alert.
    """
    lines = [
        'The scheduled ObscuraLens watchlist check detected changes to a '
        'watched target.',
        '',
        f'- **Changed targets:** {report.get("change_count", 0)}',
        f'- **Lookups failed:** {report.get("error_count", 0)} '
        '(excluded from the diff below)',
        f'- **Generated:** {report.get("generated_at", "unknown")} (UTC)',
        '',
    ]

    for entry in report.get('changes', []):
        added = entry.get('added') or {}
        removed = entry.get('removed') or {}
        changed = entry.get('changed') or {}
        lines.append(f'### `{entry.get("target", "?")}` '
                     f'({entry.get("kind", "?")})')
        lines.append('')
        lines.append(f'+{len(added)} new · -{len(removed)} gone · '
                     f'~{len(changed)} changed')
        lines.append('')
        rows = []
        for key, value in added.items():
            rows.append((key, 'added', '', _preview(value)))
        for key, value in removed.items():
            rows.append((key, 'removed', _preview(value), ''))
        for key, pair in changed.items():
            if isinstance(pair, dict):
                old, new = pair.get('from'), pair.get('to')
            elif isinstance(pair, (list, tuple)) and len(pair) == 2:
                old, new = pair[0], pair[1]
            else:  # tolerate any shape the differ produces
                old, new = pair, pair
            rows.append((key, 'changed', _preview(old), _preview(new)))
        if rows:
            lines.append('| Field | Change | Old | New |')
            lines.append('| --- | --- | --- | --- |')
            for key, kind, old, new in rows:
                lines.append(f'| `{key}` | {kind} | {old} | {new} |')
        else:
            lines.append('_No field-level detail recorded._')
        lines.append('')

    errors = report.get('errors') or []
    if errors:
        lines.append('### Failed lookups (no diff computed)')
        lines.append('')
        for err in errors:
            lines.append(f'- `{err.get("target", "?")}`: '
                         f'{err.get("error", "unknown error")}')
        lines.append('')

    lines.append('---')
    lines.append('')
    lines.append('A field moving between values is reported as *changed*; '
                 'volatile fields (timestamps, TTLs, response times) are '
                 'excluded before diffing. Tune `VOLATILE_KEYS` in '
                 '`obscuralens/watchlist.py` or pass `--ignore-keys` if a '
                 'noisy field keeps appearing here.')
    lines.append('The full machine-readable report is attached to this '
                 'workflow run as the `watch-report` artifact.')
    lines.append('')
    return '\n'.join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Scheduled watchlist check')
    parser.add_argument('--targets', required=True,
                        help='file with one target per line (# comments allowed)')
    parser.add_argument('--state', default='.watch-state.json',
                        help='JSON snapshot file (default: .watch-state.json)')
    parser.add_argument('--report', help='write the JSON report to this file')
    parser.add_argument('--markdown',
                        help='write a ready-to-post GitHub issue body to this '
                             'file (only written when changes are detected)')
    parser.add_argument('--webhook', help='POST the report to this URL on changes')
    parser.add_argument('--ignore-keys', default='',
                        help='comma-separated field names to exclude from the '
                             'diff in addition to VOLATILE_KEYS (tune down '
                             'noise from chatty sources)')
    args = parser.parse_args(argv)

    targets_path = Path(args.targets)
    if not targets_path.exists():
        print(f"targets file not found: {targets_path}", file=sys.stderr)
        return 2
    targets = read_targets(args.targets)
    if not targets:
        print('no targets found in file', file=sys.stderr)
        return 2

    ignore_keys = {name.strip() for name in args.ignore_keys.split(',')
                   if name.strip()}

    state_path = Path(args.state)
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding='utf-8'))
        except ValueError:
            print('state file is not valid JSON; starting fresh', file=sys.stderr)

    new_state = dict(state)
    results = []
    changes = []
    errors = []

    for target in targets:
        kind = detect_kind(target)
        if kind is None:
            print(f"skip: cannot determine target type for {target!r}",
                  file=sys.stderr)
            continue
        try:
            result = TRACKERS[kind]().track(target)
        except Exception as e:  # one bad target must not stop the run
            message = f"{type(e).__name__}: {e}"
            print(f"error: {target}: {message}", file=sys.stderr)
            errors.append({'target': target, 'kind': kind, 'error': message})
            continue

        # --ignore-keys hides a noisy field from the diff on BOTH sides (a
        # key present in the stored snapshot but filtered from the fresh one
        # would otherwise always report as removed). The snapshot itself
        # keeps every field so nothing is lost for future runs.
        stored = flatten(result)
        old = {key: value for key, value
               in (state.get(target) or {}).get('fields', {}).items()
               if key not in ignore_keys}
        fields = ({key: value for key, value in stored.items()
                   if key not in ignore_keys} if ignore_keys else stored)
        first_run = not old
        added, removed, changed = (
            ({}, {}, {}) if first_run else diff_snapshots(old, fields))
        new_state[target] = {'kind': kind, 'fields': stored}

        entry = {
            'target': target,
            'kind': kind,
            'first_run': first_run,
            'success': bool(result.get('success', True)),
            'added': added,
            'removed': removed,
            'changed': changed,
        }
        results.append(entry)
        if not first_run and (added or removed or changed):
            changes.append(entry)
            print(f"[changed] {target} (+{len(added)} -{len(removed)} "
                  f"~{len(changed)})", file=sys.stderr)
        else:
            print(f"[ok] {target}"
                  + (" (first run)" if first_run else ""), file=sys.stderr)

    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(new_state, indent=2, sort_keys=True),
                          encoding='utf-8')

    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'targets': targets,
        'change_count': len(changes),
        'error_count': len(errors),
        'changes': changes,
        'errors': errors,
        'results': results,
    }
    if args.report:
        Path(args.report).write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding='utf-8')
    if args.markdown and changes:
        Path(args.markdown).write_text(render_markdown(report),
                                       encoding='utf-8')

    if changes and args.webhook:
        try:
            import requests
            requests.post(args.webhook, json=report, timeout=30)
        except Exception as e:
            print(f"webhook failed: {type(e).__name__}: {e}", file=sys.stderr)

    # Every target failed: nothing was actually checked, so "no changes" would
    # be a lie. Report an infrastructure error instead.
    checked = len(results)
    exit_code = 1 if changes else 0
    if not checked and targets:
        print('error: every target failed; nothing was checked',
              file=sys.stderr)
        exit_code = 3

    _github_output('changes', 'true' if changes else 'false')
    _github_output('change_count', len(changes))
    _github_output('error_count', len(errors))
    _github_output('status',
                   'changes' if changes else ('error' if exit_code == 3 else 'ok'))
    if changes:
        summary = ', '.join(
            f"{entry['target']} (+{len(entry['added'])} "
            f"-{len(entry['removed'])} ~{len(entry['changed'])})"
            for entry in changes)
    elif checked:
        summary = f'no changes across {checked} target(s)'
    else:
        summary = 'all lookups failed'
    _github_output('summary', summary.replace('\n', ' '))
    _github_output('done', 'true')

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
