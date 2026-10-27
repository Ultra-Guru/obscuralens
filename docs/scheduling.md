# Scheduled monitoring

`scripts/scheduled_check.py` looks up a list of targets, compares each result
against a JSON snapshot, and reports what changed (new ports, subdomains,
breaches, DNS records, username status, …). It is designed to be driven by any
scheduler and returns:

| exit code | meaning |
|---|---|
| `0` | no changes |
| `1` | changes detected |
| `2` | usage/config error |
| `3` | infrastructure error — every lookup failed, nothing was checked |

A single failing target does **not** fail the run: it is recorded in the
report's `errors` list (and its previous snapshot is kept), so one dead source
can never masquerade as a watchlist change.

```powershell
python scripts/scheduled_check.py `
  --targets watch_targets.txt `
  --state .watch-state.json `
  --report watch-report.json
```

Add `--webhook https://...` to POST the JSON report when something changes,
`--markdown watch-changes.md` to write a ready-to-post GitHub issue body for
the detected changes, and `--ignore-keys rank,ttl` to hide known-noisy fields
from the diff (on both sides, so an ignored key never reports as removed).

## Windows Task Scheduler

```powershell
$action  = New-ScheduledTaskAction -Execute "python" `
  -Argument "scripts/scheduled_check.py --targets watch_targets.txt --state .watch-state.json" `
  -WorkingDirectory "D:\ObscuraLens"
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName "ObscuraLens watch" -Action $action -Trigger $trigger
```

## cron (Linux/macOS)

```cron
0 6 * * * cd /opt/ObscuraLens && /usr/bin/python3 scripts/scheduled_check.py --targets watch_targets.txt --state .watch-state.json >> /var/log/obscuralens-watch.log 2>&1
```

## systemd timer

`/etc/systemd/system/obscuralens-watch.service`:

```ini
[Unit]
Description=ObscuraLens watchlist check

[Service]
Type=oneshot
WorkingDirectory=/opt/ObscuraLens
ExecStart=/usr/bin/python3 scripts/scheduled_check.py --targets watch_targets.txt --state .watch-state.json
```

`/etc/systemd/system/obscuralens-watch.timer`:

```ini
[Unit]
Description=Run the ObscuraLens watchlist check daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Then `systemctl enable --now obscuralens-watch.timer`.

## GitHub Actions

`.github/workflows/watch.yml` runs the same script daily (and on demand from
the Actions tab), caches the state file between runs, uploads the report as an
artifact and opens an issue when a change is detected. Edit `watch_targets.txt`
to choose what is monitored.

The issue is driven by the script's machine-readable step outputs, **not** by
its exit code: a non-zero exit alone never opens an issue (a failed lookup is
an infrastructure signal, not a watchlist change). When real changes are
detected the workflow closes the previous open `watchlist` issue and opens a
fresh one whose body is the rendered Markdown diff, so the tracker holds at
most one open report at a time. A systematically broken check (every lookup
failed, or the script crashed) turns the run red instead — visible in the
Actions tab and by email — and a couple of flaky lookups only emit a workflow
warning. Overlapping runs (cron plus a manual dispatch) are serialized by a
`concurrency` group so the same change cannot be reported twice.
