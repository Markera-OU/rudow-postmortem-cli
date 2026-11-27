# rudow-postmortem

A free, standalone, offline CLI that turns a log file into a Markdown
incident timeline and post-mortem draft.

It is the free sibling of [Rudow](https://rudow.ai), the hosted AI SRE
product that detects incidents from live logs, alerts in Slack, and
auto-drafts post-mortems. This tool does the same shape of work on a
single log file on your own machine. No account, no cloud, no network.

## Install

Python 3.9 or newer. Standard library only, zero dependencies.

```bash
pipx install rudow-postmortem
```

Or with pip:

```bash
pip install rudow-postmortem
```

Or run it without installing, straight from a checkout:

```bash
python3 -m rudow_postmortem --log examples/app.log --deploy 2026-11-27T09:38:00Z#842
```

## Usage

```bash
rudow-postmortem --log app.log --deploy 2026-11-27T09:38:00Z [--deploy ...] [--since ...] [--until ...] [--out postmortem.md]
```

| Flag | What it does |
| --- | --- |
| `--log app.log` | Path to the log file. Required. |
| `--deploy 2026-11-27T09:38:00Z` | A deploy time, ISO format. Repeat the flag for more deploys. A label can follow a `#`, for example `--deploy 2026-11-27T09:38:00Z#842`. |
| `--since 2026-11-27T09:00:00Z` | Only use log lines at or after this time. |
| `--until 2026-11-27T10:00:00Z` | Only use log lines at or before this time. |
| `--out postmortem.md` | Write the Markdown to this file. Without it, the report prints to stdout. |

### Try it in one command

The repo ships with a fixture log that has a baked-in incident: normal
traffic, a deploy, an error spike starting minutes after the deploy,
then recovery.

```bash
rudow-postmortem --log examples/app.log --deploy 2026-11-27T09:38:00Z#842 --out postmortem.md
```

## What it understands

Log formats are auto-detected per line:

- **JSON lines** with `level`, `message`, `timestamp`, `status`, `route`, and latency fields where present.
- **Plain text** with timestamps (ISO, `YYYY-MM-DD HH:MM:SS`, and common syslog style).
- **Apache / Nginx combined format** access logs.

Lines it cannot parse are counted and kept as raw text. They do not
break the run.

## How incidents are found

The tool buckets log lines into one-minute windows and compares each
window's error rate against the surrounding baseline, which is a low
percentile of the window error rates, so a long spike cannot drag the
baseline up with it. A window is flagged when it has enough traffic
and errors and its error rate clearly exceeds that baseline. Flagged
windows that touch or nearly touch merge into one incident.

It also records new error strings that first appear during the
incident and p95 latency rises where latency is parseable. Both are
supporting signals, not incidents on their own.

The detection is deterministic: the same log always gives the same
report.

## Sample output

From the fixture log (`examples/app.log`, deploy `2026-11-27T09:38:00Z#842`):

```markdown
# Incident post-mortem

Source log: `examples/app.log`
Log covers 2026-11-27T09:00:00Z to 2026-11-27T10:05:24Z (396 lines, 0 unparseable).

## Summary

From 2026-11-27T09:41:00Z to 2026-11-27T09:53:00Z (12 minutes) the service had an error spike, peaking at 80.0% errors in its worst minute. 96 errors were logged in that window, most often '502 upstream timeout calling checkout service'. The spike started 3 minutes after a deploy, so the deploy is a likely suspect.

## Impact

- Duration: 12 minutes (2026-11-27T09:41:00Z to 2026-11-27T09:53:00Z)
- Peak error rate: 80.0%
- Average error rate during the incident: 80.0%
- Baseline error rate: 0.0%
- Total errors in the incident window: 96
- Failing HTTP 5xx requests in the window: 96
- p95 latency peak: 2350 ms (usual p95: 110 ms)
- Affected routes:
  - /api/checkout: 72 errors
  - /api/orders: 24 errors
- Error groups:
  - 72x 502 upstream timeout calling checkout service
  - 24x 503 service unavailable

## Timeline

| Time | Event | Source |
| --- | --- | --- |
| 2026-11-27T09:38:00Z | Deploy 842 | deploy flag |
| 2026-11-27T09:40:00Z | First error: 502 upstream timeout calling checkout service | log |
| 2026-11-27T09:41:00Z | Peak error rate 80.0% | log |
| 2026-11-27T09:53:00Z | Error rate back to baseline | log |

## Detection

- Error rate crossed the threshold of 20.0% (baseline 0.0%). Confidence: High.
- New error strings appeared during the incident: 502 upstream timeout calling checkout service, 503 service unavailable.
- p95 latency rose to 2350 ms, more than double the usual 110 ms.
- Minutes from first bad minute to detection: 1.

## Probable Cause

Probable, not certain. The most frequent error group was '502 upstream timeout calling checkout service' (72 occurrences in the incident window).
The error spike started 3 minutes after the deploy at 2026-11-27T09:38:00Z (842), so the deploy is the leading suspect. Check what changed in that deploy first.

## What to fix

- [ ] Check the upstream service health and timeout settings for this call. (502 upstream timeout calling checkout service)
- [ ] Check the upstream or load balancer health and capacity. (503 service unavailable)

## Action items

- [ ] Confirm the fix and watch the error rate for one full hour after it ships.
- [ ] Add a regression check that covers the top error group from this incident.
- [ ] Review alert thresholds so a spike like this pages sooner next time.
- [ ] Review the deploy checklist for the change that went out just before the spike.

---

Hosted Rudow detects incidents automatically and drafts post-mortems from live logs. Learn more at https://rudow.ai
```

If no incident window is found, the tool says so plainly and still
reports what the log shows: volume, error count, and top errors. It
never invents an incident.

## Privacy

Fully offline. The tool makes no network calls and reads only the log
file you name on the command line. Nothing leaves your machine. No
account, no telemetry, no log data sent anywhere.

## Going further with Rudow

This CLI looks backwards at one log file after the fact. Hosted Rudow
watches your live logs, detects incidents automatically as they
happen, alerts your team in Slack, and drafts the post-mortem for you.
Learn more at [rudow.ai](https://rudow.ai).

## Development

```bash
python3 -m unittest discover -s tests
```

## License

MIT. See [LICENSE](LICENSE).
