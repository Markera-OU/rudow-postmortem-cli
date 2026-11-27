"""Rudow Postmortem CLI: log parsing, incident detection, Markdown output.

Everything here is original code written for this tool. It uses only the
Python standard library, makes no network calls, and reads only the log
file named on the command line.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median

VERSION = "0.1.0"
WINDOW_SECONDS = 60
# A window counts as bad when it clears all three of these.
MIN_WINDOW_REQUESTS = 3
MIN_WINDOW_ERRORS = 3
MIN_ERROR_RATE = 0.20
# A spike starting within this long after a deploy counts as correlated.
DEPLOY_CORRELATION_MINUTES = 15

# ---------------------------------------------------------------------------
# Log events
# ---------------------------------------------------------------------------

LEVELS = {"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"}
ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL"}

_ISO_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_DATE_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_SYSLOG_RE = re.compile(
    r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2}) "
    r"(\d{2}:\d{2}:\d{2})\b"
)
_MONTHS = {
    name: i + 1
    for i, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    )
}
_APACHE_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+)'
)
_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b")
_STATUS_RE = re.compile(r"\b([1-5]\d\d)\b")
_ROUTE_RE = re.compile(r"\s(/[\w\-./?=&%~+#]*)\b")
_LATENCY_RE = re.compile(r"(\d+(?:\.\d+)?)\s?ms\b")


@dataclass
class LogEvent:
    """One parsed log line."""

    raw: str
    timestamp: datetime | None = None
    level: str | None = None
    message: str = ""
    status: int | None = None
    route: str | None = None
    latency_ms: float | None = None
    parsed: bool = False

    @property
    def is_error(self) -> bool:
        if self.level in ERROR_LEVELS:
            return True
        if self.status is not None and self.status >= 500:
            return True
        return False

    @property
    def is_5xx(self) -> bool:
        return self.status is not None and 500 <= self.status <= 599

    @property
    def error_signature(self) -> str:
        """A stable group key for an error line.

        The message is lowercased and numbers, ids and hex strings are
        stripped so the same failure with different values groups together.
        """
        text = (self.message or self.raw).strip().lower()
        text = re.sub(r"0x[0-9a-f]+", "#", text)
        text = re.sub(r"\d+", "#", text)
        text = re.sub(r"\s+", " ", text)
        if self.status is not None and self.status >= 500:
            return f"{self.status} {text}"[:160]
        return text[:160] or "unknown error"


def _parse_timestamp(text: str) -> datetime | None:
    """Parse an ISO or date-time timestamp into an aware UTC datetime."""
    text = text.strip()
    candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_apache_timestamp(text: str) -> datetime | None:
    try:
        parsed = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _parse_json_line(line: str) -> LogEvent | None:
    try:
        data = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    event = LogEvent(raw=line, parsed=True)
    for key in ("timestamp", "ts", "time", "@timestamp", "datetime"):
        if data.get(key):
            event.timestamp = _parse_timestamp(str(data[key]))
            if event.timestamp is not None:
                break
    level = data.get("level") or data.get("severity") or data.get("lvl")
    if level:
        event.level = str(level).upper()
        if event.level == "WARNING":
            event.level = "WARN"
    for key in ("message", "msg", "error", "log"):
        if data.get(key):
            event.message = str(data[key])
            break
    for key in ("status", "status_code", "statusCode", "code"):
        value = data.get(key)
        if isinstance(value, int):
            event.status = value
            break
        if isinstance(value, str) and value.isdigit():
            event.status = int(value)
            break
    for key in ("route", "path", "url", "endpoint"):
        if data.get(key):
            event.route = str(data[key])
            break
    for key in ("duration_ms", "latency_ms", "response_time_ms", "elapsed_ms"):
        value = data.get(key)
        if isinstance(value, (int, float)):
            event.latency_ms = float(value)
            break
    if not event.message:
        event.message = line.strip()
    if event.level is None and event.status is not None and event.status >= 500:
        event.level = "ERROR"
    return event


def _parse_apache_line(line: str) -> LogEvent | None:
    match = _APACHE_RE.match(line)
    if not match:
        return None
    _ip, raw_ts, method, route, status, _size = match.groups()
    event = LogEvent(raw=line, parsed=True)
    event.timestamp = _parse_apache_timestamp(raw_ts)
    event.status = int(status)
    event.route = route
    event.message = f"{method} {route} {status}"
    event.level = "ERROR" if event.status >= 500 else "INFO"
    return event


def _parse_plain_line(line: str) -> LogEvent:
    """Plain text line with a timestamp, or an unparseable raw line."""
    event = LogEvent(raw=line)
    match = _ISO_RE.search(line) or _DATE_TIME_RE.search(line)
    if match:
        event.timestamp = _parse_timestamp(match.group(1))
    else:
        syslog = _SYSLOG_RE.search(line)
        if syslog:
            month, day, clock = syslog.groups()
            hour, minute, second = (int(part) for part in clock.split(":"))
            year = datetime.now(timezone.utc).year
            event.timestamp = datetime(
                year, _MONTHS[month], int(day), hour, minute, second,
                tzinfo=timezone.utc,
            )
    if event.timestamp is None:
        return event
    event.parsed = True
    level_match = _LEVEL_RE.search(line)
    if level_match:
        event.level = level_match.group(1)
        if event.level == "WARNING":
            event.level = "WARN"
    status_match = _STATUS_RE.search(line)
    if status_match:
        event.status = int(status_match.group(1))
    route_match = _ROUTE_RE.search(line)
    if route_match:
        event.route = route_match.group(1)
    latency_match = _LATENCY_RE.search(line)
    if latency_match:
        event.latency_ms = float(latency_match.group(1))
    if event.level is None:
        event.level = "ERROR" if (event.status or 0) >= 500 else "INFO"
    # Message is the line with the timestamp and level token removed.
    message = line
    if match:
        message = message.replace(match.group(1), "", 1)
    if level_match:
        message = message.replace(level_match.group(1), "", 1)
    event.message = re.sub(r"\s+", " ", message).strip(" -:[]")
    return event


def parse_line(line: str) -> LogEvent:
    """Parse one log line, auto-detecting its format."""
    stripped = line.strip()
    if not stripped:
        return LogEvent(raw=line)
    if stripped.startswith("{"):
        parsed = _parse_json_line(stripped)
        if parsed is not None:
            return parsed
    apache = _parse_apache_line(stripped)
    if apache is not None:
        return apache
    return _parse_plain_line(stripped)


@dataclass
class ParsedLog:
    events: list[LogEvent] = field(default_factory=list)
    unparseable: int = 0

    @property
    def timed_events(self) -> list[LogEvent]:
        return [event for event in self.events if event.timestamp is not None]


def parse_log(path: str) -> ParsedLog:
    """Parse a whole log file. Only this file is read."""
    parsed = ParsedLog()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            event = parse_line(line)
            parsed.events.append(event)
            if not event.parsed:
                parsed.unparseable += 1
    return parsed


def filter_by_time(
    parsed: ParsedLog,
    since: datetime | None,
    until: datetime | None,
) -> ParsedLog:
    """Keep events inside [since, until], plus untimed lines."""
    if since is None and until is None:
        return parsed
    kept = ParsedLog()
    for event in parsed.events:
        if event.timestamp is None:
            kept.events.append(event)
            continue
        if since is not None and event.timestamp < since:
            continue
        if until is not None and event.timestamp > until:
            continue
        kept.events.append(event)
    kept.unparseable = sum(1 for event in kept.events if not event.parsed)
    return kept


# ---------------------------------------------------------------------------
# Incident detection
# ---------------------------------------------------------------------------

@dataclass
class Window:
    start: datetime
    total: int = 0
    errors: int = 0
    five_xx: int = 0
    latencies: list[float] = field(default_factory=list)
    signatures: Counter = field(default_factory=Counter)

    @property
    def end(self) -> datetime:
        return self.start + timedelta(seconds=WINDOW_SECONDS)

    @property
    def error_rate(self) -> float:
        return self.errors / self.total if self.total else 0.0

    @property
    def p95_latency(self) -> float | None:
        if not self.latencies:
            return None
        ordered = sorted(self.latencies)
        index = math.ceil(0.95 * len(ordered)) - 1
        return ordered[max(0, index)]


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = math.ceil(pct * len(ordered)) - 1
    return ordered[max(0, index)]


def build_windows(events: list[LogEvent]) -> list[Window]:
    """Bucket timed events into one-minute windows."""
    buckets: dict[datetime, Window] = {}
    for event in events:
        if event.timestamp is None:
            continue
        start = event.timestamp.replace(second=0, microsecond=0)
        window = buckets.setdefault(start, Window(start=start))
        window.total += 1
        if event.is_error:
            window.errors += 1
            window.signatures[event.error_signature] += 1
        if event.is_5xx:
            window.five_xx += 1
        if event.latency_ms is not None:
            window.latencies.append(event.latency_ms)
    return [buckets[key] for key in sorted(buckets)]


@dataclass
class Incident:
    start: datetime
    end: datetime
    peak_window: Window
    windows: list[Window]
    total_requests: int
    total_errors: int
    five_xx: int
    baseline_error_rate: float
    baseline_p95: float | None
    new_signatures: list[str] = field(default_factory=list)
    first_error_at: datetime | None = None

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    @property
    def duration_minutes(self) -> float:
        return self.duration.total_seconds() / 60

    @property
    def peak_error_rate(self) -> float:
        return self.peak_window.error_rate

    @property
    def average_error_rate(self) -> float:
        if not self.total_requests:
            return 0.0
        return self.total_errors / self.total_requests

    @property
    def p95_peak(self) -> float | None:
        values = [w.p95_latency for w in self.windows if w.p95_latency is not None]
        return max(values) if values else None

    @property
    def confidence(self) -> str:
        if (
            self.peak_error_rate >= 0.5
            and self.total_errors >= 10
            and self.new_signatures
        ):
            return "High"
        if self.peak_error_rate >= 0.4 and self.total_errors >= 5:
            return "Medium"
        return "Low"


def detect_incidents(events: list[LogEvent]) -> tuple[list[Incident], dict]:
    """Detect incidents from one-minute error-rate windows.

    A window is flagged when it has enough traffic and errors and its
    error rate clearly exceeds the surrounding baseline, which is a low
    percentile of the window error rates, so a long spike cannot drag
    the baseline up with it. Flagged windows that touch or nearly touch
    are merged into one incident. New error strings and p95 latency
    rises are recorded as supporting signals. The onset of an incident
    is the first bad minute in the 15 minutes before the first flagged
    window, so a short ramp counts as part of the incident.
    """
    windows = build_windows(events)
    stats: dict = {
        "windows": len(windows),
        "baseline_error_rate": 0.0,
        "baseline_p95": None,
    }
    if not windows:
        return [], stats
    rates = [w.error_rate for w in windows if w.total >= MIN_WINDOW_REQUESTS]
    baseline_rate = _percentile(rates, 0.10) or 0.0
    all_p95 = [w.p95_latency for w in windows if w.p95_latency is not None]
    baseline_p95 = _percentile(all_p95, 0.10)
    stats["baseline_error_rate"] = baseline_rate
    stats["baseline_p95"] = baseline_p95

    threshold = max(
        MIN_ERROR_RATE, baseline_rate * 3, baseline_rate + 0.10
    )
    stats["threshold"] = threshold
    flagged = [
        w for w in windows
        if w.total >= MIN_WINDOW_REQUESTS
        and w.errors >= MIN_WINDOW_ERRORS
        and w.error_rate >= threshold
    ]
    if not flagged:
        return [], stats

    # Second pass: report baselines from the unflagged windows only,
    # so the reported "usual" figures describe normal traffic, not the
    # incident. The low-percentile first pass only decides the flags.
    flagged_starts = {w.start for w in flagged}
    quiet = [w for w in windows if w.start not in flagged_starts]
    quiet_rates = [w.error_rate for w in quiet if w.total >= MIN_WINDOW_REQUESTS]
    if quiet_rates:
        stats["baseline_error_rate"] = median(quiet_rates)
        baseline_rate = stats["baseline_error_rate"]
    quiet_p95 = [w.p95_latency for w in quiet if w.p95_latency is not None]
    if quiet_p95:
        stats["baseline_p95"] = median(quiet_p95)
        baseline_p95 = stats["baseline_p95"]

    # Merge flagged windows separated by at most one unflagged minute.
    groups: list[list[Window]] = [[flagged[0]]]
    for window in flagged[1:]:
        gap = (window.start - groups[-1][-1].start).total_seconds()
        if gap <= 2 * WINDOW_SECONDS:
            groups[-1].append(window)
        else:
            groups.append([window])

    # Signatures seen before each group, for new-error detection.
    # The reference point is the onset minute, not the first flagged
    # window, so errors that appear during a short ramp still count
    # as new when they were not seen before the incident began.
    timed_sorted = sorted(
        (e for e in events if e.timestamp is not None),
        key=lambda e: e.timestamp,
    )
    incidents: list[Incident] = []
    for group in groups:
        lookback = group[0].start - timedelta(minutes=DEPLOY_CORRELATION_MINUTES)
        onset = group[0].start
        first_error = None
        for event in timed_sorted:
            if event.timestamp is None:
                continue
            if lookback <= event.timestamp < group[-1].end and event.is_error:
                first_error = event.timestamp
                onset = min(onset, event.timestamp.replace(second=0, microsecond=0))
                break
        seen = {
            sig
            for w in windows
            if w.start < onset
            for sig in w.signatures
        }
        new_signatures = sorted(
            {
                sig
                for w in windows
                if onset <= w.start < group[-1].end
                for sig in w.signatures
                if sig not in seen
            }
        )
        peak = max(group, key=lambda w: (w.error_rate, w.errors))
        incidents.append(
            Incident(
                start=group[0].start,
                end=group[-1].end,
                peak_window=peak,
                windows=group,
                total_requests=sum(w.total for w in group),
                total_errors=sum(w.errors for w in group),
                five_xx=sum(w.five_xx for w in group),
                baseline_error_rate=baseline_rate,
                baseline_p95=baseline_p95,
                new_signatures=new_signatures,
                first_error_at=first_error,
            )
        )
    # Keep the worst incident first.
    incidents.sort(key=lambda i: (-i.peak_error_rate, -i.total_errors))
    return incidents, stats


# ---------------------------------------------------------------------------
# Deploys
# ---------------------------------------------------------------------------

@dataclass
class Deploy:
    timestamp: datetime
    label: str = ""


def parse_deploy(value: str) -> Deploy:
    """Parse --deploy values like 2026-11-27T09:38:00Z or ...#842."""
    label = ""
    raw = value
    if "#" in value:
        raw, label = value.split("#", 1)
    timestamp = _parse_timestamp(raw)
    if timestamp is None:
        raise ValueError(f"Cannot parse deploy time: {value!r}")
    return Deploy(timestamp=timestamp, label=label.strip())


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt_ts(moment: datetime | None) -> str:
    if moment is None:
        return "unknown"
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_minutes(value: float) -> str:
    if value == int(value):
        return str(int(value))
    return f"{value:.1f}"


def _fmt_pct(rate: float) -> str:
    return f"{rate * 100:.1f}%"


def _error_groups(events: list[LogEvent]) -> Counter:
    groups: Counter = Counter()
    for event in events:
        if event.is_error:
            groups[event.error_signature] += 1
    return groups


def _routes(events: list[LogEvent]) -> Counter:
    routes: Counter = Counter()
    for event in events:
        if event.is_error and event.route:
            routes[event.route] += 1
    return routes


def _fix_for_group(signature: str) -> str:
    text = signature.lower()
    if "timeout" in text or "timed out" in text:
        return "Check the upstream service health and timeout settings for this call."
    if "refused" in text or "connection" in text:
        return "Check the service is running and reachable on the expected host and port."
    if "502" in text or "503" in text or "unavailable" in text:
        return "Check the upstream or load balancer health and capacity."
    if "500" in text:
        return "Reproduce the 500 in a test environment and fix the failing code path."
    if "database" in text or "db" in text or "sql" in text:
        return "Check database connectivity, connection pool size, and slow queries."
    if "out of memory" in text or "oom" in text:
        return "Check memory usage and limits on the affected service."
    if "disk" in text or "no space" in text:
        return "Free disk space and check log rotation on the affected host."
    return "Investigate this error group and fix the root cause."


def render_postmortem(
    parsed: ParsedLog,
    incidents: list[Incident],
    deploys: list[Deploy],
    log_path: str,
    stats: dict,
) -> str:
    """Render the full Markdown post-mortem."""
    events = parsed.events
    timed = parsed.timed_events
    total_errors = sum(1 for e in events if e.is_error)
    total_5xx = sum(1 for e in events if e.is_5xx)
    groups = _error_groups(events)
    routes = _routes(events)
    lines: list[str] = []
    lines.append("# Incident post-mortem")
    lines.append("")
    lines.append(f"Source log: `{log_path}`")
    if timed:
        lines.append(
            f"Log covers {_fmt_ts(timed[0].timestamp)} to "
            f"{_fmt_ts(timed[-1].timestamp)} "
            f"({len(events)} lines, {parsed.unparseable} unparseable)."
        )
    else:
        lines.append(f"Log has {len(events)} lines, {parsed.unparseable} unparseable.")
    lines.append("")

    if not incidents:
        lines.append("## Summary")
        lines.append("")
        lines.append(
            "No incident window was found in this log. Error levels stayed "
            "close to the baseline for the whole period covered."
        )
        lines.append("")
        lines.append("## Impact")
        lines.append("")
        lines.append(f"- Total log lines: {len(events)}")
        lines.append(f"- Total errors: {total_errors}")
        lines.append(f"- Failing HTTP 5xx requests: {total_5xx}")
        lines.append(f"- Unparseable lines: {parsed.unparseable}")
        lines.append("")
        if groups:
            lines.append("Top error groups:")
            lines.append("")
            for signature, count in groups.most_common(5):
                lines.append(f"- {count}x {signature}")
            lines.append("")
        lines.append("## Timeline")
        lines.append("")
        lines.append("No incident timeline: no window crossed the error-rate threshold.")
        lines.append("")
        for deploy in sorted(deploys, key=lambda d: d.timestamp):
            label = f" ({deploy.label})" if deploy.label else ""
            lines.append(f"- {_fmt_ts(deploy.timestamp)} Deploy{label}")
        lines.append("")
        lines.append("## Detection")
        lines.append("")
        lines.append("No detection signal fired. Nothing to report here.")
        lines.append("")
        lines.append("## Probable Cause")
        lines.append("")
        lines.append("No incident, so no cause to assess.")
        lines.append("")
        lines.append("## What to fix")
        lines.append("")
        lines.append("- [ ] Nothing urgent found in this log window.")
        lines.append("")
        lines.append("## Action items")
        lines.append("")
        lines.append("- [ ] Keep the current alert thresholds under review.")
        lines.append("")
        lines.append(_footer())
        return "\n".join(lines)

    primary = incidents[0]
    incident_events = [
        e for e in timed
        if e.timestamp is not None and primary.start <= e.timestamp < primary.end
    ]
    incident_groups = _error_groups(incident_events)
    incident_routes = _routes(incident_events)
    top_group, top_count = (
        incident_groups.most_common(1)[0] if incident_groups else ("none", 0)
    )

    # Deploy correlation: nearest deploy before the incident start.
    correlated: Deploy | None = None
    for deploy in sorted(deploys, key=lambda d: d.timestamp):
        if deploy.timestamp <= primary.start:
            gap = (primary.start - deploy.timestamp).total_seconds() / 60
            if gap <= DEPLOY_CORRELATION_MINUTES:
                correlated = deploy
    deploy_gap = None
    if correlated is not None:
        deploy_gap = (primary.start - correlated.timestamp).total_seconds() / 60

    first_error = primary.first_error_at
    detection_at = primary.start
    minutes_to_detect = 0.0
    if first_error is not None:
        first_bad_minute = first_error.replace(second=0, microsecond=0)
        minutes_to_detect = (
            detection_at - first_bad_minute
        ).total_seconds() / 60

    # -- Summary ------------------------------------------------------------
    lines.append("## Summary")
    lines.append("")
    summary = (
        f"From {_fmt_ts(primary.start)} to {_fmt_ts(primary.end)} "
        f"({_fmt_minutes(primary.duration_minutes)} minutes) the service "
        f"had an error spike, peaking at {_fmt_pct(primary.peak_error_rate)} "
        f"errors in its worst minute. {primary.total_errors} errors were "
        f"logged in that window, most often '{top_group}'."
    )
    if correlated is not None:
        summary += (
            f" The spike started {_fmt_minutes(deploy_gap or 0)} minutes "
            f"after a deploy, so the deploy is a likely suspect."
        )
    if len(incidents) > 1:
        summary += f" {len(incidents)} separate incident windows were found in total."
    lines.append(summary)
    lines.append("")

    # -- Impact -------------------------------------------------------------
    lines.append("## Impact")
    lines.append("")
    lines.append(f"- Duration: {_fmt_minutes(primary.duration_minutes)} minutes "
                 f"({_fmt_ts(primary.start)} to {_fmt_ts(primary.end)})")
    lines.append(f"- Peak error rate: {_fmt_pct(primary.peak_error_rate)}")
    lines.append(f"- Average error rate during the incident: "
                 f"{_fmt_pct(primary.average_error_rate)}")
    lines.append(f"- Baseline error rate: {_fmt_pct(primary.baseline_error_rate)}")
    lines.append(f"- Total errors in the incident window: {primary.total_errors}")
    lines.append(f"- Failing HTTP 5xx requests in the window: {primary.five_xx}")
    if primary.p95_peak is not None and primary.baseline_p95 is not None:
        lines.append(
            f"- p95 latency peak: {primary.p95_peak:.0f} ms "
            f"(usual p95: {primary.baseline_p95:.0f} ms)"
        )
    elif primary.p95_peak is not None:
        lines.append(f"- p95 latency peak: {primary.p95_peak:.0f} ms")
    if incident_routes:
        lines.append("- Affected routes:")
        for route, count in incident_routes.most_common():
            lines.append(f"  - {route}: {count} errors")
    if incident_groups:
        lines.append("- Error groups:")
        for signature, count in incident_groups.most_common():
            lines.append(f"  - {count}x {signature}")
    lines.append("")

    # -- Timeline -----------------------------------------------------------
    lines.append("## Timeline")
    lines.append("")
    lines.append("| Time | Event | Source |")
    lines.append("| --- | --- | --- |")
    timeline: list[tuple[datetime, str, str]] = []
    for deploy in deploys:
        label = f"Deploy {deploy.label}" if deploy.label else "Deploy"
        timeline.append((deploy.timestamp, label, "deploy flag"))
    if first_error is not None:
        timeline.append((first_error, f"First error: {top_group}", "log"))
    timeline.append(
        (primary.peak_window.start,
         f"Peak error rate {_fmt_pct(primary.peak_error_rate)}",
         "log")
    )
    timeline.append((primary.end, "Error rate back to baseline", "log"))
    for moment, event_text, source in sorted(timeline, key=lambda row: row[0]):
        lines.append(f"| {_fmt_ts(moment)} | {event_text} | {source} |")
    lines.append("")

    # -- Detection ----------------------------------------------------------
    lines.append("## Detection")
    lines.append("")
    lines.append(
        f"- Error rate crossed the threshold of "
        f"{_fmt_pct(stats.get('threshold', 0.0))} "
        f"(baseline {_fmt_pct(primary.baseline_error_rate)}). "
        f"Confidence: {primary.confidence}."
    )
    if primary.new_signatures:
        lines.append(
            f"- New error strings appeared during the incident: "
            f"{', '.join(primary.new_signatures[:5])}."
        )
    if primary.p95_peak is not None and primary.baseline_p95:
        if primary.p95_peak > 2 * primary.baseline_p95:
            lines.append(
                f"- p95 latency rose to {primary.p95_peak:.0f} ms, "
                f"more than double the usual {primary.baseline_p95:.0f} ms."
            )
    lines.append(
        f"- Minutes from first bad minute to detection: "
        f"{_fmt_minutes(minutes_to_detect)}."
    )
    lines.append("")

    # -- Probable Cause -----------------------------------------------------
    lines.append("## Probable Cause")
    lines.append("")
    lines.append(
        "Probable, not certain. The most frequent error group was "
        f"'{top_group}' ({top_count} occurrences in the incident window)."
    )
    if correlated is not None:
        label = f" ({correlated.label})" if correlated.label else ""
        lines.append(
            f"The error spike started {_fmt_minutes(deploy_gap or 0)} minutes "
            f"after the deploy at {_fmt_ts(correlated.timestamp)}{label}, "
            f"so the deploy is the leading suspect. Check what changed in "
            f"that deploy first."
        )
    else:
        lines.append(
            "No deploy in the log window lines up with the spike, so the "
            "cause is not tied to a deploy here."
        )
    lines.append("")

    # -- What to fix --------------------------------------------------------
    lines.append("## What to fix")
    lines.append("")
    for signature, _count in incident_groups.most_common():
        lines.append(f"- [ ] {_fix_for_group(signature)} ({signature})")
    lines.append("")

    # -- Action items -------------------------------------------------------
    lines.append("## Action items")
    lines.append("")
    lines.append("- [ ] Confirm the fix and watch the error rate for one full hour after it ships.")
    lines.append("- [ ] Add a regression check that covers the top error group from this incident.")
    lines.append("- [ ] Review alert thresholds so a spike like this pages sooner next time.")
    if correlated is not None:
        lines.append("- [ ] Review the deploy checklist for the change that went out just before the spike.")
    lines.append("")
    lines.append(_footer())
    return "\n".join(lines)


def _footer() -> str:
    return (
        "---\n\n"
        "Hosted Rudow detects incidents automatically and drafts "
        "post-mortems from live logs. Learn more at https://rudow.ai"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rudow-postmortem",
        description=(
            "Generate a Markdown incident timeline and post-mortem draft "
            "from a log file. Fully offline, no account, no network."
        ),
    )
    parser.add_argument("--log", required=True, help="Path to the log file.")
    parser.add_argument(
        "--deploy", action="append", default=[],
        help="Deploy time, ISO format, optionally with a label: "
        "2026-11-27T09:38:00Z#842. Repeatable.",
    )
    parser.add_argument("--since", help="Only use log lines at or after this ISO time.")
    parser.add_argument("--until", help="Only use log lines at or before this ISO time.")
    parser.add_argument(
        "--out", help="Write the Markdown to this file. Default: print to stdout."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        deploys = [parse_deploy(value) for value in args.deploy]
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    since = _parse_timestamp(args.since) if args.since else None
    until = _parse_timestamp(args.until) if args.until else None
    if args.since and since is None:
        print(f"Error: cannot parse --since value: {args.since!r}", file=sys.stderr)
        return 2
    if args.until and until is None:
        print(f"Error: cannot parse --until value: {args.until!r}", file=sys.stderr)
        return 2

    try:
        parsed = parse_log(args.log)
    except OSError as exc:
        print(f"Error: cannot read log file: {exc}", file=sys.stderr)
        return 2

    parsed = filter_by_time(parsed, since, until)
    incidents, stats = detect_incidents(parsed.timed_events)
    output = render_postmortem(parsed, incidents, deploys, args.log, stats)

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            print(f"Error: cannot write output file: {exc}", file=sys.stderr)
            return 2
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
