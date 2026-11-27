"""Tests for the Rudow Postmortem CLI: parser, detection, rendering."""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rudow_postmortem.cli import (
    build_windows,
    detect_incidents,
    filter_by_time,
    parse_deploy,
    parse_line,
    parse_log,
    render_postmortem,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "app.log")


def _ts(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _json_event(minute, level="INFO", status=200, route="/api/orders",
                message="GET /api/orders 200", latency=50):
    import json
    return parse_line(json.dumps({
        "timestamp": f"2026-11-27T09:{minute:02d}:00Z",
        "level": level, "message": message, "status": status,
        "route": route, "duration_ms": latency,
    }))


class ParserTests(unittest.TestCase):
    def test_json_line(self):
        event = _json_event(5, level="ERROR", status=502,
                            route="/api/checkout",
                            message="upstream timeout", latency=900)
        self.assertTrue(event.parsed)
        self.assertEqual(event.timestamp, _ts("2026-11-27T09:05:00Z"))
        self.assertEqual(event.level, "ERROR")
        self.assertEqual(event.status, 502)
        self.assertEqual(event.route, "/api/checkout")
        self.assertEqual(event.latency_ms, 900)
        self.assertTrue(event.is_error)
        self.assertTrue(event.is_5xx)

    def test_plain_text_iso(self):
        event = parse_line(
            "2026-11-27 09:10:00 ERROR something failed on /api/orders 500")
        self.assertTrue(event.parsed)
        self.assertEqual(event.timestamp, _ts("2026-11-27T09:10:00Z"))
        self.assertEqual(event.level, "ERROR")
        self.assertEqual(event.status, 500)
        self.assertTrue(event.is_error)

    def test_apache_combined(self):
        event = parse_line(
            '127.0.0.1 - - [27/Nov/2026:09:10:00 +0000] '
            '"GET /api/checkout HTTP/1.1" 503 1234')
        self.assertTrue(event.parsed)
        self.assertEqual(event.timestamp, _ts("2026-11-27T09:10:00Z"))
        self.assertEqual(event.status, 503)
        self.assertEqual(event.route, "/api/checkout")
        self.assertTrue(event.is_error)

    def test_unparseable_line_counted_and_kept(self):
        event = parse_line("some garbage with no timestamp at all")
        self.assertFalse(event.parsed)
        self.assertIsNone(event.timestamp)
        self.assertEqual(event.raw, "some garbage with no timestamp at all")

    def test_error_groups_normalise_numbers(self):
        first = _json_event(5, level="ERROR", status=500,
                            message="timeout after 1234 ms for order 987")
        second = _json_event(6, level="ERROR", status=500,
                             message="timeout after 567 ms for order 12")
        self.assertEqual(first.error_signature, second.error_signature)

    def test_deploy_with_label(self):
        deploy = parse_deploy("2026-11-27T09:38:00Z#842")
        self.assertEqual(deploy.timestamp, _ts("2026-11-27T09:38:00Z"))
        self.assertEqual(deploy.label, "842")

    def test_deploy_without_label(self):
        deploy = parse_deploy("2026-11-27T09:38:00Z")
        self.assertEqual(deploy.label, "")

    def test_deploy_bad_value(self):
        with self.assertRaises(ValueError):
            parse_deploy("not-a-time")


class DetectionTests(unittest.TestCase):
    def _events(self):
        # 10 quiet minutes, then 3 bad minutes (8 of 10 errors), then quiet.
        events = []
        for minute in range(0, 10):
            for i in range(10):
                events.append(_json_event(minute, latency=60))
        for minute in range(10, 13):
            for i in range(10):
                if i < 8:
                    events.append(_json_event(
                        minute, level="ERROR", status=502,
                        route="/api/checkout",
                        message="upstream timeout calling checkout service",
                        latency=1200))
                else:
                    events.append(_json_event(minute, latency=60))
        for minute in range(13, 16):
            for i in range(10):
                events.append(_json_event(minute, latency=60))
        return events

    def test_spike_detected(self):
        incidents, stats = detect_incidents(self._events())
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident.start, _ts("2026-11-27T09:10:00Z"))
        self.assertEqual(incident.end, _ts("2026-11-27T09:13:00Z"))
        self.assertAlmostEqual(incident.peak_error_rate, 0.8)
        self.assertAlmostEqual(incident.average_error_rate, 0.8)
        self.assertEqual(incident.total_errors, 24)
        self.assertEqual(incident.total_requests, 30)
        self.assertEqual(incident.five_xx, 24)
        self.assertAlmostEqual(incident.baseline_error_rate, 0.0)

    def test_new_error_signature_recorded(self):
        incidents, _ = detect_incidents(self._events())
        self.assertTrue(any("timeout" in sig for sig in incidents[0].new_signatures))

    def test_p95_rise_recorded(self):
        incidents, stats = detect_incidents(self._events())
        self.assertEqual(incidents[0].p95_peak, 1200)
        self.assertEqual(stats["baseline_p95"], 60)

    def test_no_incident_on_clean_log(self):
        events = [_json_event(m) for m in range(10) for _ in range(10)]
        incidents, _ = detect_incidents(events)
        self.assertEqual(incidents, [])

    def test_single_bad_line_is_not_an_incident(self):
        events = [_json_event(m) for m in range(10) for _ in range(10)]
        events.append(_json_event(3, level="ERROR", status=500,
                                  message="one off failure"))
        incidents, _ = detect_incidents(events)
        self.assertEqual(incidents, [])

    def test_windows_bucket_by_minute(self):
        windows = build_windows(self._events())
        self.assertEqual(len(windows), 16)
        self.assertEqual(windows[10].errors, 8)
        self.assertEqual(windows[10].total, 10)


class RenderingTests(unittest.TestCase):
    def test_fixture_renders_all_sections_with_correct_numbers(self):
        parsed = parse_log(FIXTURE)
        incidents, stats = detect_incidents(parsed.timed_events)
        deploy = parse_deploy("2026-11-27T09:38:00Z#842")
        output = render_postmortem(parsed, incidents, [deploy], "examples/app.log", stats)
        for section in ("Summary", "Impact", "Timeline", "Detection",
                        "Probable Cause", "What to fix", "Action items"):
            self.assertIn(f"## {section}", output)
        # Fixture facts: 12 minute incident, 96 errors, 80% peak, 96 x 5xx.
        self.assertIn("12 minutes", output)
        self.assertIn("96 errors", output)
        self.assertIn("80.0%", output)
        self.assertIn("96", output)
        self.assertIn("3 minutes after a deploy", output)
        self.assertIn("p95 latency peak: 2350 ms (usual p95: 110 ms)", output)
        self.assertIn("rudow.ai", output)
        # No em dashes anywhere in the output.
        self.assertNotIn("\u2014", output)

    def test_no_incident_output_says_so_plainly(self):
        events = [_json_event(m) for m in range(10) for _ in range(10)]
        from rudow_postmortem.cli import ParsedLog
        parsed = ParsedLog(events=events)
        incidents, stats = detect_incidents(parsed.timed_events)
        output = render_postmortem(parsed, incidents, [], "clean.log", stats)
        self.assertIn("No incident window was found", output)
        self.assertIn("## Summary", output)
        self.assertIn("## Action items", output)

    def test_since_until_filter(self):
        # Range must include some normal minutes, or there is no baseline
        # for the detector to compare the spike against.
        parsed = parse_log(FIXTURE)
        since = _ts("2026-11-27T09:38:00Z")
        until = _ts("2026-11-27T09:52:59Z")
        kept = filter_by_time(parsed, since, until)
        self.assertEqual(len(kept.events), 141)
        incidents, _ = detect_incidents(kept.timed_events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].total_errors, 96)


if __name__ == "__main__":
    unittest.main()
