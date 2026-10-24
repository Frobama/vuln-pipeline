from datetime import date

import pytest

from src import sla_monitor
from src.sla_monitor import classify

WARN = {"info": 30, "low": 14, "medium": 7, "high": 2, "critical": 1}
TODAY = date(2026, 10, 23)


def issue(due, labels=("vulnpipe", "severity-medium"), category="indeterminate"):
    return {"id": "1", "key": "SCRUM-1", "fields": {
        "summary": "x", "duedate": due, "labels": list(labels),
        "status": {"statusCategory": {"key": category}}, "assignee": None}}


def test_overdue():
    alert = classify(issue("2026-10-20"), TODAY, WARN)
    assert alert.kind == "overdue" and alert.days == 3


def test_due_today_is_still_due_soon_not_overdue():
    alert = classify(issue("2026-10-23"), TODAY, WARN)
    assert alert.kind == "due_soon" and alert.days == 0


def test_outside_warning_window_is_ignored():
    assert classify(issue("2026-11-22"), TODAY, WARN) is None


def test_done_tickets_are_ignored():
    assert classify(issue("2026-10-01", category="done"), TODAY, WARN) is None


def test_ticket_without_due_date_is_ignored():
    assert classify(issue(None), TODAY, WARN) is None


def test_warning_window_depends_on_severity():
    due = "2026-10-26"  # faltan 3 días
    assert classify(issue(due, labels=("vulnpipe", "severity-medium")), TODAY, WARN) is not None
    assert classify(issue(due, labels=("vulnpipe", "severity-critical")), TODAY, WARN) is None


def test_escalated_label_is_not_mistaken_for_a_severity():
    labels = ("vulnpipe", "severity-escalated", "severity-critical")
    assert classify(issue("2026-10-26", labels), TODAY, WARN) is None  # crítica avisa a 1 día, no a 3


def test_notification_state_comes_from_labels():
    warned_then_late = classify(issue("2026-10-20", ("vulnpipe", "severity-medium", "sla-por-vencer")), TODAY, WARN)
    assert warned_then_late.kind == "overdue" and not warned_then_late.already_notified
    breached = classify(issue("2026-10-20", ("vulnpipe", "severity-medium", "sla-vencido")), TODAY, WARN)
    assert breached.already_notified
    warned = classify(issue("2026-10-25", ("vulnpipe", "severity-medium", "sla-por-vencer")), TODAY, WARN)
    assert warned.kind == "due_soon" and warned.already_notified


def test_webhook_error_does_not_leak_url(monkeypatch):
    class Rejected:
        ok = False
        status_code = 400

    monkeypatch.setattr(sla_monitor.requests, "post", lambda *a, **k: Rejected())
    with pytest.raises(RuntimeError) as exc:
        sla_monitor.send_webhook("https://hooks.slack.com/services/T000/B000/SECRETTOKEN", "hola")
    assert "SECRETTOKEN" not in str(exc.value)


def test_webhook_payload_key_depends_on_provider(monkeypatch):
    sent = {}

    class Accepted:
        ok = True
        status_code = 204

    def fake_post(url, json, timeout):
        sent.clear()
        sent.update(json)
        return Accepted()

    monkeypatch.setattr(sla_monitor.requests, "post", fake_post)
    sla_monitor.send_webhook("https://discord.com/api/webhooks/1/abc", "hola")
    assert sent == {"content": "hola"}
    sla_monitor.send_webhook("https://hooks.slack.com/services/T/B/x", "hola")
    assert sent == {"text": "hola"}
