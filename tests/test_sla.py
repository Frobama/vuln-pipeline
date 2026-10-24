from datetime import date

import pytest

from src.sla import SlaConfigError, compute_due_date, load_sla, load_warn_days

SLA = {"info": 180, "low": 90, "medium": 30, "high": 7, "critical": 3}


def write(tmp_path, text):
    path = tmp_path / "sla.yaml"
    path.write_text(text)
    return path


def test_due_date_adds_calendar_days():
    assert compute_due_date("critical", SLA, start=date(2026, 10, 22)) == date(2026, 10, 25)
    assert compute_due_date("medium", SLA, start=date(2026, 10, 22)) == date(2026, 11, 21)


def test_due_date_crosses_year_boundary():
    assert compute_due_date("critical", SLA, start=date(2026, 12, 30)) == date(2027, 1, 2)


def test_real_sla_file_is_valid():
    assert set(load_sla()) == {"info", "low", "medium", "high", "critical"}


def test_incoherent_sla_is_rejected(tmp_path):
    path = write(tmp_path, "sla_days: {info: 180, low: 90, medium: 30, high: 7, critical: 30}\n")
    with pytest.raises(SlaConfigError):
        load_sla(path)


def test_missing_severity_is_rejected(tmp_path):
    path = write(tmp_path, "sla_days: {low: 90, medium: 30, high: 7, critical: 3}\n")
    with pytest.raises(SlaConfigError):
        load_sla(path)


def test_non_integer_days_are_rejected(tmp_path):
    path = write(tmp_path, "sla_days: {info: 180, low: 90, medium: '30', high: 7, critical: 3}\n")
    with pytest.raises(SlaConfigError):
        load_sla(path)

def test_real_warn_days_are_valid():
    assert set(load_warn_days()) == {"info", "low", "medium", "high", "critical"}


def test_warn_must_be_shorter_than_sla(tmp_path):
    path = write(tmp_path, """sla_days: {info: 180, low: 90, medium: 30, high: 7, critical: 3}
warn_before_days: {info: 30, low: 14, medium: 7, high: 7, critical: 1}
""")
    with pytest.raises(SlaConfigError):
        load_warn_days(path)
