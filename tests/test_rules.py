import pytest

from src.rules import RulesConfigError, evaluate, load_rules

FINDING = {
    "severity": "medium",
    "owasp": "A05:2021 Security Misconfiguration",
    "alert_ref": "10038-1",
    "name": "CSP Header Not Set",
    "url": "http://juiceshop:3000/ftp/x.bak",
}

CONFIG = {
    "defaults": {"assignee": "appsec"},
    "rules": [
        {"name": "ftp", "match": {"url_regex": "/ftp"},
         "actions": {"severity": "critical", "labels": ["exposicion"]}},
        {"name": "a05", "match": {"owasp": ["A05"]},
         "actions": {"assignee": "plataforma", "labels": ["hardening", "exposicion"]}},
        {"name": "otra", "match": {"owasp": ["A05"]}, "actions": {"assignee": "frontend"}},
    ],
}


def test_labels_accumulate_without_duplicates():
    assert evaluate(FINDING, CONFIG).labels == ["exposicion", "hardening"]


def test_first_assignee_wins():
    assert evaluate(FINDING, CONFIG).assignee == "plataforma"


def test_default_assignee_when_no_rule_matches():
    other = {**FINDING, "url": "http://juiceshop:3000/x", "owasp": "A01:2021 Broken Access Control"}
    decision = evaluate(other, CONFIG)
    assert decision.assignee == "appsec"
    assert decision.matched_rules == []


def test_severity_escalates_but_never_lowers():
    assert evaluate(FINDING, CONFIG).severity == "critical"
    lowering = {"rules": [{"name": "baja", "match": {"severity": ["medium"]}, "actions": {"severity": "low"}}]}
    assert evaluate(FINDING, lowering).severity == "medium"


def test_unknown_condition_is_rejected(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text('rules:\n  - name: typo\n    match:\n      ulr_regex: "/x"\n    actions:\n      labels: [a]\n')
    with pytest.raises(RulesConfigError):
        load_rules(path)


def test_real_rules_file_is_valid():
    load_rules()
