import json

from src.processor import parse_report


def make_report(instances):
    return {
        "site": [{
            "@name": "http://x",
            "alerts": [{
                "pluginid": "10038",
                "alert": "CSP Header Not Set",
                "riskcode": "2",
                "riskdesc": "Medium (High)",
                "cweid": "693",
                "desc": "<p>Descripcion</p><p>Segundo parrafo</p>",
                "solution": "<p>Arreglar</p>",
                "reference": "<p>http://ref</p>",
                "instances": instances,
            }],
        }]
    }


def write(tmp_path, report):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    return path


def test_dedup_ignores_query_string(tmp_path):
    report = make_report([
        {"uri": "http://x/a?id=1", "method": "GET"},
        {"uri": "http://x/a?id=2", "method": "GET"},
        {"uri": "http://x/b", "method": "GET"},
    ])
    findings, total = parse_report(write(tmp_path, report), {})
    assert total == 3
    assert len(findings) == 2


def test_method_distinguishes_findings(tmp_path):
    report = make_report([
        {"uri": "http://x/a", "method": "GET"},
        {"uri": "http://x/a", "method": "POST"},
    ])
    findings, _ = parse_report(write(tmp_path, report), {})
    assert len(findings) == 2


def test_html_stripped_and_severity_mapped(tmp_path):
    report = make_report([{"uri": "http://x/a", "method": "GET"}])
    (finding,), _ = parse_report(write(tmp_path, report), {"10038": "A05:2021 Security Misconfiguration"})
    assert "<p>" not in finding.description
    assert finding.severity == "medium"
    assert finding.confidence == "high"
    assert finding.owasp == "A05:2021 Security Misconfiguration"

def test_subtypes_of_same_plugin_are_not_merged(tmp_path):
    def alert(ref, name):
        return {
            "pluginid": "90004", "alertRef": ref, "alert": name, "riskcode": "1",
            "riskdesc": "Low (Medium)", "cweid": "693",
            "instances": [{"uri": "http://x/a", "method": "GET"}],
        }

    report = {"site": [{"@name": "http://x", "alerts": [
        alert("90004-2", "COEP Missing"),
        alert("90004-3", "COOP Missing"),
    ]}]}
    findings, _ = parse_report(write(tmp_path, report), {"90004-2": "A04:2021 Insecure Design"})
    by_ref = {f.alert_ref: f for f in findings}
    assert len(findings) == 2
    assert by_ref["90004-2"].owasp == "A04:2021 Insecure Design"
    assert by_ref["90004-3"].owasp == "Sin clasificar"

def test_empty_path_equals_root(tmp_path):
    report = make_report([
        {"uri": "http://x", "method": "GET"},
        {"uri": "http://x/", "method": "GET"},
    ])
    findings, _ = parse_report(write(tmp_path, report), {})
    assert len(findings) == 1
