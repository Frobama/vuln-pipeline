from src.ticketer import build_description, build_labels, build_summary, owasp_label

FINDING = {
    "fingerprint": "abc123def456", "severity": "medium", "confidence": "high",
    "owasp": "A05:2021 Security Misconfiguration", "url": "http://juiceshop:3000/ftp/",
    "method": "GET", "param": "", "cwe_id": "693", "name": "CSP Header Not Set",
    "description": "Texto\n\nOtro párrafo", "solution": "Arreglar", "evidence": "",
    "reference": "http://ref",
}


def test_owasp_label():
    assert owasp_label("A05:2021 Security Misconfiguration") == "owasp-a05"
    assert owasp_label("Sin clasificar") == "owasp-sin-clasificar"


def test_labels_have_no_spaces_and_carry_fingerprint():
    labels = build_labels(FINDING)
    assert "fp-abc123def456" in labels
    assert all(" " not in label for label in labels)


def test_summary_has_path_and_respects_limit():
    assert build_summary(FINDING) == "[MEDIUM] CSP Header Not Set - /ftp/"
    assert len(build_summary({**FINDING, "name": "x" * 400})) <= 255


def test_description_is_valid_adf_without_empty_text_nodes():
    doc = build_description(FINDING)
    assert doc["type"] == "doc" and doc["version"] == 1

    def walk(node):
        if node.get("type") == "text":
            assert node["text"] != ""
        for child in node.get("content", []):
            walk(child)

    walk(doc)
