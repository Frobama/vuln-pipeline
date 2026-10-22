"""Lee el reporte JSON de ZAP, normaliza, deduplica y clasifica los hallazgos."""
import argparse
import hashlib
import html
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT = ROOT / "reports" / "zap-report.json"
DEFAULT_OUTPUT = ROOT / "reports" / "findings.json"
OWASP_MAP_PATH = ROOT / "config" / "owasp_map.yaml"

UNMAPPED = "Sin clasificar"
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
# ZAP solo emite 0-3; "critical" queda reservado para reglas de escalamiento (Fase 4)
SEVERITY_BY_RISKCODE = {"0": "info", "1": "low", "2": "medium", "3": "high"}

TAG_RE = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    plugin_id: str
    alert_ref: str
    name: str
    severity: str
    confidence: str
    cwe_id: str
    owasp: str
    url: str
    method: str
    param: str
    evidence: str
    description: str
    solution: str
    reference: str


def clean_html(text: str) -> str:
    """ZAP entrega desc/solution/reference con etiquetas <p>; Jira necesita texto plano."""
    text = re.sub(r"</p>\s*<p>", "\n\n", text or "")
    return html.unescape(TAG_RE.sub("", text)).strip()


def normalize_url(uri: str) -> str:
    """Descarta query string y fragmento, y trata la ruta vacía como '/'."""
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def make_fingerprint(alert_ref: str, method: str, url: str, param: str) -> str:
    raw = "|".join([alert_ref, method.upper(), url, param])
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def parse_confidence(riskdesc: str) -> str:
    """'Medium (High)' -> 'high' (el paréntesis es la confianza de ZAP)."""
    match = re.search(r"\(([^)]+)\)\s*$", riskdesc or "")
    return match.group(1).lower() if match else "unknown"


def load_owasp_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return {str(key): value for key, value in data.items()}


def parse_report(report_path: Path, owasp_map: dict[str, str]) -> tuple[list[Finding], int]:
    """Devuelve (hallazgos únicos, total de instancias leídas del reporte)."""
    data = json.loads(report_path.read_text())
    findings: dict[str, Finding] = {}
    total_instances = 0

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            plugin_id = str(alert.get("pluginid", ""))
            alert_ref = str(alert.get("alertRef") or plugin_id)
            riskdesc = alert.get("riskdesc", "")
            severity = SEVERITY_BY_RISKCODE.get(str(alert.get("riskcode")), "info")

            for inst in alert.get("instances", []):
                total_instances += 1
                url = normalize_url(inst.get("uri", ""))
                method = inst.get("method", "GET")
                param = inst.get("param", "")
                fingerprint = make_fingerprint(alert_ref, method, url, param)
                if fingerprint in findings:
                    continue  # duplicado
                findings[fingerprint] = Finding(
                    fingerprint=fingerprint,
                    plugin_id=plugin_id,
		    alert_ref=alert_ref,
                    name=alert.get("alert", alert.get("name", "")),
                    severity=severity,
                    confidence=parse_confidence(riskdesc),
                    cwe_id=str(alert.get("cweid", "")),
                    owasp=owasp_map.get(alert_ref) or owasp_map.get(plugin_id, UNMAPPED),
                    url=url,
                    method=method,
                    param=param,
                    evidence=inst.get("evidence", ""),
                    description=clean_html(alert.get("desc", "")),
                    solution=clean_html(alert.get("solution", "")),
                    reference=clean_html(alert.get("reference", "")),
                )
    return list(findings.values()), total_instances


def print_summary(findings: list[Finding], total_instances: int, min_severity: str) -> None:
    print(f"Instancias leídas del reporte: {total_instances}")
    print(f"Hallazgos tras deduplicar y filtrar (>= {min_severity}): {len(findings)}")
    by_severity = Counter(f.severity for f in findings)
    for severity in reversed(SEVERITY_ORDER):
        if by_severity[severity]:
            print(f"  {severity:<9} {by_severity[severity]}")

    unmapped = sorted({(f.alert_ref, f.name, f.cwe_id) for f in findings if f.owasp == UNMAPPED})
    if unmapped:
        print("\nSin categoría OWASP (agrégalas a config/owasp_map.yaml):")
        for alert_ref, name, cwe in unmapped:
            print(f"  alertRef={alert_ref}  CWE-{cwe}  {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Procesa un reporte JSON de ZAP")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="low")
    args = parser.parse_args()

    owasp_map = load_owasp_map(OWASP_MAP_PATH)
    findings, total_instances = parse_report(args.report, owasp_map)
    min_index = SEVERITY_ORDER.index(args.min_severity)
    findings = [f for f in findings if SEVERITY_ORDER.index(f.severity) >= min_index]

    args.output.write_text(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))
    print_summary(findings, total_instances, args.min_severity)
    print(f"\nHallazgos guardados en {args.output}")


if __name__ == "__main__":
    main()
