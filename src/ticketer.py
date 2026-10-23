import argparse
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from src.jira_client import JiraClient, JiraError
from src.rules import DEFAULT_RULES_PATH, evaluate, load_rules
from src.sla import DEFAULT_SLA_PATH, compute_due_date, load_sla

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FINDINGS = ROOT / "reports" / "findings.json"
BASE_LABEL = "vulnpipe"
FINGERPRINT_PREFIX = "fp-"
MAX_CONSECUTIVE_FAILURES = 3

def _text(text: str, bold: bool = False) -> dict:
    node = {"type": "text", "text": text}  # ADF no admite nodos de texto vacíos
    if bold:
        node["marks"] = [{"type": "strong"}]
    return node

def _paragraph(*nodes: dict) -> dict:
    return {"type": "paragraph", "content": list(nodes)}


def _heading(text: str) -> dict:
    return {"type": "heading", "attrs": {"level": 3}, "content": [_text(text)]}


def _paragraphs(text: str) -> list[dict]:
    return [_paragraph(_text(chunk.strip())) for chunk in re.split(r"\n\s*\n", text) if chunk.strip()]


def _field(label: str, value: str) -> dict:
    return _paragraph(_text(f"{label}: ", bold=True), _text(value))


def build_description(f: dict) -> dict:
    blocks = [
        _field(
            "Severidad",
            f"{f['severity']} (ZAP reportó: {f.get('severity_reported', f['severity'])}; confianza: {f['confidence']})",
        ),
        _field("Categoría OWASP", f["owasp"]),
        _field("URL afectada", f"{f['method']} {f['url']}"),
    ]
    if f.get("sla_due"):
        blocks.append(_field("Fecha límite (SLA)", f"{f['sla_due']} ({f['sla_days']} días corridos desde la creación)"))
    if f.get("param"):
        blocks.append(_field("Parámetro", f["param"]))
    if f.get("cwe_id"):
        blocks.append(_field("CWE", f"CWE-{f['cwe_id']}"))
    if f.get("description"):
        blocks += [_heading("Descripción"), *_paragraphs(f["description"])]
    if f.get("solution"):
        blocks += [_heading("Remediación recomendada"), *_paragraphs(f["solution"])]
    if f.get("evidence"):
        blocks += [_heading("Evidencia"), {"type": "codeBlock", "content": [_text(f["evidence"][:500])]}]
    if f.get("reference"):
        blocks += [_heading("Referencias"), *_paragraphs(f["reference"])]
    if f.get("matched_rules"):
        blocks.append(_field("Reglas aplicadas", "; ".join(f["matched_rules"])))
    blocks.append(
        _paragraph(_text(f"ID del hallazgo: {f['fingerprint']} · generado automáticamente por vuln-pipeline a partir de un escaneo ZAP."))
    )
    return {"type": "doc", "version": 1, "content": blocks}


def build_summary(f: dict) -> str:
    path = urlsplit(f["url"]).path or "/"
    return f"[{f['severity'].upper()}] {f['name']} - {path}"[:250]  # Jira limita el resumen a 255


def owasp_label(owasp: str) -> str:
    match = re.match(r"A(\d{2}):", owasp)
    return f"owasp-a{match.group(1)}" if match else "owasp-sin-clasificar"


def build_labels(f: dict, extra: list[str] | tuple = ()) -> list[str]:
    # Las etiquetas de Jira no admiten espacios
    labels = [BASE_LABEL, f"severity-{f['severity']}", owasp_label(f["owasp"]), f"{FINGERPRINT_PREFIX}{f['fingerprint']}"]
    if f.get("severity_reported", f["severity"]) != f["severity"]:
        labels.append("severity-escalated")
    labels += [label for label in extra if label not in labels]
    return labels


def resolve_assignee(key: str | None) -> str | None:
    """Clave lógica ('appsec') -> accountId, leído de JIRA_ASSIGNEE_APPSEC. Nada de IDs en el repo."""
    if not key:
        return None
    return os.getenv(f"JIRA_ASSIGNEE_{key.upper()}", "").strip() or None

def existing_fingerprints(client: JiraClient) -> set[str]:
    jql = f'project = "{client.project_key}" AND labels = "{BASE_LABEL}"'
    issues = client.search_issues(jql, fields=["labels"])
    return {
        label[len(FINGERPRINT_PREFIX):]
        for issue in issues
        for label in issue["fields"]["labels"]
        if label.startswith(FINGERPRINT_PREFIX)
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Crea issues de Jira a partir de findings.json")
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    parser.add_argument("--dry-run", action="store_true", help="Muestra qué se crearía, sin crear nada")
    parser.add_argument("--limit", type=int, default=None, help="Máximo de tickets a crear en esta ejecución")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_PATH)
    parser.add_argument("--sla", type=Path, default=DEFAULT_SLA_PATH)
    args = parser.parse_args()

    findings = json.loads(args.findings.read_text())
    rules = load_rules(args.rules)
    sla = load_sla(args.sla)
    client = JiraClient.from_env()
    issue_type = os.getenv("JIRA_ISSUE_TYPE", "Task")
    available = client.issue_type_names()
    if issue_type not in available:
        raise SystemExit(
            f"JIRA_ISSUE_TYPE={issue_type!r} no existe en {client.project_key}. Tipos disponibles: {available}"
        )
    known = existing_fingerprints(client)
    print(f"[ticketer] {len(findings)} hallazgos | {len(known)} ya tienen ticket en {client.project_key}")

    created = skipped = failed = consecutive_failures = 0
    warned = set()
    for finding in findings:
        if finding["fingerprint"] in known:
            skipped += 1
            continue
        if args.limit is not None and created >= args.limit:
            break

        decision = evaluate(finding, rules)
        due_date = compute_due_date(decision.severity, sla)
        enriched = {
            **finding,
            "severity_reported": finding["severity"],
            "severity": decision.severity,
            "matched_rules": decision.matched_rules,
            "sla_due": due_date.isoformat(),
            "sla_days": sla[decision.severity],
        }
        account_id = resolve_assignee(decision.assignee)
        if decision.assignee and not account_id and decision.assignee not in warned:
            warned.add(decision.assignee)
            print(f"[aviso] JIRA_ASSIGNEE_{decision.assignee.upper()} no está definida: esos tickets quedarán sin asignar")

        summary = build_summary(enriched)
        labels = build_labels(enriched, decision.labels)
        if args.dry_run:
            asignado = decision.assignee if account_id else f"{decision.assignee} (sin asignar)"
            print(f"[dry-run] {summary}\n          responsable={asignado} vence={due_date} labels={labels}")
            created += 1
            continue

        try:
            key = client.create_issue(
                summary, build_description(enriched), issue_type, labels, account_id, due_date.isoformat()
            )
        except JiraError as exc:
            failed += 1
            consecutive_failures += 1
            if "duedate" in str(exc):
                print("        Pista: el campo 'Fecha de vencimiento' no está disponible al crear issues en este proyecto (ver guía de la Fase 5).")
            print(f"[error] {summary}\n        {exc}")
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                print(f"[ticketer] {MAX_CONSECUTIVE_FAILURES} fallos seguidos: abortando.")
                break
            continue

        consecutive_failures = 0
        known.add(finding["fingerprint"])
        created += 1
        print(f"[ok] {key}  {summary}")
        time.sleep(0.2)

    verb = "se crearían" if args.dry_run else "creados"
    print(f"\nResumen: {verb}={created}  omitidos(ya existían)={skipped}  fallidos={failed}")


if __name__ == "__main__":
    main()
