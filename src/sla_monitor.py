"""Revisa los tickets abiertos del pipeline y avisa de los vencidos y por vencer.

Por defecto es de solo lectura (informa por consola). Con --comment y/o --webhook notifica
y marca cada ticket con una etiqueta para no repetir el aviso.
"""
import argparse
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import requests

from src.jira_client import JiraClient, JiraError
from src.processor import SEVERITY_ORDER
from src.sla import DEFAULT_SLA_PATH, load_warn_days
from src.ticketer import BASE_LABEL

LABEL_WARNED = "sla-por-vencer"
LABEL_BREACHED = "sla-vencido"
SEVERITY_PREFIX = "severity-"
DEFAULT_SEVERITY = "medium"  # si el ticket no trae una etiqueta de severidad válida


@dataclass(frozen=True)
class Alert:
    key: str
    summary: str
    kind: str  # "overdue" | "due_soon"
    days: int  # días de atraso (overdue) o que faltan (due_soon)
    due: date
    assignee: str
    already_notified: bool


def severity_of(labels: list[str]) -> str:
    # Solo valores válidos: 'severity-escalated' también empieza con 'severity-' pero no es una severidad
    for label in labels:
        value = label[len(SEVERITY_PREFIX):]
        if label.startswith(SEVERITY_PREFIX) and value in SEVERITY_ORDER:
            return value
    return DEFAULT_SEVERITY


def is_open(issue: dict) -> bool:
    # La categoría ('new' | 'indeterminate' | 'done') no depende del idioma; el nombre del estado sí
    return issue["fields"]["status"]["statusCategory"]["key"] != "done"


def classify(issue: dict, today: date, warn_days: dict[str, int]) -> Alert | None:
    if not is_open(issue):
        return None
    fields = issue["fields"]
    raw_due = fields.get("duedate")
    if not raw_due:
        return None
    due = date.fromisoformat(raw_due)
    labels = fields.get("labels") or []
    days_left = (due - today).days

    if days_left < 0:
        kind, days, notified = "overdue", -days_left, LABEL_BREACHED in labels
    elif days_left <= warn_days[severity_of(labels)]:
        kind, days, notified = "due_soon", days_left, bool({LABEL_WARNED, LABEL_BREACHED} & set(labels))
    else:
        return None

    return Alert(
        key=issue.get("key") or issue["id"],
        summary=fields.get("summary", ""),
        kind=kind,
        days=days,
        due=due,
        assignee=(fields.get("assignee") or {}).get("displayName", "sin asignar"),
        already_notified=notified,
    )


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (a.kind != "overdue", a.due))  # vencidos primero


def format_line(a: Alert) -> str:
    if a.kind == "overdue":
        when = f"VENCIDO hace {a.days} d (límite {a.due})"
    else:
        when = f"POR VENCER en {a.days} d (límite {a.due})"
    return f"{when} | {a.key} | {a.assignee} | {a.summary}"


def comment_text(a: Alert) -> str:
    if a.kind == "overdue":
        return f"[SLA VENCIDO] La fecha límite era {a.due} (hace {a.days} día(s)). Este hallazgo sigue abierto."
    return f"[SLA POR VENCER] Quedan {a.days} día(s): la fecha límite es {a.due}."


def digest(alerts: list[Alert], today: date) -> str:
    lines = [f"Alertas de SLA al {today}: {len(alerts)} ticket(s)"]
    lines += [format_line(a) for a in sort_alerts(alerts)]
    return "\n".join(lines)


def send_webhook(url: str, text: str) -> None:
    """Slack espera {'text': ...}; Discord {'content': ...} (máx. 2000 caracteres)."""
    key = "content" if "discord.com/api/webhooks" in url else "text"
    try:
        response = requests.post(url, json={key: text[:1900]}, timeout=15)
    except requests.RequestException as exc:
        # No propagamos exc: su mensaje incluye la URL, y la URL contiene el token del webhook
        raise RuntimeError(f"No se pudo contactar al webhook ({type(exc).__name__})") from None
    if not response.ok:
        raise RuntimeError(f"El webhook respondió HTTP {response.status_code}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Revisa el SLA de los tickets abiertos del pipeline")
    parser.add_argument("--sla", type=Path, default=DEFAULT_SLA_PATH)
    parser.add_argument("--today", type=date.fromisoformat, default=None,
                        help="Simula la fecha (AAAA-MM-DD) para pruebas y demos")
    parser.add_argument("--comment", action="store_true", help="Comenta en cada ticket con alerta nueva")
    parser.add_argument("--webhook", action="store_true", help="Envía un resumen a Slack/Discord (ALERT_WEBHOOK_URL)")
    args = parser.parse_args()

    today = args.today or date.today()
    warn_days = load_warn_days(args.sla)
    client = JiraClient.from_env()  # también carga el .env

    webhook_url = ""
    if args.webhook:
        webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
        if not webhook_url:
            raise SystemExit("--webhook requiere ALERT_WEBHOOK_URL en tu .env")

    writes = args.comment or args.webhook
    if args.today and writes:
        print("[aviso] Fecha simulada con escritura: las etiquetas de estado quedarán en Jira y suprimirán "
              "los avisos reales. Al terminar, reinicia con scripts.reset_tickets.")

    issues = client.search_issues(
        f'project = "{client.project_key}" AND labels = "{BASE_LABEL}"',
        fields=["summary", "duedate", "labels", "status", "assignee"],
    )
    open_issues = [issue for issue in issues if is_open(issue)]
    alerts = sort_alerts([a for issue in open_issues if (a := classify(issue, today, warn_days))])
    pending = [a for a in alerts if not a.already_notified]

    print(f"[sla] {today} | {len(issues)} tickets del pipeline | {len(open_issues)} abiertos | "
          f"{len(alerts)} con alerta ({len(pending)} nuevas)")
    for a in alerts:
        print(f"  {format_line(a)}{'  (ya notificado)' if a.already_notified else ''}")
    if not alerts:
        print("  Sin alertas.")

    if not writes:
        if pending:
            print("\nModo solo lectura: usa --comment y/o --webhook para notificar.")
        return
    if not pending:
        return

    webhook_ok = True
    if args.webhook:
        try:
            send_webhook(webhook_url, digest(pending, today))
            print("[sla] Resumen enviado al webhook")
        except RuntimeError as exc:
            webhook_ok = False
            print(f"[error] {exc}")

    for alert in pending:
        delivered = webhook_ok if args.webhook else True
        if args.comment:
            try:
                client.add_comment(alert.key, comment_text(alert))
            except JiraError as exc:
                delivered = False
                print(f"[error] comentario en {alert.key}: {exc}")
        if delivered:  # entrega al menos una vez: si algo falló, no se marca y se reintenta
            label = LABEL_BREACHED if alert.kind == "overdue" else LABEL_WARNED
            try:
                client.add_labels(alert.key, [label])
                print(f"[ok] {alert.key} notificado ({label})")
            except JiraError as exc:
                print(f"[error] etiqueta en {alert.key}: {exc}")


if __name__ == "__main__":
    main()
