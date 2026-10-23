"""Herramienta de desarrollo: borra los issues creados por el pipeline (etiqueta 'vulnpipe').

Solo afecta al proyecto configurado en JIRA_PROJECT_KEY. Sin --yes solo simula.
Uso: python -m scripts.reset_tickets [--yes]
"""
import argparse

from src.jira_client import JiraClient
from src.ticketer import BASE_LABEL


def main() -> None:
    parser = argparse.ArgumentParser(description="Borra los issues del pipeline en Jira")
    parser.add_argument("--yes", action="store_true", help="Confirma el borrado (irreversible)")
    args = parser.parse_args()

    client = JiraClient.from_env()
    jql = f'project = "{client.project_key}" AND labels = "{BASE_LABEL}"'
    issues = client.search_issues(jql, fields=["summary"])
    print(f"{len(issues)} issues con la etiqueta '{BASE_LABEL}' en {client.project_key}")

    if not args.yes:
        print("Simulación: no se borró nada. Usa --yes para borrarlos.")
        return
    for issue in issues:
        client.delete_issue(issue.get("key") or issue["id"])
    print("Borrados.")


if __name__ == "__main__":
    main()
