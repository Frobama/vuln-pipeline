import os
import time
from typing import Any

import requests
from dotenv import load_dotenv

class JiraError(RuntimeError):
    """Error devuelto por Jira o problema de configuración"""

def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise JiraError(f"Falta la variable de entorno {name}")
    return value

class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str, project_key: str, timeout: int = 30):
            self.base_url = base_url.rstrip("/")
            self.project_key = project_key
            self.timeout = timeout
            self.session = requests.Session()
            self.session.auth = (email, api_token)
            self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    @classmethod
    def from_env(cls) -> "JiraClient":
        load_dotenv()
        return cls(
            base_url=_require_env("JIRA_BASE_URL"),
            email=_require_env("JIRA_EMAIL"),
            api_token=_require_env("JIRA_API_TOKEN"),
            project_key=_require_env("JIRA_PROJECT_KEY"),
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
            url = f"{self.base_url}{path}"
            for _ in range(3):
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if response.status_code != 429:
                    break
                wait = int(response.headers.get("Retry-After", 5))
                print(f"[jira] Límite de tasa alcanzado; reintentando en {wait}s")
                time.sleep(wait)
            if not response.ok:
                # Jira explica el motivo en el cuerpo (errorMessages / errors). Nunca se imprimen credenciales.
                raise JiraError(f"{method} {path} -> HTTP {response.status_code}: {response.text[:500]}")
            return response.json() if response.content else None

    def myself(self) -> dict:
        return self._request("GET", "/rest/api/3/myself")

    def issue_type_names(self) -> list[str]:
        project = self._request("GET", f"/rest/api/3/project/{self.project_key}")
        return [issue_type["name"] for issue_type in project.get("issueTypes", [])]

    def create_issue(
        self,
        summary: str,
        description: dict,
        issue_type: str,
        labels: list[str],
        assignee_account_id: str | None = None,
        due_date: str | None = None,
    ) -> str:
        fields: dict[str, Any] = {
            "project": {"key": self.project_key},
            "issuetype": {"name": issue_type},
            "summary": summary,
            "description": description,
            "labels": labels,
        }
        if assignee_account_id:
            fields["assignee"] = {"accountId": assignee_account_id}
        if due_date:
            fields["duedate"] = due_date  # formato AAAA-MM-DD
        return self._request("POST", "/rest/api/3/issue", json={"fields": fields})["key"]

    def delete_issue(self, issue_key: str) -> None:
        self._request("DELETE", f"/rest/api/3/issue/{issue_key}")

    def search_issues(self, jql: str, fields: list[str]) -> list[dict]:
        """Búsqueda JQL con paginación por token."""
        issues: list[dict] = []
        page_token = None
        while True:
            body: dict[str, Any] = {"jql": jql, "fields": fields, "maxResults": 100}
            if page_token:
                body["nextPageToken"] = page_token
            data = self._request("POST", "/rest/api/3/search/jql", json=body)
            issues.extend(data.get("issues", []))
            page_token = data.get("nextPageToken")
            if data.get("isLast", True) or not page_token:
                return issues


def main() -> None:
    """Comprobación de conexión: `python -m src.jira_client`"""
    client = JiraClient.from_env()
    me = client.myself()
    print(f"[jira] Autenticado como: {me.get('displayName')} ({me.get('emailAddress', 'email oculto')})")
    print(f"[jira] accountId: {me.get('accountId')}  (lo usaremos en la Fase 4 para asignar)")
    print(f"[jira] Tipos de issue en {client.project_key}: {client.issue_type_names()}")


if __name__ == "__main__":
    main()
