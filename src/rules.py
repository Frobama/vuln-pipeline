"""Motor de reglas: decide responsable, etiquetas y severidad efectiva de cada hallazgo."""
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from src.processor import SEVERITY_ORDER

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_PATH = ROOT / "config" / "rules.yaml"

MATCH_KEYS = {"severity", "owasp", "alert_ref", "name_regex", "url_regex"}
ACTION_KEYS = {"assignee", "labels", "severity"}


class RulesConfigError(ValueError):
    """La configuración de reglas es inválida."""


@dataclass
class Decision:
    severity: str
    assignee: str | None = None
    labels: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _validate(config: dict) -> None:
    unknown = set(config) - {"defaults", "rules"}
    if unknown:
        raise RulesConfigError(f"Claves desconocidas en la raíz: {sorted(unknown)}")

    for index, rule in enumerate(config.get("rules") or []):
        name = rule.get("name")
        if not name:
            raise RulesConfigError(f"La regla #{index + 1} no tiene 'name'")
        extra = set(rule) - {"name", "match", "actions"}
        if extra:
            raise RulesConfigError(f"Regla {name!r}: claves desconocidas {sorted(extra)}")

        match = rule.get("match") or {}
        if not match:
            raise RulesConfigError(f"Regla {name!r}: sin condiciones (coincidiría con todo)")
        bad = set(match) - MATCH_KEYS
        if bad:
            raise RulesConfigError(f"Regla {name!r}: condiciones desconocidas {sorted(bad)}")
        for key in ("name_regex", "url_regex"):
            if key in match:
                try:
                    re.compile(match[key])
                except re.error as exc:
                    raise RulesConfigError(f"Regla {name!r}: {key} inválida ({exc})") from exc

        actions = rule.get("actions") or {}
        bad = set(actions) - ACTION_KEYS
        if bad:
            raise RulesConfigError(f"Regla {name!r}: acciones desconocidas {sorted(bad)}")
        if "severity" in actions and actions["severity"] not in SEVERITY_ORDER:
            raise RulesConfigError(f"Regla {name!r}: severidad {actions['severity']!r} no válida")
        for label in actions.get("labels", []):
            if re.search(r"\s", label):
                raise RulesConfigError(f"Regla {name!r}: la etiqueta {label!r} no puede tener espacios")


def load_rules(path: Path = DEFAULT_RULES_PATH) -> dict:
    config = yaml.safe_load(Path(path).read_text()) or {}
    _validate(config)
    return config


def _matches(finding: dict, match: dict) -> bool:
    checks = {
        "severity": lambda v: finding["severity"] in [str(x) for x in _as_list(v)],
        "owasp": lambda v: any(finding["owasp"].upper().startswith(str(p).upper()) for p in _as_list(v)),
        "alert_ref": lambda v: finding["alert_ref"] in [str(x) for x in _as_list(v)],
        "name_regex": lambda v: re.search(v, finding["name"], re.IGNORECASE) is not None,
        "url_regex": lambda v: re.search(v, finding["url"]) is not None,
    }
    return all(checks[key](value) for key, value in match.items())


def evaluate(finding: dict, config: dict) -> Decision:
    decision = Decision(
        severity=finding["severity"],
        assignee=(config.get("defaults") or {}).get("assignee"),
    )
    assignee_decided = False

    for rule in config.get("rules") or []:
        if not _matches(finding, rule["match"]):
            continue
        decision.matched_rules.append(rule["name"])
        actions = rule.get("actions") or {}

        for label in actions.get("labels", []):
            if label not in decision.labels:
                decision.labels.append(label)

        if "assignee" in actions and not assignee_decided:
            decision.assignee = actions["assignee"]
            assignee_decided = True

        new_severity = actions.get("severity")
        if new_severity and SEVERITY_ORDER.index(new_severity) > SEVERITY_ORDER.index(decision.severity):
            decision.severity = new_severity

    return decision
