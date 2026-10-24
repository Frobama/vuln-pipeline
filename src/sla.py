"""Cálculo de plazos SLA y ventanas de aviso a partir de la severidad efectiva."""
from datetime import date, timedelta
from pathlib import Path

import yaml

from src.processor import SEVERITY_ORDER

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SLA_PATH = ROOT / "config" / "sla.yaml"


class SlaConfigError(ValueError):
    """La configuración de SLA es inválida."""


def _read_config(path: Path) -> dict:
    config = yaml.safe_load(Path(path).read_text()) or {}
    unknown = set(config) - {"sla_days", "warn_before_days"}
    if unknown:
        raise SlaConfigError(f"Claves desconocidas en la raíz: {sorted(unknown)}")
    return config


def _validate_days(name: str, days: dict) -> dict[str, int]:
    missing = [s for s in SEVERITY_ORDER if s not in days]
    extra = [s for s in days if s not in SEVERITY_ORDER]
    if missing or extra:
        raise SlaConfigError(f"{name} debe definir exactamente {SEVERITY_ORDER}; faltan {missing}, sobran {extra}")

    for severity, value in days.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise SlaConfigError(f"{name}.{severity} debe ser un entero positivo (recibido: {value!r})")

    # Coherencia: algo más severo nunca puede tener MÁS días que algo menos severo
    for lower, higher in zip(SEVERITY_ORDER, SEVERITY_ORDER[1:]):
        if days[higher] > days[lower]:
            raise SlaConfigError(
                f"{name} incoherente: {higher} ({days[higher]}d) tiene más días que {lower} ({days[lower]}d)"
            )
    return days


def load_sla(path: Path = DEFAULT_SLA_PATH) -> dict[str, int]:
    return _validate_days("sla_days", _read_config(path).get("sla_days") or {})


def load_warn_days(path: Path = DEFAULT_SLA_PATH) -> dict[str, int]:
    config = _read_config(path)
    sla = _validate_days("sla_days", config.get("sla_days") or {})
    warn = _validate_days("warn_before_days", config.get("warn_before_days") or {})
    for severity in SEVERITY_ORDER:
        if warn[severity] >= sla[severity]:
            raise SlaConfigError(
                f"warn_before_days.{severity} ({warn[severity]}d) debe ser menor que su plazo ({sla[severity]}d)"
            )
    return warn


def compute_due_date(severity: str, sla_days: dict[str, int], start: date | None = None) -> date:
    """Fecha límite = inicio + días corridos. `start` se inyecta para poder probarlo con fechas fijas."""
    return (start or date.today()) + timedelta(days=sla_days[severity])
