"""Utilidad de desarrollo: muestra la estructura del reporte JSON de ZAP."""
import json
import sys
from pathlib import Path

path = Path(sys.argv[1] if len(sys.argv) > 1 else "reports/zap-report.json")
data = json.loads(path.read_text())

print("Claves de primer nivel:", list(data.keys()))
for site in data["site"]:
    print(f"\nSitio: {site['@name']}  |  alertas: {len(site['alerts'])}")
    for alert in site["alerts"][:3]:
        resumen = {k: alert.get(k) for k in ("pluginid", "alert", "riskcode", "riskdesc", "cweid", "wascid")}
        print(resumen, "| instancias:", len(alert["instances"]))
