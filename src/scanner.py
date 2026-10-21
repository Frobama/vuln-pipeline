"""Ejecuta un escaneo baseline de ZAP (en Docker) y devuelve la ruta del reporte JSON."""
import argparse
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
DOCKER_NETWORK = "vulnnet"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

# Salvaguarda: solo se escanean hosts que controlo. Ampliar esta lista es una decisión consciente.
ALLOWED_HOSTS = {"juiceshop"}

# ZAP: 0 = OK, 1 = fallo de reglas, 2 = advertencias, otros = error real de ejecución
ZAP_OK_EXIT_CODES = {0, 1, 2}


def assert_target_allowed(target: str) -> None:
    host = urlparse(target).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError(
            f"Objetivo no permitido: {host!r}. Solo se permite escanear: {sorted(ALLOWED_HOSTS)}"
        )


def run_scan(
    target: str,
    report_name: str = "zap-report",
    spider_minutes: int = 3,
    ajax_spider: bool = False,
) -> Path:
    assert_target_allowed(target)
    REPORTS_DIR.mkdir(exist_ok=True)
    # El contenedor corre como usuario 'zap' (no root) y necesita escribir aquí
    REPORTS_DIR.chmod(0o777)

    zap_args = ["-t", target, "-m", str(spider_minutes), "-I"]
    if ajax_spider:
        # Opt-in: en este entorno el job del navegador headless hacía fallar el plan de ZAP
        zap_args.append("-j")
    zap_args += ["-J", f"{report_name}.json", "-r", f"{report_name}.html"]

    cmd = [
        "docker", "run", "--rm",
        "--network", DOCKER_NETWORK,
        "-v", f"{REPORTS_DIR}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py",
        *zap_args,
    ]
    print(f"[scan] Ejecutando: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False)
    report = REPORTS_DIR / f"{report_name}.json"
    if result.returncode not in ZAP_OK_EXIT_CODES or not report.exists():
        raise RuntimeError(
            f"ZAP terminó con código {result.returncode} y el reporte {report} "
            f"{'existe' if report.exists() else 'no existe'}"
        )
    return report


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Escaneo baseline de ZAP contra un objetivo local")
    parser.add_argument("--target", default=os.getenv("TARGET_URL", "http://juiceshop:3000"))
    parser.add_argument("--name", default="zap-report", help="Nombre base del reporte (sin extensión)")
    parser.add_argument("--spider-minutes", type=int, default=3)
    parser.add_argument("--ajax", action="store_true", help="Activa el AJAX Spider")
    args = parser.parse_args()

    report = run_scan(args.target, args.name, args.spider_minutes, ajax_spider=args.ajax)
    print(f"[scan] Reporte JSON listo: {report}")


if __name__ == "__main__":
    main()
