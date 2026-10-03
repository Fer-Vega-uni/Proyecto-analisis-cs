"""
Análisis de vulnerabilidades en dependencias con Grype.

Proceso:
1. Para cada repositorio, lee el SBOM generado por Syft (results/<repo>-sbom.json).
2. Ejecuta Grype sobre ese SBOM, así Syft y Grype analizan el mismo inventario.
3. Normaliza cada vulnerabilidad: ID, severidad, CVSS, paquete, versión,
   versión que la corrige y archivo de manifiesto donde aparece la dependencia.
4. Guarda el resultado en results/<repo>-grype.json.

Severidad:
    Se usa la severidad que entrega Grype (critical, high, medium, low,
    negligible o unknown). El puntaje CVSS se guarda aparte; si hay varios,
    se usa el más alto.

Uso:
    .venv/bin/python miner/generate_grype.py
"""

import json
import subprocess
from pathlib import Path

RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_RESULTADOS = RUTA_BASE / "results"

SUFIJO_SBOM = "-sbom.json"
SUFIJO_GRYPE = "-grype.json"


class GrypeAnalyzer:
    def __init__(self, results_path: Path):
        self.results_path = Path(results_path)
        self.version = self._grype_version()

    def _grype_version(self) -> str:
        resultado = subprocess.run(["grype", "version", "-o", "json"],
                                   capture_output=True, text=True, check=True)
        return json.loads(resultado.stdout).get("version", "unknown")

    def discover_sboms(self) -> list[Path]:
        """Lista los SBOMs generados por Syft, en orden alfabético."""
        sboms = sorted(self.results_path.glob(f"*{SUFIJO_SBOM}"))
        if not sboms:
            raise FileNotFoundError("No hay SBOMs en results/. Ejecuta primero generate_sboms.py")
        return sboms

    def run_grype(self, sbom_path: Path) -> dict:
        """Ejecuta Grype sobre un SBOM y devuelve su salida JSON."""
        resultado = subprocess.run(
            ["grype", f"sbom:{sbom_path}", "-o", "json", "-q"],
            capture_output=True, text=True, check=True,
        )
        return json.loads(resultado.stdout)

    def max_cvss(self, vulnerabilidad: dict, relacionadas: list[dict]) -> float | None:
        """Devuelve el puntaje CVSS más alto disponible para la vulnerabilidad."""
        puntajes = []
        for fuente in [vulnerabilidad] + relacionadas:
            for cvss in fuente.get("cvss") or []:
                puntaje = (cvss.get("metrics") or {}).get("baseScore")
                if puntaje is not None:
                    puntajes.append(float(puntaje))
        return max(puntajes) if puntajes else None

    def parse_matches(self, salida_grype: dict) -> list[dict]:
        """Convierte la salida de Grype en una lista de hallazgos normalizados."""
        hallazgos = []

        for match in salida_grype.get("matches", []):
            vuln = match.get("vulnerability", {})
            artefacto = match.get("artifact", {})
            relacionadas = match.get("relatedVulnerabilities") or []
            fix = vuln.get("fix") or {}

            # Descripción: a veces viene solo en la vulnerabilidad relacionada (CVE)
            descripcion = vuln.get("description") or next(
                (r.get("description") for r in relacionadas if r.get("description")), ""
            )
            # CVE asociado cuando el ID principal es un GHSA
            cves = sorted({r["id"] for r in relacionadas if r.get("id", "").startswith("CVE-")})
            # Archivos de manifiesto donde aparece la dependencia
            ubicaciones = sorted({loc["path"].lstrip("/")
                                  for loc in artefacto.get("locations") or [] if loc.get("path")})

            hallazgos.append({
                "vuln_id": vuln.get("id"),
                "cve": ", ".join(cves) if cves else None,
                "severity": (vuln.get("severity") or "unknown").lower(),
                "cvss_score": self.max_cvss(vuln, relacionadas),
                "package": artefacto.get("name"),
                "version": artefacto.get("version"),
                "ecosystem": artefacto.get("type"),
                "fix_state": fix.get("state"),
                "fix_versions": ", ".join(fix.get("versions") or []) or None,
                "file": ", ".join(ubicaciones) if ubicaciones else None,
                "description": descripcion,
                "url": vuln.get("dataSource"),
            })

        hallazgos.sort(key=lambda h: (h["package"] or "", h["vuln_id"] or ""))
        return hallazgos

    def analyze(self, sbom_path: Path) -> dict:
        """Analiza un SBOM y devuelve el resultado normalizado."""
        nombre = sbom_path.name.removesuffix(SUFIJO_SBOM)
        resultado = {"repo": nombre, "analysis": "dependencies", "grype_version": self.version,
                     "status": "ok", "error": None, "total_findings": 0, "findings": []}
        try:
            salida = self.run_grype(sbom_path)
            resultado["db_built"] = (salida.get("descriptor", {}).get("db", {})
                                     .get("status", {}).get("built"))
            resultado["findings"] = self.parse_matches(salida)
            resultado["total_findings"] = len(resultado["findings"])
        except subprocess.CalledProcessError as error:
            resultado["status"] = "grype_failed"
            resultado["error"] = (error.stderr or "").strip()[-2000:]
        return resultado

    def run(self, overwrite: bool = False) -> list[dict]:
        """Ejecuta Grype sobre el SBOM de cada repositorio."""
        sboms = self.discover_sboms()
        print(f"Grype {self.version}")
        resumen = []

        for i, sbom_path in enumerate(sboms, start=1):
            nombre = sbom_path.name.removesuffix(SUFIJO_SBOM)
            salida = self.results_path / f"{nombre}{SUFIJO_GRYPE}"
            print(f"[{i}/{len(sboms)}] Grype: {nombre}")

            if salida.exists() and not overwrite:
                print("    Ya analizado, se omite.")
                continue

            resultado = self.analyze(sbom_path)
            salida.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")

            if resultado["status"] == "ok":
                print(f"    {resultado['total_findings']} vulnerabilidades")
            else:
                print(f"    estado '{resultado['status']}'")
            resumen.append({"repo": nombre, "status": resultado["status"],
                            "findings": resultado["total_findings"]})

        print("Listo: análisis de Grype guardados en results/")
        return resumen


if __name__ == "__main__":
    GrypeAnalyzer(RUTA_RESULTADOS).run()