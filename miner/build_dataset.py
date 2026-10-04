"""
Construcción del dataset estructurado.

Junta todos los resultados del Miner en dos tablas CSV, listas para el Analyzer:

1. results/dataset/findings.csv -> una fila por hallazgo (CodeQL y Grype).
   Cada fila indica el repositorio de origen, la herramienta, el tipo de
   vulnerabilidad, su severidad y su ubicación.

2. results/dataset/repos.csv -> una fila por repositorio analizado, incluidos
   los que no tienen hallazgos, con su estado y conteos por severidad.
   "language" es la etiqueta de GitHub; "analyzed_language" es el lenguaje
   que realmente analizó CodeQL.

Severidad normalizada (misma escala para ambas herramientas):
    critical, high, medium, low, negligible, unknown

Área de la ubicación (para separar código real de pruebas o documentación):
    source, test, docs, example, ci

Uso:
    .venv/bin/python miner/build_dataset.py
"""

import csv
import json
from pathlib import Path

RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_RESULTADOS = RUTA_BASE / "results"
RUTA_DATASET = RUTA_RESULTADOS / "dataset"

SEVERIDADES = ["critical", "high", "medium", "low", "negligible", "unknown"]

COLUMNAS_HALLAZGOS = [
    "repo", "tool", "finding_type", "vuln_id", "title", "cwe", "cve",
    "severity", "score", "file", "start_line", "area",
    "package", "version", "ecosystem", "fix_versions", "message",
]

COLUMNAS_REPOS = [
    "repo", "url", "language", "analyzed_language", "stars", "commit_sha", "packages",
    "codeql_status", "pipeline_status", "grype_status",
    "total_findings", "code_findings", "ci_findings", "dependency_findings",
] + [f"{s}_findings" for s in SEVERIDADES]


def leer_json(ruta: Path) -> dict | list | None:
    return json.loads(ruta.read_text(encoding="utf-8")) if ruta.exists() else None


def clasificar_area(ruta: str | None, finding_type: str) -> str:
    """Clasifica la ubicación del hallazgo según la carpeta donde está."""
    if finding_type == "ci":
        return "ci"
    if not ruta:
        return "source"
    partes = [p.lower() for p in ruta.split(",")[0].strip().split("/")]
    archivo = partes[-1]
    if any(p in ("test", "tests", "testing") for p in partes) or archivo.startswith("test_"):
        return "test"
    if any(p in ("doc", "docs", "documentation") for p in partes):
        return "docs"
    if any(p in ("example", "examples", "sample", "samples") for p in partes):
        return "example"
    return "source"


def normalizar_severidad(severidad: str | None) -> str:
    severidad = (severidad or "unknown").lower()
    return severidad if severidad in SEVERIDADES else "unknown"


def hallazgos_codeql(datos: dict, finding_type: str) -> list[dict]:
    filas = []
    for h in datos.get("findings", []):
        filas.append({
            "repo": datos["repo"],
            "tool": "codeql",
            "finding_type": finding_type,
            "vuln_id": h["rule_id"],
            "title": h["rule_name"],
            "cwe": h["cwe"],
            "cve": None,
            "severity": normalizar_severidad(h["severity"]),
            "score": h["security_severity"],
            "file": h["file"],
            "start_line": h["start_line"],
            "area": clasificar_area(h["file"], finding_type),
            "package": None,
            "version": None,
            "ecosystem": None,
            "fix_versions": None,
            "message": h["message"],
        })
    return filas


def hallazgos_grype(datos: dict) -> list[dict]:
    filas = []
    for h in datos.get("findings", []):
        filas.append({
            "repo": datos["repo"],
            "tool": "grype",
            "finding_type": "dependency",
            "vuln_id": h["vuln_id"],
            "title": f"{h['package']} {h['version']}",
            "cwe": None,
            "cve": h["cve"],
            "severity": normalizar_severidad(h["severity"]),
            "score": h["cvss_score"],
            "file": h["file"],
            "start_line": None,
            "area": clasificar_area(h["file"], "dependency"),
            "package": h["package"],
            "version": h["version"],
            "ecosystem": h["ecosystem"],
            "fix_versions": h["fix_versions"],
            "message": (h["description"] or "")[:500],
        })
    return filas


def contar_paquetes(repo: str) -> int | None:
    sbom = leer_json(RUTA_RESULTADOS / f"{repo}-sbom.json")
    return len(sbom.get("artifacts", [])) if sbom else None


def estado(datos: dict | None) -> str:
    return datos["status"] if datos else "missing"


def build() -> None:
    repos = leer_json(RUTA_RESULTADOS / "repos.json")
    if not repos:
        raise FileNotFoundError("No existe results/repos.json. Ejecuta primero el Miner.")

    todos_hallazgos = []
    filas_repos = []

    for meta in repos:
        nombre = meta["repo"]
        codeql = leer_json(RUTA_RESULTADOS / f"{nombre}-codeql.json")
        pipeline = leer_json(RUTA_RESULTADOS / f"{nombre}-pipeline.json")
        grype = leer_json(RUTA_RESULTADOS / f"{nombre}-grype.json")

        hallazgos = []
        if codeql:
            hallazgos += hallazgos_codeql(codeql, "code")
        if pipeline:
            hallazgos += hallazgos_codeql(pipeline, "ci")
        if grype:
            hallazgos += hallazgos_grype(grype)
        todos_hallazgos += hallazgos

        fila = {
            "repo": nombre,
            "url": meta["url"],
            "language": meta["language"],
            "analyzed_language": codeql["language"] if codeql else None,
            "stars": meta["stars"],
            "commit_sha": meta["commit_sha"],
            "packages": contar_paquetes(nombre),
            "codeql_status": estado(codeql),
            "pipeline_status": estado(pipeline),
            "grype_status": estado(grype),
            "total_findings": len(hallazgos),
            "code_findings": sum(h["finding_type"] == "code" for h in hallazgos),
            "ci_findings": sum(h["finding_type"] == "ci" for h in hallazgos),
            "dependency_findings": sum(h["finding_type"] == "dependency" for h in hallazgos),
        }
        for s in SEVERIDADES:
            fila[f"{s}_findings"] = sum(h["severity"] == s for h in hallazgos)
        filas_repos.append(fila)

    RUTA_DATASET.mkdir(parents=True, exist_ok=True)
    escribir_csv(RUTA_DATASET / "findings.csv", COLUMNAS_HALLAZGOS, todos_hallazgos)
    escribir_csv(RUTA_DATASET / "repos.csv", COLUMNAS_REPOS, filas_repos)

    print(f"Dataset generado en {RUTA_DATASET.relative_to(RUTA_BASE)}/")
    print(f"    findings.csv: {len(todos_hallazgos)} hallazgos")
    print(f"    repos.csv:    {len(filas_repos)} repositorios")
    for s in SEVERIDADES:
        cantidad = sum(h["severity"] == s for h in todos_hallazgos)
        if cantidad:
            print(f"        {s}: {cantidad}")


def escribir_csv(ruta: Path, columnas: list[str], filas: list[dict]) -> None:
    with open(ruta, "w", newline="", encoding="utf-8") as archivo:
        writer = csv.DictWriter(archivo, fieldnames=columnas, lineterminator="\n")
        writer.writeheader()
        writer.writerows(filas)


if __name__ == "__main__":
    build()