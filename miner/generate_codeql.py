"""
Análisis estático de código con CodeQL.

Para cada repositorio clonado en miner/repos/ se hacen dos análisis:
1. Código fuente (Python o JavaScript) -> results/<repo>-codeql.json
2. Workflows de GitHub Actions (CI/CD) -> results/<repo>-pipeline.json

Pasos de cada análisis:
1. Crear la base de datos de CodeQL (sin compilar: --build-mode=none).
2. Ejecutar la suite de seguridad "security-extended".
3. Guardar el SARIF original en results/sarif/ (evidencia sin modificar).
4. Normalizar los hallazgos: regla, CWE, severidad, archivo y línea.

Severidad:
    Se usa el puntaje "security-severity" de cada regla (escala tipo CVSS, 0 a 10):
    >= 9.0 critical, >= 7.0 high, >= 4.0 medium, > 0 low.
    Si una regla no tiene puntaje, se usa el nivel del SARIF (error/warning/note).

Uso:
    .venv/bin/python miner/generate_codeql.py
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_REPOS = RUTA_BASE / "miner" / "repos"
RUTA_RESULTADOS = RUTA_BASE / "results"

SUFIJO_CODIGO = "-codeql.json"
SUFIJO_PIPELINE = "-pipeline.json"

EXTENSIONES = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
}
CARPETAS_IGNORADAS = {".git", "node_modules", ".venv", "venv"}

SUITES = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "actions": "codeql/actions-queries:codeql-suites/actions-security-extended.qls",
}
# Memoria máxima (MB) que puede usar CodeQL al analizar
RAM_CODEQL_MB = 6144
SEVERIDAD_POR_NIVEL = {"error": "high", "warning": "medium", "note": "low"}


def severidad_desde_puntaje(puntaje: float) -> str:
    """Convierte el puntaje security-severity (0-10) a una categoría."""
    if puntaje >= 9.0:
        return "critical"
    if puntaje >= 7.0:
        return "high"
    if puntaje >= 4.0:
        return "medium"
    if puntaje > 0:
        return "low"
    return "none"


class CodeQLAnalyzer:
    def __init__(self, repos_path: Path, results_path: Path):
        self.repos_path = Path(repos_path)
        self.results_path = Path(results_path)
        self.sarif_path = self.results_path / "sarif"
        self.version = self._codeql_version()

    def _codeql_version(self) -> str:
        resultado = subprocess.run(["codeql", "version", "--format=terse"],
                                   capture_output=True, text=True, check=True)
        return resultado.stdout.strip()

    def discover_repositories(self) -> list[Path]:
        """Lista las carpetas de repositorios clonados, en orden alfabético."""
        if not self.repos_path.exists():
            raise FileNotFoundError(
                f"No existe {self.repos_path}. Ejecuta primero generate_github_api.py"
            )
        return sorted(p for p in self.repos_path.iterdir() if p.is_dir())

    def detect_language(self, repo_path: Path) -> str | None:
        """Detecta el lenguaje principal contando archivos por extensión."""
        conteo = {}
        for archivo in repo_path.rglob("*"):
            if any(parte in CARPETAS_IGNORADAS for parte in archivo.parts):
                continue
            lenguaje = EXTENSIONES.get(archivo.suffix.lower())
            if lenguaje and archivo.is_file():
                conteo[lenguaje] = conteo.get(lenguaje, 0) + 1
        return max(conteo, key=conteo.get) if conteo else None

    def has_workflows(self, repo_path: Path) -> bool:
        """Revisa si el repositorio tiene workflows de GitHub Actions."""
        carpeta = repo_path / ".github" / "workflows"
        return carpeta.is_dir() and any(carpeta.glob("*.y*ml"))

    def run_codeql(self, repo_path: Path, language: str, sarif_salida: Path) -> None:
        """Crea la base de datos de CodeQL, la analiza y deja el SARIF en sarif_salida."""
        with tempfile.TemporaryDirectory(prefix="codeql-db-") as carpeta_temp:
            db = Path(carpeta_temp) / "db"

            crear = ["codeql", "database", "create", str(db),
                     f"--language={language}", f"--source-root={repo_path}",
                     "--threads=0", "--overwrite"]
            if language != "actions":
                crear.append("--build-mode=none")
            subprocess.run(crear, check=True, capture_output=True, text=True)

            subprocess.run(
                ["codeql", "database", "analyze", str(db), SUITES[language],
                                  "--format=sarif-latest", f"--output={sarif_salida}",
                 "--threads=0", f"--ram={RAM_CODEQL_MB}"],
                check=True, capture_output=True, text=True,
            )

    def parse_sarif(self, sarif_path: Path) -> list[dict]:
        """Convierte el SARIF en una lista de hallazgos normalizados."""
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        hallazgos = []

        for run in sarif.get("runs", []):
            # Las reglas pueden estar en el driver o en las extensiones (query packs)
            reglas = {}
            componentes = [run["tool"]["driver"]] + run["tool"].get("extensions", [])
            for componente in componentes:
                for regla in componente.get("rules", []):
                    reglas[regla["id"]] = regla

            for resultado in run.get("results", []):
                rule_id = resultado.get("ruleId", "unknown")
                regla = reglas.get(rule_id, {})
                propiedades = regla.get("properties", {})

                # Severidad: primero el puntaje de la regla, si no, el nivel del SARIF
                puntaje = propiedades.get("security-severity")
                nivel = resultado.get("level") or \
                    regla.get("defaultConfiguration", {}).get("level", "warning")
                if puntaje is not None:
                    puntaje = float(puntaje)
                    severidad = severidad_desde_puntaje(puntaje)
                else:
                    severidad = SEVERIDAD_POR_NIVEL.get(nivel, "unknown")

                # CWE desde las etiquetas de la regla, por ejemplo "external/cwe/cwe-079"
                cwes = [
                    "CWE-" + str(int(tag.rsplit("-", 1)[1]))
                    for tag in propiedades.get("tags", [])
                    if tag.startswith("external/cwe/cwe-")
                ]

                ubicacion = (resultado.get("locations") or [{}])[0].get("physicalLocation", {})
                region = ubicacion.get("region", {})

                hallazgos.append({
                    "rule_id": rule_id,
                    "rule_name": regla.get("shortDescription", {}).get("text", ""),
                    "severity": severidad,
                    "security_severity": puntaje,
                    "level": nivel,
                    "cwe": ", ".join(cwes) if cwes else None,
                    "message": resultado.get("message", {}).get("text", ""),
                    "file": ubicacion.get("artifactLocation", {}).get("uri"),
                    "start_line": region.get("startLine"),
                    "end_line": region.get("endLine", region.get("startLine")),
                })

        hallazgos.sort(key=lambda h: (h["file"] or "", h["start_line"] or 0, h["rule_id"]))
        return hallazgos

    def analyze(self, repo_path: Path, language: str | None, tipo: str) -> dict:
        """Ejecuta un análisis (código o pipeline) y devuelve el resultado normalizado."""
        nombre = repo_path.name
        resultado = {"repo": nombre, "analysis": tipo, "language": language,
                     "codeql_version": self.version, "status": "ok",
                     "error": None, "total_findings": 0, "findings": []}

        if language is None:
            resultado["status"] = "unsupported" if tipo == "code" else "no_workflows"
            return resultado

        sarif_salida = self.sarif_path / f"{nombre}-{tipo}.sarif"
        try:
            self.run_codeql(repo_path, language, sarif_salida)
            resultado["findings"] = self.parse_sarif(sarif_salida)
            resultado["total_findings"] = len(resultado["findings"])
        except subprocess.CalledProcessError as error:
            resultado["status"] = "codeql_failed"
            resultado["error"] = (error.stderr or "").strip()[-2000:]
        return resultado

    def save(self, resultado: dict, sufijo: str) -> None:
        ruta = self.results_path / f"{resultado['repo']}{sufijo}"
        ruta.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")

    def run(self, overwrite: bool = False) -> list[dict]:
        """Analiza el código y los workflows de cada repositorio clonado."""
        self.sarif_path.mkdir(parents=True, exist_ok=True)
        repos = self.discover_repositories()
        print(f"CodeQL {self.version}")
        resumen = []

        for i, repo_path in enumerate(repos, start=1):
            nombre = repo_path.name
            print(f"[{i}/{len(repos)}] CodeQL: {nombre}")

            for tipo, sufijo in (("code", SUFIJO_CODIGO), ("pipeline", SUFIJO_PIPELINE)):
                salida = self.results_path / f"{nombre}{sufijo}"
                if salida.exists() and not overwrite:
                    print(f"    {tipo}: ya analizado, se omite.")
                    continue

                if tipo == "code":
                    lenguaje = self.detect_language(repo_path)
                else:
                    lenguaje = "actions" if self.has_workflows(repo_path) else None

                print(f"    {tipo}: analizando ({lenguaje or 'sin archivos para analizar'})...")
                resultado = self.analyze(repo_path, lenguaje, tipo)
                self.save(resultado, sufijo)

                if resultado["status"] == "ok":
                    print(f"    {tipo}: {resultado['total_findings']} hallazgos")
                else:
                    print(f"    {tipo}: estado '{resultado['status']}'")
                resumen.append({"repo": nombre, "analysis": tipo, "status": resultado["status"],
                                "findings": resultado["total_findings"]})

        print("Listo: análisis de CodeQL guardados en results/")
        return resumen


if __name__ == "__main__":
    CodeQLAnalyzer(RUTA_REPOS, RUTA_RESULTADOS).run()