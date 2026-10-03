"""
Generación de SBOMs (Software Bill of Materials) con Syft.

Proceso:
1. Recorre cada repositorio clonado en miner/repos/.
2. Ejecuta Syft sobre el directorio del repositorio.
3. Guarda el SBOM en results/<repo>-sbom.json (formato syft-json).

El SBOM generado aquí es el que después usa Grype para buscar
vulnerabilidades en las dependencias, así ambas herramientas
analizan exactamente el mismo inventario.

Uso:
    .venv/bin/python miner/generate_sboms.py
"""

import json
import subprocess
from pathlib import Path

RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_REPOS = RUTA_BASE / "miner" / "repos"
RUTA_RESULTADOS = RUTA_BASE / "results"

SUFIJO_SBOM = "-sbom.json"
FORMATO_SYFT = "syft-json"


class SBOMGenerator:
    def __init__(self, repos_path: Path, results_path: Path):
        self.repos_path = Path(repos_path)
        self.results_path = Path(results_path)

    def discover_repositories(self) -> list[Path]:
        """Lista las carpetas de repositorios clonados, en orden alfabético."""
        if not self.repos_path.exists():
            raise FileNotFoundError(
                f"No existe {self.repos_path}. Ejecuta primero generate_github_api.py"
            )
        return sorted(p for p in self.repos_path.iterdir() if p.is_dir())

    def generate_sbom(self, repo_path: Path) -> Path:
        """Ejecuta Syft sobre un repositorio y guarda el SBOM en results/."""
        salida = self.results_path / f"{repo_path.name}{SUFIJO_SBOM}"
        subprocess.run(
            ["syft", f"dir:{repo_path}", "-o", f"{FORMATO_SYFT}={salida}", "-q"],
            check=True,
            capture_output=True,
            text=True,
        )
        return salida

    def count_packages(self, sbom_path: Path) -> int:
        """Cuenta cuántos paquetes (dependencias) encontró Syft."""
        datos = json.loads(sbom_path.read_text(encoding="utf-8"))
        return len(datos.get("artifacts", []))

    def run(self, overwrite: bool = False) -> list[dict]:
        """Genera el SBOM de cada repositorio clonado."""
        self.results_path.mkdir(parents=True, exist_ok=True)
        repos = self.discover_repositories()
        resumen = []

        for i, repo_path in enumerate(repos, start=1):
            nombre = repo_path.name
            salida = self.results_path / f"{nombre}{SUFIJO_SBOM}"
            print(f"[{i}/{len(repos)}] Syft: {nombre}")

            if salida.exists() and not overwrite:
                print("    SBOM ya existe, se omite.")
                estado = "ok"
            else:
                try:
                    self.generate_sbom(repo_path)
                    estado = "ok"
                except subprocess.CalledProcessError as error:
                    estado = "sbom_failed"
                    print(f"    ERROR en Syft: {error.stderr.strip()}")

            paquetes = self.count_packages(salida) if estado == "ok" else 0
            if estado == "ok":
                print(f"    {paquetes} paquetes encontrados")
            resumen.append({"repo": nombre, "sbom_status": estado, "packages": paquetes})

        generados = sum(1 for r in resumen if r["sbom_status"] == "ok")
        print(f"Listo: {generados} de {len(resumen)} SBOMs en results/")
        return resumen


if __name__ == "__main__":
    SBOMGenerator(RUTA_REPOS, RUTA_RESULTADOS).run()