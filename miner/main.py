"""
Miner: ejecuta el proceso completo de extracción sobre la organización.

Pasos:
1. Obtiene y clona los repositorios (API de GitHub).
2. Genera el SBOM de cada repositorio (Syft).
3. Analiza el código fuente y los workflows (CodeQL).
4. Busca vulnerabilidades en las dependencias (Grype).

Cada paso omite lo que ya fue procesado, así que si la ejecución se
interrumpe, basta con volver a ejecutarla para continuar donde quedó.

Uso:
    .venv/bin/python miner/main.py          -> todos los repos útiles (máximo 50)
    .venv/bin/python miner/main.py 3        -> solo 3 repos (para pruebas)
"""

import sys
import time

from generate_github_api import (GetReposGitHubAPI, ORGANIZACION, MAXIMO_REPOS,
                                 RUTA_REPOS, RUTA_RESULTADOS)
from generate_sboms import SBOMGenerator
from generate_codeql import CodeQLAnalyzer
from generate_grype import GrypeAnalyzer


def paso(numero: int, titulo: str) -> float:
    print(f"\n========== Paso {numero}: {titulo} ==========")
    return time.time()


def fin(inicio: float) -> None:
    minutos = (time.time() - inicio) / 60
    print(f"---------- Tiempo del paso: {minutos:.1f} minutos ----------")


def main():
    cantidad = int(sys.argv[1]) if len(sys.argv) > 1 else MAXIMO_REPOS
    inicio_total = time.time()

    t = paso(1, f"Obtener y clonar repositorios de '{ORGANIZACION}'")
    GetReposGitHubAPI(RUTA_REPOS, RUTA_RESULTADOS, ORGANIZACION).run(cantidad)
    fin(t)

    t = paso(2, "Generar SBOMs con Syft")
    SBOMGenerator(RUTA_REPOS, RUTA_RESULTADOS).run()
    fin(t)

    t = paso(3, "Analizar código y workflows con CodeQL")
    CodeQLAnalyzer(RUTA_REPOS, RUTA_RESULTADOS).run()
    fin(t)

    t = paso(4, "Analizar dependencias con Grype")
    GrypeAnalyzer(RUTA_RESULTADOS).run()
    fin(t)

    total = (time.time() - inicio_total) / 60
    print(f"\nMiner terminado en {total:.1f} minutos. Resultados en results/")


if __name__ == "__main__":
    main()