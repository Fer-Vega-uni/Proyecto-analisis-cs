"""
Obtención y clonación de repositorios de GitHub.

Proceso:
1. Consulta la API de GitHub para listar los repositorios públicos de la organización.
2. Filtra los repositorios útiles: sin forks, sin archivados y con lenguaje soportado.
3. Ordena por estrellas (más populares primero) y toma hasta la cantidad pedida.
4. Clona cada repositorio (solo el último commit) en miner/repos/.
5. Guarda los metadatos de cada repo en results/repos.json.

Token de GitHub:
    Es opcional. Si existe GITHUB_TOKEN en el archivo .env, se usa para evitar
    el límite de peticiones de GitHub. Si no existe, funciona igual sin token.

Uso:
    .venv/bin/python miner/generate_github_api.py          -> procesa todos los repos útiles
    .venv/bin/python miner/generate_github_api.py 2        -> procesa solo 2 (para pruebas)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_REPOS = RUTA_BASE / "miner" / "repos"
RUTA_RESULTADOS = RUTA_BASE / "results"

ORGANIZACION = "scrapy"
LENGUAJES_SOPORTADOS = ["Python", "JavaScript", "TypeScript"]
MINIMO_REPOS = 20
MAXIMO_REPOS = 50


class GetReposGitHubAPI:
    def __init__(self, repos_path: Path, results_path: Path, github_org: str):
        self.repos_path = Path(repos_path)
        self.results_path = Path(results_path)
        self.github_org = github_org

        load_dotenv(RUTA_BASE / ".env")
        token = os.getenv("GITHUB_TOKEN", "").strip()

        self.headers = {"Accept": "application/vnd.github+json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
            print("Usando token de GitHub desde .env")
        else:
            print("AVISO: no se encontró GITHUB_TOKEN. Se usará la API sin autenticar "
                  "(límite de 60 peticiones por hora).")

    def get_all_repos(self) -> list[dict]:
        """Obtiene todos los repositorios públicos de la organización, página por página."""
        repos = []
        page = 1

        while True:
            url = f"https://api.github.com/orgs/{self.github_org}/repos"
            params = {"type": "public", "per_page": 100, "page": page}
            response = requests.get(url, headers=self.headers, params=params, timeout=30)

            if response.status_code != 200:
                raise Exception(
                    f"Error al obtener repositorios ({response.status_code}): "
                    f"{response.json().get('message', '')}"
                )

            pagina = response.json()
            if not pagina:
                break

            repos.extend(pagina)
            page += 1

        return repos

    def filter_useful_repos(self, repos: list[dict], incluir_archivados: bool = False) -> list[dict]:
        """Filtra repos sin forks, con lenguaje soportado y, opcionalmente, sin archivados."""
        utiles = []
        for repo in repos:
            if repo["fork"]:
                continue
            if repo["archived"] and not incluir_archivados:
                continue
            if repo["language"] not in LENGUAJES_SOPORTADOS:
                continue
            utiles.append(repo)
        return utiles

    def get_useful_repos(self, quantity: int) -> list[dict]:
        """Devuelve los repos útiles ordenados por estrellas, hasta la cantidad pedida."""
        todos = self.get_all_repos()
        print(f"La organización '{self.github_org}' tiene {len(todos)} repositorios públicos.")

        utiles = self.filter_useful_repos(todos)
        print(f"Repositorios útiles (sin forks ni archivados): {len(utiles)}")

        # Si no alcanzan el mínimo, se agregan también los archivados
        if len(utiles) < MINIMO_REPOS:
            utiles = self.filter_useful_repos(todos, incluir_archivados=True)
            print(f"Menos de {MINIMO_REPOS}: se incluyen archivados. Total: {len(utiles)}")

        utiles.sort(key=lambda r: r["stargazers_count"], reverse=True)
        return utiles[:quantity]

    def clone_repo(self, repo_url: str, destination: Path) -> None:
        """Clona solo el último commit del repositorio."""
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", repo_url, str(destination)],
            check=True,
        )

    def get_commit_sha(self, repo_path: Path) -> str:
        """Obtiene el SHA del commit clonado, para que el análisis sea reproducible."""
        resultado = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path, capture_output=True, text=True, check=True,
        )
        return resultado.stdout.strip()

    def save_metadata(self, metadata: list[dict]) -> None:
        """Guarda los metadatos de los repos procesados en results/repos.json."""
        self.results_path.mkdir(parents=True, exist_ok=True)
        ruta = self.results_path / "repos.json"
        ruta.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Metadatos guardados en {ruta.relative_to(RUTA_BASE)}")

    def run(self, quantity: int = MAXIMO_REPOS) -> list[dict]:
        """Ejecuta el proceso completo de obtención y clonación."""
        self.repos_path.mkdir(parents=True, exist_ok=True)
        useful_repos = self.get_useful_repos(quantity)
        metadata = []

        for i, repo in enumerate(useful_repos, start=1):
            nombre = repo["name"]
            destino = self.repos_path / nombre
            print(f"[{i}/{len(useful_repos)}] {nombre} ({repo['stargazers_count']} estrellas)")

            estado = "ok"
            sha = None
            try:
                if destino.exists():
                    print("    Ya estaba clonado, se omite la clonación.")
                else:
                    self.clone_repo(repo["clone_url"], destino)
                sha = self.get_commit_sha(destino)
            except subprocess.CalledProcessError as error:
                estado = "clone_failed"
                print(f"    ERROR al clonar: {error}")

            metadata.append({
                "repo": nombre,
                "full_name": repo["full_name"],
                "url": repo["html_url"],
                "language": repo["language"],
                "stars": repo["stargazers_count"],
                "archived": repo["archived"],
                "commit_sha": sha,
                "clone_status": estado,
            })

        self.save_metadata(metadata)
        clonados = sum(1 for m in metadata if m["clone_status"] == "ok")
        print(f"Listo: {clonados} de {len(metadata)} repositorios disponibles en miner/repos/")
        return metadata


if __name__ == "__main__":
    cantidad = int(sys.argv[1]) if len(sys.argv) > 1 else MAXIMO_REPOS
    GetReposGitHubAPI(RUTA_REPOS, RUTA_RESULTADOS, ORGANIZACION).run(cantidad)