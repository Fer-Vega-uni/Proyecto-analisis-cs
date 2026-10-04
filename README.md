# Análisis de vulnerabilidades en repositorios de Scrapy

Proyecto semestral de Ciberseguridad (ICC610), Universidad de La Frontera.

La solución detecta, analiza y visualiza vulnerabilidades en los repositorios públicos de la organización [Scrapy](https://github.com/scrapy), y además audita la seguridad de este mismo repositorio.

## Arquitectura

La solución tiene cuatro componentes separados:

| Componente | Carpeta | Responsabilidad |
|---|---|---|
| Miner | `miner/` | Clona los repositorios, ejecuta CodeQL, Syft y Grype, y construye el dataset |
| Analyzer | `analyzer/` | Notebooks que estudian el dataset |
| Visualizer | `visualizer/` | Interfaz interactiva para explorar los resultados |
| Reporter | *(por definir)* | Audita este repositorio y genera un reporte con un modelo de lenguaje |

Flujo principal: **Miner → Analyzer → Visualizer**, comunicados mediante archivos en `results/`. El Reporter es independiente y analiza este repositorio directamente.

## Requisitos

Solo se necesita instalar en el computador:

- [Docker Desktop](https://www.docker.com/products/docker-desktop) (en Windows, con WSL 2)
- [Visual Studio Code](https://code.visualstudio.com/) con la extensión **Dev Containers** de Microsoft

Todo lo demás (CodeQL, Syft, Grype, Python, Node y las bibliotecas) se instala automáticamente dentro del contenedor.

> **Windows:** si Docker Desktop muestra *"Virtualization support not detected"*, ejecutar en PowerShell como administrador `wsl --install --no-distribution` y reiniciar.

## Puesta en marcha

1. Clonar el repositorio y abrir la carpeta en VS Code.
2. Con Docker Desktop abierto, presionar `Ctrl+Shift+P` y elegir **Dev Containers: Reopen in Container**.
3. Esperar a que termine la construcción. La primera vez tarda entre 10 y 20 minutos; al final, la terminal muestra las versiones de las herramientas.

| Herramienta | Versión |
|---|---|
| CodeQL | 2.27.1 |
| Syft | 1.54.0 |
| Grype | 0.120.0 |
| Python | 3.13 |
| Node.js | 20 |

### Credenciales

Las credenciales nunca se guardan en el repositorio. Se configuran en un archivo `.env` (incluido en `.gitignore`) a partir de la plantilla `.env.example`:

```bash
cp .env.example .env
```

- **`GITHUB_TOKEN`** *(opcional)*: token personal de GitHub de solo lectura de repositorios públicos ([crear aquí](https://github.com/settings/personal-access-tokens/new)). Sin token, el Miner funciona igual, pero con el límite de 60 peticiones por hora de la API de GitHub.

## Miner

### Ejecución

```bash
.venv/bin/python miner/main.py        # procesa todos los repositorios útiles
.venv/bin/python miner/main.py 3      # procesa solo 3 (para pruebas)
```

Cada paso omite lo que ya fue procesado, así que si la ejecución se interrumpe basta con volver a ejecutarla. Para reprocesar un repositorio, se borran sus archivos en `results/`.

### Pasos

| Paso | Archivo | Salida |
|---|---|---|
| 1. Obtener y clonar repositorios | `generate_github_api.py` | `miner/repos/`, `results/repos.json` |
| 2. Generar SBOM | `generate_sboms.py` | `results/<repo>-sbom.json` |
| 3. Analizar código y workflows | `generate_codeql.py` | `results/<repo>-codeql.json`, `results/<repo>-pipeline.json`, `results/sarif/` |
| 4. Analizar dependencias | `generate_grype.py` | `results/<repo>-grype.json` |
| 5. Construir el dataset | `build_dataset.py` | `results/dataset/findings.csv`, `results/dataset/repos.csv` |

La ejecución completa sobre los 22 repositorios toma alrededor de 15 minutos.

### Dataset

El dataset está en `results/dataset/` y se puede cargar directamente con pandas:

```python
import pandas as pd
findings = pd.read_csv("results/dataset/findings.csv")
repos = pd.read_csv("results/dataset/repos.csv")
```

**`findings.csv`**: una fila por hallazgo.

| Columna | Descripción |
|---|---|
| `repo` | Repositorio de origen |
| `tool` | `codeql` o `grype` |
| `finding_type` | `code` (código fuente), `ci` (workflows de GitHub Actions) o `dependency` (dependencias) |
| `vuln_id` | Regla de CodeQL (ej. `py/reflective-xss`) o ID de la vulnerabilidad (ej. `GHSA-...`) |
| `title` | Nombre de la regla, o paquete y versión |
| `cwe` | Tipo de debilidad (ej. `CWE-79`); solo CodeQL |
| `cve` | CVE asociado; solo Grype |
| `severity` | `critical`, `high`, `medium`, `low`, `negligible` o `unknown` |
| `score` | Puntaje numérico de 0 a 10 (`security-severity` en CodeQL, CVSS en Grype) |
| `file` | Archivo donde está el hallazgo (o manifiesto donde se declara la dependencia) |
| `start_line` | Línea del hallazgo; solo CodeQL |
| `area` | `source`, `test`, `docs`, `example` o `ci`, según la carpeta del archivo |
| `package`, `version`, `ecosystem` | Dependencia afectada; solo Grype |
| `fix_versions` | Versión que corrige la vulnerabilidad; solo Grype |
| `message` | Descripción del hallazgo |

**`repos.csv`**: una fila por repositorio analizado, incluidos los que no tienen hallazgos. Contiene URL, lenguaje, estrellas, commit analizado (`commit_sha`), número de dependencias (`packages`), estado de cada herramienta y conteos de hallazgos por tipo y por severidad.

### Decisiones de diseño

- **Organización:** Scrapy fue elegida porque sus repositorios están escritos principalmente en Python, lo que permite analizarlos con CodeQL sin compilar.
- **Selección de repositorios:** se excluyen forks y repositorios archivados, y se consideran solo los de Python, JavaScript o TypeScript, ordenados por estrellas. Con estos filtros quedan 22 repositorios. Si fueran menos de 20, el Miner incluye automáticamente los archivados.
- **Reproducibilidad:** las herramientas tienen versiones fijas, los repositorios se clonan con `--depth 1` y se registra el commit exacto analizado de cada uno.
- **CodeQL:** se usa la suite `security-extended`, que se enfoca en seguridad con pocos falsos positivos. Además del código fuente, se analizan los workflows de GitHub Actions para detectar problemas en CI/CD.
- **Severidad:** en CodeQL se usa el puntaje `security-severity` de cada regla (≥ 9 critical, ≥ 7 high, ≥ 4 medium, > 0 low), en vez del nivel genérico del SARIF. En Grype se usa la severidad que entrega la herramienta, y el CVSS se guarda aparte. Ambas quedan en la misma escala.
- **Syft y Grype:** Grype analiza el SBOM generado por Syft, de modo que ambas herramientas trabajan sobre el mismo inventario de dependencias.
- **Evidencia:** se conservan los SARIF originales de CodeQL en `results/sarif/` para que cada hallazgo pueda verificarse.

### Limitaciones conocidas

- Grype solo puede comparar versiones exactas. Como la mayoría de las librerías de Python declaran rangos de versiones (ej. `lxml>=4.6`), las dependencias detectadas como vulnerables provienen casi solo de archivos con versiones fijas, como `docs/requirements.txt`.
- La severidad de Grype (tomada de GitHub Advisories) y el CVSS (que puede venir de NVD) a veces no coinciden, porque provienen de fuentes distintas.

## Analyzer

*(Por completar)*

## Visualizer

*(Por completar)*

## Reporter

*(Por completar)*