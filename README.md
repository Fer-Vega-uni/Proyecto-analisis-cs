# **Análisis de vulnerabilidades en repositorios de PyPA**

Proyecto semestral de Ciberseguridad (ICC610), Universidad de La Frontera.  
La solución detecta, analiza y visualiza vulnerabilidades en los repositorios públicos de la [Python Packaging Authority (PyPA)](https://github.com/pypa), el grupo que mantiene las herramientas oficiales de empaquetado de Python (pip, virtualenv, setuptools, entre otras), y además audita la seguridad de este mismo repositorio.

## **Arquitectura**

La solución tiene cuatro componentes separados:

| Componente | Carpeta | Responsabilidad |
| :---- | :---- | :---- |
| Miner | miner/ | Clona los repositorios, ejecuta CodeQL, Syft y Grype, y construye el dataset |
| Analyzer | analyzer/ | Notebooks que estudian el dataset |
| Visualizer | visualizer/ | Interfaz interactiva para explorar los resultados |
| Reporter | .github/aw/ | Audita este repositorio mediante un Agentic Workflow (gh-aw) y genera reportes automáticos en Issues |

Flujo principal: **Miner → Analyzer → Visualizer**, comunicados mediante archivos en results/. El Reporter es independiente y analiza este repositorio directamente mediante flujos agénticos en GitHub Actions.

## **Requisitos**

Solo se necesita instalar en el computador:

> * [Docker Desktop](https://www.docker.com/products/docker-desktop) (en Windows, con WSL 2\)  
> * [Visual Studio Code](https://code.visualstudio.com/) con la extensión **Dev Containers** de Microsoft  
> * [GitHub CLI (gh)](https://cli.github.com/) con la extensión github/gh-aw instalada (gh extension install github/gh-aw) para la compilación de flujos del Reporter.

Todo lo demás (CodeQL, Syft, Grype, Python, Node y las bibliotecas) se instala automáticamente dentro del contenedor.  
**Windows:** si Docker Desktop muestra *"Virtualization support not detected"*, ejecutar en PowerShell como administrador wsl \--install \--no-distribution y reiniciar.

## **Puesta en marcha**

> 1. Clonar el repositorio y abrir la carpeta en VS Code.  
> 2. Con Docker Desktop abierto, presionar Ctrl+Shift+P y elegir **Dev Containers: Reopen in Container**.  
> 3. Esperar a que termine la construcción. La primera vez tarda entre 10 y 20 minutos; al final, la terminal muestra las versiones de las herramientas.

| Herramienta | Versión |
| :---- | :---- |
| CodeQL | 2.27.1 |
| Syft | 1.54.0 |
| Grype | 0.120.0 |
| Python | 3.13 |
| Node.js | 20 |

### **Credenciales**

Las credenciales nunca se guardan en el repositorio. Se configuran en un archivo .env (incluido en .gitignore) a partir de la plantilla .env.example:  
cp .env.example .env

> * **GITHUB\_TOKEN** *(opcional)*: token personal de GitHub de solo lectura de repositorios públicos ([crear aquí](https://github.com/settings/personal-access-tokens/new)). Sin token, el Miner funciona igual, pero con el límite de 60 peticiones por hora de la API de GitHub.  
> * **OPENAI\_API\_KEY** *(opcional para Reporter)*: API Key configurada como un *Repository Secret* en GitHub Actions para el motor del Agentic Workflow (ej. OpenRouter).

## **Miner**

### **Ejecución**

.venv/bin/python miner/main.py \# procesa todos los repositorios útiles  
.venv/bin/python miner/main.py 3 \# procesa solo 3 (para pruebas)  
Cada paso omite lo que ya fue procesado, así que si la ejecución se interrumpe basta con volver a ejecutarla. Para reprocesar un repositorio, se borran sus archivos en results/.

### **Pasos**

| Paso | Archivo | Salida |
| :---- | :---- | :---- |
| 1\. Obtener y clonar repositorios | generate\_github\_api.py | miner/repos/, results/repos.json |
| 2\. Generar SBOM | generate\_sboms.py | results/\<repo\>-sbom.json |
| 3\. Analizar código y workflows | generate\_codeql.py | results/\<repo\>-codeql.json, results/\<repo\>-pipeline.json, results/sarif/ |
| 4\. Analizar dependencias | generate\_grype.py | results/\<repo\>-grype.json |
| 5\. Construir el dataset | build\_dataset.py | results/dataset/findings.csv, results/dataset/repos.csv |

La ejecución completa sobre los 38 repositorios de PyPA toma alrededor de 30 minutos (la mayor parte corresponde a CodeQL).

### **Dataset**

El dataset está en results/dataset/ y se puede cargar directamente con pandas:  
import pandas as pd  
findings \= pd.read\_csv("results/dataset/findings.csv")  
repos \= pd.read\_csv("results/dataset/repos.csv")  
**findings.csv**: una fila por hallazgo.

| Columna | Descripción |
| :---- | :---- |
| repo | Repositorio de origen |
| tool | codeql o grype |
| finding\_type | code (código fuente), ci (workflows de GitHub Actions) o dependency (dependencias) |
| vuln\_id | Regla de CodeQL (ej. py/reflective-xss) o ID de la vulnerabilidad (ej. GHSA-...) |
| title | Nombre de la regla, o paquete y versión |
| cwe | Tipo de debilidad (ej. CWE-79); solo CodeQL |
| cve | CVE asociado; solo Grype |
| severity | critical, high, medium, low, negligible o unknown |
| score | Puntaje numérico de 0 a 10 (security-severity en CodeQL, CVSS en Grype) |
| file | Archivo donde está el hallazgo (o manifiesto donde se declara la dependencia) |
| start\_line | Línea del hallazgo; solo CodeQL |
| area | source (código o dependencias propias), vendor (código de terceros copiado dentro del repo), test, docs, example o ci, según la carpeta del archivo |
| package, version, ecosystem | Dependencia afectada; solo Grype |
| fix\_versions | Versión que corrige la vulnerabilidad; solo Grype |
| message | Descripción del hallazgo |

**repos.csv**: una fila por repositorio analizado, incluidos los que no tienen hallazgos. Contiene URL, lenguaje según GitHub (language), lenguaje analizado por CodeQL (analyzed\_language), estrellas, commit analizado (commit\_sha), número de dependencias (packages), estado de cada herramienta y conteos de hallazgos por tipo y por severidad.

### **Resultados**

Se analizaron 38 repositorios (37 en Python y 1 en TypeScript) y se obtuvieron 311 hallazgos: 3 critical, 120 high, 161 medium y 27 low.

| Tipo | Hallazgos | Detalle por área |
| :---- | :---- | :---- |
| Código (CodeQL) | 77 | 18 en código propio, 42 en pruebas, 17 en código de terceros copiado (vendor) |
| Workflows de CI/CD (CodeQL) | 78 | Todos en .github/workflows |
| Dependencias (Grype) | 156 | 129 en manifiestos del proyecto, 27 en archivos de ejemplo |

28 de los 38 repositorios tienen al menos un hallazgo.

### **Decisiones de diseño**

> * **Organización:** primero se analizó [Scrapy](https://github.com/scrapy) (26 repositorios), pero entregó solo 38 hallazgos, concentrados en 2 repositorios. Se probaron Jazzband y PyPA con sus 3 repositorios más populares, y se eligió PyPA por la cantidad de hallazgos y por su relevancia: sus herramientas forman parte de la cadena de suministro de casi todo el software de Python. Los resultados de Scrapy se conservan en la etiqueta analisis-scrapy del repositorio.  
> * **Selección de repositorios:** se excluyen forks, repositorios archivados y repositorios sin código Python, JavaScript o TypeScript. Como GitHub asigna el lenguaje principal según los bytes de cada lenguaje, algunas librerías de Python quedan etiquetadas como HTML por sus archivos de prueba; en esos casos el Miner consulta los lenguajes reales del repositorio. Se descartan los lenguajes compilados (C, C++, Shell, etc.), que CodeQL solo puede analizar compilando el proyecto. De los 59 repositorios de PyPA quedan 38, todos dentro del límite de 50, por lo que se analiza la totalidad de los repositorios útiles.  
> * **Reproducibilidad:** las herramientas tienen versiones fijas, los repositorios se clonan con \--depth 1 y se registra el commit exacto analizado de cada uno.  
> * **CodeQL:** se usa la suite security-extended, que se enfoca en seguridad con pocos falsos positivos. Además del código fuente, se analizan los workflows de GitHub Actions para detectar problemas en CI/CD.  
> * **Severidad:** en CodeQL se usa el puntaje security-severity de cada regla (≥ 9 critical, ≥ 7 high, ≥ 4 medium, \> 0 low), en vez del nivel genérico del SARIF. En Grype se usa la severidad que entrega la herramienta, y el CVSS se guarda aparte. Ambas quedan en la misma escala.  
> * **Syft y Grype:** Grype analiza el SBOM generado por Syft, de modo que ambas herramientas trabajan sobre el mismo inventario de dependencias.  
> * **Área del hallazgo:** cada hallazgo se clasifica según su ubicación (source, vendor, test, docs, example, ci), para distinguir el código propio de las pruebas, los ejemplos y el código de terceros.  
> * **Evidencia:** se conservan los SARIF originales de CodeQL en results/sarif/ para que cada hallazgo pueda verificarse.

### **Limitaciones conocidas**

> * **Código copiado (vendoring):** pip incluye copias de otras librerías en src/pip/\_vendor/, y pipenv incluye una copia completa de pip. CodeQL detecta los mismos hallazgos en cada copia, por lo que algunos se repiten entre repositorios. Estas copias no aparecen como dependencias declaradas, así que Syft y Grype no las registran.  
> * **Grype solo compara versiones exactas:** los proyectos que fijan versiones (por ejemplo con uv.lock o requirements.txt con \==) muestran más vulnerabilidades que los que declaran rangos (\>=), aunque fijar versiones sea una mejor práctica. La cantidad de vulnerabilidades de dependencias refleja en parte cuánta información de versiones tiene cada repositorio.  
> * **Archivos de ejemplo:** algunos hallazgos de dependencias provienen de archivos de ejemplo (como examples/Pipfile.lock en pipfile); se identifican con el área example.  
> * **Lenguaje principal:** CodeQL analiza solo el lenguaje principal de cada repositorio.  
> * La severidad de Grype (tomada de GitHub Advisories) y el CVSS (que puede venir de NVD) a veces no coinciden, porque provienen de fuentes distintas.

## **Analyzer**

El módulo Analyzer procesa los datasets consolidados (findings.csv y los reportes individuales en results/) para calcular distribuciones estadísticas y matrices de riesgo.

### **Ejecución y Generación de Datasets**

Los notebooks de análisis están ubicados en la carpeta analyzer/ y en la raíz (analyzer.ipynb). Para ejecutar el flujo de agregación:

> 1. Abre el notebook analyzer.ipynb en VS Code.  
> 2. Ejecuta todas las celdas (*Run All*).

El notebook procesa los hallazgos y exporta los siguientes archivos JSON en results/tool-analysis/:

> * **severity\_summary.json**: Conteo global de vulnerabilidades por nivel de severidad (critical, high, medium, low).  
> * **tool\_summary.json**: Distribución de hallazgos entre herramientas SAST (CodeQL) y SCA (Grype).  
> * **top\_repos.json**: Listado de los repositorios con mayor concentración de riesgo y vulnerabilidades.  
> * **ecosystem\_summary.json**: Desglose de afectación por entornos/ecosistemas.

## **Visualizer**

El módulo Visualizer es un dashboard web interactivo e independiente construido con **HTML5, CSS3 y D3.js (v7)**. Permite explorar visualmente los patrones de seguridad identificados.

### **Puesta en Marcha**

Para abrir la interfaz interactiva desde el contenedor:

> 1. Abre la terminal en VS Code y ejecuta el servidor local de Python:  
>    python \-m http.server 8000  
> 2. Abre tu navegador e ingresa a:  
>    http\://localhost:8000/visualizer/

### **Componentes de la Interfaz**

> * **Indicadores Clave (KPIs):** Resumen de total de hallazgos (311), repositorios auditados (28) y nivel de riesgo predominante (MEDIUM \- 51.8%).  
> * **Distribución de Vulnerabilidades:** Gráficos de barras interactivos por severidad.  
> * **Proporción SAST vs SCA:** Gráfico circular (Donut) con despiece proporcional entre CodeQL y Grype.  
> * **Matriz de Severidad por Herramienta:** Gráfico de barras horizontales apiladas que cruza el origen del hallazgo con la severidad.  
> * **Top Repositorios:** Tabla detallada de los proyectos más vulnerables (setuptools-scm, browntruck, hatch, etc.) con badge de riesgo y conteos.

## **Reporter**

El módulo Reporter audita la seguridad de este mismo repositorio mediante **GitHub Agentic Workflows (gh-aw)**. A diferencia de los análisis locales tradicionales, ejecuta un agente autónomo de IA integrado directamente dentro de GitHub Actions.

### **Definición de Flujos Agénticos**

Los archivos de definición de los flujos agénticos se encuentran en la carpeta .github/aw/:

> * **security-scan-copilot.md**: Flujo agéntico configurado para ejecutarse con el motor de GitHub Copilot (gpt-4.1).  
> * **security-scan-openrouter.md**: Flujo agéntico configurado para conectarse con modelos externos vía OpenRouter (ej. openai/gpt-5.6-luna).

### **Compilación y Puesta en Marcha**

> 1. **Compilar flujos agénticos:**  
>    Cada vez que se modifica la definición en Markdown dentro de .github/aw/, se debe compilar el flujo con la CLI de gh-aw:  
>    gh aw compile \--approve  
>    Esto generará los workflows ejecutables correspondientes dentro de .github/workflows/.  
> 2. **Ejecución en GitHub Actions:**  
   * Sube los cambios al repositorio (git push origin main).  
   * Ve a la pestaña **Actions** en el repositorio de GitHub.  
   * Selecciona el flujo deseado (security-scan-copilot o security-scan-openrouter) y haz clic en **Run workflow**.  
> 3. **Publicación de Resultados:**  
>    El agente agéntico analiza la totalidad del código fuente, configuraciones y dependencias del repositorio y utiliza la acción create\_issue para publicar automáticamente un **Issue de GitHub** estructurado en español con el Resumen Ejecutivo, Puntuación de Seguridad y Hallazgos Detallados con Trazabilidad.