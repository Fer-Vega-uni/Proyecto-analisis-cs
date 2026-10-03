#!/usr/bin/env bash
set -e

echo "==> Creando entorno virtual de Python"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "==> Registrando kernel de Jupyter"
.venv/bin/python -m ipykernel install --user --name proyecto --display-name "Python (proyecto)"

echo "==> Descargando base de datos de vulnerabilidades de Grype"
grype db update || echo "AVISO: no se pudo actualizar la base de Grype; se intentará al ejecutar el Miner."

echo "==> Herramientas disponibles"
codeql version | head -1
syft version | grep -i "^Version"
grype version | grep -i "^Version"
python3 --version
node --version