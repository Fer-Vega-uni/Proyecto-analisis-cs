FROM mcr.microsoft.com/devcontainers/python:3.13-bookworm

# Versiones fijas para que el entorno sea reproducible
ARG CODEQL_VERSION=2.27.1
ARG SYFT_VERSION=1.54.0
ARG GRYPE_VERSION=0.120.0

# Syft y Grype: instalador oficial de Anchore, tomado del tag de la versión (no de main)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/v${SYFT_VERSION}/install.sh \
        | sh -s -- -b /usr/local/bin v${SYFT_VERSION} \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/v${GRYPE_VERSION}/install.sh \
        | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}

# CodeQL bundle: incluye la CLI y los query packs (Python, JavaScript, Actions, etc.)
RUN curl -sSfL https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz \
        -o /tmp/codeql.tar.gz \
    && tar -xzf /tmp/codeql.tar.gz -C /opt \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && rm /tmp/codeql.tar.gz

# Verificación de herramientas instaladas
RUN codeql version && syft version && grype version