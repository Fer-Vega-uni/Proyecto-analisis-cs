import streamlit as st
import pandas as pd
import json
import plotly.express as px
from pathlib import Path

# Configuración de la página
st.set_page_config(
    page_title="Dashboard de Seguridad - Módulo Visualizer",
    page_icon="🛡️",
    layout="wide"
)

# Rutas dinámicas para encontrar la carpeta de resultados
BASE_DIR = Path(__file__).resolve().parent.parent
ANALYSIS_DIR = BASE_DIR / "results" / "tool-analysis"

@st.cache_data
def load_json(filename):
    filepath = ANALYSIS_DIR / filename
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            return pd.DataFrame(json.load(f))
    return pd.DataFrame()

# Carga de datasets JSON generados por el Analyzer
df_sev = load_json("severity_summary.json")
df_tool = load_json("tool_summary.json")
df_repos = load_json("top_repos.json")
df_rules = load_json("top_rules.json")

# Encabezado principal
st.title("🛡️ Dashboard de Seguridad y Vulnerabilidades")
st.markdown("**Visualización interactiva de hallazgos para 28 repositorios (CodeQL & Grype)**")
st.divider()

# Cifras Clave (KPIs)
if not df_sev.empty:
    total_findings = df_sev["count"].sum()
    crit = df_sev[df_sev["severity"] == "critical"]["count"].sum() if "critical" in df_sev["severity"].values else 0
    high = df_sev[df_sev["severity"] == "high"]["count"].sum() if "high" in df_sev["severity"].values else 0
    med = df_sev[df_sev["severity"] == "medium"]["count"].sum() if "medium" in df_sev["severity"].values else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Hallazgos", total_findings)
    col2.metric("Críticos 🚨", crit)
    col3.metric("Altos ⚠️", high)
    col4.metric("Medios 🟡", med)

st.divider()

# Gráficos en columnas
c1, c2 = st.columns(2)

with c1:
    st.subheader("📊 Distribución por Severidad")
    if not df_sev.empty:
        color_map = {'critical': '#d9534f', 'high': '#f0ad4e', 'medium': '#5bc0de', 'low': '#5cb85c'}
        fig_sev = px.bar(
            df_sev, 
            x="severity", 
            y="count", 
            color="severity",
            color_discrete_map=color_map,
            text_auto=True,
            labels={"severity": "Severidad", "count": "Cantidad"}
        )
        fig_sev.update_layout(showlegend=False)
        st.plotly_chart(fig_sev, use_container_width=True)

with c2:
    st.subheader("🛠️ Cobertura: CodeQL vs Grype")
    if not df_tool.empty:
        fig_tool = px.pie(
            df_tool, 
            names="tool", 
            values="count", 
            hole=0.4,
            color_discrete_sequence=['#3498db', '#e67e22']
        )
        st.plotly_chart(fig_tool, use_container_width=True)

st.divider()

c3, c4 = st.columns(2)

with c3:
    st.subheader("🏢 Top 5 Repositorios con Mayor Riesgo")
    if not df_repos.empty:
        fig_repos = px.bar(
            df_repos, 
            x="count", 
            y="repo_name", 
            orientation="h",
            color="count", 
            color_continuous_scale="Reds",
            text_auto=True,
            labels={"count": "Hallazgos", "repo_name": "Repositorio"}
        )
        fig_repos.update_layout(yaxis=dict(autorange="reversed"), showlegend=False)
        st.plotly_chart(fig_repos, use_container_width=True)

with c4:
    st.subheader("⚠️ Top 10 Reglas / CWEs Más Frecuentes")
    if not df_rules.empty:
        fig_rules = px.bar(
            df_rules, 
            x="count", 
            y="rule_or_cwe", 
            orientation="h",
            color="count", 
            color_continuous_scale="Blues",
            text_auto=True,
            labels={"count": "Ocurrencias", "rule_or_cwe": "CWE / Regla"}
        )
        fig_rules.update_layout(yaxis=dict(autorange="reversed"), showlegend=False)
        st.plotly_chart(fig_rules, use_container_width=True)