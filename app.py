"""Demo de firma digital: SHA-256 + RSA-PSS + PKI (X.509).

Punto de entrada unico.  Ejecutar:  streamlit run app.py

La logica criptografica esta en crypto_core/ (no se toca desde aqui) y la
interfaz esta repartida en ui/: una vista por pestana mas los componentes
comunes (progreso, explicaciones, diagrama).
"""
import streamlit as st

from ui import (
    barra_lateral,
    bienvenida,
    componentes,
    estado,
    vista_claves,
    vista_firmar,
    vista_hash,
    vista_pki,
    vista_verificar,
)

st.set_page_config(page_title="Demo de firma digital", page_icon="🔏", layout="wide")

estado.inicializar()

# Portada: se muestra sola hasta que el usuario elige como empezar.
if not st.session_state.iniciado:
    bienvenida.mostrar()
    st.stop()

barra_lateral.mostrar()

st.title("🔏 Demo de firma digital")
st.caption("SHA-256 · RSA-PSS · Certificados X.509 (PKI). Proyecto académico: "
           "Introducción a la criptografía.")

# Flujo guiado: en que paso estamos y que falta por desbloquear.
componentes.barra_progreso()

with st.expander("🗺️ Ver el diagrama del flujo (se resalta el paso actual)"):
    componentes.diagrama_flujo(estado.paso_actual())

st.divider()

# Las etiquetas de las pestanas son fijas a proposito: si cambiaran en cada
# rerun, Streamlit devolveria al usuario a la primera pestana.
t_hash, t_keys, t_sign, t_verify, t_pki = st.tabs([
    "#️⃣ 1. Hash SHA-256",
    "🔑 2. Claves RSA",
    "✍️ 3. Firmar",
    "🔎 4. Verificar",
    "🏛️ 5. PKI / Certificados",
])

with t_hash:
    vista_hash.mostrar()

with t_keys:
    vista_claves.mostrar()

with t_sign:
    vista_firmar.mostrar()

with t_verify:
    vista_verificar.mostrar()

with t_pki:
    vista_pki.mostrar()
