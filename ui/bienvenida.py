"""Pantalla de inicio: contexto en pocas lineas y dos formas de arrancar."""
import streamlit as st

from . import estado


def mostrar() -> None:
    """Portada de la demo. Devuelve el control solo si el usuario ya arranco."""
    st.title("🔏 Demo de firma digital")
    st.caption("SHA-256 · RSA-PSS · Certificados X.509 (PKI) — Proyecto académico "
               "de Introducción a la criptografía.")

    st.markdown(
        """
Esta app demuestra, paso a paso, **cómo se firma digitalmente un documento y cómo
se detecta si alguien lo alteró**. Vas a generar un par de claves RSA, firmar un
documento, modificarlo para ver cómo la firma deja de ser válida, y por último
emitir un **certificado X.509** con una Autoridad Certificadora propia.

Al final simulamos un **ataque**: un impostor que copia el nombre de la CA y falla
igual. Todo el cálculo es real, no está simulado.
        """
    )

    c1, c2, c3 = st.columns(3)
    with c1.container(border=True):
        st.markdown("**🔐 Integridad**")
        st.caption("Detectar si el documento cambió, aunque sea un carácter.")
    with c2.container(border=True):
        st.markdown("**🪪 Autenticidad**")
        st.caption("Comprobar quién firmó, con su clave privada.")
    with c3.container(border=True):
        st.markdown("**🏛️ Confianza**")
        st.caption("Vincular una clave pública a una identidad vía CA.")

    st.divider()

    b1, b2 = st.columns(2)
    if b1.button("▶️ Comenzar paso a paso", type="primary", width="stretch",
                 help="Recorre el flujo tú mismo: generar claves, firmar, verificar y PKI."):
        st.session_state.iniciado = True
        st.rerun()

    if b2.button("⚡ Usar datos de ejemplo", width="stretch",
                 help="Genera claves, firma un documento y crea la CA y el certificado "
                      "automáticamente para explorar la app sin hacer cada paso a mano."):
        with st.spinner("Generando claves RSA, firmando el documento y creando la CA..."):
            estado.cargar_datos_ejemplo()
        st.rerun()

    st.caption("Consejo para la exposición: «Usar datos de ejemplo» deja todo listo, "
               "pero las verificaciones quedan sin ejecutar para poder mostrarlas en vivo.")
