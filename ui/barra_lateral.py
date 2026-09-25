"""Barra lateral: resumen del estado de la demo y acciones rapidas."""
import streamlit as st

from crypto_core import keys

from . import estado


def _fila(etiqueta: str, listo: bool, detalle_ok: str, detalle_falta: str) -> None:
    icono = "✅" if listo else "⬜"
    st.markdown(f"{icono} **{etiqueta}**")
    st.caption(detalle_ok if listo else detalle_falta)


def mostrar() -> None:
    ss = st.session_state
    with st.sidebar:
        st.header("📋 Estado de la demo")

        hechos, total = estado.progreso()
        st.progress(hechos / total, text=f"{hechos}/{total} pasos")

        _fila("Claves RSA", ss.public_key is not None,
              f"Par RSA-{ss.public_key.key_size} en memoria." if ss.public_key else "",
              "Sin generar.")
        _fila("Documento firmado", ss.signature is not None,
              f"«{ss.doc_name}» · firma de {len(ss.signature)} bytes." if ss.signature else "",
              "Ningún documento firmado.")
        _fila("Firma verificada", ss.verificacion_ok is not None,
              "Válida ✔" if ss.verificacion_ok else "Inválida ✘ (alteración detectada)",
              "Sin verificar todavía.")
        _fila("Certificado X.509", ss.cert is not None,
              "Emitido por la CA." if ss.cert else "",
              "Sin emitir.")
        _fila("Cadena de confianza", ss.cert_validado is True,
              "Validada contra la CA.", "Sin validar contra la CA.")

        if ss.public_key:
            with st.expander("🔎 Huella de la clave pública"):
                st.code(keys.fingerprint(ss.public_key)[:32] + "…", language=None)
                st.caption("Identifica la clave sin exponerla entera.")

        st.divider()
        st.subheader("⚙️ Acciones")

        if not ss.public_key:
            if st.button("⚡ Cargar datos de ejemplo", width="stretch",
                         help="Genera claves, firma un documento y crea la CA de una sola vez."):
                with st.spinner("Preparando la demo completa..."):
                    estado.cargar_datos_ejemplo()
                st.rerun()

        if st.button("🏠 Volver al inicio", width="stretch",
                     help="Vuelve a la portada sin borrar lo que ya generaste."):
            ss.iniciado = False
            st.rerun()

        if st.button("🗑️ Reiniciar todo", type="secondary", width="stretch",
                     help="Borra claves, documento, firma y certificados de la sesión."):
            estado.reiniciar()
            st.rerun()

        st.divider()
        st.caption("**Glosario rápido**")
        st.caption("**Hash:** huella digital de tamaño fijo.  \n"
                   "**RSA-PSS:** esquema de firma RSA con relleno aleatorio.  \n"
                   "**CA:** autoridad que firma certificados.  \n"
                   "**X.509:** formato estándar de certificado.")
