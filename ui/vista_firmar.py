"""Pestana 3: firmar un documento con la clave privada."""
import base64

import streamlit as st

from crypto_core import hashing, keys, signing

from . import estado
from .componentes import encabezado, explicacion, interpretacion, siguiente_paso

TEXTO_POR_DEFECTO = "CONSTANCIA: el estudiante Mateo aprobó la asignatura X."


def _desbloqueo() -> None:
    """Atajo para generar claves sin salir de esta pestana."""
    ss = st.session_state
    st.warning("🔒 **Paso bloqueado.** " + estado.falta_para("firmar"))
    st.caption("Puedes ir a la pestaña **2. Claves RSA** o generarlas aquí mismo:")
    if st.button("🔑 Generar claves RSA-3072 ahora", type="primary", key="atajo_claves"):
        with st.spinner("Generando par de claves RSA-3072…"):
            ss.private_key, ss.public_key = keys.generate_rsa_keypair(3072)
        ss.tam_clave_actual = 3072
        estado.invalidar_desde_claves()
        st.rerun()


def mostrar() -> None:
    ss = st.session_state

    encabezado("✍️", "Firmar un documento con la clave privada",
               "Paso 2 del flujo guiado: se firma la huella, no el archivo completo.")

    st.info("📖 **En una frase:** se calcula el SHA-256 del documento y ese resumen se cifra "
            "con tu clave privada usando RSA-PSS. El resultado es la firma digital.")

    explicacion(
        "Qué es RSA-PSS y por qué no se firma «a pelo»",
        que_pasa=(
            "**PSS** (*Probabilistic Signature Scheme*) añade un valor aleatorio (*salt*) y una máscara "
            "MGF1 al hash antes de aplicar la operación RSA. Por eso, si firmas **el mismo documento dos "
            "veces, obtienes dos firmas distintas**, y ambas son válidas."
        ),
        por_que=(
            "El relleno determinista antiguo (PKCS#1 v1.5) es vulnerable a ataques de falsificación "
            "y de firma existencial. PSS tiene una demostración formal de seguridad y es el esquema "
            "recomendado hoy. La firma aporta **autenticidad** (solo tu clave privada pudo generarla), "
            "**integridad** (va atada al hash exacto) y **no repudio**."
        ),
    )

    if estado.falta_para("firmar"):
        _desbloqueo()
        return

    modo = st.radio("¿Qué quieres firmar?", ["Escribir texto", "Subir archivo"], horizontal=True,
                    help="Cualquier secuencia de bytes se puede firmar: texto, PDF, imagen, ZIP…")

    if modo == "Escribir texto":
        texto = st.text_area("📄 Contenido del documento", TEXTO_POR_DEFECTO, height=120,
                             help="Este es el documento que quedará vinculado a tu firma.")
        datos, nombre = texto.encode("utf-8"), "documento.txt"
    else:
        arch = st.file_uploader("📎 Archivo a firmar", key="sign_file",
                                help="Se firma el contenido binario exacto del archivo.")
        datos, nombre = (arch.getvalue(), arch.name) if arch else (None, None)

    if not datos:
        st.info("ℹ️ Escribe un texto o sube un archivo para poder firmarlo.")
        return

    st.markdown("#### 1️⃣ Huella del documento (lo que se va a firmar)")
    st.code(hashing.sha256_hex(datos), language=None)
    interpretacion("Esta huella de 256 bits representa al documento entero. "
                   "Si el documento cambia, cambia la huella y la firma deja de cuadrar.")

    st.markdown("#### 2️⃣ Aplicar la clave privada")
    if st.button("✍️ Firmar documento", type="primary",
                 help="Aplica RSA-PSS sobre el hash SHA-256 usando tu clave privada."):
        with st.spinner("Aplicando RSA-PSS con la clave privada…"):
            ss.doc_bytes, ss.doc_name = datos, nombre
            ss.hash_firmado = hashing.sha256_hex(datos)
            ss.signature = signing.sign(ss.private_key, datos)
        # La firma nueva invalida cualquier verificacion anterior.
        ss.verificacion_ok = None
        st.rerun()

    if not ss.signature:
        return

    st.divider()
    firmado_es_actual = ss.doc_bytes == datos
    if firmado_es_actual:
        st.success(f"✅ **Documento firmado:** «{ss.doc_name}». "
                   "La firma queda atada a este contenido exacto y a tu clave privada.")
    else:
        st.warning(f"⚠️ Hay una firma guardada de «{ss.doc_name}», pero el contenido de arriba "
                   "ya no es el mismo. Vuelve a pulsar **Firmar documento** si quieres firmar lo nuevo.")

    m1, m2, m3 = st.columns(3)
    m1.metric("Tamaño de la firma", f"{len(ss.signature)} bytes", border=True,
              help="La firma RSA ocupa exactamente el tamaño del módulo de la clave.")
    m2.metric("Bits de la firma", f"{len(ss.signature) * 8:,}", border=True,
              help="Coincide con el tamaño de la clave RSA usada para firmar.")
    m3.metric("Algoritmo", "RSA-PSS + SHA-256", border=True,
              help="Relleno probabilístico PSS con máscara MGF1-SHA256.")

    st.markdown("#### 🔏 Firma digital (Base64)")
    st.code(base64.b64encode(ss.signature).decode(), language=None)
    interpretacion("Esta cadena no contiene el documento ni tu clave privada: es la prueba matemática "
                   "de que quien posee esa clave aprobó exactamente ese contenido. "
                   "Fírmalo otra vez y verás una firma distinta (eso es PSS), igual de válida.")

    st.markdown("#### ⬇️ Lo que enviarías al receptor")
    s1, s2, s3 = st.columns(3)
    s1.download_button("⬇️ Documento", ss.doc_bytes, ss.doc_name, width="stretch",
                       help="El documento original, sin cifrar: firmar no es cifrar.")
    s2.download_button("⬇️ Firma (.sig)", ss.signature, "firma.sig", width="stretch",
                       help="La firma va aparte, en su propio archivo.")
    s3.download_button("⬇️ Clave pública (.pem)", keys.public_key_to_pem(ss.public_key),
                       "clave_publica.pem", width="stretch",
                       help="El receptor la necesita para verificar.")
    st.caption("🔓 Ojo: la firma **no oculta** el contenido. Firmar demuestra autoría e integridad; "
               "para confidencialidad haría falta cifrado.")

    siguiente_paso("ve a **4. Verificar**, edita una letra del documento y comprueba cómo la firma falla.")
