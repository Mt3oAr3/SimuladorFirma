"""Pestana 1: funcion hash SHA-256 y efecto avalancha."""
import streamlit as st

from crypto_core import hashing

from .componentes import encabezado, explicacion, interpretacion, siguiente_paso


def mostrar() -> None:
    encabezado("#️⃣", "Hash SHA-256: la huella del documento",
               "El cimiento de todo: antes de firmar, hay que resumir el documento.")

    st.info("📖 **En una frase:** SHA-256 convierte cualquier dato, sin importar su tamaño, "
            "en una huella de 256 bits. Si cambias un solo carácter, la huella cambia por completo.")

    explicacion(
        "Cómo funciona y por qué se firma el hash y no el documento",
        que_pasa=(
            "SHA-256 procesa los bytes del documento en bloques y devuelve siempre 256 bits "
            "(64 caracteres hexadecimales). Es **determinista** (el mismo dato da siempre la misma "
            "huella) y **de un solo sentido**: no se puede reconstruir el documento desde la huella."
        ),
        por_que=(
            "RSA solo puede firmar datos pequeños, así que se firma la huella, no el archivo entero. "
            "Eso funciona porque encontrar dos documentos con el mismo SHA-256 (una *colisión*) es "
            "computacionalmente inviable: si la huella coincide, el documento es el mismo. "
            "Aquí nace la **integridad**."
        ),
    )

    st.markdown("#### 🌪️ Efecto avalancha: cambia un carácter, cambia todo")
    st.caption("Compara dos textos casi idénticos y mira lo que pasa con sus huellas.")

    c1, c2 = st.columns(2)
    a = c1.text_area("📄 Texto A", "Transferir $100 a Mateo", key="hash_a",
                     help="El documento original.")
    b = c2.text_area("📝 Texto B", "Transferir $101 a Mateo", key="hash_b",
                     help="Cambia un carácter respecto al A y observa la huella.")

    ha, hb = hashing.sha256_hex(a.encode()), hashing.sha256_hex(b.encode())
    c1.caption("Huella SHA-256 del texto A")
    c1.code(ha, language=None)
    c2.caption("Huella SHA-256 del texto B")
    c2.code(hb, language=None)

    distintos = hashing.bits_distintos(ha, hb)
    porcentaje = distintos / 256 * 100

    m1, m2, m3 = st.columns(3)
    m1.metric("Bits distintos", f"{distintos} / 256", border=True,
              help="Cuántos de los 256 bits de la huella cambiaron.")
    m2.metric("Porcentaje cambiado", f"{porcentaje:.1f} %", border=True,
              help="Un hash seguro cambia cerca del 50 % de los bits ante cualquier modificación.")
    m3.metric("Tamaño de la huella", "256 bits", border=True,
              help="Siempre 256 bits, sin importar si el documento pesa 1 KB o 1 GB.")

    if a == b:
        st.info("ℹ️ Los dos textos son idénticos, por eso las huellas coinciden exactamente. "
                "Cambia un carácter en el texto B.")
        interpretacion("Huellas iguales ⇒ documentos byte a byte iguales. Así se comprueba la integridad.")
    elif 90 < distintos < 166:
        st.success(f"✅ Efecto avalancha confirmado: cambiaron **{distintos} de 256 bits** "
                   f"({porcentaje:.1f} %) por una diferencia mínima en el texto.")
        interpretacion("Un atacante no puede retocar el documento «un poquito» para que la huella "
                       "se parezca: cualquier cambio produce una huella totalmente distinta y la "
                       "alteración queda en evidencia.")
    else:
        st.warning(f"⚠️ Cambiaron {distintos} de 256 bits, lejos del ~50 % esperado. "
                   "Con textos tan cortos puede pasar por azar; prueba con otro cambio.")

    st.divider()
    st.markdown("#### 📎 Huella de un archivo real")
    st.caption("El mismo cálculo sobre cualquier archivo: así se publican los *checksums* de las descargas.")

    up = st.file_uploader("Sube cualquier archivo", key="hash_file",
                          help="El archivo no sale de tu equipo: el hash se calcula localmente.")
    if up:
        with st.spinner("Calculando SHA-256..."):
            h = hashing.sha256_hex(up.getvalue())
        st.success(f"✅ Huella calculada para **{up.name}** ({len(up.getvalue()):,} bytes).")
        st.code(h, language=None)
        interpretacion("Si el sitio de descarga publica esta misma cadena, el archivo llegó íntegro. "
                       "Si difiere en un solo carácter, no confíes en él.")

    siguiente_paso("genera tu par de claves RSA en la pestaña **2. Claves RSA** para poder firmar esta huella.")
