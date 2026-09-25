"""Pestana 2: generacion del par de claves RSA."""
import streamlit as st

from crypto_core import keys

from . import estado
from .componentes import encabezado, explicacion, interpretacion, siguiente_paso


def mostrar() -> None:
    ss = st.session_state

    encabezado("🔑", "Par de claves RSA",
               "Paso 1 del flujo guiado: sin claves no hay firma posible.")

    st.info("📖 **En una frase:** la **clave privada** firma y jamás se comparte; "
            "la **clave pública** verifica y se puede publicar sin riesgo.")

    explicacion(
        "Qué es realmente un par de claves RSA",
        que_pasa=(
            "Se eligen dos números primos grandes y secretos y se calcula su producto **n** (el módulo). "
            "La clave pública es el par `(n, e)` con `e = 65537`; la privada guarda el exponente `d` que "
            "solo puede deducirse conociendo los primos. Lo que se firma con `d` se comprueba con `e`, "
            "y nunca al revés."
        ),
        por_que=(
            "La seguridad se apoya en que **factorizar n es inviable** con la tecnología actual. "
            "Eso permite el **no repudio**: como solo el dueño tiene la clave privada, si una firma "
            "verifica con su clave pública, no puede negar haberla hecho. RSA-2048 se considera seguro "
            "hoy; RSA-3072 es la recomendación para protección a largo plazo."
        ),
    )

    c1, c2 = st.columns(2)
    tam = c1.selectbox("Tamaño de clave (bits)", [2048, 3072], index=1,
                       help="Más bits = más seguridad y más lentitud. 3072 bits equivale a ~128 bits "
                            "de seguridad simétrica (recomendación NIST para largo plazo).")
    pwd = c2.text_input("Contraseña para proteger la clave privada", value="demo1234", type="password",
                        help="La clave privada se exporta cifrada con esta contraseña (PKCS#8). "
                             "Si alguien roba el archivo, sin la contraseña no le sirve.")

    if st.button("🔑 Generar par de claves", type="primary",
                 help="Genera dos primos grandes y deriva el par RSA. Puede tardar unos segundos."):
        with st.spinner(f"Generando par de claves RSA-{tam}… (buscando primos grandes)"):
            ss.private_key, ss.public_key = keys.generate_rsa_keypair(tam)
        ss.tam_clave_actual = tam
        # Firma, certificado y verificaciones previas dejan de tener validez.
        estado.invalidar_desde_claves()
        st.rerun()

    if not ss.public_key:
        st.warning("🔒 Aún no hay claves en esta sesión. Pulsa **Generar par de claves** para empezar.")
        st.caption("Todo lo demás (firmar, verificar, certificados) depende de este paso.")
        return

    nums = ss.public_key.public_numbers()
    st.success(f"✅ **Par de claves RSA-{ss.public_key.key_size} generado.** "
               "La privada se queda en memoria de esta sesión; la pública ya puedes repartirla.")
    interpretacion("Acabas de crear tu identidad criptográfica: la clave privada es tu firma manuscrita "
                   "y la pública es la muestra de firma que cualquiera puede usar para contrastarla.")

    m1, m2, m3 = st.columns(3)
    m1.metric("Tamaño de la clave", f"{ss.public_key.key_size} bits", border=True,
              help="Longitud del módulo n. Determina el tamaño de la firma.")
    m2.metric("Exponente público (e)", f"{nums.e:,}", border=True,
              help="65537 es el valor estándar: primo y rápido de calcular.")
    m3.metric("Dígitos hex del módulo", f"{len(format(nums.n, 'x')):,}", border=True,
              help="El módulo n es el número que habría que factorizar para romper la clave.")

    st.markdown("#### 🪪 Huella de la clave pública (SHA-256)")
    st.code(keys.fingerprint(ss.public_key), language=None)
    interpretacion("Sirve para comparar claves de un vistazo por teléfono o en persona. "
                   "Si tu huella y la del receptor coinciden, tenéis la misma clave pública.")

    with st.expander("🔬 Ver el módulo (n) y la clave pública en PEM"):
        st.caption("Módulo (n), primeros 64 dígitos hexadecimales:")
        st.code(format(nums.n, "x")[:64] + "...", language=None)
        st.caption("Clave pública completa en formato PEM (lo que se comparte):")
        st.code(keys.public_key_to_pem(ss.public_key).decode(), language=None)

    st.markdown("#### ⬇️ Exportar")
    d1, d2 = st.columns(2)
    d1.download_button("⬇️ Descargar clave pública (.pem)",
                       keys.public_key_to_pem(ss.public_key), "clave_publica.pem",
                       width="stretch",
                       help="Este archivo se reparte libremente: solo sirve para verificar firmas.")
    d2.download_button("⬇️ Descargar clave privada cifrada (.pem)",
                       keys.private_key_to_pem(ss.private_key, pwd or None), "clave_privada.pem",
                       width="stretch",
                       help="Cifrada con la contraseña de arriba. En un caso real esto no se descarga "
                            "desde una web.")

    if not pwd:
        st.error("⚠️ Sin contraseña, la clave privada se exportaría **sin cifrar**. "
                 "Escribe una contraseña antes de descargarla.")
    else:
        st.warning("🔐 **Regla de oro:** la clave privada nunca se comparte ni viaja por la red. "
                   "Aquí se puede descargar solo porque es una demostración académica.")

    siguiente_paso("ve a la pestaña **3. Firmar** para firmar un documento con esta clave privada.")
