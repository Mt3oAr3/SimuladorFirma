"""Pestana 4: verificar la firma y demostrar la deteccion de alteraciones."""
import streamlit as st

from crypto_core import hashing, keys, signing

from .componentes import encabezado, explicacion, interpretacion, siguiente_paso


def _resultado_valido() -> None:
    st.success("✔️ **FIRMA VÁLIDA.** El documento es idéntico al que se firmó y la firma "
               "proviene de la clave privada que corresponde a esta clave pública.")
    interpretacion("Quedan probadas las tres propiedades: **integridad** (nada cambió), "
                   "**autenticidad** (lo firmó el dueño de la clave privada) y "
                   "**no repudio** (no puede negar haberlo firmado).")


def _resultado_invalido(bits: int, mismo_hash: bool) -> None:
    st.error("✘ **FIRMA INVÁLIDA.** El documento no se puede dar por auténtico.")
    if not mismo_hash:
        st.markdown(
            "**¿Por qué falla exactamente?**\n\n"
            "1. Al firmar, RSA-PSS no firmó el texto: firmó su **huella SHA-256**.\n"
            "2. Has modificado el documento, así que al recalcular la huella salen "
            f"**{bits} de 256 bits distintos** ({bits / 256 * 100:.1f} %) respecto a la original.\n"
            "3. La verificación deriva de la firma la huella que se firmó y la compara con la "
            "recién calculada. Como ya no coinciden, la comprobación matemática falla.\n\n"
            "No hace falta saber *qué* se cambió ni *quién* lo cambió: basta con que algo cambió."
        )
        interpretacion("Esto es lo que protege a un contrato o una factura firmada: cambiar "
                       "«$100» por «$1000» rompe la firma y la manipulación queda en evidencia.")
    else:
        st.markdown(
            "**¿Por qué falla si el documento no cambió?**\n\n"
            "La huella es la misma, así que el problema no es la integridad sino la "
            "**procedencia**: la firma fue creada con una clave privada **distinta** de la que "
            "corresponde a esta clave pública, o el archivo de firma no es el de este documento."
        )
        interpretacion("Una firma correcta pero de otra clave no sirve: la autenticidad va atada "
                       "a un par de claves concreto, no solo al contenido.")


def _modo_sesion() -> None:
    ss = st.session_state

    if not ss.signature:
        st.warning("🔒 **Paso bloqueado.** Necesitas un documento firmado: sin firma no hay "
                   "nada que comprobar.")
        st.caption("Ve a la pestaña **3. Firmar**, firma un documento y vuelve aquí. "
                   "También puedes usar el modo **Cargar archivos** con ficheros externos.")
        return

    st.markdown("#### 📨 El documento tal como lo recibe el destinatario")
    try:
        base_txt = ss.doc_bytes.decode("utf-8")
    except UnicodeDecodeError:
        base_txt = None

    if base_txt is not None:
        st.caption("✏️ **Simula un ataque:** edita el texto (aunque sea una sola letra), "
                   "pulsa Ctrl+Enter y después **Verificar firma**.")
        recibido = st.text_area(
            "Documento recibido", base_txt, height=120,
            key=f"recibido_{ss.hash_firmado[:12]}",
            help="Este es el contenido que llega al receptor. La firma no cambia; el documento "
                 "sí pudo haber sido manipulado por el camino.",
        ).encode("utf-8")
    else:
        st.info("ℹ️ El documento firmado es un archivo binario: se verifica tal cual, sin edición.")
        recibido = ss.doc_bytes

    h_ahora = hashing.sha256_hex(recibido)
    alterado = h_ahora != ss.hash_firmado
    bits = hashing.bits_distintos(ss.hash_firmado, h_ahora)

    if alterado:
        st.warning(f"⚠️ El documento mostrado **ya no coincide** con el firmado: "
                   f"{bits} de 256 bits de la huella son distintos. Verifica para ver el efecto.")
    else:
        st.caption("Por ahora el documento es idéntico al que se firmó.")

    if st.button("🔎 Verificar firma", type="primary",
                 help="Recalcula el SHA-256 del documento recibido y comprueba la firma con la "
                      "clave pública."):
        with st.spinner("Recalculando la huella y comprobando la firma con la clave pública…"):
            ok = signing.verify(ss.public_key, recibido, ss.signature)
        ss.verificacion_ok = ok

        st.markdown("#### 🧾 Comparación de huellas")
        c1, c2 = st.columns(2)
        c1.caption("Huella **al momento de firmar**")
        c1.code(ss.hash_firmado, language=None)
        c2.caption("Huella del **documento recibido**")
        c2.code(h_ahora, language=None)

        m1, m2 = st.columns(2)
        m1.metric("Bits distintos entre las huellas", f"{bits} / 256", border=True,
                  help="Cero significa que el documento es byte a byte el mismo.")
        m2.metric("Resultado de la verificación", "Válida ✔" if ok else "Inválida ✘", border=True,
                  help="Salida de la comprobación RSA-PSS con la clave pública.")

        if ok:
            _resultado_valido()
        else:
            _resultado_invalido(bits, mismo_hash=not alterado)

        siguiente_paso("pasa a **5. PKI / Certificados** para responder la siguiente pregunta: "
                       "¿cómo sé que esta clave pública es de quien dice ser?")


def _modo_archivos() -> None:
    st.caption("Verificación «desde cero», como la haría un tercero: documento + firma + clave "
               "pública. Puedes usar los archivos de `salida/` que genera `demo_consola.py`.")
    f1, f2, f3 = st.columns(3)
    doc_f = f1.file_uploader("📄 Documento", key="v_doc", help="El archivo original recibido.")
    sig_f = f2.file_uploader("🔏 Firma (.sig)", key="v_sig",
                             help="La firma que acompaña al documento.")
    pub_f = f3.file_uploader("🔑 Clave pública (.pem)", key="v_pub",
                             help="La clave pública del supuesto firmante, en formato PEM.")

    if not st.button("🔎 Verificar firma", type="primary", key="v_btn"):
        return

    if not (doc_f and sig_f and pub_f):
        st.warning("⚠️ Faltan archivos: se necesitan los tres (documento, firma y clave pública).")
        return

    try:
        pub = keys.load_public_key(pub_f.getvalue())
    except ValueError:
        st.error("✘ La clave pública no tiene un formato PEM válido: debe empezar por "
                 "-----BEGIN PUBLIC KEY-----.")
        return

    with st.spinner("Comprobando la firma…"):
        ok = signing.verify(pub, doc_f.getvalue(), sig_f.getvalue())
    st.session_state.verificacion_ok = ok

    st.caption("Huella SHA-256 del documento cargado")
    st.code(hashing.sha256_hex(doc_f.getvalue()), language=None)

    m1, m2 = st.columns(2)
    m1.metric("Tamaño de la firma", f"{len(sig_f.getvalue())} bytes", border=True)
    m2.metric("Resultado de la verificación", "Válida ✔" if ok else "Inválida ✘", border=True)

    if ok:
        _resultado_valido()
    else:
        st.error("✘ **FIRMA INVÁLIDA.**")
        st.markdown(
            "**Las causas posibles son tres:**\n\n"
            "1. El **documento fue alterado** tras firmarse: su huella SHA-256 ya no es la firmada.\n"
            "2. La **clave pública no corresponde** al firmante real (la firma es de otra clave).\n"
            "3. El **archivo de firma** pertenece a otro documento o llegó corrupto.\n\n"
            "En los tres casos la conclusión práctica es la misma: **no confíes en ese documento.**"
        )
        interpretacion("La verificación no dice qué salió mal, y no hace falta: cualquier "
                       "discrepancia basta para rechazar el documento.")


def mostrar() -> None:
    encabezado("🔎", "Verificar la firma con la clave pública",
               "Paso 3 del flujo guiado: aquí es donde se detecta cualquier alteración.")

    st.info("📖 **En una frase:** el receptor recalcula el SHA-256 del documento y comprueba, con "
            "la clave pública, que la firma corresponde a esa huella. Si el documento cambió, no cuadra.")

    explicacion(
        "Qué hace exactamente la verificación",
        que_pasa=(
            "La operación RSA con el exponente público aplicada a la firma reconstruye el bloque "
            "PSS. De ahí se recupera el *salt*, se vuelve a derivar el hash esperado y se compara "
            "con el SHA-256 del documento recibido. Si todo encaja, la firma es válida; si no, la "
            "librería lanza `InvalidSignature` y la función devuelve `False`."
        ),
        por_que=(
            "La verificación **solo necesita datos públicos**: documento, firma y clave pública. "
            "Cualquiera puede comprobarla sin conocer ningún secreto, y eso es justo lo que hace "
            "útil a la firma digital frente a terceros (un juez, un auditor, otro servidor)."
        ),
    )

    origen = st.radio("Origen de los datos",
                      ["Usar lo firmado en esta sesión", "Cargar archivos"], horizontal=True,
                      help="La primera opción usa la firma creada en esta sesión; la segunda "
                           "permite verificar archivos externos.")

    if origen == "Usar lo firmado en esta sesión":
        _modo_sesion()
    else:
        _modo_archivos()
