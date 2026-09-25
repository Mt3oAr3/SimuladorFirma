"""Pestana 5: PKI, certificados X.509 y simulacion de un certificado falso."""
import streamlit as st

from crypto_core import keys, pki, signing

from .componentes import encabezado, explicacion, interpretacion, siguiente_paso


def _paso(numero: int, titulo: str, listo: bool, disponible: bool = True) -> None:
    """Cabecera numerada de cada sub-paso de la pestana, con su estado."""
    icono = "✅" if listo else ("🔵" if disponible else "🔒")
    st.markdown(f"##### {icono} Paso {numero}. {titulo}")


def mostrar() -> None:
    ss = st.session_state

    encabezado("🏛️", "PKI: ¿cómo sé que esa clave pública es de quien dice ser?",
               "Paso 4 del flujo guiado: la firma prueba la matemática; el certificado prueba la identidad.")

    st.info("📖 **En una frase:** una **Autoridad Certificadora (CA)** es un tercero de confianza que "
            "firma un **certificado X.509**, un documento que une un nombre con una clave pública.")

    explicacion(
        "Por qué la firma sola no basta y qué resuelve la CA",
        que_pasa=(
            "Un certificado X.509 contiene el **sujeto** (a quién identifica), su **clave pública**, "
            "un período de validez y la **firma de la CA** sobre todo lo anterior. Validarlo consiste "
            "en comprobar dos cosas: que está vigente y que su firma se verifica con la **clave "
            "pública de la CA**, que ya se tenía de antemano."
        ),
        por_que=(
            "Sin certificado, un atacante puede enviarte *su* clave pública diciendo que es la de "
            "Mateo: firmaría documentos que verificarían perfectamente. El certificado traslada la "
            "confianza a un único punto —la CA— en lugar de exigir conocer de antemano la clave de "
            "cada persona. Es el mismo mecanismo que usa HTTPS en tu navegador."
        ),
    )

    if not ss.public_key:
        st.warning("🔒 **Paso bloqueado.** Necesitas una clave pública: el certificado es "
                   "precisamente lo que le da identidad.")
        st.caption("Genera el par de claves en la pestaña **2. Claves RSA** y vuelve aquí.")
        return

    c1, c2 = st.columns(2)
    nombre_ca = c1.text_input("Nombre de la CA", "CA Demo ESPOCH",
                              help="Common Name (CN) de la autoridad certificadora. En el mundo real "
                                   "sería algo como «DigiCert» o «Let's Encrypt».")
    nombre_emisor = c2.text_input("Nombre del emisor del documento", "Emisor Demo - Mateo",
                                  help="Identidad que quedará vinculada a tu clave pública dentro "
                                       "del certificado.")

    st.divider()

    # ---------------------------------------------------------- 1. crear CA
    _paso(1, "Crear la CA de confianza (autofirmada)", listo=ss.ca_cert is not None)
    st.caption("La CA se firma a sí misma: es la **raíz de confianza**, el punto donde la cadena "
               "se detiene porque decidimos confiar en ella.")
    if st.button("🏛️ Crear CA de prueba", type="primary" if not ss.ca_cert else "secondary",
                 help="Genera un par de claves propio de la CA y un certificado autofirmado."):
        with st.spinner("Generando las claves de la CA y su certificado autofirmado…"):
            ss.ca_key, ss.ca_cert = pki.create_ca(nombre_ca)
        ss.cert = ss.cert_validado = ss.ataque_rechazado = None
        st.rerun()

    if ss.ca_cert:
        st.success(f"✅ **CA «{nombre_ca}» creada.** Su clave privada es el secreto más valioso de "
                   "toda la PKI: quien la tenga puede emitir certificados en los que todos confían.")
        interpretacion("Esta CA es ahora nuestro *trust anchor*: todo lo que ella firme lo daremos "
                       "por bueno, y nada más.")
    else:
        st.caption("Sin CA no hay quien avale tu clave pública.")
        return

    st.divider()

    # ---------------------------------------------------------- 2. emitir certificado
    _paso(2, "La CA emite tu certificado", listo=ss.cert is not None)
    st.caption("La CA toma tu clave pública (la de la pestaña 2), le añade tu nombre y firma el "
               "conjunto con su propia clave privada.")
    if st.button("📜 Emitir certificado", disabled=not (ss.ca_key and ss.public_key),
                 type="primary" if not ss.cert else "secondary",
                 help="Crea un certificado X.509 que vincula tu identidad con tu clave pública."):
        with st.spinner("La CA firma tu certificado X.509…"):
            ss.cert = pki.issue_certificate(ss.ca_key, ss.ca_cert, nombre_emisor, ss.public_key)
        ss.cert_validado = None
        st.rerun()

    if not ss.cert:
        st.caption("Pulsa **Emitir certificado** para continuar.")
        return

    st.success(f"✅ **Certificado emitido para «{nombre_emisor}».** Tu clave pública ya no es un "
               "número anónimo: tiene un nombre respaldado por la CA.")

    m1, m2, m3 = st.columns(3)
    dias = (ss.cert.not_valid_after_utc - ss.cert.not_valid_before_utc).days
    m1.metric("Vigencia", f"{dias} días", border=True,
              help="Los certificados caducan a propósito: limita el daño si la clave se ve comprometida.")
    m2.metric("Algoritmo de firma", "SHA-256 + RSA", border=True,
              help="Con qué algoritmo firmó la CA este certificado.")
    m3.metric("Clave certificada", f"RSA-{ss.cert.public_key().key_size} bits", border=True,
              help="Tamaño de la clave pública que el certificado avala.")

    st.table(pki.describe(ss.cert))
    interpretacion("Fíjate en **Sujeto** (a quién identifica) y **Emisor** (quién lo firmó): en tu "
                   "certificado son distintos; en el de la CA serían el mismo, porque es autofirmado.")

    with st.expander("🔬 Ver el certificado en formato PEM"):
        st.code(pki.cert_to_pem(ss.cert).decode(), language=None)
        st.caption("Este bloque es exactamente lo que un servidor HTTPS envía a tu navegador.")
    with st.expander("⬇️ Descargar certificados"):
        d1, d2 = st.columns(2)
        d1.download_button("⬇️ Certificado del emisor (.pem)", pki.cert_to_pem(ss.cert),
                           "certificado.pem", width="stretch")
        d2.download_button("⬇️ Certificado raíz de la CA (.pem)", pki.cert_to_pem(ss.ca_cert),
                           "ca.pem", width="stretch")

    st.divider()

    # ---------------------------------------------------------- 3. validar cadena
    _paso(3, "Validar la cadena de confianza", listo=ss.cert_validado is True)
    st.caption("¿La firma de este certificado se corresponde con la clave pública de nuestra CA "
               "de confianza? ¿Y sigue vigente?")
    if st.button("🔗 Verificar certificado contra la CA",
                 help="Comprueba vigencia y que la firma del certificado sea realmente de la CA."):
        with st.spinner("Validando vigencia y firma de la CA…"):
            ok, msg = pki.verify_certificate(ss.cert, ss.ca_cert)
        ss.cert_validado = ok
        if ok:
            st.success("✔️ " + msg)
            interpretacion("La cadena cierra: confiamos en la CA ⇒ confiamos en que esta clave "
                           "pública pertenece de verdad a «" + nombre_emisor + "».")
        else:
            st.error("✘ " + msg)
            interpretacion("La cadena está rota: aunque el nombre parezca correcto, no hay ninguna "
                           "autoridad de confianza respaldando esa clave.")

    st.divider()

    # ---------------------------------------------------------- 4. verificacion completa
    _paso(4, "Verificación completa: identidad + integridad", listo=False,
          disponible=ss.signature is not None)
    st.caption("Las dos comprobaciones juntas: que el certificado sea legítimo **y** que la firma "
               "del documento se valide con la clave que el certificado avala.")
    if not ss.signature:
        st.info("🔒 Firma un documento en la pestaña **3. Firmar** para habilitar este paso.")
    if st.button("🛡️ Verificar documento con el certificado", disabled=not ss.signature,
                 help="Verificación en dos niveles: la identidad (certificado) y el contenido (firma)."):
        with st.spinner("Validando el certificado y la firma del documento…"):
            ok_cert, msg = pki.verify_certificate(ss.cert, ss.ca_cert)
            ok_firma = signing.verify(ss.cert.public_key(), ss.doc_bytes, ss.signature)
        ss.cert_validado = ok_cert

        v1, v2 = st.columns(2)
        with v1.container(border=True):
            st.markdown(("✔️" if ok_cert else "✘") + " **Identidad (certificado)**")
            st.caption(msg)
        with v2.container(border=True):
            st.markdown(("✔️" if ok_firma else "✘") + " **Integridad y autoría (firma)**")
            st.caption("La firma del documento se valida con la clave pública del certificado."
                       if ok_firma else
                       "La firma no se valida con la clave pública del certificado.")

        if ok_cert and ok_firma:
            st.success("🛡️ **Documento confiable.** Integridad, autenticidad e identidad verificadas: "
                       "sabemos que el contenido no cambió, que lo firmó la clave privada "
                       "correspondiente y que esa clave pertenece a una identidad avalada por la CA.")
        else:
            st.error("⛔ **Documento NO confiable.** Falla al menos una de las dos comprobaciones, "
                     "y ambas son necesarias.")

    st.divider()

    # ---------------------------------------------------------- 5. ataque
    _paso(5, "Simular un ataque: certificado falso", listo=ss.ataque_rechazado is True)
    st.warning("🎭 **El escenario:** un atacante monta su propia CA con **exactamente el mismo "
               "nombre** que la nuestra y se emite a sí mismo un certificado a nombre de "
               f"«{nombre_emisor}». ¿Cuela?")

    if st.button("🎭 Simular certificado falso", type="secondary",
                 help="Crea una CA impostora con el mismo nombre y un certificado falso, y los "
                      "somete a la misma validación."):
        with st.spinner("El atacante genera su CA impostora y su certificado…"):
            rk, rca = pki.create_ca(nombre_ca, key_size=2048)  # mismo nombre que la CA real
            atk_priv, atk_pub = keys.generate_rsa_keypair(2048)
            falso = pki.issue_certificate(rk, rca, nombre_emisor, atk_pub)
        ok, msg = pki.verify_certificate(falso, ss.ca_cert)
        ss.ataque_rechazado = not ok

        st.write(f"El certificado falso dice ser de «{nombre_emisor}», emitido por «{nombre_ca}»: "
                 "en el texto es indistinguible del auténtico.")

        a1, a2 = st.columns(2)
        with a1.container(border=True):
            st.markdown("**🤔 Lo que el atacante SÍ puede hacer**")
            if ss.doc_bytes:
                firma_atk = signing.sign(atk_priv, ss.doc_bytes)
                valida = signing.verify(falso.public_key(), ss.doc_bytes, firma_atk)
                st.caption(("✔️ " if valida else "✘ ") +
                           "Firmar el documento con su propia clave: la firma es matemáticamente "
                           "válida **respecto a su propio certificado**.")
            else:
                st.caption("Copiar el nombre de la CA y el nombre del emisor al detalle.")
            st.caption("Copiar cualquier texto visible del certificado.")
        with a2.container(border=True):
            st.markdown("**🚫 Lo que NO puede hacer**")
            st.caption("Firmar con la **clave privada de la CA real**, que nunca salió de la CA. "
                       "Sin ella, su certificado no pasa la validación de la cadena.")

        if not ok:
            st.success("🛡️ **ATAQUE RECHAZADO.** " + msg)
        else:
            st.error("✘ El certificado falso fue aceptado (esto no debería ocurrir).")

        st.info("💡 **Por qué falla el ataque:** validar un certificado no consiste en leer el "
                "nombre de la CA, sino en comprobar su **firma** con la clave pública de la CA en "
                "la que ya confiamos. El nombre se puede copiar; la clave privada de la CA, no. "
                "**La confianza está en la clave, no en el nombre.**")

    if ss.ataque_rechazado:
        siguiente_paso("ya has recorrido el flujo completo. Usa **🗑️ Reiniciar todo** en la barra "
                       "lateral para repetir la demo desde cero.")
