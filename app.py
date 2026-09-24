"""Demo de firma digital: SHA-256 + RSA-PSS + PKI (X.509).

Ejecutar:  streamlit run app.py
"""
import base64

import streamlit as st

from crypto_core import hashing, keys, pki, signing

st.set_page_config(page_title="Demo de firma digital", page_icon="🔏", layout="wide")

ss = st.session_state
for clave in ("private_key", "public_key", "doc_bytes", "doc_name", "signature",
              "hash_firmado", "ca_key", "ca_cert", "cert"):
    ss.setdefault(clave, None)

st.title("🔏 Demo de firma digital")
st.caption("SHA-256 · RSA-PSS · Certificados X.509 (PKI). Proyecto académico: "
           "Introducción a la criptografía.")

t_hash, t_keys, t_sign, t_verify, t_pki = st.tabs([
    "1. Hash SHA-256", "2. Claves RSA", "3. Firmar", "4. Verificar", "5. PKI / Certificados",
])

# ---------------------------------------------------------------- 1. HASH
with t_hash:
    st.subheader("Función hash y efecto avalancha")
    st.write("SHA-256 convierte cualquier dato en una huella de 256 bits. "
             "Cambia un solo carácter y la huella cambia por completo.")
    c1, c2 = st.columns(2)
    a = c1.text_area("Texto A", "Transferir $100 a Mateo", key="hash_a")
    b = c2.text_area("Texto B", "Transferir $101 a Mateo", key="hash_b")
    ha, hb = hashing.sha256_hex(a.encode()), hashing.sha256_hex(b.encode())
    c1.code(ha, language=None)
    c2.code(hb, language=None)
    distintos = hashing.bits_distintos(ha, hb)
    st.metric("Bits distintos entre ambos hashes", f"{distintos} / 256")
    st.caption("Un buen hash cambia cerca del 50 % de los bits (≈128) aunque el cambio sea mínimo.")

    st.divider()
    st.subheader("Hash de un archivo")
    up = st.file_uploader("Sube cualquier archivo", key="hash_file")
    if up:
        st.code(hashing.sha256_hex(up.getvalue()), language=None)

# ---------------------------------------------------------------- 2. CLAVES
with t_keys:
    st.subheader("Par de claves RSA")
    st.write("La **clave privada** firma y no se comparte. La **clave pública** verifica y se distribuye libremente.")
    c1, c2 = st.columns(2)
    tam = c1.selectbox("Tamaño de clave (bits)", [2048, 3072], index=1)
    pwd = c2.text_input("Contraseña para proteger la clave privada", value="demo1234", type="password")

    if st.button("Generar par de claves", type="primary"):
        with st.spinner("Generando claves RSA..."):
            ss.private_key, ss.public_key = keys.generate_rsa_keypair(tam)
        # Lo que dependía de las claves anteriores ya no es válido
        ss.signature = ss.doc_bytes = ss.hash_firmado = ss.cert = None

    if ss.public_key:
        nums = ss.public_key.public_numbers()
        st.success(f"Par de claves RSA-{ss.public_key.key_size} generado.")
        st.write("**Huella de la clave pública (SHA-256)**")
        st.code(keys.fingerprint(ss.public_key), language=None)
        st.write(f"**Exponente público (e):** {nums.e}")
        st.write("**Módulo (n), primeros 64 dígitos hex:**")
        st.code(format(nums.n, "x")[:64] + "...", language=None)
        pub_pem = keys.public_key_to_pem(ss.public_key)
        with st.expander("Ver clave pública (PEM)"):
            st.code(pub_pem.decode(), language=None)
        d1, d2 = st.columns(2)
        d1.download_button("⬇ Descargar clave pública", pub_pem, "clave_publica.pem")
        d2.download_button("⬇ Descargar clave privada (cifrada)",
                           keys.private_key_to_pem(ss.private_key, pwd or None),
                           "clave_privada.pem")
        st.warning("La clave privada nunca se comparte. Aquí se descarga solo por ser una demo.")
    else:
        st.info("Aún no hay claves. Pulsa el botón para generarlas.")

# ---------------------------------------------------------------- 3. FIRMAR
with t_sign:
    st.subheader("Firmar un documento con la clave privada")
    if not ss.private_key:
        st.warning("Primero genera las claves en la pestaña 2.")
    else:
        modo = st.radio("Documento a firmar", ["Escribir texto", "Subir archivo"], horizontal=True)
        if modo == "Escribir texto":
            texto = st.text_area("Contenido", "CONSTANCIA: el estudiante Mateo aprobó la asignatura X.",
                                 height=120)
            datos, nombre = texto.encode("utf-8"), "documento.txt"
        else:
            arch = st.file_uploader("Archivo a firmar", key="sign_file")
            datos, nombre = (arch.getvalue(), arch.name) if arch else (None, None)

        if datos:
            st.caption("SHA-256 del documento actual")
            st.code(hashing.sha256_hex(datos), language=None)
            if st.button("✍ Firmar documento", type="primary"):
                ss.doc_bytes, ss.doc_name = datos, nombre
                ss.hash_firmado = hashing.sha256_hex(datos)
                ss.signature = signing.sign(ss.private_key, datos)
        else:
            st.info("Escribe o sube un documento para poder firmarlo.")

        if ss.signature:
            st.success(f"Documento firmado: {ss.doc_name}")
            st.write(f"**Firma digital** ({len(ss.signature)} bytes, en Base64):")
            st.code(base64.b64encode(ss.signature).decode(), language=None)
            s1, s2 = st.columns(2)
            s1.download_button("⬇ Descargar firma (.sig)", ss.signature, "firma.sig")
            s2.download_button("⬇ Descargar documento", ss.doc_bytes, ss.doc_name)

# ---------------------------------------------------------------- 4. VERIFICAR
with t_verify:
    st.subheader("Verificar con la clave pública")
    origen = st.radio("Origen de los datos",
                      ["Usar lo firmado en esta sesión", "Cargar archivos"], horizontal=True)

    if origen == "Usar lo firmado en esta sesión":
        if not ss.signature:
            st.warning("Primero firma un documento en la pestaña 3.")
        else:
            try:
                base_txt = ss.doc_bytes.decode("utf-8")
            except UnicodeDecodeError:
                base_txt = None
            if base_txt is not None:
                st.caption("Este es el documento «recibido». Edítalo (aunque sea una letra) "
                           "y pulsa Ctrl+Enter para simular una alteración.")
                recibido = st.text_area("Documento recibido", base_txt, height=120).encode("utf-8")
            else:
                st.info("El documento firmado es un archivo binario: se verifica tal cual.")
                recibido = ss.doc_bytes

            if st.button("🔎 Verificar firma", type="primary"):
                h_ahora = hashing.sha256_hex(recibido)
                c1, c2 = st.columns(2)
                c1.caption("Hash al momento de firmar")
                c1.code(ss.hash_firmado, language=None)
                c2.caption("Hash del documento recibido")
                c2.code(h_ahora, language=None)
                if signing.verify(ss.public_key, recibido, ss.signature):
                    st.success("✔ FIRMA VÁLIDA: el documento es íntegro y fue firmado con la clave privada correspondiente.")
                else:
                    st.error("✘ FIRMA INVÁLIDA: el documento fue alterado o la firma no corresponde a esta clave.")
    else:
        f1, f2, f3 = st.columns(3)
        doc_f = f1.file_uploader("Documento", key="v_doc")
        sig_f = f2.file_uploader("Firma (.sig)", key="v_sig")
        pub_f = f3.file_uploader("Clave pública (.pem)", key="v_pub")
        if st.button("🔎 Verificar firma", type="primary", key="v_btn"):
            if not (doc_f and sig_f and pub_f):
                st.warning("Carga los tres archivos.")
            else:
                try:
                    pub = keys.load_public_key(pub_f.getvalue())
                    st.code(hashing.sha256_hex(doc_f.getvalue()), language=None)
                    if signing.verify(pub, doc_f.getvalue(), sig_f.getvalue()):
                        st.success("✔ FIRMA VÁLIDA")
                    else:
                        st.error("✘ FIRMA INVÁLIDA")
                except ValueError:
                    st.error("La clave pública no tiene un formato PEM válido.")

# ---------------------------------------------------------------- 5. PKI
with t_pki:
    st.subheader("PKI: ¿cómo sé que la clave pública es realmente de quien dice ser?")
    st.write("Una **Autoridad Certificadora (CA)** firma un **certificado X.509** que une una identidad "
             "con una clave pública. Confiar en la CA permite confiar en el certificado.")
    c1, c2 = st.columns(2)
    nombre_ca = c1.text_input("Nombre de la CA", "CA Demo ESPOCH")
    nombre_emisor = c2.text_input("Nombre del emisor", "Emisor Demo - Mateo")

    st.markdown("**Paso 1.** Crear la CA de confianza")
    if st.button("Crear CA de prueba"):
        with st.spinner("Generando CA..."):
            ss.ca_key, ss.ca_cert = pki.create_ca(nombre_ca)
            ss.cert = None

    st.markdown("**Paso 2.** La CA emite el certificado del emisor (usa la clave pública de la pestaña 2)")
    if st.button("Emitir certificado", disabled=not (ss.ca_key and ss.public_key)):
        ss.cert = pki.issue_certificate(ss.ca_key, ss.ca_cert, nombre_emisor, ss.public_key)
    if not ss.public_key:
        st.caption("Falta generar las claves en la pestaña 2.")

    if ss.cert:
        st.table(pki.describe(ss.cert))
        with st.expander("Ver certificado (PEM)"):
            st.code(pki.cert_to_pem(ss.cert).decode(), language=None)

        st.markdown("**Paso 3.** Validar la cadena de confianza")
        if st.button("Verificar certificado contra la CA"):
            ok, msg = pki.verify_certificate(ss.cert, ss.ca_cert)
            (st.success if ok else st.error)(("✔ " if ok else "✘ ") + msg)

        st.markdown("**Paso 4.** Verificación completa: certificado + firma del documento")
        if st.button("Verificar documento con el certificado", disabled=not ss.signature):
            ok_cert, msg = pki.verify_certificate(ss.cert, ss.ca_cert)
            ok_firma = signing.verify(ss.cert.public_key(), ss.doc_bytes, ss.signature)
            st.write(("✔" if ok_cert else "✘") + " Certificado: " + msg)
            st.write(("✔" if ok_firma else "✘") + " Firma del documento con la clave del certificado")
            if ok_cert and ok_firma:
                st.success("Documento confiable: integridad, autenticidad e identidad verificadas.")
            else:
                st.error("Documento NO confiable.")
        if not ss.signature:
            st.caption("Firma un documento en la pestaña 3 para habilitar este paso.")

        st.divider()
        st.markdown("**Paso 5. Simular un ataque:** un atacante crea su propia CA con el *mismo nombre* "
                    "y emite un certificado falso a su nombre.")
        if st.button("Simular certificado falso", type="secondary"):
            with st.spinner("El atacante genera su CA y su certificado..."):
                rk, rca = pki.create_ca(nombre_ca, key_size=2048)  # mismo nombre que la CA real
                atk_priv, atk_pub = keys.generate_rsa_keypair(2048)
                falso = pki.issue_certificate(rk, rca, nombre_emisor, atk_pub)
            ok, msg = pki.verify_certificate(falso, ss.ca_cert)
            st.write("El certificado falso dice ser de «" + nombre_emisor + "», emitido por «" + nombre_ca + "».")
            if ss.doc_bytes:
                firma_atk = signing.sign(atk_priv, ss.doc_bytes)
                st.write("La firma del atacante es matemáticamente válida con su propia clave: "
                         + ("✔" if signing.verify(falso.public_key(), ss.doc_bytes, firma_atk) else "✘"))
            (st.success if ok else st.error)(
                ("✔ " if ok else "✘ RECHAZADO: ") + msg)
            st.caption("El atacante puede copiar el nombre, pero no puede falsificar la firma de la CA "
                       "sin su clave privada. Por eso la confianza está en la CA, no en el nombre.")
