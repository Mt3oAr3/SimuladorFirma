"""Estado de la sesion y calculo del progreso del flujo guiado.

Aqui se define el "hilo conductor" de la demo: Claves -> Firmar ->
Verificar -> PKI. Cada paso sabe si esta bloqueado, disponible o hecho,
y eso es lo que alimenta la barra de progreso y los avisos de la interfaz.
"""
from pathlib import Path

import streamlit as st

from crypto_core import hashing, keys, pki, signing

# Claves de session_state que usa la app (se limpian al reiniciar la demo).
CLAVES_SESION = (
    "private_key", "public_key", "doc_bytes", "doc_name", "signature",
    "hash_firmado", "ca_key", "ca_cert", "cert", "verificacion_ok",
    "cert_validado", "ataque_rechazado", "iniciado", "tam_clave_actual",
)

# (id, etiqueta corta, icono) de cada etapa del flujo guiado.
PASOS = (
    ("claves", "Generar claves", "🔑"),
    ("firmar", "Firmar", "✍️"),
    ("verificar", "Verificar", "🔎"),
    ("pki", "PKI / Certificados", "🏛️"),
)

DOC_EJEMPLO = Path("documentos/ejemplo.txt")
TEXTO_EJEMPLO = (
    "CONSTANCIA\nEl estudiante Mateo aprobo la asignatura Criptografia "
    "con una nota de 9.5/10."
)


def inicializar() -> None:
    """Crea en session_state todas las claves que la app espera encontrar."""
    for clave in CLAVES_SESION:
        st.session_state.setdefault(clave, None)
    st.session_state.setdefault("iniciado", False)


def reiniciar() -> None:
    """Borra todo el estado: la demo vuelve a la pantalla de bienvenida."""
    st.session_state.clear()
    inicializar()


def invalidar_desde_claves() -> None:
    """Un par de claves nuevo invalida firma, certificado y verificaciones."""
    ss = st.session_state
    ss.signature = ss.doc_bytes = ss.doc_name = ss.hash_firmado = None
    ss.cert = ss.verificacion_ok = ss.cert_validado = ss.ataque_rechazado = None


# ------------------------------------------------------------ progreso

def estado_pasos() -> dict[str, str]:
    """Devuelve el estado de cada paso: 'hecho', 'activo' o 'bloqueado'.

    'activo' = ya se puede hacer pero todavia no se ha completado.
    """
    ss = st.session_state
    hay_claves = ss.public_key is not None
    hay_firma = ss.signature is not None

    def marcar(hecho: bool, habilitado: bool) -> str:
        if hecho:
            return "hecho"
        return "activo" if habilitado else "bloqueado"

    return {
        "claves": marcar(hay_claves, True),
        "firmar": marcar(hay_firma, hay_claves),
        "verificar": marcar(ss.verificacion_ok is not None, hay_firma),
        "pki": marcar(bool(ss.cert) and ss.cert_validado is True, hay_claves),
    }


def paso_actual() -> str:
    """Primer paso que todavia no esta 'hecho' (el que toca ahora mismo)."""
    estados = estado_pasos()
    for pid, _, _ in PASOS:
        if estados[pid] != "hecho":
            return pid
    return "pki"


def progreso() -> tuple[int, int]:
    """(pasos completados, total de pasos)."""
    estados = estado_pasos()
    return sum(1 for e in estados.values() if e == "hecho"), len(PASOS)


def falta_para(paso: str) -> str | None:
    """Mensaje de que hace falta para desbloquear un paso, o None si ya esta."""
    if estado_pasos()[paso] != "bloqueado":
        return None
    return {
        "firmar": "Necesitas un par de claves RSA: sin clave privada no hay con que firmar.",
        "verificar": "Necesitas un documento firmado: sin firma no hay nada que comprobar.",
        "pki": "Necesitas una clave publica: el certificado es justamente lo que le da identidad.",
    }.get(paso)


# ------------------------------------------------------------ datos de ejemplo

def cargar_datos_ejemplo(tam: int = 2048, nombre_ca: str = "CA Demo ESPOCH",
                         nombre_emisor: str = "Emisor Demo - Mateo") -> None:
    """Ejecuta el flujo completo de una vez para poder explorar la app.

    Usa RSA-2048 (en vez de 3072) solo para que el arranque sea rapido
    durante la exposicion; en la pestana 2 se puede regenerar a 3072.
    """
    ss = st.session_state
    datos = DOC_EJEMPLO.read_bytes() if DOC_EJEMPLO.exists() else TEXTO_EJEMPLO.encode("utf-8")

    ss.private_key, ss.public_key = keys.generate_rsa_keypair(tam)
    ss.tam_clave_actual = tam

    ss.doc_bytes, ss.doc_name = datos, "constancia_ejemplo.txt"
    ss.hash_firmado = hashing.sha256_hex(datos)
    ss.signature = signing.sign(ss.private_key, datos)

    ss.ca_key, ss.ca_cert = pki.create_ca(nombre_ca, key_size=tam)
    ss.cert = pki.issue_certificate(ss.ca_key, ss.ca_cert, nombre_emisor, ss.public_key)

    # Se dejan sin marcar a proposito: que el usuario pulse "Verificar" y
    # "Validar certificado" es justamente la parte interesante de la demo.
    ss.verificacion_ok = ss.cert_validado = ss.ataque_rechazado = None
    ss.iniciado = True
