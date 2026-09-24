"""Pruebas del nucleo criptografico. Ejecutar con:  pytest -v"""
import pytest

from crypto_core import hashing, keys, pki, signing

DOC = b"Constancia: el estudiante Mateo aprobo la asignatura X."


@pytest.fixture(scope="module")
def par():
    return keys.generate_rsa_keypair(2048)  # 2048 para que las pruebas sean rapidas


def test_sha256_vector_conocido():
    # Vector de prueba oficial de NIST para "abc"
    assert hashing.sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_efecto_avalancha():
    a = hashing.sha256_hex(b"Transferir $100")
    b = hashing.sha256_hex(b"Transferir $101")
    assert 90 < hashing.bits_distintos(a, b) < 166  # ~128 de 256 bits


def test_firma_valida(par):
    priv, pub = par
    assert signing.verify(pub, DOC, signing.sign(priv, DOC))


def test_documento_alterado_invalida_firma(par):
    priv, pub = par
    firma = signing.sign(priv, DOC)
    assert not signing.verify(pub, DOC.replace(b"aprobo", b"reprobo"), firma)


def test_clave_publica_ajena_no_verifica(par):
    priv, _ = par
    _, otra_pub = keys.generate_rsa_keypair(2048)
    assert not signing.verify(otra_pub, DOC, signing.sign(priv, DOC))


def test_pem_ida_y_vuelta(par):
    priv, pub = par
    priv2 = keys.load_private_key(keys.private_key_to_pem(priv, "clave"), "clave")
    pub2 = keys.load_public_key(keys.public_key_to_pem(pub))
    assert signing.verify(pub2, DOC, signing.sign(priv2, DOC))


def test_cadena_pki_valida(par):
    _, pub = par
    ca_key, ca_cert = pki.create_ca("CA Demo", key_size=2048)
    cert = pki.issue_certificate(ca_key, ca_cert, "Emisor Demo", pub)
    assert pki.verify_certificate(cert, ca_cert)[0]


def test_certificado_falso_es_rechazado(par):
    _, pub = par
    ca_key, ca_cert = pki.create_ca("CA Demo", key_size=2048)
    # Atacante: CA falsa con el MISMO nombre
    rogue_key, rogue_ca = pki.create_ca("CA Demo", key_size=2048)
    falso = pki.issue_certificate(rogue_key, rogue_ca, "Emisor Demo", pub)
    ok, _ = pki.verify_certificate(falso, ca_cert)
    assert not ok
