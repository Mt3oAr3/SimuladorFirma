"""Firma y verificacion digital con RSA-PSS + SHA-256."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def _pss() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=hashes.SHA256().digest_size,
    )


def sign(private_key, data: bytes) -> bytes:
    """Calcula SHA-256 de los datos y lo firma con la clave privada."""
    return private_key.sign(data, _pss(), hashes.SHA256())


def verify(public_key, data: bytes, signature: bytes) -> bool:
    """True si la firma corresponde a los datos y a la clave publica."""
    try:
        public_key.verify(signature, data, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
