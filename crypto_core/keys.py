"""Generacion, serializacion y carga de claves RSA."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(key_size: int = 3072):
    """Genera un par de claves RSA. Devuelve (clave_privada, clave_publica)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def private_key_to_pem(private_key, password: str | None = None) -> bytes:
    """Exporta la clave privada en PEM (PKCS8), cifrada si hay contrasena."""
    enc = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, password: str | None = None):
    return serialization.load_pem_private_key(
        pem, password=password.encode() if password else None
    )


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def fingerprint(public_key) -> str:
    """Huella (SHA-256) de la clave publica: sirve para identificarla."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()
