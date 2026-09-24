"""Funciones hash (SHA-256)."""
import hashlib


def sha256_hex(data: bytes) -> str:
    """Devuelve el hash SHA-256 de los datos en hexadecimal (64 caracteres)."""
    return hashlib.sha256(data).hexdigest()


def bits_distintos(hex_a: str, hex_b: str) -> int:
    """Cuenta cuantos bits difieren entre dos hashes (efecto avalancha)."""
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")
