"""Version por consola (plan B si falla la interfaz en la exposicion).

Uso:  python demo_consola.py
Genera archivos en salida/ que tambien puedes cargar en la app web.
"""
from pathlib import Path

from crypto_core import hashing, keys, signing

SALIDA = Path("salida")
SALIDA.mkdir(exist_ok=True)

doc = Path("documentos/ejemplo.txt").read_bytes()
print("Documento original:\n", doc.decode(), sep="")
print("SHA-256:", hashing.sha256_hex(doc), "\n")

print("Generando claves RSA-3072...")
priv, pub = keys.generate_rsa_keypair(3072)
(SALIDA / "clave_publica.pem").write_bytes(keys.public_key_to_pem(pub))
(SALIDA / "clave_privada.pem").write_bytes(keys.private_key_to_pem(priv, "demo1234"))
print("Huella de la clave publica:", keys.fingerprint(pub)[:32], "...\n")

firma = signing.sign(priv, doc)
(SALIDA / "documento.txt").write_bytes(doc)
(SALIDA / "firma.sig").write_bytes(firma)
print(f"Firma generada ({len(firma)} bytes): {firma.hex()[:64]}...\n")

print("Prueba 1 - documento original :", "VALIDA" if signing.verify(pub, doc, firma) else "INVALIDA")
alterado = doc.replace(b"aprobo", b"reprobo")
print("Prueba 2 - documento alterado :", "VALIDA" if signing.verify(pub, alterado, firma) else "INVALIDA")
print("\nArchivos guardados en salida/ (puedes cargarlos en la pestana 'Verificar' de la app).")
