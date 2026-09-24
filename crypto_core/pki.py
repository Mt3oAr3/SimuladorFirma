"""Mini-PKI: Autoridad Certificadora (CA) y certificados X.509."""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .keys import fingerprint


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Criptografia"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key_usage(**flags) -> x509.KeyUsage:
    base = dict(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    base.update(flags)
    return x509.KeyUsage(**base)


def create_ca(common_name: str, days: int = 365, key_size: int = 3072):
    """Crea una CA autofirmada. Devuelve (clave_privada_ca, certificado_ca)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = _name(common_name)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # autofirmado: emisor == sujeto
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True, digital_signature=True), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_certificate(ca_key, ca_cert, common_name: str, subject_public_key, days: int = 180):
    """La CA firma un certificado que vincula un nombre con una clave publica."""
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(digital_signature=True, content_commitment=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def verify_certificate(cert, ca_cert) -> tuple[bool, str]:
    """Valida vigencia y que la firma del certificado sea de la CA indicada."""
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return False, "El certificado esta vencido o aun no es vigente."
    try:
        cert.verify_directly_issued_by(ca_cert)
    except InvalidSignature:
        return False, "La firma del certificado NO corresponde a la CA de confianza."
    except (ValueError, TypeError) as exc:
        return False, f"El certificado no fue emitido por esta CA ({exc})."
    return True, "Certificado valido: firmado por la CA de confianza y vigente."


def cert_to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert(pem: bytes):
    return x509.load_pem_x509_certificate(pem)


def describe(cert) -> dict:
    """Resumen legible de un certificado."""
    cn = lambda n: n.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return {
        "Sujeto (a quien identifica)": cn(cert.subject),
        "Emisor (quien lo firmo)": cn(cert.issuer),
        "Numero de serie": format(cert.serial_number, "x")[:24] + "...",
        "Valido desde": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "Valido hasta": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "Algoritmo de firma": cert.signature_algorithm_oid._name,
        "Huella de la clave publica": fingerprint(cert.public_key())[:32] + "...",
    }
