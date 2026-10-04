"""Disposable synthetic certificates for native gateway policy tests only."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

directory = Path(sys.argv[1])
directory.mkdir(mode=0o700, exist_ok=True)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "001122334455")])
stamp = datetime.now(timezone.utc)
signer = ec.generate_private_key(ec.SECP256R1())
for variant in ("good", "other", "expired", "server", "ca", "noeku"):
    key = ec.generate_private_key(ec.SECP256R1())
    before = stamp - timedelta(days=3)
    after = stamp - timedelta(days=1) if variant == "expired" else stamp + timedelta(days=3)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(before).not_valid_after(after)
               .add_extension(x509.BasicConstraints(ca=variant == "ca", path_length=0 if variant == "ca" else None), True))
    if variant != "noeku":
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if variant == "server" else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
    cert = builder.sign(signer, hashes.SHA256())
    (directory / f"{variant}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
