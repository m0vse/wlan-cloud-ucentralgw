"""Create disposable synthetic gateway fixtures; never production CA material."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

destination = Path(sys.argv[1])
destination.mkdir(mode=0o700, exist_ok=False)
now = datetime.now(timezone.utc)

def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def certificate(name, subject_key, issuer=None, signer=None, ca=False, server=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject).public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=1 if ca else None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False))
    if issuer:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False)
    if ca:
        builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
    else:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
    return builder.sign(signer or subject_key, hashes.SHA256())

def save(name, cert, private_key=None):
    (destination / f'{name}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if private_key:
        path = destination / f'{name}-key.pem'
        path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        path.chmod(0o600)

root_key = key()
root = certificate('Synthetic isolated CA', root_key, ca=True)
issuer_key = key()
issuer = certificate('Synthetic isolated issuer', issuer_key, root, root_key, ca=True)
server_key = key()
server = certificate('localhost', server_key, root, root_key, server=True)
save('root', root)
save('issuer', issuer)
save('websocket-cert', server)
save('restapi-ca', root)
save('restapi-cert', server)
for name in ('websocket', 'restapi'):
    path = destination / f'{name}-key.pem'
    path.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.chmod(0o600)
(destination / 'clientcas.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM)
    + issuer.public_bytes(serialization.Encoding.PEM))
for name in ('cas', 'logs', 'data', 'uploads'):
    (destination / name).mkdir()
fingerprints = []
for name in ('good', 'other'):
    device_key = key()
    device = certificate('001122334455', device_key, issuer, issuer_key)
    save(name, device, device_key)
    fingerprints.append(device.fingerprint(hashes.SHA256()).hex())
policy = {'schemaVersion': 1, 'version': 1, 'expires': int(now.timestamp()) + 300,
    'inventory': {'001122334455': {'enabled': True, 'fingerprints': [fingerprints[0]]}}, 'revoked': []}
(destination / 'policy.json').write_text(json.dumps(policy))
(destination / 'policy.json').chmod(0o640)
source = Path(__file__).resolve().parents[2] / 'owgw.properties'
properties = source.read_text().replace('$OWGW_ROOT', '/tmp/runtime').replace('/tmp/runtime/certs/', '/tmp/runtime/').replace('= mypassword', '=')
properties += '''
# Isolated network-none test configuration only; no external listeners.
openwifi.privatepki.policy = /tmp/runtime/policy.json
openwifi.privatepki.owner = 0
openwifi.security.restapi.disable = true
openwifi.kafka.enable = false
rtty.enabled = false
rtty.internal = false
alb.enable = false
archiver.enabled = false
autoprovisioning.process = default
logging.type = console
logging.asynch = false
logging.websocket = true
'''
(destination / 'owgw.properties').write_text(properties)
print('Disposable synthetic gateway fixtures created.')
