"""Create a local CA and an HTTPS certificate for the KARMA dashboard domain.

Run once on the KARMA PC:  python tools/make_cert.py
Then trust <data dir>/tls/karma-local-ca.pem (tools/setup-demo.ps1 does this).
"""
import datetime
import ipaddress
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from backend import config


def build(name, issuer_name, public_key, signer, ca, sans=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
               .issuer_name(issuer_name)
               .public_key(public_key)
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=3650 if ca else 365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = (builder
                   .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.SubjectAlternativeName(list(sans)), critical=False))
    return builder.sign(signer, hashes.SHA256())


def main():
    out = config.TLS_CERT.parent
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "KARMA Local Demo CA")])
    ca = build("KARMA Local Demo CA", ca_name, ca_key.public_key(), ca_key, True)
    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.DNSName(config.DOMAIN), x509.DNSName("www." + config.DOMAIN), x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    leaf = build(config.DOMAIN, ca_name, key.public_key(), ca_key, False, sans)
    pem = serialization.Encoding.PEM
    (out / "karma-local-ca.pem").write_bytes(ca.public_bytes(pem))
    config.TLS_CERT.write_bytes(leaf.public_bytes(pem) + ca.public_bytes(pem))
    with open(config.TLS_KEY, "wb", opener=lambda p, f: os.open(p, f, 0o600)) as file:
        file.write(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # The CA private key is discarded on purpose: nothing else can ever be signed with it.
    print("Certificate for https://%s written to %s" % (config.DOMAIN, out))
    print("Trust this CA on the KARMA PC:", out / "karma-local-ca.pem")


if __name__ == "__main__":
    main()
