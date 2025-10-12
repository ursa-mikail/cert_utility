# Generate Cert and Get Info 
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# Generate private key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Certificate subject and issuer (self-signed)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
    x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
])

# Build certificate
cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    key.public_key()).serial_number(
    x509.random_serial_number()).not_valid_before(
    datetime.utcnow()).not_valid_after(
    datetime.utcnow() + timedelta(days=365)).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("example.com")]),
    critical=False,
).sign(key, hashes.SHA256())

# Save cert and key to files
with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open("key.pem", "wb") as f:
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

# Parse the certificate and get issuer information
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load cert
with open("cert.pem", "rb") as f:
    cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

# Get issuer information
issuer = cert.issuer

print("Issuer Details:")
for attribute in issuer:
    print(f"{attribute.oid._name}: {attribute.value}")

print("Subject:", cert.subject)
print("Serial Number:", cert.serial_number)
print("Valid From:", cert.not_valid_before)
print("Valid Until:", cert.not_valid_after)
print("Public Key:", cert.public_key())
print("Extensions:")
for ext in cert.extensions:
    print(f"- {ext.oid._name}: {ext.value}")


"""
Issuer Details:
countryName: US
stateOrProvinceName: California
localityName: San Francisco
organizationName: Example Corp
commonName: example.com
Subject: <Name(C=US,ST=California,L=San Francisco,O=Example Corp,CN=example.com)>
Serial Number: 697469564282780852252799741253342050277719303502
Valid From: 2025-07-02 18:05:40
Valid Until: 2026-07-02 18:05:40
Public Key: <cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey object at 0x7be24078e130>
Extensions:
- subjectAltName: <SubjectAlternativeName(<GeneralNames([<DNSName(value='example.com')>])>)>
/tmp/ipython-input-4-2084266668.py:59: CryptographyDeprecationWarning: Properties that return a naïve datetime object have been deprecated. Please switch to not_valid_before_utc.
  print("Valid From:", cert.not_valid_before)
/tmp/ipython-input-4-2084266668.py:60: CryptographyDeprecationWarning: Properties that return a naïve datetime object have been deprecated. Please switch to not_valid_after_utc.
  print("Valid Until:", cert.not_valid_after)
"""