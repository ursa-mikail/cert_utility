import os
import time
import base64
import hashlib
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# Generate RSA key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Create a self-signed certificate and save it to a folder
def create_certificate(private_key, public_key, folder="certs"):
    os.makedirs(folder, exist_ok=True)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    cert_path = os.path.join(folder, "certificate.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path

# Challenge-response authentication with nonce
def sign_nonce(private_key, nonce):
    signature = private_key.sign(
        nonce.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_nonce(public_key, nonce, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            nonce.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Simulating authentication
if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    cert_path = create_certificate(private_key, public_key)
    print(f"Certificate saved at: {cert_path}")
    
    nonce = "5a5a"
    
    print(f"Client signing nonce: {nonce}")
    signature = sign_nonce(private_key, nonce)
    print(f"Signature: {signature}")
    
    print("Server verifying signature...")
    if verify_nonce(public_key, nonce, signature):
        print("Authentication successful!")
    else:
        print("Authentication failed!")


"""
Certificate saved at: certs/certificate.pem
Client signing nonce: 5a5a
Signature: HpQfyR+YafgM/votoQGpIBdwG56aiVEBDHmiIys2JNUgs7Q8eKp8PFuKjDBsGwFjFKtF4bvGpyOb2HPzQ5ipF5VdI3MvJUGeJlLAp0/s+s08IP+DX8EDbzj5bv3krULGoPbkPjhdMp83GnaO46HJedNZ/Zeqjw0zoUjk5+eGGuWZzsVGspPjmO1snX2iA/RWK7Ma5GoSp/x8YCoDyIubywOp3tlhrxiKsTKFaGgPuoIHJJTCZHbco/UehSQwYaxy6PeW/NN/5q9IqypEJUXyUCU9mB3Ztz49unTqtjqxpC3szDaV0ffowQcj9xBDH+A3UTE9xEXmFMbEB4WBKM5yZw==
Server verifying signature...
Authentication successful!
"""