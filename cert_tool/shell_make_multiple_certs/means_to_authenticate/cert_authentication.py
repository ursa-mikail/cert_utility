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

# Create a self-signed certificate
def create_certificate(private_key, public_key):
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
    return cert

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
    cert = create_certificate(private_key, public_key)
    
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
Client signing nonce: 5a5a
Signature: a5kVIwpAG3+zwsPzc2oyOO1HHN3IYkeHr9oSYQuAjm4z/HRlO4GxJQSk6acJvQfLCOhZ7ZdKeB5s8hF2+tHN7jIHCU9CURQY1v9iloNB08IdW2qs9DDasu4scuR8vMRcDVZ4bqg1TlosDCKbDmWBxeSLTPrEmk9Dzg80Fhi35nyJnnC/lg8+gZVhKrO+m5/ZQllnWNjzfsFdqXxzRF0QaC0YcTygr3yxC3bxlTvB7minOBmRSROcCBaYtTIqGr+7gWU2UtjlGmf4v5FtlzbUDe4FKcNL0Uxj7kXPdWAXEFg1SWpNSgXF50xRcgKpReKJK9NdNFwZ+4bvqg6M8sdGfQ==
Server verifying signature...
Authentication successful!
"""