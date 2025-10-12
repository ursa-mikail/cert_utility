#!pip install pycryptodome 

# cert_utility.py
import os
import sys
import binascii
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import secrets

class Config:
    def __init__(self):
        self.entity_name = "demo_user"
        self.base_path = "./"
        
        # Initialize paths
        self.key_store_path = Path(self.base_path) / "key_store"
        self.certs_path = Path(self.base_path) / "certs"
        self.csr_path = Path(self.base_path) / "csr"
        self.cnf_path = Path(self.base_path) / "cnf"
        self.sig_path = Path(self.base_path) / "signatures"
        self.data_plaintext_path = Path(self.base_path) / "data_plaintext"
        self.data_ciphered_path = Path(self.base_path) / "data_ciphered"
        
        # Cryptographic parameters
        self.rsa_key_length = 2048
        self.ecc_curve = ec.SECP256R1()
        self.hash_algo = hashes.SHA256()
        self.cert_days = 365
        
        # Certificate subject
        self.country = "US"
        self.state = "California"
        self.locality = "San Jose"
        self.org = "Demo Organization"
        self.ou = "Cryptography Unit"
        self.cn = "www.demo_user.com"
        self.email = "demo_user@demo.com"
    
    @classmethod
    def load_from_cnf(cls):
        config = cls()
        cnf_path = config.cnf_path
        
        if not cnf_path.exists():
            return config
            
        for cnf_file in cnf_path.glob("*.cnf"):
            try:
                config._parse_cnf_file(cnf_file)
            except Exception as e:
                print(f"Warning: Error parsing CNF file {cnf_file}: {e}")
                
        return config
    
    def _parse_cnf_file(self, cnf_file):
        current_section = ""
        
        with open(cnf_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if line.startswith('#') or not line:
                    continue
                
                # Check for section headers
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                    continue
                
                # Parse key-value pairs
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if current_section == "req":
                        if key == "default_bits":
                            self.rsa_key_length = int(value)
                        elif key == "default_md":
                            if value == "sha256":
                                self.hash_algo = hashes.SHA256()
                            elif value == "sha384":
                                self.hash_algo = hashes.SHA384()
                            elif value == "sha512":
                                self.hash_algo = hashes.SHA512()
                    
                    elif current_section == "dn":
                        if key == "C":
                            self.country = value
                        elif key == "ST":
                            self.state = value
                        elif key == "L":
                            self.locality = value
                        elif key == "O":
                            self.org = value
                        elif key == "OU":
                            self.ou = value
                        elif key == "CN":
                            self.cn = value
                        elif key == "emailAddress":
                            self.email = value
                    
                    else:
                        # Global settings
                        if key == "entity_node_name":
                            self.entity_name = value


class KeyStore:
    def __init__(self, config):
        self.config = config
        
        # RSA Keys
        self.rsa_oaep_private_key = None
        self.rsa_oaep_public_key = None
        self.rsa_pss_private_key = None
        self.rsa_pss_public_key = None
        
        # ECC Keys
        self.ecc_private_key = None
        self.ecc_public_key = None
        
        # Symmetric Keys
        self.aes_key = None
        self.hmac_key = None
    
    def setup_folder_structure(self):
        """Initialize folder structure"""
        print("=" * 50)
        print("[Setting up folder structure]")
        print("=" * 50)
        
        folders = [
            (self.config.key_store_path, "Key Store"),
            (self.config.certs_path, "Certificates"),
            (self.config.csr_path, "Certificate Signing Requests"),
            (self.config.cnf_path, "Configuration Files"),
            (self.config.sig_path, "Signatures"),
            (self.config.data_plaintext_path, "Plaintext Data"),
            (self.config.data_ciphered_path, "Encrypted Data"),
        ]
        
        for folder_path, description in folders:
            folder_path.mkdir(parents=True, exist_ok=True)
            print(f"Created folder: {description} ({folder_path})")
        
        print("\n✓ Folder structure created successfully")
    
    def generate_all_keys(self):
        """Generate all cryptographic keys"""
        print("=" * 50)
        print("[Generating all cryptographic keys]")
        print("=" * 50)
        print()
        
        self.generate_rsa_pss_keys()
        print()
        
        self.generate_rsa_oaep_keys()
        print()
        
        self.generate_ecc_keys()
        print()
        
        self.generate_aes_key()
        print()
        
        self.generate_hmac_key()
        print()
        
        print("✓ All keys generated successfully")
    
    def generate_rsa_oaep_keys(self):
        """Generate RSA-OAEP key pair"""
        print("=" * 50)
        print("[Generating RSA-OAEP key for encryption]")
        print("=" * 50)
        
        self.rsa_oaep_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.rsa_key_length
        )
        self.rsa_oaep_public_key = self.rsa_oaep_private_key.public_key()
        
        # Save to files
        private_key_file = self.config.key_store_path / "demo_user_rsa_oaep_private.pem"
        public_key_file = self.config.key_store_path / "demo_user_rsa_oaep_public.pem"
        
        self._save_rsa_private_key(self.rsa_oaep_private_key, private_key_file)
        self._save_rsa_public_key(self.rsa_oaep_public_key, public_key_file)
        
        print(f"✓ RSA-OAEP key pair generated ({self.config.rsa_key_length} bits)")
        print(f"  Private: {private_key_file}")
        print(f"  Public:  {public_key_file}")
    
    def generate_rsa_pss_keys(self):
        """Generate RSA-PSS key pair"""
        print("=" * 50)
        print("[Generating RSA-PSS key for signing]")
        print("=" * 50)
        
        self.rsa_pss_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.rsa_key_length
        )
        self.rsa_pss_public_key = self.rsa_pss_private_key.public_key()
        
        # Save to files
        private_key_file = self.config.key_store_path / "demo_user_rsa_pss_private.pem"
        public_key_file = self.config.key_store_path / "demo_user_rsa_pss_public.pem"
        
        self._save_rsa_private_key(self.rsa_pss_private_key, private_key_file)
        self._save_rsa_public_key(self.rsa_pss_public_key, public_key_file)
        
        print(f"✓ RSA-PSS key pair generated ({self.config.rsa_key_length} bits)")
        print(f"  Private: {private_key_file}")
        print(f"  Public:  {public_key_file}")
    
    def generate_ecc_keys(self):
        """Generate ECC key pair"""
        print("=" * 50)
        print("[Generating ECC key for signing]")
        print("=" * 50)
        
        self.ecc_private_key = ec.generate_private_key(self.config.ecc_curve)
        self.ecc_public_key = self.ecc_private_key.public_key()
        
        # Save to files
        private_key_file = self.config.key_store_path / "demo_user_ecc_private.pem"
        public_key_file = self.config.key_store_path / "demo_user_ecc_public.pem"
        
        self._save_ecc_private_key(self.ecc_private_key, private_key_file)
        self._save_ecc_public_key(self.ecc_public_key, public_key_file)
        
        curve_name = "P-256"
        if isinstance(self.config.ecc_curve, ec.SECP384R1):
            curve_name = "P-384"
        elif isinstance(self.config.ecc_curve, ec.SECP521R1):
            curve_name = "P-521"
        
        print(f"✓ ECC key pair generated (curve: {curve_name})")
        print(f"  Private: {private_key_file}")
        print(f"  Public:  {public_key_file}")
    
    def generate_aes_key(self):
        """Generate AES-256 key"""
        print("=" * 50)
        print("[Generating AES-256 key for ciphering]")
        print("=" * 50)
        
        self.aes_key = secrets.token_bytes(32)  # 256 bits
        
        # Save to file
        key_file = self.config.key_store_path / "demo_user_aes256.key"
        with open(key_file, 'w') as f:
            f.write(binascii.hexlify(self.aes_key).decode())
        
        print(f"✓ AES-256 key generated")
        print(f"  File: {key_file}")
    
    def generate_hmac_key(self):
        """Generate HMAC-SHA256 key"""
        print("=" * 50)
        print("[Generating HMAC-SHA256 key]")
        print("=" * 50)
        
        self.hmac_key = secrets.token_bytes(32)  # 256 bits
        
        # Save to file
        key_file = self.config.key_store_path / "demo_user_hmac_sha256.key"
        with open(key_file, 'w') as f:
            f.write(binascii.hexlify(self.hmac_key).decode())
        
        print(f"✓ HMAC-SHA256 key generated")
        print(f"  File: {key_file}")
    
    def _save_rsa_private_key(self, private_key, filename):
        """Save RSA private key to file"""
        with open(filename, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def _save_rsa_public_key(self, public_key, filename):
        """Save RSA public key to file"""
        with open(filename, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def _save_ecc_private_key(self, private_key, filename):
        """Save ECC private key to file"""
        with open(filename, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def _save_ecc_public_key(self, public_key, filename):
        """Save ECC public key to file"""
        with open(filename, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def _load_rsa_private_key(self, filename):
        """Load RSA private key from file"""
        with open(filename, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    def _load_rsa_public_key(self, filename):
        """Load RSA public key from file"""
        with open(filename, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
    
    def _load_ecc_private_key(self, filename):
        """Load ECC private key from file"""
        with open(filename, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    def _load_ecc_public_key(self, filename):
        """Load ECC public key from file"""
        with open(filename, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
    
    def _load_aes_key(self, filename):
        """Load AES key from file"""
        with open(filename, 'r') as f:
            return binascii.unhexlify(f.read().strip())
    
    def generate_rsa_certificate(self):
        """Generate RSA certificate"""
        print("=" * 50)
        print("[Generating RSA certificate]")
        print("=" * 50)
        
        # Use RSA-OAEP keys for certificate generation (matching Go version)
        if self.rsa_oaep_private_key is None:
            # Try to load from file
            private_key_file = self.config.key_store_path / "demo_user_rsa_oaep_private.pem"
            if not private_key_file.exists():
                raise Exception("RSA private key not found. Please generate keys first (option 2)")
            
            self.rsa_oaep_private_key = self._load_rsa_private_key(private_key_file)
            self.rsa_oaep_public_key = self.rsa_oaep_private_key.public_key()
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.config.country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.config.ou),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.config.locality),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config.state),
            x509.NameAttribute(NameOID.COMMON_NAME, self.config.cn),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.config.email),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.rsa_oaep_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=self.config.cert_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(self.config.cn),
                x509.DNSName(f"{self.config.entity_name}.com"),
                x509.DNSName(f"demo.{self.config.entity_name}.com"),
            ]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                data_encipherment=True,
                content_commitment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=False
        ).sign(self.rsa_oaep_private_key, self.config.hash_algo)
        
        # Save certificate
        cert_file = self.config.certs_path / "demo_user_rsa.crt"
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"✓ RSA certificate generated")
        print(f"  Certificate: {cert_file}")
        print(f"  Valid for: {self.config.cert_days} days")
    
    def generate_ecc_certificate(self):
        """Generate ECC certificate"""
        print("=" * 50)
        print("[Generating ECC certificate]")
        print("=" * 50)
        
        if self.ecc_private_key is None:
            # Try to load from file
            private_key_file = self.config.key_store_path / "demo_user_ecc_private.pem"
            if not private_key_file.exists():
                raise Exception("ECC private key not found. Please generate keys first (option 2)")
            
            self.ecc_private_key = self._load_ecc_private_key(private_key_file)
            self.ecc_public_key = self.ecc_private_key.public_key()
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.config.country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config.org),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.config.ou),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.config.locality),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config.state),
            x509.NameAttribute(NameOID.COMMON_NAME, self.config.cn),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.config.email),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ecc_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=self.config.cert_days)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(self.config.cn),
                x509.DNSName(f"{self.config.entity_name}.com"),
                x509.DNSName(f"demo.{self.config.entity_name}.com"),
            ]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                data_encipherment=False,
                content_commitment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
                x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=False
        ).sign(self.ecc_private_key, self.config.hash_algo)
        
        # Save certificate
        cert_file = self.config.certs_path / "demo_user_ecc.crt"
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"✓ ECC certificate generated")
        print(f"  Certificate: {cert_file}")
        print(f"  Valid for: {self.config.cert_days} days")
    
    def view_certificate(self):
        """View certificate details"""
        print("=" * 50)
        print("[View Certificate Details]")
        print("=" * 50)
        print()
        print("Select certificate:")
        print("1. RSA Certificate")
        print("2. ECC Certificate")
        choice = input("Choice: ").strip()
        print()
        
        if choice == "1":
            self._view_certificate_file("demo_user_rsa.crt")
        elif choice == "2":
            self._view_certificate_file("demo_user_ecc.crt")
        else:
            print("Invalid choice")
    
    def _view_certificate_file(self, filename):
        """View specific certificate file"""
        cert_file = self.config.certs_path / filename
        
        if not cert_file.exists():
            print(f"✗ Certificate not found: {cert_file}")
            return
        
        with open(cert_file, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        
        print(f"Certificate: {cert_file}")
        print()
        print(f"Subject: {cert.subject}")
        print(f"Issuer: {cert.issuer}")
        print(f"Serial Number: {cert.serial_number}")
        print(f"Valid From: {cert.not_valid_before}")
        print(f"Valid Until: {cert.not_valid_after}")
        print(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
        
        # Key usage
        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            print(f"Key Usage: {key_usage.value}")
        except x509.ExtensionNotFound:
            pass
        
        # Extended key usage
        try:
            ext_key_usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            print(f"Extended Key Usage: {ext_key_usage.value}")
        except x509.ExtensionNotFound:
            pass
        
        # Subject Alternative Name
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            print(f"DNS Names: {[name.value for name in san.value if isinstance(name, x509.DNSName)]}")
        except x509.ExtensionNotFound:
            pass
        
        # Email addresses
        email_addresses = []
        for attr in cert.subject:
            if attr.oid == NameOID.EMAIL_ADDRESS:
                email_addresses.append(attr.value)
        if email_addresses:
            print(f"Email Addresses: {', '.join(email_addresses)}")
    
    def sign_with_rsa_pss(self, message):
        """Sign message with RSA-PSS"""
        print("=" * 50)
        print("[Sign Message with RSA-PSS]")
        print("=" * 50)
        print()
        
        if self.rsa_pss_private_key is None:
            # Try to load from file
            private_key_file = self.config.key_store_path / "demo_user_rsa_pss_private.pem"
            if not private_key_file.exists():
                raise Exception("RSA private key not found. Please generate keys first (option 2)")
            
            self.rsa_pss_private_key = self._load_rsa_private_key(private_key_file)
        
        # Sign the message
        signature = self.rsa_pss_private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(self.config.hash_algo),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self.config.hash_algo
        )
        
        # Save signature
        sig_file = self.config.sig_path / "demo_user_rsa.sig"
        with open(sig_file, 'wb') as f:
            f.write(signature)
        
        # Save message
        msg_file = self.config.data_plaintext_path / "message.txt"
        with open(msg_file, 'w') as f:
            f.write(message)
        
        print(f"✓ Message signed with RSA-PSS")
        print(f"  Signature: {sig_file}")
    
    def verify_rsa_pss(self, message):
        """Verify RSA-PSS signature"""
        print("=" * 50)
        print("[Verify RSA-PSS Signature]")
        print("=" * 50)
        print()
        
        if self.rsa_pss_public_key is None:
            # Try to load from file
            public_key_file = self.config.key_store_path / "demo_user_rsa_pss_public.pem"
            if not public_key_file.exists():
                raise Exception("RSA public key not found. Please generate keys first (option 2)")
            
            self.rsa_pss_public_key = self._load_rsa_public_key(public_key_file)
        
        sig_file = self.config.sig_path / "demo_user_rsa.sig"
        if not sig_file.exists():
            raise Exception("Signature file not found. Please sign a message first (option 5)")
        
        with open(sig_file, 'rb') as f:
            signature = f.read()
        
        try:
            self.rsa_pss_public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(self.config.hash_algo),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self.config.hash_algo
            )
            print("✓ Signature VALID")
        except Exception:
            print("✗ Signature INVALID")
    
    def sign_with_ecc(self, message):
        """Sign message with ECC"""
        print("=" * 50)
        print("[Sign Message with ECC]")
        print("=" * 50)
        print()
        
        if self.ecc_private_key is None:
            # Try to load from file
            private_key_file = self.config.key_store_path / "demo_user_ecc_private.pem"
            if not private_key_file.exists():
                raise Exception("ECC private key not found. Please generate keys first (option 2)")
            
            self.ecc_private_key = self._load_ecc_private_key(private_key_file)
        
        # Sign the message
        signature = self.ecc_private_key.sign(
            message.encode(),
            ec.ECDSA(self.config.hash_algo)
        )
        
        # Save signature
        sig_file = self.config.sig_path / "demo_user_ecc.sig"
        with open(sig_file, 'wb') as f:
            f.write(signature)
        
        # Save message
        msg_file = self.config.data_plaintext_path / "message.txt"
        with open(msg_file, 'w') as f:
            f.write(message)
        
        print(f"✓ Message signed with ECDSA")
        print(f"  Signature: {sig_file}")
    
    def verify_ecc(self, message):
        """Verify ECC signature"""
        print("=" * 50)
        print("[Verify ECC Signature]")
        print("=" * 50)
        print()
        
        if self.ecc_public_key is None:
            # Try to load from file
            public_key_file = self.config.key_store_path / "demo_user_ecc_public.pem"
            if not public_key_file.exists():
                raise Exception("ECC public key not found. Please generate keys first (option 2)")
            
            self.ecc_public_key = self._load_ecc_public_key(public_key_file)
        
        sig_file = self.config.sig_path / "demo_user_ecc.sig"
        if not sig_file.exists():
            raise Exception("Signature file not found. Please sign a message first (option 7)")
        
        with open(sig_file, 'rb') as f:
            signature = f.read()
        
        try:
            self.ecc_public_key.verify(
                signature,
                message.encode(),
                ec.ECDSA(self.config.hash_algo)
            )
            print("✓ Signature VALID")
        except Exception:
            print("✗ Signature INVALID")
    
    def encrypt_with_aes(self, message):
        """Encrypt message with AES-256-GCM"""
        print("=" * 50)
        print("[Encrypt with AES-256-GCM]")
        print("=" * 50)
        print()
        
        if self.aes_key is None:
            # Try to load from file
            key_file = self.config.key_store_path / "demo_user_aes256.key"
            if not key_file.exists():
                raise Exception("AES key not found. Please generate AES key first (option 9)")
            
            self.aes_key = self._load_aes_key(key_file)
        
        # Generate a random 96-bit nonce
        nonce = secrets.token_bytes(12)
        
        # Encrypt using AES-GCM
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Combine nonce, ciphertext, and tag
        encrypted_data = nonce + ciphertext + encryptor.tag
        
        # Save encrypted data
        ciphertext_file = self.config.data_ciphered_path / "message.enc"
        with open(ciphertext_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Save plaintext for reference
        plaintext_file = self.config.data_plaintext_path / "message.txt"
        with open(plaintext_file, 'w') as f:
            f.write(message)
        
        print(f"✓ File encrypted")
        print(f"  Plaintext: {plaintext_file}")
        print(f"  Ciphertext: {ciphertext_file}")
    
    def decrypt_with_aes(self):
        """Decrypt message with AES-256-GCM"""
        print("=" * 50)
        print("[Decrypt with AES-256-GCM]")
        print("=" * 50)
        print()
        
        if self.aes_key is None:
            # Try to load from file
            key_file = self.config.key_store_path / "demo_user_aes256.key"
            if not key_file.exists():
                raise Exception("AES key not found. Please generate AES key first (option 9)")
            
            self.aes_key = self._load_aes_key(key_file)
        
        ciphertext_file = self.config.data_ciphered_path / "message.enc"
        if not ciphertext_file.exists():
            raise Exception("Encrypted file not found")
        
        with open(ciphertext_file, 'rb') as f:
            encrypted_data = f.read()
        
        # Extract nonce, ciphertext, and tag
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(self.aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Save decrypted text
        decrypted_file = self.config.data_plaintext_path / "message_decrypted.txt"
        with open(decrypted_file, 'w') as f:
            f.write(plaintext.decode())
        
        print(f"✓ File decrypted")
        print()
        print("Decrypted message:")
        print(plaintext.decode())
    
    def complete_rsa_workflow(self):
        """Complete RSA workflow demo"""
        print("=" * 50)
        print("[Complete RSA Workflow Demo]")
        print("=" * 50)
        print()
        print("This will demonstrate:")
        print("1. Key generation")
        print("2. Certificate creation")
        print("3. Message signing")
        print("4. Signature verification")
        print()
        input("Press Enter to begin...")
        
        print()
        self.generate_rsa_pss_keys()
        
        print()
        self.generate_rsa_certificate()
        
        print()
        print("[Signing test message]")
        test_message = "Test message for RSA-PSS signing"
        self.sign_with_rsa_pss(test_message)
        
        print()
        print("[Verifying signature]")
        self.verify_rsa_pss(test_message)
        
        print()
        print("✓ RSA workflow complete!")
    
    def complete_ecc_workflow(self):
        """Complete ECC workflow demo"""
        print("=" * 50)
        print("[Complete ECC Workflow Demo]")
        print("=" * 50)
        print()
        print("This will demonstrate:")
        print("1. Key generation")
        print("2. Certificate creation")
        print("3. Message signing")
        print("4. Signature verification")
        print()
        input("Press Enter to begin...")
        
        print()
        self.generate_ecc_keys()
        
        print()
        self.generate_ecc_certificate()
        
        print()
        print("[Signing test message]")
        test_message = "Test message for ECDSA signing"
        self.sign_with_ecc(test_message)
        
        print()
        print("[Verifying signature]")
        self.verify_ecc(test_message)
        
        print()
        print("✓ ECC workflow complete!")


def print_demo_menu():
    """Print the main menu"""
    print("=" * 50)
    print("    CERTIFICATE UTILITY DEMO (Python)")
    print("=" * 50)
    print()
    print("[SETUP]")
    print("1  : Initialize folder structure")
    print("2  : Generate keys (RSA-OAEP, RSA-PSS, ECC)")
    print()
    print("[CSR & CERTIFICATES]")
    print("3  : Generate self-signed certificate")
    print("4  : View certificate details")
    print()
    print("[SIGNING - RSA-PSS]")
    print("5  : Sign message with RSA-PSS")
    print("6  : Verify RSA-PSS signature")
    print()
    print("[SIGNING - ECC]")
    print("7  : Sign message with ECC")
    print("8  : Verify ECC signature")
    print()
    print("[CIPHERING - AES]")
    print("9  : Generate AES key")
    print("10 : Encrypt message with AES")
    print("11 : Decrypt message with AES")
    print()
    print("[COMPLETE WORKFLOW]")
    print("12 : Run complete RSA workflow demo")
    print("13 : Run complete ECC workflow demo")
    print()
    print("x  : Exit")
    print("=" * 50)


def main():
    """Main function"""
    # Initialize configuration
    config = Config.load_from_cnf()
    key_store = KeyStore(config)
    
    print(f"Entity: {config.entity_name}")
    print()
    
    while True:
        print_demo_menu()
        choice = input("Select option: ").strip()
        print()
        
        try:
            if choice == "1":
                key_store.setup_folder_structure()
            elif choice == "2":
                key_store.generate_all_keys()
            elif choice == "3":
                print("Select key type:")
                print("1. RSA-PSS")
                print("2. ECC")
                cert_choice = input("Choice: ").strip()
                print()
                
                if cert_choice == "1":
                    key_store.generate_rsa_certificate()
                elif cert_choice == "2":
                    key_store.generate_ecc_certificate()
                else:
                    print("Invalid choice")
            elif choice == "4":
                key_store.view_certificate()
            elif choice == "5":
                message = input("Enter message to sign: ").strip()
                key_store.sign_with_rsa_pss(message)
            elif choice == "6":
                message = input("Enter message to verify: ").strip()
                key_store.verify_rsa_pss(message)
            elif choice == "7":
                message = input("Enter message to sign: ").strip()
                key_store.sign_with_ecc(message)
            elif choice == "8":
                message = input("Enter message to verify: ").strip()
                key_store.verify_ecc(message)
            elif choice == "9":
                key_store.generate_aes_key()
            elif choice == "10":
                message = input("Enter message to encrypt: ").strip()
                key_store.encrypt_with_aes(message)
            elif choice == "11":
                key_store.decrypt_with_aes()
            elif choice == "12":
                key_store.complete_rsa_workflow()
            elif choice == "13":
                key_store.complete_ecc_workflow()
            elif choice.lower() == "x":
                print("Exiting demo...")
                break
            else:
                print("Invalid selection!")
        except Exception as e:
            print(f"Error: {e}")
        
        if choice.lower() != "x":
            print()
            input("Press Enter to continue...")
            print()


if __name__ == "__main__":
    main()

    