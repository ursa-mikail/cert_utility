# 1️⃣ Generate an RSA Key Pair
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# 2️⃣ Create a Self-Signed Certificate
openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365 -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=example.com"

# 3️⃣ Generate a Random Nonce (Challenge)
N=16  # Change this to the desired number of bytes
openssl rand -hex $N > nonce.txt

echo "Nonce:"
cat nonce.txt

echo "\nHashing Nonce with SHA-256..."
openssl dgst -sha256 nonce.txt

# 4️⃣ Encrypt the Nonce with the Public Key (Check Encryption)
openssl pkeyutl -encrypt -inkey public_key.pem -pubin -in nonce.txt -out nonce.enc

echo "\nEncrypted Nonce (Base64 Encoded for Visual Check):"
base64 < nonce.enc

# 5️⃣ Decrypt the Nonce with the Private Key
openssl pkeyutl -decrypt -inkey private_key.pem -in nonce.enc -out nonce_decrypted.txt

echo "\nDecrypted Nonce:" 
cat nonce_decrypted.txt

# 6️⃣ Sign the Nonce
openssl dgst -sha256 -sign private_key.pem -out nonce.sig nonce.txt

echo "\nVerifying Signature..."
openssl dgst -sha256 -verify public_key.pem -signature nonce.sig nonce.txt

echo "\nDone."


echo ""
: <<'NOTE_BLOCK_AREA'

Generates an RSA key pair.
Creates a self-signed certificate.
Cipher a nonce (5a5a).
Decipher using the private key.

chmod +x ./rsa_cipher_with_cert_check.sh
./rsa_cipher_with_cert_check.sh

NOTE_BLOCK_AREA
echo ""	