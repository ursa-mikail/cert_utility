#1️⃣ Generate an RSA Key Pair
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

#2️⃣ Create a Self-Signed Certificate
openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365 -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=example.com"
#3️⃣ Sign a Nonce (Challenge)
#echo "5a5a" > nonce.txt
N=16  # Change this to the desired number of bytes
openssl rand -hex $N > nonce.txt

echo "nonce:"
cat nonce.txt

openssl dgst -sha256 -sign private_key.pem -out nonce.sig nonce.txt
#4️⃣ Verify the Signature (Response)
openssl dgst -sha256 -verify public_key.pem -signature nonce.sig nonce.txt


echo ""
: <<'NOTE_BLOCK_AREA'

Generates an RSA key pair.
Creates a self-signed certificate.
Signs a nonce (5a5a) as a challenge.
Verifies the signature using the public key.

chmod +x ./cert_authentication.sh
./cert_authentication.sh

NOTE_BLOCK_AREA
echo ""	


