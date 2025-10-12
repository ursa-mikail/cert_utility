# Generate an RSA Key Pair
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Generate a Random Nonce (Challenge)
N=16  # Change this to the desired number of bytes
openssl rand -hex $N > nonce.txt

echo "Generated Nonce:"
cat nonce.txt

# Sign the Nonce
openssl dgst -sha256 -sign private_key.pem -out nonce.sig nonce.txt

# Verify the Signature
openssl dgst -sha256 -verify public_key.pem -signature nonce.sig nonce.txt

echo "Signature verification complete."


echo ""
: <<'NOTE_BLOCK_AREA'

Generates an RSA key pair.
Signs a nonce (5a5a) as a challenge.
Verifies the signature using the public key.

chmod +x ./key_pair_authentication.sh
./key_pair_authentication.sh

NOTE_BLOCK_AREA
echo ""	