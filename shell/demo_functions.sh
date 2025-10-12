#!/bin/bash
# demo_functions.sh
# Demo-specific functions for certificate utility

# ==========================================
# SETUP FUNCTIONS
# ==========================================

function setup_folder_structure() {
    echo "=========================================="
    echo "[Setting up folder structure]"
    echo "=========================================="
    
    folders=(
        "$KEY_STORE_PATH:Key Store"
        "$CERTS_PATH:Certificates"
        "$CSR_PATH:Certificate Signing Requests"
        "$CNF_PATH:Configuration Files"
        "$SIG_PATH:Signatures"
        "$DATA_PLAINTEXT_PATH:Plaintext Data"
        "$DATA_CIPHERED_PATH:Encrypted Data"
    )
    
    for folder_info in "${folders[@]}"; do
        folder_name="${folder_info%%:*}"
        folder_description="${folder_info#*:}"
        create_folder_if_not_exist
    done
    
    echo ""
    echo "✓ Folder structure created successfully"
}

# ==========================================
# KEY GENERATION DEMOS
# ==========================================

function generate_all_keys() {
    echo "=========================================="
    echo "[Generating all cryptographic keys]"
    echo "=========================================="
    echo ""
    
    generate_key_rsa_for_signing
    echo ""
    
    generate_key_rsa_for_encryption
    echo ""
    
    generate_key_ecc_for_signing
    echo ""
    
    generate_key_dsa_for_signing
    echo ""
    
    generate_key_for_ciphering
    echo ""
    
    generate_key_for_hmac_sha256
    echo ""
    
    echo "✓ All keys generated successfully"
}

function generate_key_rsa_for_encryption() {
    label="[Generating RSA-OAEP key for encryption]"
    print_label
    
    if [ "$key_store_cipher_option" = 'ON' ]; then
        openssl genrsa -$key_store_cipher_key_algo -out "$RSA_OAEP_PRIVATE_KEY" $RSA_KEY_LENGTH 2>/dev/null
    else
        openssl genrsa -out "$RSA_OAEP_PRIVATE_KEY" $RSA_KEY_LENGTH 2>/dev/null
    fi
    
    openssl rsa -in "$RSA_OAEP_PRIVATE_KEY" -pubout -out "$RSA_OAEP_PUBLIC_KEY" 2>/dev/null
    
    echo "✓ RSA-OAEP key pair generated ($RSA_KEY_LENGTH bits)"
    echo "  Private: $RSA_OAEP_PRIVATE_KEY"
    echo "  Public:  $RSA_OAEP_PUBLIC_KEY"
}

# ==========================================
# CONFIG FILE GENERATION
# ==========================================

function create_openssl_config_rsa() {
    cat > "$CNF_RSA_FILE" << EOF
# OpenSSL Configuration File for RSA
entity_node_name = $ENTITY_NAME
name_main = ${ENTITY_NAME}.rsa${RSA_KEY_LENGTH}

[req]
default_bits = $RSA_KEY_LENGTH
default_md = $HASH_ALGO
prompt = no
distinguished_name = dn
req_extensions = ext
encrypt_key = no

[dn]
CN = $CERT_CN
emailAddress = $CERT_EMAIL
O = $CERT_ORG
OU = $CERT_OU
L = $CERT_LOCALITY
ST = $CERT_STATE
C = $CERT_COUNTRY

[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
subjectAltName = @alt_names

[alt_names]
DNS.1 = $CERT_CN
DNS.2 = ${ENTITY_NAME}.com
DNS.3 = demo.${ENTITY_NAME}.com
EOF
    
    CNF_FILE="$CNF_RSA_FILE"
}

function create_openssl_config_ecc() {
    cat > "$CNF_ECC_FILE" << EOF
# OpenSSL Configuration File for ECC
entity_node_name = $ENTITY_NAME
name_main = ${ENTITY_NAME}.ecc

[req]
default_md = $HASH_ALGO
prompt = no
distinguished_name = dn
req_extensions = ext
encrypt_key = no

[dn]
CN = $CERT_CN
emailAddress = $CERT_EMAIL
O = $CERT_ORG
OU = $CERT_OU
L = $CERT_LOCALITY
ST = $CERT_STATE
C = $CERT_COUNTRY

[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
subjectAltName = @alt_names

[alt_names]
DNS.1 = $CERT_CN
DNS.2 = ${ENTITY_NAME}.com
DNS.3 = demo.${ENTITY_NAME}.com
EOF
    
    CNF_FILE="$CNF_ECC_FILE"
}

function create_openssl_config_dsa() {
    cat > "$CNF_DSA_FILE" << EOF
# OpenSSL Configuration File for DSA
entity_node_name = $ENTITY_NAME
name_main = ${ENTITY_NAME}.dsa

[req]
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = ext
encrypt_key = no

[dn]
CN = $CERT_CN
emailAddress = $CERT_EMAIL
O = $CERT_ORG
OU = $CERT_OU
L = $CERT_LOCALITY
ST = $CERT_STATE
C = $CERT_COUNTRY

[ext]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth, clientAuth, emailProtection
subjectAltName = @alt_names

[alt_names]
DNS.1 = $CERT_CN
DNS.2 = ${ENTITY_NAME}.com
DNS.3 = demo.${ENTITY_NAME}.com
EOF
    
    CNF_FILE="$CNF_DSA_FILE"
}

# ==========================================
# CSR FUNCTIONS
# ==========================================

function create_csr_demo() {
    echo "=========================================="
    echo "[Create Certificate Signing Request]"
    echo "=========================================="
    echo ""
    echo "Select key type:"
    echo "1. RSA-PSS"
    echo "2. ECC"
    echo "3. DSA"
    echo ""
    read -n 1 -p "Choice: " csr_choice
    echo ""
    echo ""
    
    case "$csr_choice" in
        1) create_csr_rsa ;;
        2) create_csr_ecc ;;
        3) create_csr_dsa ;;
        *) echo "Invalid choice" ;;
    esac
}

function create_csr_rsa() {
    if [ ! -f "$RSA_PSS_PRIVATE_KEY" ]; then
        echo "✗ RSA private key not found. Generate it first."
        return
    fi
    
    create_openssl_config_rsa
    
    openssl req -new -key "$RSA_PSS_PRIVATE_KEY" \
        -out "$CSR_RSA_FILE" -config "$CNF_FILE" 2>/dev/null
    
    echo "✓ RSA CSR created: $CSR_RSA_FILE"
    echo ""
    echo "CSR Details:"
    openssl req -in "$CSR_RSA_FILE" -noout -text | head -30
}

function create_csr_ecc() {
    if [ ! -f "$ECC_PRIVATE_KEY" ]; then
        echo "✗ ECC private key not found. Generate it first."
        return
    fi
    
    create_openssl_config_ecc
    
    openssl req -new -key "$ECC_PRIVATE_KEY" \
        -out "$CSR_ECC_FILE" -config "$CNF_FILE" 2>/dev/null
    
    echo "✓ ECC CSR created: $CSR_ECC_FILE"
    echo ""
    echo "CSR Details:"
    openssl req -in "$CSR_ECC_FILE" -noout -text | head -30
}

function create_csr_dsa() {
    if [ ! -f "$DSA_PRIVATE_KEY" ]; then
        echo "✗ DSA private key not found. Generate it first."
        return
    fi
    
    create_openssl_config_dsa
    
    openssl req -new -key "$DSA_PRIVATE_KEY" \
        -out "$CSR_DSA_FILE" -config "$CNF_FILE" 2>/dev/null
    
    echo "✓ DSA CSR created: $CSR_DSA_FILE"
    echo ""
    echo "CSR Details:"
    openssl req -in "$CSR_DSA_FILE" -noout -text | head -30
}

# ==========================================
# CERTIFICATE GENERATION DEMOS
# ==========================================

function generate_certificate_demo() {
    echo "=========================================="
    echo "[Generate Self-Signed Certificate]"
    echo "=========================================="
    echo ""
    echo "Select key type:"
    echo "1. RSA-PSS"
    echo "2. ECC"
    echo "3. DSA"
    echo ""
    read -n 1 -p "Choice: " cert_choice
    echo ""
    echo ""
    
    case "$cert_choice" in
        1) generate_cert_from_cnf_for_signing_rsa ;;
        2) generate_cert_from_cnf_for_signing_ecc ;;
        3) generate_cert_from_cnf_for_signing_dsa ;;
        *) echo "Invalid choice" ;;
    esac
}

function view_certificate_demo() {
    echo "=========================================="
    echo "[View Certificate Details]"
    echo "=========================================="
    echo ""
    echo "Select certificate:"
    echo "1. RSA Certificate"
    echo "2. ECC Certificate"
    echo "3. DSA Certificate"
    echo ""
    read -n 1 -p "Choice: " view_choice
    echo ""
    echo ""
    
    case "$view_choice" in
        1) view_certificate "$CERT_RSA_FILE" ;;
        2) view_certificate "$CERT_ECC_FILE" ;;
        3) view_certificate "$CERT_DSA_FILE" ;;
        *) echo "Invalid choice" ;;
    esac
}

function view_certificate() {
    local cert_file=$1
    
    if [ ! -f "$cert_file" ]; then
        echo "✗ Certificate not found: $cert_file"
        return
    fi
    
    echo "Certificate: $cert_file"
    echo ""
    openssl x509 -in "$cert_file" -noout -text
}

# ==========================================
# SIGNING DEMOS
# ==========================================

function sign_with_rsa_pss_demo() {
    echo "=========================================="
    echo "[Sign Message with RSA-PSS]"
    echo "=========================================="
    echo ""
    
    if [ ! -f "$RSA_PSS_PRIVATE_KEY" ]; then
        echo "✗ RSA private key not found. Generate it first."
        return
    fi
    
    sign_message_rsa
}

function verify_rsa_pss_demo() {
    echo "=========================================="
    echo "[Verify RSA-PSS Signature]"
    echo "=========================================="
    echo ""
    
    if [ ! -f "$RSA_PSS_PUBLIC_KEY" ]; then
        echo "✗ RSA public key not found."
        return
    fi
    
    if [ ! -f "$SIG_RSA_FILE" ]; then
        echo "✗ Signature file not found."
        return
    fi
    
    verify_message_rsa
}

function sign_with_ecc_demo() {
    echo "=========================================="
    echo "[Sign Message with ECC]"
    echo "=========================================="
    echo ""
    
    if [ ! -f "$ECC_PRIVATE_KEY" ]; then
        echo "✗ ECC private key not found. Generate it first."
        return
    fi
    
    sign_message_ecc
}

function verify_ecc_demo() {
    echo "=========================================="
    echo "[Verify ECC Signature]"
    echo "=========================================="
    echo ""
    
    if [ ! -f "$ECC_PUBLIC_KEY" ]; then
        echo "✗ ECC public key not found."
        return
    fi
    
    if [ ! -f "$SIG_ECC_FILE" ]; then
        echo "✗ Signature file not found."
        return
    fi
    
    verify_message_ecc
}

# ==========================================
# AES DEMOS
# ==========================================

function generate_aes_key_demo() {
    echo "=========================================="
    echo "[Generate AES-256 Key]"
    echo "=========================================="
    echo ""
    
    generate_key_for_ciphering
    echo ""
    echo "Key saved to: $AES_KEY_FILE"
}

function cipher_with_aes_demo() {
    echo "=========================================="
    echo "[Encrypt with AES-256-CBC]"
    echo "=========================================="
    echo ""
    
    if [ ! -f "$AES_KEY_FILE" ]; then
        echo "✗ AES key not found. Generate it first."
        return
    fi
    
    read -p "Enter message to encrypt: " message

    file_input="message.txt"
    file_output="message.enc"

    echo "$message" > "${message_store_path}${file_input}"  # "$PLAINTEXT_FILE"
    echo "${message_store_path}${file_input}"
    cat "${message_store_path}${file_input}"
    
    cipher_file
}

function decipher_with_aes_demo() {
    echo "=========================================="
    echo "[Decrypt with AES-256-CBC]"
    echo "=========================================="
    echo ""
    
    CIPHERTEXT_FILE="${message_store_path}${file_output}"
    if [ ! -f "$CIPHERTEXT_FILE" ]; then
        echo "✗ Encrypted file not found."
        return
    fi
    
    if [ ! -f "$IV_FILE" ]; then
        echo "✗ IV file not found."
        return
    fi
    
    file_input="message.enc"
    file_output="message_decrypted.txt"
    
    decipher_file
    
    echo ""
    echo "Decrypted message:"
    cat "${DATA_PLAINTEXT_PATH}${file_output}"
}

# ==========================================
# COMPLETE WORKFLOW DEMOS
# ==========================================

function complete_rsa_workflow() {
    echo "=========================================="
    echo "[Complete RSA Workflow Demo]"
    echo "=========================================="
    echo ""
    echo "This will demonstrate:"
    echo "1. Key generation"
    echo "2. Certificate creation"
    echo "3. Message signing"
    echo "4. Signature verification"
    echo ""
    read -p "Press Enter to begin..."
    
    echo ""
    generate_key_rsa_for_signing
    sleep 2
    
    echo ""
    generate_cert_from_cnf_for_signing_rsa
    sleep 2
    
    echo ""
    echo "[Signing test message]"
    echo "Test message for RSA-PSS signing" > "$PLAINTEXT_FILE"
    
    openssl dgst -$HASH_ALGO -binary "$PLAINTEXT_FILE" > "${PLAINTEXT_FILE}.hash"
    openssl pkeyutl -sign -in "${PLAINTEXT_FILE}.hash" \
        -inkey "$RSA_PSS_PRIVATE_KEY" -out "$SIG_RSA_FILE" \
        -pkeyopt digest:$HASH_ALGO -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:-1 2>/dev/null
    
    echo "✓ Message signed"
    sleep 2
    
    echo ""
    echo "[Verifying signature]"
    result=$(openssl pkeyutl -verify -in "${PLAINTEXT_FILE}.hash" \
        -sigfile "$SIG_RSA_FILE" -pubin -inkey "$RSA_PSS_PUBLIC_KEY" \
        -pkeyopt digest:$HASH_ALGO -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:-1 2>&1)
    
    if [[ "$result" == *"Signature Verified Successfully"* ]]; then
        echo "✓ Signature VALID"
    else
        echo "✗ Signature INVALID"
    fi
    
    echo ""
    echo "✓ RSA workflow complete!"
}

function complete_ecc_workflow() {
    echo "=========================================="
    echo "[Complete ECC Workflow Demo]"
    echo "=========================================="
    echo ""
    echo "This will demonstrate:"
    echo "1. Key generation"
    echo "2. Certificate creation"
    echo "3. Message signing"
    echo "4. Signature verification"
    echo ""
    read -p "Press Enter to begin..."
    
    echo ""
    generate_key_ecc_for_signing
    sleep 2
    
    echo ""
    generate_cert_from_cnf_for_signing_ecc
    sleep 2
    
    echo ""
    echo "[Signing test message]"
    echo "Test message for ECDSA signing" > "$PLAINTEXT_FILE"
    
    openssl dgst -$HASH_ALGO -sign "$ECC_PRIVATE_KEY" \
        -out "$SIG_ECC_FILE" "$PLAINTEXT_FILE" 2>/dev/null
    
    echo "✓ Message signed"
    sleep 2
    
    echo ""
    echo "[Verifying signature]"
    result=$(openssl dgst -$HASH_ALGO -verify "$ECC_PUBLIC_KEY" \
        -signature "$SIG_ECC_FILE" "$PLAINTEXT_FILE" 2>&1)
    
    if [[ "$result" == *"Verified OK"* ]]; then
        echo "✓ Signature VALID"
    else
        echo "✗ Signature INVALID"
    fi
    
    echo ""
    echo "✓ ECC workflow complete!"
}