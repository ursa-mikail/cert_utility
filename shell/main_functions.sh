#!/bin/bash
# main_functions.sh
# Core cryptographic functions for certificate utility

# Source required files
if [ -f "./demo_parameters.sh" ]; then
    source "./demo_parameters.sh"
elif [ -f "./parameters.sh" ]; then
    source "./parameters.sh"
else
    echo "Error: parameters.sh not found"
    exit 1
fi

# ==========================================
# UTILITY FUNCTIONS
# ==========================================

function print_label() {
    echo "=========================================="
    echo "$label"
    echo "=========================================="
}

function print_label_with_color() {
    echo -e "\033[1;32m=========================================="
    echo "$label"
    echo "==========================================\033[0m"
}

function check_entity_name() {
    if [ -z "$ENTITY_NAME" ]; then
        ENTITY_NAME="demo_user"
    fi
    echo "Entity: $ENTITY_NAME"
}

function create_folder_if_not_exist() {
    if [ ! -d "$folder_name" ]; then
        mkdir -p "$folder_name"
        echo "Created folder: $folder_description ($folder_name)"
    else
        echo "Folder exists: $folder_description ($folder_name)"
    fi
}

# ==========================================
# KEY GENERATION FUNCTIONS
# ==========================================

function generate_key_for_ciphering() {
    label="[Generating AES-256 key for ciphering]"
    print_label
    
    openssl rand -hex 32 > "$AES_KEY_FILE"
    
    echo "✓ AES-256 key generated"
    echo "  File: $AES_KEY_FILE"
}

function generate_key_for_hmac_sha256() {
    label="[Generating HMAC-SHA256 key]"
    print_label
    
    openssl rand -hex 32 > "$key_hmac_sha256_file"
    
    echo "✓ HMAC-SHA256 key generated"
    echo "  File: $key_hmac_sha256_file"
}

function generate_key_rsa_for_signing() {
    label="[Generating RSA-PSS key for signing]"
    print_label
    
    if [ "$key_store_cipher_option" = 'ON' ]; then
        openssl genrsa -$key_store_cipher_key_algo -out "$RSA_PSS_PRIVATE_KEY" $RSA_KEY_LENGTH 2>/dev/null
    else
        openssl genrsa -out "$RSA_PSS_PRIVATE_KEY" $RSA_KEY_LENGTH 2>/dev/null
    fi
    
    openssl rsa -in "$RSA_PSS_PRIVATE_KEY" -pubout -out "$RSA_PSS_PUBLIC_KEY" 2>/dev/null
    
    echo "✓ RSA-PSS key pair generated ($RSA_KEY_LENGTH bits)"
    echo "  Private: $RSA_PSS_PRIVATE_KEY"
    echo "  Public:  $RSA_PSS_PUBLIC_KEY"
}

function generate_key_dsa_for_signing() {
    label="[Generating DSA key for signing]"
    print_label
    
    # Generate DSA parameters first
    openssl dsaparam -out "${KEY_STORE_PATH}dsa_params.pem" 2048 2>/dev/null
    
    # Generate DSA key
    openssl gendsa -out "${KEY_STORE_PATH}${KEY_NAME}_dsa_private.pem" \
        "${KEY_STORE_PATH}dsa_params.pem" 2>/dev/null
    
    openssl dsa -in "${KEY_STORE_PATH}${KEY_NAME}_dsa_private.pem" \
        -pubout -out "${KEY_STORE_PATH}${KEY_NAME}_dsa_public.pem" 2>/dev/null
    
    echo "✓ DSA key pair generated"
}

function generate_key_ecc_for_signing() {
    label="[Generating ECC key for signing]"
    print_label
    
    openssl ecparam -name "$ECC_CURVE" -genkey -noout -out "$ECC_PRIVATE_KEY" 2>/dev/null
    openssl ec -in "$ECC_PRIVATE_KEY" -pubout -out "$ECC_PUBLIC_KEY" 2>/dev/null
    
    echo "✓ ECC key pair generated (curve: $ECC_CURVE)"
    echo "  Private: $ECC_PRIVATE_KEY"
    echo "  Public:  $ECC_PUBLIC_KEY"
}

# ==========================================
# CERTIFICATE GENERATION FUNCTIONS
# ==========================================

function generate_cert_from_cnf_for_signing_rsa() {
    label="[Generating RSA certificate]"
    print_label
    
    if [ ! -f "$CNF_FILE" ]; then
        create_openssl_config_rsa
    fi
    
    openssl req -new -x509 -key "$RSA_PSS_PRIVATE_KEY" \
        -out "$CERT_RSA_FILE" -days $CERT_DAYS \
        -config "$CNF_FILE" 2>/dev/null
    
    echo "✓ RSA certificate generated"
    echo "  Certificate: $CERT_RSA_FILE"
    echo "  Valid for: $CERT_DAYS days"
}

function generate_cert_from_cnf_for_signing_dsa() {
    label="[Generating DSA certificate]"
    print_label
    
    if [ ! -f "$CNF_FILE" ]; then
        create_openssl_config_dsa
    fi
    
    openssl req -new -x509 -key "${KEY_STORE_PATH}${KEY_NAME}_dsa_private.pem" \
        -out "${CERTS_PATH}${KEY_NAME}_dsa.crt" -days $CERT_DAYS \
        -config "$CNF_FILE" 2>/dev/null
    
    echo "✓ DSA certificate generated"
}

function generate_cert_from_cnf_for_signing_ecc() {
    label="[Generating ECC certificate]"
    print_label
    
    if [ ! -f "$CNF_FILE" ]; then
        create_openssl_config_ecc
    fi
    
    openssl req -new -x509 -key "$ECC_PRIVATE_KEY" \
        -out "$CERT_ECC_FILE" -days $CERT_DAYS \
        -config "$CNF_FILE" 2>/dev/null
    
    echo "✓ ECC certificate generated"
    echo "  Certificate: $CERT_ECC_FILE"
    echo "  Valid for: $CERT_DAYS days"
}

# ==========================================
# DISPLAY FUNCTIONS
# ==========================================

function display_key_for_ciphering() {
    if [ -f "$AES_KEY_FILE" ]; then
        echo "AES-256 Key (hex):"
        cat "$AES_KEY_FILE"
    else
        echo "✗ AES key not found. Generate it first."
    fi
}

function display_key_for_authentication() {
    if [ -f "$key_hmac_sha256_file" ]; then
        echo "HMAC-SHA256 Key (hex):"
        cat "$key_hmac_sha256_file"
    else
        echo "✗ HMAC key not found. Generate it first."
    fi
}

function display_key_rsa_for_signing() {
    if [ -f "$RSA_PSS_PRIVATE_KEY" ]; then
        echo "RSA Private Key:"
        openssl rsa -in "$RSA_PSS_PRIVATE_KEY" -noout -text | head -20
    else
        echo "✗ RSA key not found. Generate it first."
    fi
}

function display_key_dsa_for_signing() {
    if [ -f "${KEY_STORE_PATH}${KEY_NAME}_dsa_private.pem" ]; then
        echo "DSA Private Key:"
        openssl dsa -in "${KEY_STORE_PATH}${KEY_NAME}_dsa_private.pem" -noout -text | head -20
    else
        echo "✗ DSA key not found. Generate it first."
    fi
}

function display_key_ecc_for_signing() {
    if [ -f "$ECC_PRIVATE_KEY" ]; then
        echo "ECC Private Key:"
        openssl ec -in "$ECC_PRIVATE_KEY" -noout -text | head -20
    else
        echo "✗ ECC key not found. Generate it first."
    fi
}

# ==========================================
# CIPHER/DECIPHER FUNCTIONS
# ==========================================

function cipher_message() {
    local message=$1
    local passcode=$2
    
    # Derive key from passcode
    local key=$(echo -n "$passcode" | openssl dgst -sha256 | cut -d' ' -f2)
    
    # Generate IV
    IV=$(openssl rand -hex 16)
    
    # Encrypt
    local encrypted=$(echo -n "$message" | openssl enc -aes-256-cbc -K "$key" -iv "$IV" | xxd -p | tr -d '\n')
    
    echo "$encrypted"
}

function decipher_message() {
    local encrypted=$1
    local passcode=$2
    
    # Derive key from passcode
    local key=$(echo -n "$passcode" | openssl dgst -sha256 | cut -d' ' -f2)
    
    # Decrypt
    local decrypted=$(echo "$encrypted" | xxd -r -p | openssl enc -d -aes-256-cbc -K "$key" -iv "$IV")
    
    echo "$decrypted"
}

function cipher_file() {
    if [ ! -f "${message_store_path}${file_input}" ]; then
        echo "✗ Input file not found: $file_input"
        return
    fi
    
    local KEY=$(cat "$AES_KEY_FILE")
    IV=$(openssl rand -hex 16)

    echo "$IV" > "$IV_FILE"
    
    openssl enc -aes-256-cbc -in "${message_store_path}${file_input}" \
        -out "${message_store_path}${file_output}" -K "$KEY" -iv "$IV" 2>/dev/null
    
    echo "✓ File encrypted"
}

function decipher_file() {
    if [ ! -f "${message_store_path}${file_input}" ]; then
        echo "${message_store_path}${file_input}"
        echo "✗ Input file not found"
        return
    fi
    
    local KEY=$(cat "$AES_KEY_FILE")
    local IV=$(cat "$IV_FILE")
    
    echo "file_input: " "${message_store_path}${file_input}"
    echo "file_output: " "${message_store_path}${file_output}"
    
    openssl enc -d -aes-256-cbc -in "${message_store_path}${file_input}" \
        -out "${message_store_path}${file_output}" -K "$KEY" -iv "$IV" 2>/dev/null
    
    echo "✓ File decrypted"
    cat "${message_store_path}${file_output}" 
}

# ==========================================
# SIGNING FUNCTIONS
# ==========================================

function sign_message_rsa() {
    read -p '[Message in text]: ' message_input
    echo "$message_input" > "$PLAINTEXT_FILE"
    
    openssl dgst -$HASH_ALGO -binary "$PLAINTEXT_FILE" > "${PLAINTEXT_FILE}.hash"
    
    openssl pkeyutl -sign -in "${PLAINTEXT_FILE}.hash" \
        -inkey "$RSA_PSS_PRIVATE_KEY" -out "$SIG_RSA_FILE" \
        -pkeyopt digest:$HASH_ALGO -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:-1 2>/dev/null
    
    echo "✓ Message signed with RSA-PSS"
    echo "  Signature: $SIG_RSA_FILE"
}

function verify_message_rsa() {
    read -p '[Message in text]: ' message_input
    echo "$message_input" > "$PLAINTEXT_FILE"
    
    openssl dgst -$HASH_ALGO -binary "$PLAINTEXT_FILE" > "${PLAINTEXT_FILE}.hash"
    
    result=$(openssl pkeyutl -verify -in "${PLAINTEXT_FILE}.hash" \
        -sigfile "$SIG_RSA_FILE" -pubin -inkey "$RSA_PSS_PUBLIC_KEY" \
        -pkeyopt digest:$HASH_ALGO -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:-1 2>&1)
    
    if [[ "$result" == *"Signature Verified Successfully"* ]]; then
        echo "✓ Signature VALID"
    else
        echo "✗ Signature INVALID"
    fi
}

function sign_message_ecc() {
    read -p '[Message in text]: ' message_input
    echo "$message_input" > "$PLAINTEXT_FILE"
    
    openssl dgst -$HASH_ALGO -sign "$ECC_PRIVATE_KEY" \
        -out "$SIG_ECC_FILE" "$PLAINTEXT_FILE" 2>/dev/null
    
    echo "✓ Message signed with ECDSA"
    echo "  Signature: $SIG_ECC_FILE"
}

function verify_message_ecc() {
    read -p '[Message in text]: ' message_input
    echo "$message_input" > "$PLAINTEXT_FILE"
    
    result=$(openssl dgst -$HASH_ALGO -verify "$ECC_PUBLIC_KEY" \
        -signature "$SIG_ECC_FILE" "$PLAINTEXT_FILE" 2>&1)
    
    if [[ "$result" == *"Verified OK"* ]]; then
        echo "✓ Signature VALID"
    else
        echo "✗ Signature INVALID"
    fi
}

# ==========================================
# HELPER FUNCTIONS
# ==========================================

function ascii_to_hex() {
    echo -n "$1" | xxd -p | tr -d '\n'
}

function hex_to_ascii() {
    echo -n "$1" | xxd -r -p
}

function check_if_file_exists_halt_and_exit_otherwise() {
    if [ ! -f "$filename" ]; then
        echo "✗ File not found: $filename"
        exit 1
    fi
}
