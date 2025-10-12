#!/bin/bash
# demo_parameters.sh
# Configuration parameters for certificate utility

# ==========================================
# ENTITY CONFIGURATION
# ==========================================
ENTITY_NAME="demo_user"
KEY_NAME="${ENTITY_NAME}"

# ==========================================
# DIRECTORY STRUCTURE
# ==========================================
BASE_PATH="./"
KEY_STORE_PATH="${BASE_PATH}key_store/"
CERTS_PATH="${BASE_PATH}certs/"
CSR_PATH="${BASE_PATH}csr/"
CNF_PATH="${BASE_PATH}cnf/"
SIG_PATH="${BASE_PATH}signatures/"
DATA_PLAINTEXT_PATH="${BASE_PATH}data_plaintext/"
DATA_CIPHERED_PATH="${BASE_PATH}data_ciphered/"

# Message store paths (legacy compatibility)
message_store_path="${DATA_PLAINTEXT_PATH}"

# ==========================================
# KEY FILES
# ==========================================
# RSA Keys
RSA_KEY_LENGTH=2048
RSA_OAEP_PRIVATE_KEY="${KEY_STORE_PATH}${KEY_NAME}_rsa_oaep_private.pem"
RSA_OAEP_PUBLIC_KEY="${KEY_STORE_PATH}${KEY_NAME}_rsa_oaep_public.pem"
RSA_PSS_PRIVATE_KEY="${KEY_STORE_PATH}${KEY_NAME}_rsa_pss_private.pem"
RSA_PSS_PUBLIC_KEY="${KEY_STORE_PATH}${KEY_NAME}_rsa_pss_public.pem"

# ECC Keys
ECC_CURVE="secp384r1"
ECC_PRIVATE_KEY="${KEY_STORE_PATH}${KEY_NAME}_ecc_private.pem"
ECC_PUBLIC_KEY="${KEY_STORE_PATH}${KEY_NAME}_ecc_public.pem"

# DSA Keys
DSA_PRIVATE_KEY="${KEY_STORE_PATH}${KEY_NAME}_dsa_private.pem"
DSA_PUBLIC_KEY="${KEY_STORE_PATH}${KEY_NAME}_dsa_public.pem"
DSA_PARAMS="${KEY_STORE_PATH}dsa_params.pem"

# Symmetric Keys
AES_KEY_FILE="${KEY_STORE_PATH}${KEY_NAME}_aes256.key"
key_hmac_sha256_file="${KEY_STORE_PATH}${KEY_NAME}_hmac_sha256.key"

# Key storage encryption
key_store_cipher_option='OFF'
key_store_cipher_key_algo='aes256'

# ==========================================
# CERTIFICATE FILES
# ==========================================
CERT_DAYS=365
CERT_RSA_FILE="${CERTS_PATH}${KEY_NAME}_rsa.crt"
CERT_ECC_FILE="${CERTS_PATH}${KEY_NAME}_ecc.crt"
CERT_DSA_FILE="${CERTS_PATH}${KEY_NAME}_dsa.crt"

# ==========================================
# CSR FILES
# ==========================================
CSR_RSA_FILE="${CSR_PATH}${KEY_NAME}_rsa.csr"
CSR_ECC_FILE="${CSR_PATH}${KEY_NAME}_ecc.csr"
CSR_DSA_FILE="${CSR_PATH}${KEY_NAME}_dsa.csr"

# ==========================================
# CONFIG FILES
# ==========================================
CNF_FILE="${CNF_PATH}${KEY_NAME}.cnf"
CNF_RSA_FILE="${CNF_PATH}${KEY_NAME}_rsa.cnf"
CNF_ECC_FILE="${CNF_PATH}${KEY_NAME}_ecc.cnf"
CNF_DSA_FILE="${CNF_PATH}${KEY_NAME}_dsa.cnf"

# ==========================================
# SIGNATURE FILES
# ==========================================
SIG_RSA_FILE="${SIG_PATH}${KEY_NAME}_rsa.sig"
SIG_ECC_FILE="${SIG_PATH}${KEY_NAME}_ecc.sig"
SIG_DSA_FILE="${SIG_PATH}${KEY_NAME}_dsa.sig"
SIG_HMAC_FILE="${SIG_PATH}${KEY_NAME}_hmac.sig"

# ==========================================
# DATA FILES
# ==========================================
PLAINTEXT_FILE="${DATA_PLAINTEXT_PATH}message.txt"
CIPHERTEXT_FILE="${DATA_CIPHERED_PATH}message.enc"
IV_FILE="${DATA_CIPHERED_PATH}message.iv"

# File operation variables
file_input="message.txt"
file_output="message.enc"

# ==========================================
# CRYPTOGRAPHIC PARAMETERS
# ==========================================
HASH_ALGO="sha256"
AES_MODE="aes-256-cbc"

# ==========================================
# CERTIFICATE SUBJECT INFORMATION
# ==========================================
CERT_COUNTRY="US"
CERT_STATE="California"
CERT_LOCALITY="San Jose"
CERT_ORG="Demo Organization"
CERT_OU="Cryptography Unit"
CERT_CN="www.${KEY_NAME}.com"
CERT_EMAIL="${KEY_NAME}@demo.com"