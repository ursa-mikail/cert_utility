#chmod +x ./menu.sh
#./menu.sh

# Load configuration from config.txt
CONFIG_FILE="./config.txt"
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    echo "Error: Configuration file $CONFIG_FILE not found."
    exit 1
fi

display_menu() {
    echo "=============================="
    echo "     Certificate Manager"
    echo "=============================="
    echo "1. Generate Key Pair"
    echo "2. Create Certificate Signing Request (CSR)"
    echo "3. Sign Certificate"
    echo "4. Verify Certificate"
    echo "5. Display Certificates"
    echo "6. Exit"
    echo "=============================="
}

generate_key() {
    read -p "Enter key name: " KEY_NAME
    echo "Select key type:"
    echo "1. RSA"
    echo "2. ECDSA"
    echo "3. EdDSA"
    read -p "Choose an option (1-3): " KEY_TYPE

    case $KEY_TYPE in
        1)
            openssl genpkey -algorithm RSA -out "key_store/$KEY_NAME.rsa.2048.private.key" -pkeyopt rsa_keygen_bits:2048
            openssl rsa -in "key_store/$KEY_NAME.rsa.2048.private.key" -pubout -out "key_store/$KEY_NAME.rsa.2048.public.key"
            ;;
        2)
            openssl genpkey -algorithm EC -out "key_store/$KEY_NAME.ecdsa.private.key" -pkeyopt ec_paramgen_curve:prime256v1
            openssl ec -in "key_store/$KEY_NAME.ecdsa.private.key" -pubout -out "key_store/$KEY_NAME.ecdsa.public.key"
            ;;
        3)
            openssl genpkey -algorithm ED25519 -out "key_store/$KEY_NAME.eddsa.private.key"
            openssl pkey -in "key_store/$KEY_NAME.eddsa.private.key" -pubout -out "key_store/$KEY_NAME.eddsa.public.key"
            ;;
        *)
            echo "Invalid key type selected."
            return
            ;;
    esac
    echo "Keys generated successfully."
}

create_csr() {
    read -p "Enter entity name: " ENTITY_NAME
    echo "Select key type:"
    echo "1. RSA"
    echo "2. ECDSA"
    echo "3. EdDSA"
    read -p "Choose an option (1-3): " KEY_TYPE

    case $KEY_TYPE in
        1)
            openssl req -new -key "key_store/$ENTITY_NAME.rsa.2048.private.key" -out "csr/$ENTITY_NAME.rsa.2048.csr" -subj "/CN=$ENTITY_NAME"
            ;;
        2)
            openssl req -new -key "key_store/$ENTITY_NAME.ecdsa.private.key" -out "csr/$ENTITY_NAME.ecdsa.csr" -subj "/CN=$ENTITY_NAME"
            ;;
        3)
            openssl req -new -key "key_store/$ENTITY_NAME.eddsa.private.key" -out "csr/$ENTITY_NAME.eddsa.csr" -subj "/CN=$ENTITY_NAME"
            ;;
        *)
            echo "Invalid key type selected."
            return
            ;;
    esac
    echo "CSR created: csr/$ENTITY_NAME.*.csr"
}

sign_cert() {
    read -p "Enter CSR name (without extension): " CSR_NAME
    echo "Select key type:"
    echo "1. RSA"
    echo "2. ECDSA"
    echo "3. EdDSA"
    read -p "Choose an option (1-3): " KEY_TYPE

    case $KEY_TYPE in
        1)
            openssl x509 -req -in "csr/$CSR_NAME.rsa.2048.csr" -signkey "key_store/$CSR_NAME.rsa.2048.private.key" -out "certs/$CSR_NAME.rsa.2048.crt" -days 3650
            ;;
        2)
            openssl x509 -req -in "csr/$CSR_NAME.ecdsa.csr" -signkey "key_store/$CSR_NAME.ecdsa.private.key" -out "certs/$CSR_NAME.ecdsa.crt" -days 3650
            ;;
        3)
            openssl x509 -req -in "csr/$CSR_NAME.eddsa.csr" -signkey "key_store/$CSR_NAME.eddsa.private.key" -out "certs/$CSR_NAME.eddsa.crt" -days 3650
            ;;
        *)
            echo "Invalid key type selected."
            return
            ;;
    esac
    echo "Certificate signed: certs/$CSR_NAME.*.crt"
}

verify_cert() {
    read -p "Enter certificate name: " CERT_NAME
    openssl x509 -in "certs/$CERT_NAME" -noout -text
}

display_certs() {
    echo "Available certificates:"
    ls certs/
}

while true; do
    display_menu
    read -p "Choose an option: " OPTION
    case $OPTION in
        1) generate_key ;;
        2) create_csr ;;
        3) sign_cert ;;
        4) verify_cert ;;
        5) display_certs ;;
        6) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option, try again." ;;
    esac
done

