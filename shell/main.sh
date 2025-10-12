#!/bin/bash
# Certificate Utility Demo
# Demonstrates: CSR creation, Certificate generation, Signing (ECC/RSA-PSS), and Ciphering (AES)

# Source configuration
source "./demo_parameters.sh"
source "./demo_functions.sh"
source "./main_functions.sh"

function print_demo_menu() {
    clear
    echo "=========================================="
    echo "    CERTIFICATE UTILITY DEMO"
    echo "=========================================="
    echo ""
    echo "[SETUP]"
    echo "1  : Initialize folder structure"
    echo "2  : Generate keys (RSA-OAEP, RSA-PSS, ECC)"
    echo ""
    echo "[CSR & CERTIFICATES]"
    echo "3  : Create CSR (Certificate Signing Request)"
    echo "4  : Generate self-signed certificate"
    echo "5  : View certificate details"
    echo ""
    echo "[SIGNING - RSA-PSS]"
    echo "6  : Sign message with RSA-PSS"
    echo "7  : Verify RSA-PSS signature"
    echo ""
    echo "[SIGNING - ECC]"
    echo "8  : Sign message with ECC"
    echo "9  : Verify ECC signature"
    echo ""
    echo "[CIPHERING - AES]"
    echo "10 : Generate AES key"
    echo "11 : Cipher message with AES"
    echo "12 : Decipher message with AES"
    echo ""
    echo "[COMPLETE WORKFLOW]"
    echo "13 : Run complete RSA workflow demo"
    echo "14 : Run complete ECC workflow demo"
    echo ""
    echo "x  : Exit"
    echo "=========================================="
}

function main_demo() {
    while true; do
        print_demo_menu
        read -n 2 -p "Select option: " choice
        echo ""
        echo ""
        
        case "$choice" in
            1)  setup_folder_structure ;;
            2)  generate_all_keys ;;
            3)  create_csr_demo ;;
            4)  generate_certificate_demo ;;
            5)  view_certificate_demo ;;
            6)  sign_with_rsa_pss_demo ;;
            7)  verify_rsa_pss_demo ;;
            8)  sign_with_ecc_demo ;;
            9)  verify_ecc_demo ;;
            10) generate_aes_key_demo ;;
            11) cipher_with_aes_demo ;;
            12) decipher_with_aes_demo ;;
            13) complete_rsa_workflow ;;
            14) complete_ecc_workflow ;;
            x|X) exit_demo ;;
            *) 
                echo "Invalid selection!"
                sleep 2
                ;;
        esac
        
        if [ "$choice" != "x" ] && [ "$choice" != "X" ]; then
            echo ""
            read -p "Press Enter to continue..."
        fi
    done
}

function exit_demo() {
    echo "Exiting demo..."
    exit 0
}

# Run the demo
main_demo