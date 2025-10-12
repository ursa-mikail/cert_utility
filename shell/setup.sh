#!/bin/bash
# Setup and Installation Script for Certificate Utility Demo

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Certificate Utility Demo - Setup"
echo "=========================================="
echo ""

# Check for OpenSSL
echo "[1/5] Checking for OpenSSL..."
if command -v openssl &> /dev/null; then
    OPENSSL_VERSION=$(openssl version)
    echo "✓ OpenSSL found: $OPENSSL_VERSION"
else
    echo "✗ OpenSSL not found!"
    echo ""
    echo "Please install OpenSSL:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  macOS:         brew install openssl"
    echo "  RHEL/CentOS:   sudo yum install openssl"
    exit 1
fi
echo ""

# Check for required tools
echo "[2/5] Checking for required tools..."
MISSING_TOOLS=()

if ! command -v tree &> /dev/null; then
    MISSING_TOOLS+=("tree")
fi

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo "⚠ Optional tools missing: ${MISSING_TOOLS[*]}"
    echo "  Install with: sudo apt-get install ${MISSING_TOOLS[*]}"
    echo "  (Not required, but recommended for better visualization)"
else
    echo "✓ All optional tools found"
fi
echo ""

# Create main scripts
echo "[3/5] Creating demo scripts..."

# Check if main.sh already exists
if [ -f "main.sh" ]; then
    read -p "main.sh already exists. Overwrite? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping main.sh creation"
    fi
fi

# Make scripts executable
if [ -f "main.sh" ]; then
    chmod +x main.sh
    echo "✓ main.sh made executable"
fi

if [ -f "demo_parameters.sh" ]; then
    chmod +x demo_parameters.sh
    echo "✓ demo_parameters.sh made executable"
fi

if [ -f "demo_functions.sh" ]; then
    chmod +x demo_functions.sh
    echo "✓ demo_functions.sh made executable"
fi

echo ""

# Create folder structure
echo "[4/5] Creating folder structure..."
mkdir -p key_store
mkdir -p csr
mkdir -p cnf
mkdir -p certs
mkdir -p data_plaintext
mkdir -p data_ciphered
mkdir -p signatures

echo "✓ Folders created:"
echo "  - key_store/      (private/public keys)"
echo "  - csr/            (certificate signing requests)"
echo "  - cnf/            (OpenSSL config files)"
echo "  - certs/          (certificates)"
echo "  - data_plaintext/ (plaintext messages)"
echo "  - data_ciphered/  (encrypted data)"
echo "  - signatures/     (digital signatures)"
echo ""

# Create test message
echo "[5/5] Creating test data..."
if [ ! -d "data_plaintext" ]; then
    mkdir -p data_plaintext
fi

if [ ! -f "data_plaintext/message.txt" ]; then
    echo "This is a confidential message for cryptographic demonstration." > data_plaintext/message.txt
    echo "✓ Test message created"
else
    echo "✓ Test message already exists"
fi
echo ""

# Summary
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Run the demo:     ./main.sh"
echo "  2. Try option 13:    Complete RSA workflow"
echo "  3. Try option 14:    Complete ECC workflow"
echo ""
echo "For help, see README.md or run:"
echo "  ./main.sh"
echo ""
echo "Quick test:"
echo "  ./main.sh"
echo "  Select option 13 (Complete RSA workflow demo)"
echo ""

# Offer to run the demo
read -p "Would you like to run the demo now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "main.sh" ]; then
        ./main.sh
    else
        echo "Error: main.sh not found. Please create the script files first."
    fi
fi