# chmod +x setup_dirs.sh
# ./setup_dirs.sh
# Define the base directory
BASE_DIR="../cert_maker_manager"

# Define the directory structure
DIRS=(
    "$BASE_DIR/key_store"
    "$BASE_DIR/csr"
    "$BASE_DIR/cnf"
    "$BASE_DIR/certs"
    "$BASE_DIR/messages"
    "$BASE_DIR/signatures"
    "$BASE_DIR/passcodes"
    "$BASE_DIR/to_sign/csr"
    "$BASE_DIR/to_sign/certs"
    "$BASE_DIR/logs"
    "$BASE_DIR/utils"
)

# Create directories
for dir in "${DIRS[@]}"; do
    mkdir -p "$dir"
    echo "Created: $dir"
done

# Create empty config and menu script
touch "$BASE_DIR/config.txt"
touch "$BASE_DIR/menu.sh"

tree .

echo "Setup complete. Directory structure is ready!"
