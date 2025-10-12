function list_files() {
    local dir=$1
    echo "Files in directory ${dir}:"
    ls -1 ${dir}
}

function view_certificate() {
    local file=$1
    openssl x509 -in ${file} -text -noout
}

function view_key() {
    local file=$1
    openssl rsa -in ${file} -check -noout
}

function menu() {
    echo "Select an option:"
    echo "1. View a certificate"
    echo "2. View a key"
    echo "3. Exit"
    read -p "Enter your choice [1-3]: " choice
    case $choice in
        1)
            list_files "certs"
            read -p "Enter the certificate file name: " cert_file
            view_certificate "certs/${cert_file}"
            ;;
        2)
            list_files "keys"
            read -p "Enter the key file name: " key_file
            view_key "keys/${key_file}"
            ;;
        3)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option, please try again."
            ;;
    esac
}

while true
do
    menu
done
