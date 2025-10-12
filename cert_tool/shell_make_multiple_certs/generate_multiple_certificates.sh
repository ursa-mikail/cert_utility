# Load the configuration file
source config.txt

# Create directories if they don't exist
mkdir -p certs keys

# Define variables
KEY_LENGTH=${rsa_keylength}
COUNTRY=${country}
STATE=${state}
LOCALITY=${locality}
ORGANIZATION=${organization}
ORGANIZATIONAL_UNIT=${organizational_unit}
DAYS_VALID=365
NUMBER_OF_CERTIFICATES=${number_of_certificates}

# Loop to generate multiple certificates with unique common names
for (( i=0; i<NUMBER_OF_CERTIFICATES; i++ ))
do
    OUTPUT_KEY="keys/domain_X_${i}.key"
    OUTPUT_CERT="certs/domain_X_${i}.cer"
    COMMON_NAME="RA_${i}"

    openssl req -newkey rsa:${KEY_LENGTH} -nodes -keyout ${OUTPUT_KEY} -x509 -days ${DAYS_VALID} -out ${OUTPUT_CERT} -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=${ORGANIZATIONAL_UNIT}/CN=${COMMON_NAME}"

    echo "Certificate generated: ${OUTPUT_CERT}"
    echo "Private key generated: ${OUTPUT_KEY}"
done
