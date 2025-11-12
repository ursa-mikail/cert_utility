# golang_cert_utility

## 🎯 Key Features
1. Default Configuration: Uses sensible defaults similar to your shell script

2. CNF File Reading: Automatically reads and parses .cnf files from the ./cnf folder

3. Complete Cryptographic Operations:
- RSA key generation (OAEP and PSS)
- ECC key generation
- AES key generation
- Certificate creation
- Digital signing (RSA-PSS and ECDSA)
- Signature verification
- AES encryption/decryption

### CNF File Support:
The LoadConfigFromCNF() function:

Scans the ./cnf folder for .cnf files

Parses sections like [req], [dn], etc.

Updates configuration parameters from CNF files

Falls back to defaults if CNF files aren't available

```
% go mod init golang_cert_utility
% go mod tidy
% go run main.go 



```
