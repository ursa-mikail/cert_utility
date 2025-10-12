// main.go
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds the configuration parameters
type Config struct {
	EntityName string
	BasePath   string

	// Paths
	KeyStorePath      string
	CertsPath         string
	CSRPath           string
	CNFPath           string
	SigPath           string
	DataPlaintextPath string
	DataCipheredPath  string

	// Cryptographic parameters
	RSAKeyLength int
	ECCCurve     elliptic.Curve
	HashAlgo     crypto.Hash
	CertDays     int

	// Certificate subject
	Country  string
	State    string
	Locality string
	Org      string
	OU       string
	CN       string
	Email    string
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	config := &Config{
		EntityName: "demo_user",
		BasePath:   "./",

		// Cryptographic parameters
		RSAKeyLength: 2048,
		ECCCurve:     elliptic.P256(),
		HashAlgo:     crypto.SHA256,
		CertDays:     365,

		// Certificate subject
		Country:  "US",
		State:    "California",
		Locality: "San Jose",
		Org:      "Demo Organization",
		OU:       "Cryptography Unit",
		CN:       "www.demo_user.com",
		Email:    "demo_user@demo.com",
	}

	// Initialize paths
	config.KeyStorePath = filepath.Join(config.BasePath, "key_store")
	config.CertsPath = filepath.Join(config.BasePath, "certs")
	config.CSRPath = filepath.Join(config.BasePath, "csr")
	config.CNFPath = filepath.Join(config.BasePath, "cnf")
	config.SigPath = filepath.Join(config.BasePath, "signatures")
	config.DataPlaintextPath = filepath.Join(config.BasePath, "data_plaintext")
	config.DataCipheredPath = filepath.Join(config.BasePath, "data_ciphered")

	return config
}

// LoadConfigFromCNF loads configuration from CNF files in the cnf folder
func LoadConfigFromCNF(baseConfig *Config) (*Config, error) {
	config := *baseConfig // Start with defaults

	cnfFiles, err := filepath.Glob(filepath.Join(config.CNFPath, "*.cnf"))
	if err != nil {
		return &config, nil // Return default if no CNF files
	}

	for _, cnfFile := range cnfFiles {
		if err := parseCNFFile(cnfFile, &config); err != nil {
			fmt.Printf("Warning: Error parsing CNF file %s: %v\n", cnfFile, err)
		}
	}

	return &config, nil
}

// parseCNFFile parses a single CNF file and updates the configuration
func parseCNFFile(filename string, config *Config) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			continue
		}

		// Parse key-value pairs
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch currentSection {
			case "req":
				switch key {
				case "default_bits":
					if bits, err := strconv.Atoi(value); err == nil {
						config.RSAKeyLength = bits
					}
				case "default_md":
					// Map hash algorithm names
					switch value {
					case "sha256":
						config.HashAlgo = crypto.SHA256
					case "sha384":
						config.HashAlgo = crypto.SHA384
					case "sha512":
						config.HashAlgo = crypto.SHA512
					}
				}
			case "dn":
				switch key {
				case "C":
					config.Country = value
				case "ST":
					config.State = value
				case "L":
					config.Locality = value
				case "O":
					config.Org = value
				case "OU":
					config.OU = value
				case "CN":
					config.CN = value
				case "emailAddress":
					config.Email = value
				}
			default:
				// Global settings (outside sections)
				switch key {
				case "entity_node_name":
					config.EntityName = value
				case "name_main":
					// Can be used for specific naming
				}
			}
		}
	}

	return scanner.Err()
}

// KeyStore manages cryptographic keys
type KeyStore struct {
	config *Config

	// RSA Keys
	RSAOAEPPrivateKey *rsa.PrivateKey
	RSAOAEPPublicKey  *rsa.PublicKey
	RSAPSSPrivateKey  *rsa.PrivateKey
	RSAPSSPublicKey   *rsa.PublicKey

	// ECC Keys
	ECCPrivateKey *ecdsa.PrivateKey
	ECCPublicKey  *ecdsa.PublicKey

	// Symmetric Keys
	AESKey      []byte
	HMACKey     []byte
}

// NewKeyStore creates a new key store with configuration
func NewKeyStore(config *Config) *KeyStore {
	return &KeyStore{
		config: config,
	}
}

// Utility functions
func createFolderIfNotExist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

func (ks *KeyStore) SetupFolderStructure() error {
	folders := []string{
		ks.config.KeyStorePath,
		ks.config.CertsPath,
		ks.config.CSRPath,
		ks.config.CNFPath,
		ks.config.SigPath,
		ks.config.DataPlaintextPath,
		ks.config.DataCipheredPath,
	}

	fmt.Println("==========================================")
	fmt.Println("[Setting up folder structure]")
	fmt.Println("==========================================")

	for _, folder := range folders {
		if err := createFolderIfNotExist(folder); err != nil {
			return fmt.Errorf("failed to create folder %s: %v", folder, err)
		}
		folderName := filepath.Base(folder)
		fmt.Printf("Created folder: %s (%s)\n", getFolderDescription(folderName), folder)
	}

	fmt.Println("")
	fmt.Println("✓ Folder structure created successfully")
	return nil
}

func getFolderDescription(folderName string) string {
	descriptions := map[string]string{
		"key_store":      "Key Store",
		"certs":          "Certificates",
		"csr":            "Certificate Signing Requests",
		"cnf":            "Configuration Files",
		"signatures":     "Signatures",
		"data_plaintext": "Plaintext Data",
		"data_ciphered":  "Encrypted Data",
	}
	if desc, exists := descriptions[folderName]; exists {
		return desc
	}
	return folderName
}

// Key generation functions
func (ks *KeyStore) GenerateAllKeys() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating all cryptographic keys]")
	fmt.Println("==========================================")
	fmt.Println()

	if err := ks.GenerateRSAPSSKeys(); err != nil {
		return err
	}
	fmt.Println()

	if err := ks.GenerateRSAOAEPKeys(); err != nil {
		return err
	}
	fmt.Println()

	if err := ks.GenerateECCKeys(); err != nil {
		return err
	}
	fmt.Println()

	if err := ks.GenerateAESKey(); err != nil {
		return err
	}
	fmt.Println()

	if err := ks.GenerateHMACKey(); err != nil {
		return err
	}
	fmt.Println()

	fmt.Println("✓ All keys generated successfully")
	return nil
}

func (ks *KeyStore) GenerateRSAOAEPKeys() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating RSA-OAEP key for encryption]")
	fmt.Println("==========================================")

	privateKey, err := rsa.GenerateKey(rand.Reader, ks.config.RSAKeyLength)
	if err != nil {
		return err
	}

	ks.RSAOAEPPrivateKey = privateKey
	ks.RSAOAEPPublicKey = &privateKey.PublicKey

	// Save to files
	privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_oaep_private.pem")
	publicKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_oaep_public.pem")

	if err := ks.saveRSAPrivateKey(ks.RSAOAEPPrivateKey, privateKeyFile); err != nil {
		return err
	}
	if err := ks.saveRSAPublicKey(ks.RSAOAEPPublicKey, publicKeyFile); err != nil {
		return err
	}

	fmt.Printf("✓ RSA-OAEP key pair generated (%d bits)\n", ks.config.RSAKeyLength)
	fmt.Printf("  Private: %s\n", privateKeyFile)
	fmt.Printf("  Public:  %s\n", publicKeyFile)
	return nil
}

func (ks *KeyStore) GenerateRSAPSSKeys() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating RSA-PSS key for signing]")
	fmt.Println("==========================================")

	privateKey, err := rsa.GenerateKey(rand.Reader, ks.config.RSAKeyLength)
	if err != nil {
		return err
	}

	ks.RSAPSSPrivateKey = privateKey
	ks.RSAPSSPublicKey = &privateKey.PublicKey

	// Save to files
	privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_pss_private.pem")
	publicKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_pss_public.pem")

	if err := ks.saveRSAPrivateKey(ks.RSAPSSPrivateKey, privateKeyFile); err != nil {
		return err
	}
	if err := ks.saveRSAPublicKey(ks.RSAPSSPublicKey, publicKeyFile); err != nil {
		return err
	}

	fmt.Printf("✓ RSA-PSS key pair generated (%d bits)\n", ks.config.RSAKeyLength)
	fmt.Printf("  Private: %s\n", privateKeyFile)
	fmt.Printf("  Public:  %s\n", publicKeyFile)
	return nil
}

func (ks *KeyStore) GenerateECCKeys() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating ECC key for signing]")
	fmt.Println("==========================================")

	privateKey, err := ecdsa.GenerateKey(ks.config.ECCCurve, rand.Reader)
	if err != nil {
		return err
	}

	ks.ECCPrivateKey = privateKey
	ks.ECCPublicKey = &privateKey.PublicKey

	// Save to files
	privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_ecc_private.pem")
	publicKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_ecc_public.pem")

	if err := ks.saveECCPrivateKey(ks.ECCPrivateKey, privateKeyFile); err != nil {
		return err
	}
	if err := ks.saveECCPublicKey(ks.ECCPublicKey, publicKeyFile); err != nil {
		return err
	}

	curveName := "P-256"
	if ks.config.ECCCurve == elliptic.P384() {
		curveName = "P-384"
	} else if ks.config.ECCCurve == elliptic.P521() {
		curveName = "P-521"
	}

	fmt.Printf("✓ ECC key pair generated (curve: %s)\n", curveName)
	fmt.Printf("  Private: %s\n", privateKeyFile)
	fmt.Printf("  Public:  %s\n", publicKeyFile)
	return nil
}

func (ks *KeyStore) GenerateAESKey() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating AES-256 key for ciphering]")
	fmt.Println("==========================================")

	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return err
	}

	ks.AESKey = key

	// Save to file
	keyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_aes256.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0644); err != nil {
		return err
	}

	fmt.Printf("✓ AES-256 key generated\n")
	fmt.Printf("  File: %s\n", keyFile)
	return nil
}

func (ks *KeyStore) GenerateHMACKey() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating HMAC-SHA256 key]")
	fmt.Println("==========================================")

	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return err
	}

	ks.HMACKey = key

	// Save to file
	keyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_hmac_sha256.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)), 0644); err != nil {
		return err
	}

	fmt.Printf("✓ HMAC-SHA256 key generated\n")
	fmt.Printf("  File: %s\n", keyFile)
	return nil
}

// Save key functions
func (ks *KeyStore) saveRSAPrivateKey(privateKey *rsa.PrivateKey, filename string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.Encode(keyFile, privateKeyBlock)
}

func (ks *KeyStore) saveRSAPublicKey(publicKey *rsa.PublicKey, filename string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.Encode(keyFile, publicKeyBlock)
}

func (ks *KeyStore) saveECCPrivateKey(privateKey *ecdsa.PrivateKey, filename string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.Encode(keyFile, privateKeyBlock)
}

func (ks *KeyStore) saveECCPublicKey(publicKey *ecdsa.PublicKey, filename string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.Encode(keyFile, publicKeyBlock)
}

// createCertificateTemplate creates a certificate template using the config
func (ks *KeyStore) createCertificateTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{ks.config.Country},
			Organization: []string{ks.config.Org},
			OrganizationalUnit: []string{ks.config.OU},
			Locality:     []string{ks.config.Locality},
			Province:     []string{ks.config.State},
			CommonName:   ks.config.CN,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, ks.config.CertDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		DNSNames:              []string{ks.config.CN, ks.config.EntityName + ".com", "demo." + ks.config.EntityName + ".com"},
		EmailAddresses:        []string{ks.config.Email},
	}
}

// Certificate functions
func (ks *KeyStore) GenerateRSACertificate() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating RSA certificate]")
	fmt.Println("==========================================")

	if ks.RSAPSSPrivateKey == nil {
		// Try to load from file
		privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_pss_private.pem")
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("RSA private key not found. Please generate keys first (option 2)")
		}
		
		keyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read RSA private key: %v", err)
		}
		
		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse RSA private key PEM")
		}
		
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %v", err)
		}
		
		ks.RSAPSSPrivateKey = privateKey
		ks.RSAPSSPublicKey = &privateKey.PublicKey
	}

	template := ks.createCertificateTemplate()

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, 
		ks.RSAPSSPublicKey, ks.RSAPSSPrivateKey)
	if err != nil {
		return err
	}

	// Save certificate
	certFile := filepath.Join(ks.config.CertsPath, "demo_user_rsa.crt")
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	fmt.Printf("✓ RSA certificate generated\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Valid for: %d days\n", ks.config.CertDays)
	return nil
}

func (ks *KeyStore) GenerateECCCertificate() error {
	fmt.Println("==========================================")
	fmt.Println("[Generating ECC certificate]")
	fmt.Println("==========================================")

	if ks.ECCPrivateKey == nil {
		// Try to load from file
		privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_ecc_private.pem")
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("ECC private key not found. Please generate keys first (option 2)")
		}
		
		keyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read ECC private key: %v", err)
		}
		
		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse ECC private key PEM")
		}
		
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECC private key: %v", err)
		}
		
		ks.ECCPrivateKey = privateKey
		ks.ECCPublicKey = &privateKey.PublicKey
	}

	template := ks.createCertificateTemplate()

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, 
		ks.ECCPublicKey, ks.ECCPrivateKey)
	if err != nil {
		return err
	}

	// Save certificate
	certFile := filepath.Join(ks.config.CertsPath, "demo_user_ecc.crt")
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	fmt.Printf("✓ ECC certificate generated\n")
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Valid for: %d days\n", ks.config.CertDays)
	return nil
}

// View certificate functions
func (ks *KeyStore) ViewCertificate() error {
	fmt.Println("==========================================")
	fmt.Println("[View Certificate Details]")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("Select certificate:")
	fmt.Println("1. RSA Certificate")
	fmt.Println("2. ECC Certificate")
	fmt.Print("Choice: ")
	
	reader := bufio.NewReader(os.Stdin)
	viewChoice, _ := reader.ReadString('\n')
	viewChoice = strings.TrimSpace(viewChoice)
	fmt.Println()

	switch viewChoice {
	case "1":
		return ks.viewCertificateFile("demo_user_rsa.crt")
	case "2":
		return ks.viewCertificateFile("demo_user_ecc.crt")
	default:
		fmt.Println("Invalid choice")
		return nil
	}
}

func (ks *KeyStore) viewCertificateFile(filename string) error {
	certFile := filepath.Join(ks.config.CertsPath, filename)
	
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return fmt.Errorf("certificate not found: %s", certFile)
	}

	// Read certificate file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Display certificate details
	fmt.Printf("Certificate: %s\n", certFile)
	fmt.Println()
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
	
	// Display key usage
	fmt.Printf("Key Usage: ")
	var keyUsage []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsage = append(keyUsage, "Data Encipherment")
	}
	fmt.Println(strings.Join(keyUsage, ", "))

	// Display extended key usage
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("Extended Key Usage: ")
		var extKeyUsage []string
		for _, usage := range cert.ExtKeyUsage {
			switch usage {
			case x509.ExtKeyUsageServerAuth:
				extKeyUsage = append(extKeyUsage, "Server Authentication")
			case x509.ExtKeyUsageClientAuth:
				extKeyUsage = append(extKeyUsage, "Client Authentication")
			case x509.ExtKeyUsageCodeSigning:
				extKeyUsage = append(extKeyUsage, "Code Signing")
			case x509.ExtKeyUsageEmailProtection:
				extKeyUsage = append(extKeyUsage, "Email Protection")
			default:
				extKeyUsage = append(extKeyUsage, "Unknown")
			}
		}
		fmt.Println(strings.Join(extKeyUsage, ", "))
	}

	// Display DNS names
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names: %s\n", strings.Join(cert.DNSNames, ", "))
	}

	// Display email addresses
	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("Email Addresses: %s\n", strings.Join(cert.EmailAddresses, ", "))
	}

	// Display public key details
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		fmt.Printf("RSA Public Key: %d bits\n", pub.N.BitLen())
	case *ecdsa.PublicKey:
		fmt.Printf("ECC Public Key: %s\n", pub.Curve.Params().Name)
	default:
		fmt.Printf("Public Key: %T\n", pub)
	}

	return nil
}

// Signing functions
func (ks *KeyStore) SignWithRSAPSS(message string) error {
	fmt.Println("==========================================")
	fmt.Println("[Sign Message with RSA-PSS]")
	fmt.Println("==========================================")
	fmt.Println()

	if ks.RSAPSSPrivateKey == nil {
		// Try to load from file
		privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_pss_private.pem")
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("RSA private key not found. Please generate keys first (option 2)")
		}
		
		keyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read RSA private key: %v", err)
		}
		
		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse RSA private key PEM")
		}
		
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %v", err)
		}
		
		ks.RSAPSSPrivateKey = privateKey
	}

	hashed := sha256.Sum256([]byte(message))

	signature, err := rsa.SignPSS(rand.Reader, ks.RSAPSSPrivateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return err
	}

	// Save signature
	sigFile := filepath.Join(ks.config.SigPath, "demo_user_rsa.sig")
	if err := os.WriteFile(sigFile, signature, 0644); err != nil {
		return err
	}

	// Save message
	msgFile := filepath.Join(ks.config.DataPlaintextPath, "message.txt")
	if err := os.WriteFile(msgFile, []byte(message), 0644); err != nil {
		return err
	}

	fmt.Printf("✓ Message signed with RSA-PSS\n")
	fmt.Printf("  Signature: %s\n", sigFile)
	return nil
}

func (ks *KeyStore) VerifyRSAPSS(message string) error {
	fmt.Println("==========================================")
	fmt.Println("[Verify RSA-PSS Signature]")
	fmt.Println("==========================================")
	fmt.Println()

	if ks.RSAPSSPublicKey == nil {
		// Try to load from file
		publicKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_rsa_pss_public.pem")
		if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("RSA public key not found. Please generate keys first (option 2)")
		}
		
		keyData, err := os.ReadFile(publicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read RSA public key: %v", err)
		}
		
		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse RSA public key PEM")
		}
		
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %v", err)
		}
		
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("not an RSA public key")
		}
		
		ks.RSAPSSPublicKey = rsaPubKey
	}

	sigFile := filepath.Join(ks.config.SigPath, "demo_user_rsa.sig")
	signature, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("signature file not found. Please sign a message first (option 5)")
	}

	hashed := sha256.Sum256([]byte(message))

	err = rsa.VerifyPSS(ks.RSAPSSPublicKey, crypto.SHA256, hashed[:], signature, nil)
	if err != nil {
		fmt.Println("✗ Signature INVALID")
		return nil
	}

	fmt.Println("✓ Signature VALID")
	return nil
}

func (ks *KeyStore) SignWithECC(message string) error {
	fmt.Println("==========================================")
	fmt.Println("[Sign Message with ECC]")
	fmt.Println("==========================================")
	fmt.Println()

	if ks.ECCPrivateKey == nil {
		// Try to load from file
		privateKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_ecc_private.pem")
		if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("ECC private key not found. Please generate keys first (option 2)")
		}
		
		keyData, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read ECC private key: %v", err)
		}
		
		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse ECC private key PEM")
		}
		
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECC private key: %v", err)
		}
		
		ks.ECCPrivateKey = privateKey
	}

	hashed := sha256.Sum256([]byte(message))

	r, s, err := ecdsa.Sign(rand.Reader, ks.ECCPrivateKey, hashed[:])
	if err != nil {
		return err
	}

	// Combine r and s into a single signature
	signature := append(r.Bytes(), s.Bytes()...)

	// Save signature
	sigFile := filepath.Join(ks.config.SigPath, "demo_user_ecc.sig")
	if err := os.WriteFile(sigFile, signature, 0644); err != nil {
		return err
	}

	// Save message
	msgFile := filepath.Join(ks.config.DataPlaintextPath, "message.txt")
	if err := os.WriteFile(msgFile, []byte(message), 0644); err != nil {
		return err
	}

	fmt.Printf("✓ Message signed with ECDSA\n")
	fmt.Printf("  Signature: %s\n", sigFile)
	return nil
}

func (ks *KeyStore) VerifyECC(message string) error {
	fmt.Println("==========================================")
	fmt.Println("[Verify ECC Signature]")
	fmt.Println("==========================================")
	fmt.Println()

	if ks.ECCPublicKey == nil {
		// Try to load from file
		publicKeyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_ecc_public.pem")
		if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("ECC public key not found. Please generate keys first (option 2)")
		}
		
		keyData, err := os.ReadFile(publicKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read ECC public key: %v", err)
		}
		
		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to parse ECC public key PEM")
		}
		
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECC public key: %v", err)
		}
		
		ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("not an ECC public key")
		}
		
		ks.ECCPublicKey = ecPubKey
	}

	sigFile := filepath.Join(ks.config.SigPath, "demo_user_ecc.sig")
	signature, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("signature file not found. Please sign a message first (option 7)")
	}

	hashed := sha256.Sum256([]byte(message))

	// Split signature into r and s components
	sigLen := len(signature) / 2
	r := new(big.Int).SetBytes(signature[:sigLen])
	s := new(big.Int).SetBytes(signature[sigLen:])

	valid := ecdsa.Verify(ks.ECCPublicKey, hashed[:], r, s)
	if valid {
		fmt.Println("✓ Signature VALID")
	} else {
		fmt.Println("✗ Signature INVALID")
	}

	return nil
}

// AES encryption/decryption functions
// Update the AES encryption/decryption functions
func (ks *KeyStore) EncryptWithAES(message string) error {
	fmt.Println("==========================================")
	fmt.Println("[Encrypt with AES-256-CBC]")
	fmt.Println("==========================================")
	fmt.Println()

	if ks.AESKey == nil {
		// Try to load from file
		keyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_aes256.key")
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			return fmt.Errorf("AES key not found. Please generate AES key first (option 9)")
		}
		
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read AES key: %v", err)
		}
		
		keyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyData)))
		if err != nil {
			return fmt.Errorf("failed to decode AES key: %v", err)
		}
		
		ks.AESKey = keyBytes
	}

	// Save plaintext message
	plaintextFile := filepath.Join(ks.config.DataPlaintextPath, "message.txt")
	if err := os.WriteFile(plaintextFile, []byte(message), 0644); err != nil {
		return err
	}

	// Read the plaintext file
	plaintext, err := os.ReadFile(plaintextFile)
	if err != nil {
		return err
	}

	// Create cipher
	block, err := aes.NewCipher(ks.AESKey)
	if err != nil {
		return err
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Save IV
	ivFile := filepath.Join(ks.config.DataCipheredPath, "message.iv")
	if err := os.WriteFile(ivFile, iv, 0644); err != nil {
		return err
	}

	// Pad the plaintext to block size
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// Save ciphertext
	ciphertextFile := filepath.Join(ks.config.DataCipheredPath, "message.enc")
	if err := os.WriteFile(ciphertextFile, ciphertext, 0644); err != nil {
		return err
	}

	fmt.Printf("✓ File encrypted\n")
	fmt.Printf("  Plaintext: %s\n", plaintextFile)
	fmt.Printf("  Ciphertext: %s\n", ciphertextFile)
	fmt.Printf("  IV: %s\n", ivFile)
	return nil
}

func (ks *KeyStore) DecryptWithAES() error {
	fmt.Println("==========================================")
	fmt.Println("[Decrypt with AES-256-CBC]")
	fmt.Println("==========================================")
	fmt.Println()

	if ks.AESKey == nil {
		// Try to load from file
		keyFile := filepath.Join(ks.config.KeyStorePath, "demo_user_aes256.key")
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			return fmt.Errorf("AES key not found. Please generate AES key first (option 9)")
		}
		
		keyData, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read AES key: %v", err)
		}
		
		keyBytes, err := hex.DecodeString(strings.TrimSpace(string(keyData)))
		if err != nil {
			return fmt.Errorf("failed to decode AES key: %v", err)
		}
		
		ks.AESKey = keyBytes
	}

	// Read IV
	ivFile := filepath.Join(ks.config.DataCipheredPath, "message.iv")
	iv, err := os.ReadFile(ivFile)
	if err != nil {
		return fmt.Errorf("IV file not found: %v", err)
	}

	// Read ciphertext
	ciphertextFile := filepath.Join(ks.config.DataCipheredPath, "message.enc")
	ciphertext, err := os.ReadFile(ciphertextFile)
	if err != nil {
		return fmt.Errorf("encrypted file not found: %v", err)
	}

	// Create cipher
	block, err := aes.NewCipher(ks.AESKey)
	if err != nil {
		return err
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("failed to remove padding: %v", err)
	}

	// Save decrypted text
	decryptedFile := filepath.Join(ks.config.DataPlaintextPath, "message_decrypted.txt")
	if err := os.WriteFile(decryptedFile, plaintext, 0644); err != nil {
		return err
	}

	fmt.Printf("✓ File decrypted\n")
	fmt.Println("")
	fmt.Println("Decrypted message:")
	fmt.Println(string(plaintext))
	return nil
}

// PKCS7 padding functions
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7: data is empty")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: data is not block-aligned")
	}
	
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("pkcs7: invalid padding")
	}
	
	// Check padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("pkcs7: invalid padding")
		}
	}
	
	return data[:len(data)-padding], nil
}

// Demo workflow functions
func (ks *KeyStore) CompleteRSAWorkflow() error {
	fmt.Println("==========================================")
	fmt.Println("[Complete RSA Workflow Demo]")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("This will demonstrate:")
	fmt.Println("1. Key generation")
	fmt.Println("2. Certificate creation")
	fmt.Println("3. Message signing")
	fmt.Println("4. Signature verification")
	fmt.Println()
	fmt.Print("Press Enter to begin...")
	fmt.Scanln()

	fmt.Println()
	if err := ks.GenerateRSAPSSKeys(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	fmt.Println()
	if err := ks.GenerateRSACertificate(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	fmt.Println()
	fmt.Println("[Signing test message]")
	testMessage := "Test message for RSA-PSS signing"
	if err := ks.SignWithRSAPSS(testMessage); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	fmt.Println()
	fmt.Println("[Verifying signature]")
	if err := ks.VerifyRSAPSS(testMessage); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("✓ RSA workflow complete!")
	return nil
}

func (ks *KeyStore) CompleteECCWorkflow() error {
	fmt.Println("==========================================")
	fmt.Println("[Complete ECC Workflow Demo]")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("This will demonstrate:")
	fmt.Println("1. Key generation")
	fmt.Println("2. Certificate creation")
	fmt.Println("3. Message signing")
	fmt.Println("4. Signature verification")
	fmt.Println()
	fmt.Print("Press Enter to begin...")
	fmt.Scanln()

	fmt.Println()
	if err := ks.GenerateECCKeys(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	fmt.Println()
	if err := ks.GenerateECCCertificate(); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	fmt.Println()
	fmt.Println("[Signing test message]")
	testMessage := "Test message for ECDSA signing"
	if err := ks.SignWithECC(testMessage); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	fmt.Println()
	fmt.Println("[Verifying signature]")
	if err := ks.VerifyECC(testMessage); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("✓ ECC workflow complete!")
	return nil
}

// Menu system
func printDemoMenu() {
	fmt.Println("==========================================")
	fmt.Println("    CERTIFICATE UTILITY DEMO (Go)")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("[SETUP]")
	fmt.Println("1  : Initialize folder structure")
	fmt.Println("2  : Generate keys (RSA-OAEP, RSA-PSS, ECC)")
	fmt.Println()
	fmt.Println("[CSR & CERTIFICATES]")
	fmt.Println("3  : Generate self-signed certificate")
	fmt.Println("4  : View certificate details")
	fmt.Println()
	fmt.Println("[SIGNING - RSA-PSS]")
	fmt.Println("5  : Sign message with RSA-PSS")
	fmt.Println("6  : Verify RSA-PSS signature")
	fmt.Println()
	fmt.Println("[SIGNING - ECC]")
	fmt.Println("7  : Sign message with ECC")
	fmt.Println("8  : Verify ECC signature")
	fmt.Println()
	fmt.Println("[CIPHERING - AES]")
	fmt.Println("9  : Generate AES key")
	fmt.Println("10 : Encrypt message with AES")
	fmt.Println("11 : Decrypt message with AES")
	fmt.Println()
	fmt.Println("[COMPLETE WORKFLOW]")
	fmt.Println("12 : Run complete RSA workflow demo")
	fmt.Println("13 : Run complete ECC workflow demo")
	fmt.Println()
	fmt.Println("x  : Exit")
	fmt.Println("==========================================")
}

func main() {
	// Initialize configuration
	baseConfig := DefaultConfig()
	config, err := LoadConfigFromCNF(baseConfig)
	if err != nil {
		fmt.Printf("Warning: Could not load CNF configuration: %v\n", err)
		config = baseConfig
	}

	keyStore := NewKeyStore(config)

	fmt.Printf("Entity: %s\n", config.EntityName)
	fmt.Println()

	// Create a buffered reader for better input handling
	reader := bufio.NewReader(os.Stdin)

	for {
		printDemoMenu()
		fmt.Print("Select option: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		fmt.Println()

		switch choice {
		case "1":
			if err := keyStore.SetupFolderStructure(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "2":
			if err := keyStore.GenerateAllKeys(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "3":
			fmt.Println("Select key type:")
			fmt.Println("1. RSA-PSS")
			fmt.Println("2. ECC")
			fmt.Print("Choice: ")
			certChoice, _ := reader.ReadString('\n')
			certChoice = strings.TrimSpace(certChoice)
			fmt.Println()

			switch certChoice {
			case "1":
				if err := keyStore.GenerateRSACertificate(); err != nil {
					fmt.Printf("Error: %v\n", err)
				}
			case "2":
				if err := keyStore.GenerateECCCertificate(); err != nil {
					fmt.Printf("Error: %v\n", err)
				}
			default:
				fmt.Println("Invalid choice")
			}
		case "4":
			if err := keyStore.ViewCertificate(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "5":
			fmt.Print("Enter message to sign: ")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)
			if err := keyStore.SignWithRSAPSS(message); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "6":
			fmt.Print("Enter message to verify: ")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)
			if err := keyStore.VerifyRSAPSS(message); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "7":
			fmt.Print("Enter message to sign: ")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)
			if err := keyStore.SignWithECC(message); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "8":
			fmt.Print("Enter message to verify: ")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)
			if err := keyStore.VerifyECC(message); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "9":
			if err := keyStore.GenerateAESKey(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "10":
			fmt.Print("Enter message to encrypt: ")
			message, _ := reader.ReadString('\n')
			message = strings.TrimSpace(message)
			if err := keyStore.EncryptWithAES(message); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "11":
			if err := keyStore.DecryptWithAES(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "12":
			if err := keyStore.CompleteRSAWorkflow(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "13":
			if err := keyStore.CompleteECCWorkflow(); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "x", "X":
			fmt.Println("Exiting demo...")
			return
		default:
			fmt.Println("Invalid selection!")
		}

		if choice != "x" && choice != "X" {
			fmt.Println()
			fmt.Print("Press Enter to continue...")
			reader.ReadString('\n')
		}
	}
}