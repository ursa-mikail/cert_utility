package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bxcodec/faker/v3"
)

type CertificateInfo struct {
	Certificate     *x509.Certificate
	Status          string
	ExpiryTime      time.Time
	IsValid         bool
	DaysUntilExpiry int
}

func main() {
	fmt.Println("🔐 Random Certificate Generator and Validator")
	fmt.Println("=============================================")

	// Generate multiple random certificates
	for i := 0; i < 3; i++ {
		fmt.Printf("\n--- Certificate #%d ---\n", i+1)

		certInfo, err := generateAndValidateCertificate()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		printCertificateSummary(certInfo)
	}
}

func generateAndValidateCertificate() (*CertificateInfo, error) {
	cert, err := generateRandomCertificate()
	if err != nil {
		return nil, err
	}

	return validateCertificateExpiryEnhanced(cert), nil
}

func generateRandomCertificate() (*x509.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Generate random validity period (1 day to 2 years)
	validityDays := time.Duration(randomInt(1, 730)) * 24 * time.Hour
	notBefore := time.Now().Add(-time.Duration(randomInt(0, 365)) * 24 * time.Hour)
	notAfter := notBefore.Add(validityDays)

	// Add random time components
	notBefore = addRandomTimeComponents(notBefore)
	notAfter = addRandomTimeComponents(notAfter)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(randomInt(1, 999999999))),
		Subject: pkix.Name{
			CommonName:         faker.DomainName(),
			Organization:       []string{faker.Word() + " Inc."},
			OrganizationalUnit: []string{faker.Word() + " Department"},
			Country:            []string{getRandomCountryCode()},
			Province:           []string{faker.Word() + " State"},
			Locality:           []string{faker.Word() + " City"},
		},
		Issuer: pkix.Name{
			CommonName:   faker.Word() + " CA",
			Organization: []string{faker.Word() + " Certificate Authority"},
			Country:      []string{getRandomCountryCode()},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{faker.DomainName(), "www." + faker.DomainName(), "api." + faker.DomainName()},
		EmailAddresses:        []string{faker.Email()},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return cert, nil
}

// Helper function to generate random integers
func randomInt(min, max int) int {
	return min + int(faker.RandomUnixTime())%(max-min+1)
}

func addRandomTimeComponents(t time.Time) time.Time {
	return t.
		Add(time.Duration(randomInt(0, 23)) * time.Hour).
		Add(time.Duration(randomInt(0, 59)) * time.Minute).
		Add(time.Duration(randomInt(0, 59)) * time.Second).
		Add(time.Duration(randomInt(0, 999)) * time.Millisecond)
}

func validateCertificateExpiryEnhanced(cert *x509.Certificate) *CertificateInfo {
	now := time.Now()
	info := &CertificateInfo{
		Certificate: cert,
		ExpiryTime:  cert.NotAfter,
	}

	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	info.DaysUntilExpiry = daysUntilExpiry

	switch {
	case now.Before(cert.NotBefore):
		info.Status = "NOT_YET_VALID"
		info.IsValid = false
	case now.After(cert.NotAfter):
		info.Status = "EXPIRED"
		info.IsValid = false
	default:
		info.Status = "VALID"
		info.IsValid = true
	}

	// Print detailed validation
	printDetailedValidation(info, now)

	return info
}

func printDetailedValidation(info *CertificateInfo, currentTime time.Time) {
	cert := info.Certificate

	fmt.Println("\n📋 Certificate Details:")
	fmt.Printf("   Subject: %s\n", cert.Subject.CommonName)
	if len(cert.Subject.Organization) > 0 {
		fmt.Printf("   Organization: %s\n", cert.Subject.Organization[0])
	}
	fmt.Printf("   Serial: %s\n", cert.SerialNumber)
	fmt.Printf("   Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05.999"))
	fmt.Printf("   Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05.999"))
	fmt.Printf("   DNS Names: %v\n", cert.DNSNames)

	fmt.Println("\n🔍 Validation Results:")
	fmt.Printf("   Current Time: %s\n", currentTime.Format("2006-01-02 15:04:05.999"))

	switch info.Status {
	case "VALID":
		fmt.Printf("   ✅ Status: VALID\n")
		fmt.Printf("   📅 Days until expiry: %d\n", info.DaysUntilExpiry)
	case "EXPIRED":
		fmt.Printf("   ❌ Status: EXPIRED\n")
		daysExpired := int(currentTime.Sub(cert.NotAfter).Hours() / 24)
		fmt.Printf("   ⏰ Expired %d days ago\n", daysExpired)
	case "NOT_YET_VALID":
		fmt.Printf("   ⏳ Status: NOT YET VALID\n")
		daysUntilValid := int(cert.NotBefore.Sub(currentTime).Hours() / 24)
		fmt.Printf("   🔮 Becomes valid in %d days\n", daysUntilValid)
	}

	// Validity period analysis
	validityPeriod := cert.NotAfter.Sub(cert.NotBefore)
	fmt.Printf("   📊 Total validity period: %.0f days\n", validityPeriod.Hours()/24)

	if info.IsValid {
		elapsed := currentTime.Sub(cert.NotBefore)
		percentage := float64(elapsed) / float64(validityPeriod) * 100
		fmt.Printf("   📈 Validity period used: %.1f%%\n", percentage)
	}
}

func printCertificateSummary(info *CertificateInfo) {
	statusEmoji := "✅"
	if !info.IsValid {
		statusEmoji = "❌"
	}

	fmt.Printf("%s Certificate: %s (Expires: %s) - %s\n",
		statusEmoji,
		info.Certificate.Subject.CommonName,
		info.ExpiryTime.Format("2006-01-02"),
		info.Status,
	)
}

func getRandomCountryCode() string {
	countries := []string{"US", "GB", "CA", "AU", "DE", "FR", "JP", "IN", "BR", "CN"}
	return countries[randomInt(0, len(countries)-1)]
}

// Optional: Save certificate to file
func saveCertificateToPEM(cert *x509.Certificate, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

/*
go mody tidy
% go run main.go
🔐 Random Certificate Generator and Validator
=============================================

--- Certificate #1 ---

📋 Certificate Details:
   Subject: QcNyerq.info
   Organization: soluta Inc.
   Serial: 793885401
   Valid From: 2025-01-20 05:37:24
   Valid Until: 2027-01-08 17:44:22
   DNS Names: [wVJscMi.org www.VHiEhOm.net api.ApCFnuv.ru]

🔍 Validation Results:
   Current Time: 2025-11-12 15:53:33.24
   ✅ Status: VALID
   📅 Days until expiry: 421
   📊 Total validity period: 719 days
   📈 Validity period used: 41.3%
✅ Certificate: QcNyerq.info (Expires: 2027-01-08) - VALID

--- Certificate #2 ---

📋 Certificate Details:
   Subject: CASyRcw.info
   Organization: molestiae Inc.
   Serial: 717904630
   Valid From: 2025-10-01 10:21:55
   Valid Until: 2026-09-17 11:25:13
   DNS Names: [WJmTMgw.ru www.vbwKgqd.net api.rTXsWCS.com]

🔍 Validation Results:
   Current Time: 2025-11-12 15:53:33.356
   ✅ Status: VALID
   📅 Days until expiry: 308
   📊 Total validity period: 351 days
   📈 Validity period used: 12.1%
✅ Certificate: CASyRcw.info (Expires: 2026-09-17) - VALID

--- Certificate #3 ---

📋 Certificate Details:
   Subject: JtwuoCq.org
   Organization: aut Inc.
   Serial: 626958331
   Valid From: 2025-05-03 22:07:07
   Valid Until: 2025-11-25 11:07:20
   DNS Names: [IvTFPWV.org www.smlckyW.biz api.IfhVvUv.net]

🔍 Validation Results:
   Current Time: 2025-11-12 15:53:33.56
   ✅ Status: VALID
   📅 Days until expiry: 12
   📊 Total validity period: 206 days
   📈 Validity period used: 93.9%
✅ Certificate: JtwuoCq.org (Expires: 2025-11-25) - VALID
*/
