// internal/tls/dev_cert.go
package tls

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "net"
    "os"
    "path/filepath"
    "time"

    "auth-service/internal/util"
    "go.uber.org/zap"
)

type DevCertGenerator struct {
    certDir string
}

func NewDevCertGenerator(certDir string) *DevCertGenerator {
    return &DevCertGenerator{
        certDir: certDir,
    }
}

func (d *DevCertGenerator) GenerateCert(hosts []string) (tls.Certificate, error) {
    certPath := filepath.Join(d.certDir, "dev-cert.pem")
    keyPath := filepath.Join(d.certDir, "dev-key.pem")

    // Check if certificates already exist and are valid
    if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
        // Verify certificate is still valid
        if d.isCertificateValid(certPath) {
            util.Info("Using existing valid certificate", zap.String("cert_path", certPath))
            return cert, nil
        }
    }

    util.Info("Generating new self-signed certificate", zap.Strings("hosts", hosts))

    // Generate new certificate
    priv, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to generate private key: %v", err)
    }

    // Create certificate template with extended validity
    serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization:  []string{"Auth Service Development"},
            Country:       []string{"US"},
            Province:      []string{"CA"},
            Locality:      []string{"San Francisco"},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        IsCA:                  false,
    }

    // Add hosts
    for _, h := range hosts {
        if ip := net.ParseIP(h); ip != nil {
            template.IPAddresses = append(template.IPAddresses, ip)
        } else {
            template.DNSNames = append(template.DNSNames, h)
        }
    }

    // Create self-signed certificate
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to create certificate: %v", err)
    }

    // Write certificate
    certOut, err := os.Create(certPath)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to open cert.pem for writing: %v", err)
    }
    pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    certOut.Close()

    // Write key
    keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to open key.pem for writing: %v", err)
    }
    pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
    keyOut.Close()

    util.Info("Successfully generated self-signed certificate",
        zap.String("cert_path", certPath),
        zap.String("key_path", keyPath))

    // Load the new certificate
    cert, err := tls.LoadX509KeyPair(certPath, keyPath)
    if err != nil {
        return tls.Certificate{}, fmt.Errorf("failed to load generated certificate: %v", err)
    }

    return cert, nil
}

func (d *DevCertGenerator) isCertificateValid(certPath string) bool {
    certData, err := os.ReadFile(certPath)
    if err != nil {
        return false
    }

    block, _ := pem.Decode(certData)
    if block == nil {
        return false
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return false
    }

    // Check if certificate is still valid
    now := time.Now()
    return now.After(cert.NotBefore) && now.Before(cert.NotAfter)
}
