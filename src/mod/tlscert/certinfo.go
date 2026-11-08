package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"imuslab.com/zoraxy/mod/acme"
)

// Managed-by values shown in the certificate list
const (
	ManagedACME   = "acme"
	ManagedUpload = "upload"
	ManagedMapDir = "mapdir"
	ManagedCSR    = "csr"
)

// KeyTypeOf names the public key of a certificate the way the ACME key type setting does (RSA2048, EC256 ...).
func KeyTypeOf(cert *x509.Certificate) string {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "EC256"
		case elliptic.P384():
			return "EC384"
		case elliptic.P521():
			return "EC521"
		}
		return "EC"
	}
	return "other"
}

// IssuerOf returns a human readable issuer: the CA recorded at issuance, else the certificate's issuer organisation / CN.
func IssuerOf(cert *x509.Certificate, info *acme.CertificateInfoJSON) string {
	if info != nil && info.AcmeName != "" && info.AcmeName != "custom" {
		return info.AcmeName
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	return ""
}

// ManagedByOf classifies who maintains a certificate. Without metadata a certificate is an upload.
func ManagedByOf(info *acme.CertificateInfoJSON) string {
	if info == nil {
		return ManagedUpload
	}
	switch info.ManagedBy {
	case "", ManagedACME:
		return ManagedACME
	case ManagedMapDir, ManagedCSR, ManagedUpload:
		return info.ManagedBy
	}
	return ManagedUpload
}
