package tlscert

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/utils"
)

type CertCache struct {
	Cert   *x509.Certificate
	PubKey string
	PriKey string
}

type HostSpecificTlsBehavior struct {
	DisableSNI                       bool              //If SNI is enabled for this server name
	DisableLegacyCertificateMatching bool              //If legacy certificate matching is disabled for this server name
	EnableAutoHTTPS                  bool              //If auto HTTPS is enabled for this server name
	PreferredCertificate             map[string]string //Preferred certificate for this server name, if empty, use the first matching certificate
}

type Manager struct {
	CertStore    string         //Path where all the certs are stored
	LoadedCerts  []*CertCache   //A list of loaded certs
	Logger       *logger.Logger //System wide logger for debug mesage
	FallbackCert string         //Name of the fallback/default certificate (no file renaming)
	TmpFolder    string         //Temporary folder holding the built-in localhost certificate and zip exports (-tmp)

	//OnCertRemoved is called after a certificate has been deleted, so other modules
	//(e.g. ACME) can drop the data they keep for it
	OnCertRemoved func(domain string) `json:"-"`

	//OnServe is called with the SNI and the certificate chosen for every handshake (fallback = the built-in
	//localhost certificate). It must be cheap and must not block.
	OnServe func(serverName string, cert *tls.Certificate, fallback bool) `json:"-"`

	/* External handlers */
	hostSpecificTlsBehavior func(serverName string) (*HostSpecificTlsBehavior, error) // Function to get host specific TLS behavior, if nil, use global TLS options
}

//go:embed localhost.pem localhost.key
var buildinCertStore embed.FS

const (
	defaultPublicCertFileMode os.FileMode = 0644
	defaultPrivateKeyFileMode os.FileMode = 0600
)

// writeFileWithMode joins relativeName onto baseDir and writes data to the
// result with the exact requested permission bits.
func writeFileWithMode(baseDir, relativeName string, data []byte, mode os.FileMode) error {
	resolvedPath, err := safeJoin(baseDir, relativeName)
	if err != nil {
		return err
	}

	if err := os.WriteFile(resolvedPath, data, mode); err != nil {
		return err
	}

	// os.WriteFile honours the process umask, so the on-disk permissions may
	// differ from the requested mode. os.Chmod sets the exact bits regardless
	// of the umask — essential for private-key files (e.g. 0600).
	return os.Chmod(resolvedPath, mode)
}

// safeJoin joins name onto baseDir and verifies the resulting absolute path
// is still located inside baseDir, rejecting any ../
func safeJoin(baseDir, name string) (string, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	absBase = filepath.Clean(absBase)

	joined := filepath.Join(absBase, name)

	if joined != absBase && !strings.HasPrefix(joined, absBase+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid filename %q: resolved path escapes base directory %q", name, baseDir)
	}
	return joined, nil
}

// DefaultTmpFolder is the temporary folder used when none is configured (the -tmp default)
const DefaultTmpFolder = "./tmp"

// NewManager creates a manager that keeps its localhost fallback certificate in DefaultTmpFolder
func NewManager(certStore string, logger *logger.Logger) (*Manager, error) {
	return NewManagerWithTmp(certStore, DefaultTmpFolder, logger)
}

// NewManagerWithTmp is NewManager with an explicit temporary folder (the -tmp flag)
func NewManagerWithTmp(certStore string, tmpFolder string, logger *logger.Logger) (*Manager, error) {
	if tmpFolder == "" {
		tmpFolder = DefaultTmpFolder
	}
	if !utils.FileExists(certStore) {
		os.MkdirAll(certStore, 0775)
	}

	os.MkdirAll(tmpFolder, 0775)
	pubKey := filepath.Join(tmpFolder, "localhost.pem")
	priKey := filepath.Join(tmpFolder, "localhost.key")

	//Check if this is initial setup
	if !utils.FileExists(pubKey) {
		buildInPubKey, _ := buildinCertStore.ReadFile(filepath.Base(pubKey))
		writeFileWithMode(filepath.Dir(pubKey), filepath.Base(pubKey), buildInPubKey, defaultPublicCertFileMode)
	}

	if !utils.FileExists(priKey) {
		buildInPriKey, _ := buildinCertStore.ReadFile(filepath.Base(priKey))
		writeFileWithMode(filepath.Dir(priKey), filepath.Base(priKey), buildInPriKey, defaultPrivateKeyFileMode)
	}

	thisManager := Manager{
		CertStore:               certStore,
		LoadedCerts:             []*CertCache{},
		hostSpecificTlsBehavior: defaultHostSpecificTlsBehavior, //Default to no SNI and no auto HTTPS
		Logger:                  logger,
		TmpFolder:               tmpFolder,
	}

	// Restore fallback cert name from metadata file
	if data, err := os.ReadFile(filepath.Join(certStore, "fallback.json")); err == nil {
		var fb struct {
			FallbackCert string `json:"fallbackCert"`
		}
		if json.Unmarshal(data, &fb) == nil && fb.FallbackCert != "" {
			thisManager.FallbackCert = fb.FallbackCert
		}
	}

	err := thisManager.UpdateLoadedCertList()
	if err != nil {
		return nil, err
	}

	return &thisManager, nil
}

// Default host specific TLS behavior
// This is used when no specific TLS behavior is defined for a server name
func GetDefaultHostSpecificTlsBehavior() *HostSpecificTlsBehavior {
	return &HostSpecificTlsBehavior{
		DisableSNI:                       false,
		DisableLegacyCertificateMatching: false,
		EnableAutoHTTPS:                  false,
		PreferredCertificate:             map[string]string{}, // No preferred certificate, use the first matching certificate
	}
}

func defaultHostSpecificTlsBehavior(serverName string) (*HostSpecificTlsBehavior, error) {
	return GetDefaultHostSpecificTlsBehavior(), nil
}

func (m *Manager) SetHostSpecificTlsBehavior(fn func(serverName string) (*HostSpecificTlsBehavior, error)) {
	m.hostSpecificTlsBehavior = fn
}

// Update domain mapping from file
func (m *Manager) UpdateLoadedCertList() error {
	//Get a list of certificates from file
	domainList, err := m.ListCertDomains()
	if err != nil {
		return err
	}

	//Load each of the certificates into memory
	certList := []*CertCache{}
	for _, certname := range domainList {
		//Read their certificate into memory
		pubKey := filepath.Join(m.CertStore, certname+".pem")
		priKey := filepath.Join(m.CertStore, certname+".key")
		certificate, err := tls.LoadX509KeyPair(pubKey, priKey)
		if err != nil {
			m.Logger.PrintAndLog("tls-router", "Certificate load failed: "+certname, err)
			continue
		}

		for _, thisCert := range certificate.Certificate {
			loadedCert, err := x509.ParseCertificate(thisCert)
			if err != nil {
				//Error pasring cert, skip this byte segment
				m.Logger.PrintAndLog("tls-router", "Certificate parse failed: "+certname, err)
				continue
			}

			thisCacheEntry := CertCache{
				Cert:   loadedCert,
				PubKey: pubKey,
				PriKey: priKey,
			}
			certList = append(certList, &thisCacheEntry)
		}
	}

	//Replace runtime cert array
	m.LoadedCerts = certList

	return nil
}

// Match cert by CN
func (m *Manager) CertMatchExists(serverName string) bool {
	for _, certCacheEntry := range m.LoadedCerts {
		if certCacheEntry.Cert.VerifyHostname(serverName) == nil || certCacheEntry.Cert.Issuer.CommonName == serverName {
			return true
		}
	}
	return false
}

// Get cert entry by matching server name, return pubKey and priKey if found
// check with CertMatchExists before calling to the load function
func (m *Manager) GetCertByX509CNHostname(serverName string) (string, string) {
	for _, certCacheEntry := range m.LoadedCerts {
		if certCacheEntry.Cert.VerifyHostname(serverName) == nil || certCacheEntry.Cert.Issuer.CommonName == serverName {
			return certCacheEntry.PubKey, certCacheEntry.PriKey
		}
	}

	return "", ""
}

// Return a list of domains by filename
func (m *Manager) ListCertDomains() ([]string, error) {
	filenames, err := m.ListCerts()
	if err != nil {
		return []string{}, err
	}

	//Remove certificates where there are missing public key or private key
	filenames = getCertPairs(filenames)

	return filenames, nil
}

// Return a list of cert files (public and private keys)
func (m *Manager) ListCerts() ([]string, error) {
	certs, err := os.ReadDir(m.CertStore)
	if err != nil {
		return []string{}, err
	}

	filenames := make([]string, 0, len(certs))
	for _, cert := range certs {
		if !cert.IsDir() {
			filenames = append(filenames, cert.Name())
		}
	}

	return filenames, nil
}

// Get a certificate from disk where its certificate matches with the helloinfo
func (m *Manager) GetCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	//Look for the certificate by hostname
	pubKey, priKey, err := m.GetCertificateByHostname(helloInfo.ServerName)
	if err != nil {
		m.Logger.PrintAndLog("tls-router", "Failed to get certificate for "+helloInfo.ServerName, err)
		return nil, err
	}

	//Load the cert and serve it
	cer, err := tls.LoadX509KeyPair(pubKey, priKey)
	if err != nil {
		return nil, nil
	}
	if m.OnServe != nil {
		m.OnServe(helloInfo.ServerName, &cer, pubKey == filepath.Join(m.tmpFolder(), "localhost.pem"))
	}

	return &cer, nil
}

// preferredCertificateFor finds the preferred certificate of a hostname. An exact key wins. Otherwise a key
// that names the same host in another spelling (Unicode / punycode) or a wildcard key ("*.example.com", the
// way a wildcard proxy rule is stored) that matches the hostname is used, so a choice made for a rule is
// also honoured for the names the rule answers to.
func preferredCertificateFor(prefs map[string]string, hostname string) string {
	if len(prefs) == 0 {
		return ""
	}
	if c, ok := prefs[hostname]; ok {
		return c
	}
	keys := make([]string, 0, len(prefs))
	for k := range prefs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if utils.NormalizeHostname(strings.ToLower(k)) == hostname {
			return prefs[k]
		}
	}
	for _, k := range keys {
		if strings.HasPrefix(k, "*.") {
			if ok, err := filepath.Match(utils.NormalizeHostname(strings.ToLower(k)), hostname); err == nil && ok {
				return prefs[k]
			}
		}
	}
	return ""
}

// CertExists reports whether a stored certificate (name without extension) has both its certificate and
// its key file. The name must be a plain file name.
func (m *Manager) CertExists(certName string) error {
	if certName == "" || certName != filepath.Base(certName) || strings.ContainsAny(certName, "/\\") || strings.Contains(certName, "..") {
		return errors.New("invalid certificate name")
	}
	if !utils.FileExists(filepath.Join(m.CertStore, certName+".pem")) || !utils.FileExists(filepath.Join(m.CertStore, certName+".key")) {
		return errors.New("certificate not found: " + certName)
	}
	return nil
}

// GetCertificateByHostname returns the certificate and private key for a given hostname
func (m *Manager) GetCertificateByHostname(hostname string) (string, string, error) {
	//SNI always carries the punycode form of an internationalised name (upstream #458)
	hostname = utils.NormalizeHostname(hostname)
	//Legacy certificate files may have been stored under the Unicode spelling the user typed
	if uni := utils.DisplayHostname(hostname); uni != hostname &&
		!utils.FileExists(filepath.Join(m.CertStore, hostname+".pem")) &&
		utils.FileExists(filepath.Join(m.CertStore, uni+".pem")) &&
		utils.FileExists(filepath.Join(m.CertStore, uni+".key")) {
		hostname = uni
	}
	//Check if the domain corrisponding cert exists
	pubKey := filepath.Join(m.tmpFolder(), "localhost.pem")
	priKey := filepath.Join(m.tmpFolder(), "localhost.key")

	tlsBehavior, err := m.hostSpecificTlsBehavior(hostname)
	if err != nil {
		tlsBehavior, _ = defaultHostSpecificTlsBehavior(hostname)
	}
	preferredCertificate := preferredCertificateFor(tlsBehavior.PreferredCertificate, hostname)

	if tlsBehavior.DisableSNI && preferredCertificate != "" &&
		utils.FileExists(filepath.Join(m.CertStore, preferredCertificate+".pem")) &&
		utils.FileExists(filepath.Join(m.CertStore, preferredCertificate+".key")) {
		//User setup a Preferred certificate, use the preferred certificate directly
		pubKey = filepath.Join(m.CertStore, preferredCertificate+".pem")
		priKey = filepath.Join(m.CertStore, preferredCertificate+".key")
	} else {
		if !tlsBehavior.DisableLegacyCertificateMatching &&
			utils.FileExists(filepath.Join(m.CertStore, hostname+".pem")) &&
			utils.FileExists(filepath.Join(m.CertStore, hostname+".key")) {
			//Legacy filename matching, use the file names directly
			//This is the legacy method of matching certificates, it will match the file names directly
			//This is used for compatibility with Zoraxy v2 setups
			pubKey = filepath.Join(m.CertStore, hostname+".pem")
			priKey = filepath.Join(m.CertStore, hostname+".key")
		} else if !tlsBehavior.DisableSNI &&
			m.CertMatchExists(hostname) {
			//SNI scan match, find the first matching certificate
			pubKey, priKey = m.GetCertByX509CNHostname(hostname)
		} else if tlsBehavior.EnableAutoHTTPS {
			//Get certificate from CA, WIP
			//TODO: Implement AutoHTTPS
		} else {
			//Fallback to the configured fallback certificate
			if m.DefaultCertExists() {
				pubKey = filepath.Join(m.CertStore, m.FallbackCert+".pem")
				priKey = filepath.Join(m.CertStore, m.FallbackCert+".key")
			}
		}
	}
	return pubKey, priKey, nil
}

// Check if both the default cert public key and private key exists
func (m *Manager) DefaultCertExists() bool {
	if m.FallbackCert == "" {
		return false
	}
	return utils.FileExists(filepath.Join(m.CertStore, m.FallbackCert+".pem")) && utils.FileExists(filepath.Join(m.CertStore, m.FallbackCert+".key"))
}

// Check if the default cert exists returning seperate results for pubkey and prikey
func (m *Manager) DefaultCertExistsSep() (bool, bool) {
	if m.FallbackCert == "" {
		return false, false
	}
	return utils.FileExists(filepath.Join(m.CertStore, m.FallbackCert+".pem")), utils.FileExists(filepath.Join(m.CertStore, m.FallbackCert+".key"))
}

func sanitizeCertDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain != filepath.Base(domain) {
		return "", fmt.Errorf("invalid domain")
	}
	if strings.Contains(domain, "/") || strings.Contains(domain, "\\") {
		return "", fmt.Errorf("invalid domain")
	}
	if domain == "" || domain == "." || domain == ".." {
		return "", fmt.Errorf("invalid domain")
	}
	return domain, nil
}

// Delete the cert if exists
func (m *Manager) RemoveCert(domain string) error {
	domain, err := sanitizeCertDomain(domain)
	if err != nil {
		return err
	}

	pubKey := filepath.Join(m.CertStore, domain+".pem")
	priKey := filepath.Join(m.CertStore, domain+".key")
	if utils.FileExists(pubKey) {
		err = os.Remove(pubKey)
		if err != nil {
			return err
		}
	}

	if utils.FileExists(priKey) {
		err = os.Remove(priKey)
		if err != nil {
			return err
		}
	}

	//Remove the ACME metadata of this certificate. A stale <name>.json would otherwise
	//override the challenge type of the next certificate issued under the same name
	infoFile := filepath.Join(m.CertStore, domain+".json")
	if utils.FileExists(infoFile) {
		if err = os.Remove(infoFile); err != nil {
			return err
		}
	}

	if m.OnCertRemoved != nil {
		m.OnCertRemoved(domain)
	}

	//Update the cert list
	m.UpdateLoadedCertList()
	return nil
}

// Check if the given file is a valid TLS file
func IsValidTLSFile(file io.Reader) bool {
	// Read the contents of the uploaded file
	contents, err := io.ReadAll(file)
	if err != nil {
		// Handle the error
		return false
	}

	// Parse the contents of the file as a PEM-encoded certificate or key
	block, _ := pem.Decode(contents)
	if block == nil {
		// The file is not a valid PEM-encoded certificate or key
		return false
	}

	// Parse the certificate or key
	if strings.Contains(block.Type, "CERTIFICATE") {
		// The file contains a certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Handle the error
			return false
		}
		// Check if the certificate is a valid TLS/SSL certificate
		return !cert.IsCA && cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 && cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0
	} else if strings.Contains(block.Type, "PRIVATE KEY") {
		// The file contains a private key
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return err == nil
	} else {
		return false
	}

}

// tmpFolder returns the configured temporary folder, or the default one
func (m *Manager) tmpFolder() string {
	if m.TmpFolder == "" {
		return DefaultTmpFolder
	}
	return m.TmpFolder
}
