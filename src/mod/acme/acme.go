// Package acme handles the acme issuing process
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/challenge/http01"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/utils"
)

var defaultNameservers = []string{
	"8.8.8.8:53", // Google DNS
	"8.8.4.4:53", // Google DNS
	"1.1.1.1:53", // Cloudflare DNS
	"1.0.0.1:53", // Cloudflare DNS
}

type CertificateInfoJSON struct {
	AcmeName                     string   `json:"acme_name"`                       // ACME provider name
	AcmeUrl                      string   `json:"acme_url"`                        // Custom ACME URL (if any)
	SkipTLS                      bool     `json:"skip_tls"`                        // Skip TLS verification of upstream
	UseDNS                       bool     `json:"dns"`                             // Use DNS challenge
	PropTimeout                  int      `json:"prop_time"`                       // Propagation timeout
	DNSServers                   []string `json:"dnsServers"`                      // DNS servers
	DisableRecursiveNssCheck     bool     `json:"disable_recursive_nss_check"`     // Disable Recursive NSs Propagation Check
	DisableAuthoritativeNssCheck bool     `json:"disable_authoritative_nss_check"` // Disable Authoritative NSs Propagation Check
	KeyType                      string   `json:"key_type,omitempty"`              // Key type the certificate was issued with (RSA2048, EC256 ...)
	AcmeProfile                  string   `json:"acme_profile,omitempty"`          // ACME profile requested from the CA
	CAProfileID                  string   `json:"ca_profile_id,omitempty"`         // Saved CA profile that issued this certificate, reused on renewal
	DNSProfileID                 string   `json:"dns_profile_id,omitempty"`        // Saved DNS credential profile used for the DNS challenge
	ManagedBy                    string   `json:"managed_by,omitempty"`            // "" / "acme" = issued here; "upload", "mapdir", "csr" = external, never auto renewed
	Source                       string   `json:"source,omitempty"`                // For managed_by=mapdir: the source path
	IssuedAt                     int64    `json:"issued_at,omitempty"`             // Unix time of the last issuance by ACME
}

type EABConfig struct {
	Kid     string `json:"kid"`
	HmacKey string `json:"HmacKey"`
}

// ACMEHandler handles ACME-related operations.
type ACMEHandler struct {
	Port           string
	Database       *database.Database
	Logger         *logger.Logger
	TestMode       bool
	KeyFileMode    os.FileMode
	PublicFileMode os.FileMode

	// CertStorePath is the folder certificates, keys and renew info are written to and
	// scanned from. Empty means DefaultCertStorePath. Set it from the -conf flag, a
	// hard coded ./conf/certs breaks installs that run with a custom config folder.
	CertStorePath string

	// issueMu serialises certificate issuance. The HTTP-01 challenge listener binds one
	// shared port, so concurrent obtain / renew requests would collide with
	// "address already in use" (upstream #1117).
	issueMu sync.Mutex
	// portMu protects Port, which may be re-picked when it was taken by someone else
	portMu sync.RWMutex
	// beforeIssue is a test hook run once the issuance lock is held; a non nil error aborts ObtainCert
	beforeIssue func() error

	// OnEvent, when set, is called after every issuance attempt (success or failure). It must not block for long.
	OnEvent func(CertEvent)
	// logSink, when set (guarded by issueMu), additionally receives every log line of the running operation
	logSink func(string)
}

// DefaultCertStorePath is used when ACMEHandler.CertStorePath is empty
const DefaultCertStorePath = "./conf/certs"

// certPath returns the path of a file in the certificate store
func (a *ACMEHandler) certPath(name string) string {
	base := a.CertStorePath
	if base == "" {
		base = DefaultCertStorePath
	}
	return filepath.Join(base, name)
}

// NewACME creates a new ACMEHandler instance.
func NewACME(
	port string, database *database.Database,
	logger *logger.Logger, testMode bool, keyFileMode os.FileMode, publicFileMode os.FileMode,
) *ACMEHandler {
	return &ACMEHandler{
		Port:           port,
		Database:       database,
		Logger:         logger,
		TestMode:       testMode,
		KeyFileMode:    keyFileMode,
		PublicFileMode: publicFileMode,
	}
}

func (a *ACMEHandler) Logf(message string, err error) {
	if a.logSink != nil {
		line := message
		if err != nil {
			line += ": " + err.Error()
		}
		a.logSink(line)
	}
	a.Logger.PrintAndLog("ACME", message, err)
}

// Close closes the ACMEHandler.
// ACME Handler does not need to close anything
// Function defined for future compatibility
func (a *ACMEHandler) Close() error {
	return nil
}

func (a *ACMEHandler) writeFileWithMode(filename string, data []byte, mode os.FileMode) error {
	err := os.WriteFile(filename, data, mode)
	if err != nil {
		return err
	}

	return os.Chmod(filename, mode)
}

// ObtainCert obtains a certificate for the specified domains.
// Only one issuance runs at a time: requests (manual clicks, auto renew, several names) queue up.
func (a *ACMEHandler) ObtainCert(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool) (bool, error) {
	return a.ObtainCertWithOptions(domains, certificateName, email, caName, caUrl, skipTLS, useDNS, propagationTimeout, dnsServers, disableRecursiveNssCheck, disableAuthoritativeNssCheck, ObtainOptions{})
}

// ObtainCertWithOptions is ObtainCert plus key type, ACME profile, saved CA profile and saved DNS profile selection.
func (a *ACMEHandler) ObtainCertWithOptions(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool, opts ObtainOptions) (bool, error) {
	a.issueMu.Lock()
	defer a.issueMu.Unlock()
	if a.beforeIssue != nil {
		if err := a.beforeIssue(); err != nil {
			return false, err
		}
	}
	return a.obtainAndNotify(domains, certificateName, email, caName, caUrl, skipTLS, useDNS, propagationTimeout, dnsServers, disableRecursiveNssCheck, disableAuthoritativeNssCheck, opts)
}

// ensureFreeChallengePort re-checks the HTTP-01 port right before use. The port is picked once
// at start-up, so something else (e.g. an outbound socket in the ephemeral range) may hold it by now.
func (a *ACMEHandler) ensureFreeChallengePort() {
	a.portMu.Lock()
	defer a.portMu.Unlock()
	port, err := strconv.Atoi(a.Port)
	if err == nil && !IsPortInUse(port) {
		return
	}
	for i := 0; i < 50; i++ {
		candidate := 30000 + int(time.Now().UnixNano()%30000) + i
		if candidate < 65535 && !IsPortInUse(candidate) {
			a.Logf("ACME challenge port "+a.Port+" is in use, switching to "+strconv.Itoa(candidate), nil)
			a.Port = strconv.Itoa(candidate)
			return
		}
	}
}

func (a *ACMEHandler) obtainCertLocked(domains []string, certificateName string, email string, caName string, caUrl string, skipTLS bool, useDNS bool, propagationTimeout int, dnsServers string, disableRecursiveNssCheck bool, disableAuthoritativeNssCheck bool, opts ObtainOptions) (bool, error) {
	ctx := context.TODO()

	// Values remembered from the previous issuance of this certificate (renewal keeps them)
	prevInfo, prevErr := LoadCertInfoJSON(a.certPath(certificateName + ".json"))
	if prevErr != nil {
		prevInfo = &CertificateInfoJSON{}
	}
	if opts.Profile == "" {
		opts.Profile = prevInfo.AcmeProfile
	}
	if opts.DNSProfileID == "" {
		opts.DNSProfileID = prevInfo.DNSProfileID
	}
	if _, kerr := NormalizeKeyType(opts.KeyType); kerr != nil {
		return false, kerr
	}
	keyTypeName := a.resolveKeyType(opts.KeyType, prevInfo.KeyType)
	legoKeyType, err := ParseKeyType(keyTypeName)
	if err != nil {
		return false, err
	}

	// A saved CA profile overrides the CA arguments
	var caProfile *CAProfile
	if opts.CAProfileID != "" {
		caProfile, err = a.GetCAProfile(opts.CAProfileID)
		if err != nil {
			return false, err
		}
		caName, caUrl = "custom", caProfile.DirectoryURL
		skipTLS = skipTLS || caProfile.SkipTLS
		if opts.Profile == "" {
			opts.Profile = caProfile.Profile
		}
	}

	a.Logf("Obtaining certificate for: "+strings.Join(domains, ", "), nil)

	// Resolve the CA directory URL before creating an account or config,
	// so we can check for an existing account before generating a new key.
	//
	// Fallback to Let's Encrypt if it is not set
	if caName == "" {
		caName = "Let's Encrypt"
	}

	// setup the custom ACME url endpoint.
	if caName == "custom" {
		a.Logf("Using Custom ACME "+caUrl+" for CA Directory URL", nil)
	} else if caUrl == "" {
		// if not custom ACME url, load it from ca.json
		caLinkOverwrite, err := loadCAApiServerFromName(caName, a.TestMode)
		if err == nil {
			caUrl = caLinkOverwrite
			a.Logf("Using "+caLinkOverwrite+" for CA Directory URL", nil)
		} else {
			caUrl, _ = loadCAApiServerFromName("Let's Encrypt", a.TestMode)
			a.Logf("Using Default ACME "+caUrl+" for CA Directory URL", nil)
		}
	} else {
		a.Logf("Using "+caUrl+" for CA Directory URL", nil)
	}

	// Reuse a previously registered ACME account for this CA if one is stored
	// in the database. Only generate a new account key if no stored account
	// is found.
	var adminUser ACMEUser
	accountLoaded := false
	if loadedKey, loadedReg, ok := a.loadACMEAccount(caUrl, email); ok {
		adminUser = ACMEUser{
			Email:        email,
			key:          loadedKey,
			Registration: loadedReg,
		}
		accountLoaded = true
		a.Logf("Reusing existing ACME account for "+caUrl, nil)
	} else {
		// generate private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			a.Logf("Private key generation failed", err)
			return false, err
		}
		// create a admin user for our new generation
		adminUser = ACMEUser{
			Email: email,
			key:   privateKey,
		}
	}

	// create config
	config := lego.NewConfig(&adminUser)
	config.CADirURL = caUrl

	// skip TLS verify if need
	// Ref: https://github.com/go-acme/lego/blob/6af2c756ac73a9cb401621afca722d0f4112b1b8/lego/client_config.go#L74
	if skipTLS {
		a.Logf("Ignoring TLS/SSL Verification Error for ACME Server", nil)
		config.HTTPClient.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	client, err := lego.NewClient(config)
	if err != nil {
		a.Logf("Failed to spawn new ACME client from current config", err)
		return false, err
	}

	// Load certificate info from JSON file
	certInfo, err := LoadCertInfoJSON(a.certPath(certificateName + ".json"))
	if err == nil {
		useDNS = certInfo.UseDNS
		if dnsServers == "" && certInfo.DNSServers != nil && len(certInfo.DNSServers) > 0 {
			dnsServers = strings.Join(certInfo.DNSServers, ",")
		}
		if certInfo.PropTimeout > 0 {
			propagationTimeout = certInfo.PropTimeout
		}
		if certInfo.DisableRecursiveNssCheck {
			disableRecursiveNssCheck = certInfo.DisableRecursiveNssCheck
		}
		if certInfo.DisableAuthoritativeNssCheck {
			disableAuthoritativeNssCheck = certInfo.DisableAuthoritativeNssCheck
		}
	}

	// Ensure at least one NSs propagation check is enabled
	// When disabling authoritative NSs check, recursive NSs check must stay enabled
	if disableAuthoritativeNssCheck && disableRecursiveNssCheck {
		a.Logf("DisableAuthoritativeNssCheck requires recursive NSs check to be enabled; forcing DisableRecursiveNssCheck = false", nil)
		disableRecursiveNssCheck = false
	}

	// Clean DNS servers
	dnsNameservers := strings.Split(dnsServers, ",")
	for i := range dnsNameservers {
		dnsNameservers[i] = strings.TrimSpace(dnsNameservers[i])
	}

	// setup how to receive challenge
	if useDNS {
		var dnsCredentials, dnsProvider string
		if opts.DNSProfileID == "" && !a.hasPerCertDNSCreds(certificateName) {
			// nothing configured for this certificate: fall back to the default credential profile, if any
			opts.DNSProfileID = a.DefaultDNSProfileID()
		}
		if opts.DNSProfileID != "" {
			dp, perr := a.GetDNSProfile(opts.DNSProfileID)
			if perr != nil {
				a.Logf("DNS credential profile lookup failed", perr)
				return false, perr
			}
			a.Logf("Using DNS credential profile "+dp.Name+" ("+dp.Provider+")", nil)
			dnsCredentials, dnsProvider = dp.Credentials, dp.Provider
			if dnsServers == "" && dp.DNSServers != "" {
				dnsNameservers = strings.Split(dp.DNSServers, ",")
				for i := range dnsNameservers {
					dnsNameservers[i] = strings.TrimSpace(dnsNameservers[i])
				}
			}
		} else {
			if !a.Database.TableExists("acme") {
				a.Database.NewTable("acme")
				return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -1)")
			}

			if !a.Database.KeyExists("acme", certificateName+"_dns_provider") || !a.Database.KeyExists("acme", certificateName+"_dns_credentials") {
				return false, errors.New("DNS Provider and DNS Credential configuration required for ACME Provider (Error -2)")
			}

			err := a.Database.Read("acme", certificateName+"_dns_credentials", &dnsCredentials)
			if err != nil {
				a.Logf("Read DNS credential failed", err)
				return false, err
			}

			err = a.Database.Read("acme", certificateName+"_dns_provider", &dnsProvider)
			if err != nil {
				a.Logf("Read DNS Provider failed", err)
				return false, err
			}
		}

		provider, err := GetDnsChallengeProviderByName(dnsProvider, dnsCredentials, propagationTimeout)
		if err != nil {
			a.Logf("Unable to resolve DNS challenge provider", err)
			return false, err
		}

		opts := &dns01.Options{}

		if len(dnsNameservers) > 0 && dnsNameservers[0] != "" {
			a.Logf("Using DNS servers: "+strings.Join(dnsNameservers, ", "), nil)
			opts.RecursiveNameservers = dnsNameservers
		} else {
			// Use default DNS-01 nameservers if dnsServers is empty
			opts.RecursiveNameservers = defaultNameservers
		}

		dns01.SetDefaultClient(dns01.NewClient(opts))

		dnsOpts := []dns01.ChallengeOption{}
		if disableRecursiveNssCheck {
			dnsOpts = append(dnsOpts, dns01.DisableRecursiveNSsPropagationRequirement())
		}
		if disableAuthoritativeNssCheck {
			dnsOpts = append(dnsOpts, dns01.DisableAuthoritativeNssPropagationRequirement())
		}
		err = client.Challenge.SetDNS01Provider(provider, dnsOpts...)
		if err != nil {
			a.Logf("Failed to resolve DNS01 Provider", err)
			return false, err
		}
	} else {
		a.ensureFreeChallengePort()
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", a.Getport()))
		if err != nil {
			a.Logf("Failed to resolve HTTP01 Provider", err)
			return false, err
		}
	}

	// New users will need to register
	/*
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Println(err)
			return false, err
		}
	*/
	var reg *acme.ExtendedAccount
	// New users will need to register. If we reused an account loaded from
	// disk, it is already registered - registering again would count against
	// the CA's "new registrations per IP" rate limit, so skip it entirely.
	if accountLoaded {
		reg = adminUser.Registration
	} else if client.GetServerMetadata().ExternalAccountRequired {
		a.Logf("External Account Required for this ACME Provider", nil)
		// IF KID and HmacEncoded is overidden

		var kid string
		var hmacEncoded string
		if caProfile != nil && caProfile.EABKid != "" {
			kid, hmacEncoded = caProfile.EABKid, caProfile.EABHmac
		} else {
			if !a.Database.TableExists("acme") {
				a.Database.NewTable("acme")
				return false, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -1)")
			}

			if !a.Database.KeyExists("acme", config.CADirURL+"_kid") || !a.Database.KeyExists("acme", config.CADirURL+"_hmacEncoded") {
				return false, errors.New("kid and HmacEncoded configuration required for ACME Provider (Error -2)")
			}

			err := a.Database.Read("acme", config.CADirURL+"_kid", &kid)
			if err != nil {
				a.Logf("Failed to read kid from database", err)
				return false, err
			}

			err = a.Database.Read("acme", config.CADirURL+"_hmacEncoded", &hmacEncoded)
			if err != nil {
				a.Logf("Failed to read HMAC from database", err)
				return false, err
			}
		}

		// Never log the HMAC key
		a.Logf("EAB credential retrieved (key id "+kid+")", nil)
		if kid != "" && hmacEncoded != "" {
			reg, err = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  kid,
				HmacEncoded:          hmacEncoded,
			})
		}
		if err != nil {
			a.Logf("Register with external account binder failed", err)
			return false, err
		}
		// return false, errors.New("External Account Required for this ACME Provider.")
	} else {
		reg, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			a.Logf("Unable to register client", err)
			return false, err
		}
	}
	adminUser.Registration = reg

	// Persist a freshly registered account so future certificate requests and
	// renewals reuse it instead of registering a brand new account each time.
	if !accountLoaded && reg != nil {
		if serr := a.saveACMEAccount(config.CADirURL, &adminUser); serr != nil {
			a.Logf("Failed to persist ACME account (may hit account create limits, try a different IP)", serr)
		} else {
			a.Logf("Persisted ACME account for reuse on "+config.CADirURL, nil)
		}
	}

	// obtain the certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
		KeyType: legoKeyType,
		Profile: opts.Profile,
	}

	certificates, err := client.Certificate.Obtain(ctx, request)
	if err != nil {
		a.Logf("Obtain certificate failed", err)
		return false, err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL.
	err = a.writeFileWithMode(a.certPath(certificateName+".pem"), certificates.Certificate, a.PublicFileMode)
	if err != nil {
		a.Logf("Failed to write public key to disk", err)
		return false, err
	}
	err = a.writeFileWithMode(a.certPath(certificateName+".key"), certificates.PrivateKey, a.KeyFileMode)
	if err != nil {
		a.Logf("Failed to write private key to disk", err)
		return false, err
	}

	// Save certificate's ACME info for renew usage
	certInfo = &CertificateInfoJSON{
		AcmeName:                     caName,
		AcmeUrl:                      caUrl,
		SkipTLS:                      skipTLS,
		UseDNS:                       useDNS,
		PropTimeout:                  propagationTimeout,
		DNSServers:                   dnsNameservers,
		DisableRecursiveNssCheck:     disableRecursiveNssCheck,
		DisableAuthoritativeNssCheck: disableAuthoritativeNssCheck,
		KeyType:                      keyTypeName,
		AcmeProfile:                  opts.Profile,
		CAProfileID:                  opts.CAProfileID,
		DNSProfileID:                 opts.DNSProfileID,
		ManagedBy:                    "acme",
		IssuedAt:                     time.Now().Unix(),
	}

	certInfoBytes, err := json.Marshal(certInfo)
	if err != nil {
		a.Logf("Marshal certificate renew config failed", err)
		return false, err
	}

	err = a.writeFileWithMode(a.certPath(certificateName+".json"), certInfoBytes, a.PublicFileMode)
	if err != nil {
		a.Logf("Failed to write certificate renew config to file", err)
		return false, err
	}

	return true, nil
}

// CheckCertificate returns a list of domains that are in expired certificates.
// It will return all domains that is in expired certificates
// *** if there is a vaild certificate contains the domain and there is a expired certificate contains the same domain
// it will said expired as well!
func (a *ACMEHandler) CheckCertificate() []string {
	// read from dir
	filenames, err := os.ReadDir(a.certPath(""))

	expiredCerts := []string{}

	if err != nil {
		a.Logf("Failed to load certificate folder", err)
		return []string{}
	}

	for _, filename := range filenames {
		certFilepath := a.certPath(filename.Name())

		certBytes, err := os.ReadFile(certFilepath)
		if err != nil {
			// Unable to load this file
			continue
		} else {
			// Cert loaded. Check its expiry time
			block, _ := pem.Decode(certBytes)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					elapsed := time.Since(cert.NotAfter)
					if elapsed > 0 {
						// if it is expired then add it in
						// make sure it's uniqueless
						for _, dnsName := range cert.DNSNames {
							if !contains(expiredCerts, dnsName) {
								expiredCerts = append(expiredCerts, dnsName)
							}
						}
						if !contains(expiredCerts, cert.Subject.CommonName) {
							expiredCerts = append(expiredCerts, cert.Subject.CommonName)
						}
					}
				}
			}
		}
	}

	return expiredCerts
}

// return the current port number
func (a *ACMEHandler) Getport() string {
	a.portMu.RLock()
	defer a.portMu.RUnlock()
	return a.Port
}

// contains checks if a string is present in a slice.
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// HandleGetExpiredDomains handles the HTTP GET request to retrieve the list of expired domains.
// It calls the CheckCertificate method to obtain the expired domains and sends a JSON response
// containing the list of expired domains.
func (a *ACMEHandler) HandleGetExpiredDomains(w http.ResponseWriter, r *http.Request) {
	type ExpiredDomains struct {
		Domain []string `json:"domain"`
	}

	info := ExpiredDomains{
		Domain: a.CheckCertificate(),
	}

	js, _ := json.MarshalIndent(info, "", " ")
	utils.SendJSONResponse(w, string(js))
}

// HandleRenewCertificate handles the HTTP GET request to renew a certificate for the provided domains.
// It retrieves the domains and filename parameters from the request, calls the ObtainCert method
// to renew the certificate, and sends a JSON response indicating the result of the renewal process.
func (a *ACMEHandler) HandleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	domainPara, err := utils.PostPara(r, "domains")

	// Clean each domain
	cleanedDomains := []string{}
	if domainPara != "" {
		for _, d := range strings.Split(domainPara, ",") {
			// Apply normalization on each domain
			nd, err := netutils.NormalizeDomain(d)
			if err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			cleanedDomains = append(cleanedDomains, nd)
		}
	}

	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}

	filename, err := utils.PostPara(r, "filename")
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}
	// Make sure the wildcard * do not goes into the filename
	filename = strings.ReplaceAll(filename, "*", "_")

	email, err := utils.PostPara(r, "email")
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}

	var caUrl string

	ca, err := utils.PostPara(r, "ca")
	if err != nil {
		a.Logf("CA not set. Using default", nil)
		ca, caUrl = "", ""
	}

	if ca == "custom" {
		caUrl, err = utils.PostPara(r, "caURL")
		if err != nil {
			a.Logf("Custom CA set but no URL provide, Using default", nil)
			ca, caUrl = "", ""
		}
	}

	if ca == "" {
		// default. Use Let's Encrypt
		ca = "Let's Encrypt"
	}

	skipTLS, _ := utils.PostBool(r, "skipTLS")
	dns, _ := utils.PostBool(r, "dns")

	// Default propagation timeout is 600 seconds (10 minutes)
	propagationTimeout := 600
	if dns {
		ppgTimeout, err := utils.PostPara(r, "ppgTimeout")
		if err == nil {
			propagationTimeout, err = strconv.Atoi(ppgTimeout)
			if err != nil {
				utils.SendErrorResponse(w, "Invalid propagation timeout value")
				return
			}
			if propagationTimeout < 60 {
				// Minimum propagation timeout is 60 seconds
				propagationTimeout = 60
			}
		}
	}

	// Extract SANs from existing PEM to ensure all domains are included
	pemPath := a.certPath(filename + ".pem")
	sanDomains, err := ExtractDomainsFromPEM(pemPath)
	if err == nil {
		// Merge domainPara + SANs
		domainSet := map[string]struct{}{}
		for _, d := range cleanedDomains {
			domainSet[d] = struct{}{}
		}
		for _, d := range sanDomains {
			domainSet[d] = struct{}{}
		}

		// Rebuild cleanedDomains with all unique domains
		cleanedDomains = []string{}
		for d := range domainSet {
			cleanedDomains = append(cleanedDomains, d)
		}

		a.Logf("Renewal domains including SANs from PEM: "+strings.Join(cleanedDomains, ","), nil)
	} else {
		a.Logf("Could not extract SANs from PEM, using domainPara only", err)
	}

	// Extract DNS servers from the request
	var dnsServers []string
	dnsServersPara, err := utils.PostPara(r, "dnsServers")
	if err == nil && dnsServersPara != "" {
		dnsServers = strings.Split(dnsServersPara, ",")
		for i := range dnsServers {
			dnsServers[i] = strings.TrimSpace(dnsServers[i])
		}
	}

	// Convert DNS servers slice to a single string
	dnsServersString := strings.Join(dnsServers, ",")

	// PostBool returns false if the key is missing or not a valid bool
	disableRecursiveNssCheck, _ := utils.PostBool(r, "disable_recursive_nss_check")
	disableAuthoritativeNssCheck, _ := utils.PostBool(r, "disable_authoritative_nss_check")

	opts := ObtainOptions{}
	opts.KeyType, _ = utils.PostPara(r, "keyType")
	opts.Profile, _ = utils.PostPara(r, "acmeProfile")
	opts.CAProfileID, _ = utils.PostPara(r, "caProfile")
	opts.DNSProfileID, _ = utils.PostPara(r, "dnsProfile")
	if _, kerr := NormalizeKeyType(opts.KeyType); kerr != nil {
		utils.SendErrorResponse(w, jsonEscape(kerr.Error()))
		return
	}

	result, err := a.ObtainCertWithOptions(cleanedDomains, filename, email, ca, caUrl, skipTLS, dns, propagationTimeout, dnsServersString, disableRecursiveNssCheck, disableAuthoritativeNssCheck, opts)
	if err != nil {
		utils.SendErrorResponse(w, jsonEscape(err.Error()))
		return
	}
	utils.SendJSONResponse(w, strconv.FormatBool(result))
}

// Escape JSON string
func jsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		// log.Println("Unable to escape json data: " + err.Error())
		return i
	}
	s := string(b)
	return s[1 : len(s)-1]
}

// Helper function to check if a port is in use
func IsPortInUse(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return true // Port is in use
	}
	defer listener.Close()
	return false // Port is not in use
}

// Load cert information from json file
func LoadCertInfoJSON(filename string) (*CertificateInfoJSON, error) {
	certInfoBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certInfo := &CertificateInfoJSON{}
	if err = json.Unmarshal(certInfoBytes, certInfo); err != nil {
		return nil, err
	}

	// Clean DNS servers
	for i := range certInfo.DNSServers {
		certInfo.DNSServers[i] = strings.TrimSpace(certInfo.DNSServers[i])
	}

	return certInfo, nil
}
