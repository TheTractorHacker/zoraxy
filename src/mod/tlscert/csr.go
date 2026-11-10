package tlscert

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v5/certcrypto"
	"imuslab.com/zoraxy/mod/acme"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	csr.go

	Certificate signing requests for internal / enterprise CAs (upstream #433).

	A request creates a private key and a CSR. The key never leaves the server: it is kept
	with mode 0600 in <certstore>/pending-csr/ (a sub folder, so it is never loaded as a
	certificate) until the issued certificate is uploaded and verified against it. Then the pair
	moves to the certificate store as <name>.pem / <name>.key with metadata managed_by=csr
	(never auto renewed).
*/

const pendingCSRFolder = "pending-csr"

// CSRRequest are the user supplied parameters of a new CSR.
type CSRRequest struct {
	CommonName   string   `json:"commonName"`
	SANs         []string `json:"sans"` // DNS names (wildcards allowed) or IP addresses
	KeyType      string   `json:"keyType"`
	Organization string   `json:"organization"`
	OrgUnit      string   `json:"orgUnit"`
	Country      string   `json:"country"`
	State        string   `json:"state"`
	Locality     string   `json:"locality"`
	Name         string   `json:"name"` // store name of the certificate once issued; default derived from the common name
}

// PendingCSR is the metadata saved next to a pending key.
type PendingCSR struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Created time.Time  `json:"created"`
	Request CSRRequest `json:"request"`
}

var storeNameRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var pendingIDRegex = regexp.MustCompile(`^[a-f0-9]{16}$`)

// StoreNameFromDomain converts a domain (possibly wildcard) to a certificate store name.
func StoreNameFromDomain(domain string) string {
	d := strings.TrimSpace(domain)
	if strings.HasPrefix(d, "*") {
		d = "_" + strings.TrimPrefix(d, "*")
	}
	d = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, d)
	d = strings.TrimLeft(d, ".-")
	if len(d) > 128 {
		d = d[:128]
	}
	return d
}

func (m *Manager) pendingDir() string { return filepath.Join(m.CertStore, pendingCSRFolder) }

func (m *Manager) pendingPath(id, ext string) string {
	return filepath.Join(m.pendingDir(), id+ext)
}

func marshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// GenerateCSR creates the key and CSR, stores the pending request and returns it with the CSR PEM.
func (m *Manager) GenerateCSR(req CSRRequest) (*PendingCSR, []byte, error) {
	req.CommonName = strings.TrimSpace(req.CommonName)
	if req.CommonName == "" {
		return nil, nil, errors.New("common name is required")
	}
	kt, err := acme.ParseKeyType(req.KeyType)
	if err != nil {
		return nil, nil, err
	}
	req.KeyType, _ = acme.NormalizeKeyType(req.KeyType)
	if req.KeyType == "" {
		req.KeyType = acme.DefaultKeyType
	}

	var dnsNames []string
	var ips []net.IP
	sans := append([]string{}, req.SANs...)
	nameKind := "subject alternative name"
	if len(sans) == 0 {
		sans = []string{req.CommonName}
		nameKind = "common name" // no alternative names given: the common name is what is being checked
	}
	cleaned := []string{}
	for _, s := range sans {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			if strings.ContainsAny(s, " /\\@:") {
				return nil, nil, fmt.Errorf("invalid %s %q", nameKind, truncateForError(s))
			}
			dnsNames = append(dnsNames, strings.ToLower(s))
		}
		cleaned = append(cleaned, s)
	}
	req.SANs = cleaned

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = StoreNameFromDomain(req.CommonName)
	}
	if !storeNameRegex.MatchString(name) {
		return nil, nil, errors.New("invalid certificate name (letters, digits, dot, dash, underscore)")
	}
	req.Name = name

	subject := pkix.Name{CommonName: req.CommonName}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrgUnit != "" {
		subject.OrganizationalUnit = []string{req.OrgUnit}
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}
	if req.State != "" {
		subject.Province = []string{req.State}
	}
	if req.Locality != "" {
		subject.Locality = []string{req.Locality}
	}

	key, err := certcrypto.GeneratePrivateKey(kt)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, DNSNames: dnsNames, IPAddresses: ips,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyPEM, err := marshalPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	idb := make([]byte, 8)
	rand.Read(idb)
	pending := &PendingCSR{ID: hex.EncodeToString(idb), Name: name, Created: time.Now().UTC(), Request: req}

	if err := os.MkdirAll(m.pendingDir(), 0o700); err != nil {
		return nil, nil, err
	}
	meta, _ := json.MarshalIndent(pending, "", " ")
	for _, f := range []struct {
		ext  string
		data []byte
		mode os.FileMode
	}{{".key", keyPEM, 0o600}, {".csr", csrPEM, 0o644}, {".json", meta, 0o600}} {
		if err := os.WriteFile(m.pendingPath(pending.ID, f.ext), f.data, f.mode); err != nil {
			m.RemovePendingCSR(pending.ID)
			return nil, nil, err
		}
		os.Chmod(m.pendingPath(pending.ID, f.ext), f.mode)
	}
	return pending, csrPEM, nil
}

// ListPendingCSRs returns pending requests, newest first.
func (m *Manager) ListPendingCSRs() []*PendingCSR {
	list := []*PendingCSR{}
	entries, err := os.ReadDir(m.pendingDir())
	if err != nil {
		return list
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.pendingDir(), e.Name()))
		if err != nil {
			continue
		}
		var p PendingCSR
		if json.Unmarshal(b, &p) == nil && pendingIDRegex.MatchString(p.ID) {
			list = append(list, &p)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.After(list[j].Created) })
	return list
}

// ReadCSR returns the CSR PEM of a pending request.
func (m *Manager) ReadCSR(id string) ([]byte, error) {
	if !pendingIDRegex.MatchString(id) {
		return nil, errors.New("invalid request id")
	}
	return os.ReadFile(m.pendingPath(id, ".csr"))
}

// RemovePendingCSR deletes a pending request and its key.
func (m *Manager) RemovePendingCSR(id string) error {
	if !pendingIDRegex.MatchString(id) {
		return errors.New("invalid request id")
	}
	var firstErr error
	for _, ext := range []string{".key", ".csr", ".json"} {
		if err := os.Remove(m.pendingPath(id, ext)); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// parseCertChain returns all certificates of a PEM bundle (leaf first as given).
func parseCertChain(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unparsable certificate in bundle: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return certs, nil
}

// sameKey tells whether a public key equals the public half of a private key.
func sameKey(pub any, priv crypto.PrivateKey) bool {
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return false
	}
	a, err1 := x509.MarshalPKIXPublicKey(pub)
	b, err2 := x509.MarshalPKIXPublicKey(signer.Public())
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}

// namesCovered returns the requested names the certificate does not cover.
func namesCovered(cert *x509.Certificate, requested []string) []string {
	var missing []string
	for _, n := range requested {
		if ip := net.ParseIP(n); ip != nil {
			if cert.VerifyHostname(n) != nil {
				missing = append(missing, n)
			}
			continue
		}
		covered := false
		for _, have := range cert.DNSNames {
			if strings.EqualFold(have, n) {
				covered = true
			}
		}
		if !covered {
			missing = append(missing, n)
		}
	}
	return missing
}

// CompleteCSR pairs an issued certificate with the pending key and installs it in the store.
// The leaf certificate must match the key and cover the requested names (unless force) and must not
// be expired. An existing certificate of the same name is only replaced when overwrite is set.
func (m *Manager) CompleteCSR(id string, certPEM []byte, force bool, overwrite bool) (string, error) {
	if !pendingIDRegex.MatchString(id) {
		return "", errors.New("invalid request id")
	}
	metaBytes, err := os.ReadFile(m.pendingPath(id, ".json"))
	if err != nil {
		return "", errors.New("pending request not found")
	}
	var pending PendingCSR
	if err := json.Unmarshal(metaBytes, &pending); err != nil {
		return "", err
	}
	keyPEM, err := os.ReadFile(m.pendingPath(id, ".key"))
	if err != nil {
		return "", errors.New("the private key of this request is missing")
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", errors.New("the stored private key is unreadable")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	chain, err := parseCertChain(certPEM)
	if err != nil {
		return "", err
	}
	leaf := chain[0]
	if !sameKey(leaf.PublicKey, priv) {
		return "", errors.New("the certificate does not match the private key of this request (the first certificate in the file must be the issued leaf)")
	}
	if time.Now().After(leaf.NotAfter) {
		return "", errors.New("the certificate is expired")
	}
	if !force {
		if missing := namesCovered(leaf, pending.Request.SANs); len(missing) > 0 {
			return "", fmt.Errorf("the certificate does not cover the requested names: %s", strings.Join(missing, ", "))
		}
	}

	name := pending.Name
	if !storeNameRegex.MatchString(name) {
		return "", errors.New("invalid certificate name")
	}
	pemPath := filepath.Join(m.CertStore, name+".pem")
	if utils.FileExists(pemPath) && !overwrite {
		return "", fmt.Errorf("a certificate named %q already exists in the store", name)
	}

	// key first, certificate last: the pair is only usable once both exist
	if err := writeFileWithMode(m.CertStore, name+".key", keyPEM, defaultPrivateKeyFileMode); err != nil {
		return "", err
	}
	if err := writeFileWithMode(m.CertStore, name+".pem", certPEM, defaultPublicCertFileMode); err != nil {
		return "", err
	}
	info := &acme.CertificateInfoJSON{ManagedBy: "csr", KeyType: pending.Request.KeyType, AcmeName: leaf.Issuer.CommonName}
	if err := acme.SaveCertInfoJSON(filepath.Join(m.CertStore, name+".json"), info, defaultPublicCertFileMode); err != nil {
		return "", err
	}
	m.RemovePendingCSR(id)
	m.UpdateLoadedCertList()
	return name, nil
}

// HandleCSR serves /api/cert/csr
//
//	GET                       list pending requests
//	GET  id=<id>&download=1   download the CSR (PEM)
//	POST op=generate          commonName, sans (comma/newline separated), keyType, name, O/OU/C/ST/L
//	POST op=complete          id, cert (PEM text), force, overwrite
//	POST op=delete            id
func (m *Manager) HandleCSR(w http.ResponseWriter, r *http.Request) {
	fail := func(err error) { utils.SendErrorResponse(w, strings.ReplaceAll(err.Error(), `"`, `'`)) }
	if r.Method == http.MethodGet {
		if dl, _ := utils.GetBool(r, "download"); dl {
			id, _ := utils.GetPara(r, "id")
			csr, err := m.ReadCSR(id)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.csr"`)
			w.Write(csr)
			return
		}
		js, _ := json.Marshal(map[string]any{"pending": m.ListPendingCSRs(), "keyTypes": acme.KeyTypeNames})
		utils.SendJSONResponse(w, string(js))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	op, _ := utils.PostPara(r, "op")
	switch op {
	case "generate":
		req := CSRRequest{}
		req.CommonName, _ = utils.PostPara(r, "commonName")
		req.KeyType, _ = utils.PostPara(r, "keyType")
		req.Name, _ = utils.PostPara(r, "name")
		req.Organization, _ = utils.PostPara(r, "organization")
		req.OrgUnit, _ = utils.PostPara(r, "orgUnit")
		req.Country, _ = utils.PostPara(r, "country")
		req.State, _ = utils.PostPara(r, "state")
		req.Locality, _ = utils.PostPara(r, "locality")
		sans, _ := utils.PostPara(r, "sans")
		req.SANs = strings.FieldsFunc(sans, func(c rune) bool { return c == ',' || c == '\n' || c == '\r' || c == ' ' })
		pending, csr, err := m.GenerateCSR(req)
		if err != nil {
			fail(err)
			return
		}
		js, _ := json.Marshal(map[string]any{"id": pending.ID, "name": pending.Name, "csr": string(csr)})
		utils.SendJSONResponse(w, string(js))
	case "complete":
		id, _ := utils.PostPara(r, "id")
		certPEM, _ := utils.PostPara(r, "cert")
		force, _ := utils.PostBool(r, "force")
		overwrite, _ := utils.PostBool(r, "overwrite")
		name, err := m.CompleteCSR(id, []byte(certPEM), force, overwrite)
		if err != nil {
			fail(err)
			return
		}
		js, _ := json.Marshal(map[string]string{"name": name})
		utils.SendJSONResponse(w, string(js))
	case "delete":
		id, _ := utils.PostPara(r, "id")
		if err := m.RemovePendingCSR(id); err != nil {
			fail(err)
			return
		}
		utils.SendOK(w)
	default:
		utils.SendErrorResponse(w, "invalid operation")
	}
}

// truncateForError keeps a user supplied value short enough to quote in an error message.
func truncateForError(s string) string {
	if r := []rune(s); len(r) > 60 {
		return string(r[:60]) + "..."
	}
	return s
}
