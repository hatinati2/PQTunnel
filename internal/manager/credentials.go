package manager

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

const (
	credentialDir      = "/etc/pqtunnel/pki"
	peerBundlePath     = "/var/lib/pqtunnel-manager/pqtunnel-dialer-bundle.zip"
	pkiCommandPath     = "/usr/local/sbin/pqtunnel-pki"
	maxPeerBundleBytes = 1 << 20
	maxCredentialBytes = 256 << 10
)

type dialerBundle struct {
	CACert     []byte
	ServerCert []byte
	ClientCert []byte
	ClientKey  []byte
	ServerName string
	PeerName   string
}

func credentialPath(name string) string { return filepath.Join(credentialDir, name) }

func (m *Controller) credentialStatus(cfg adminapi.TunnelConfiguration) (bool, string, bool) {
	bundleAvailable := false
	if m.role == RoleGateway {
		if data, err := readCredentialFile(peerBundlePath, true); err == nil && len(data) > 0 && len(data) <= maxPeerBundleBytes {
			bundleAvailable = true
		}
		caPEM, err := readCredentialFile(credentialPath("ca.crt"), false)
		if err != nil { return false, "Generate Gateway credentials before starting the tunnel.", bundleAvailable }
		serverPEM, err := readCredentialFile(credentialPath("server.crt"), false)
		if err != nil { return false, "Gateway server certificate is missing.", bundleAvailable }
		keyPEM, err := readCredentialFile(credentialPath("server.key"), true)
		if err != nil { return false, "Gateway server private key is missing or has unsafe permissions.", bundleAvailable }
		serverName, err := readCredentialText(credentialPath("server-name.txt"))
		if err != nil || !validServerName(serverName) { return false, "Gateway certificate identity metadata is missing or invalid.", bundleAvailable }
		peerName, err := readCredentialText(credentialPath("peer-name.txt"))
		if err != nil || !validPKIIdentity(peerName) { return false, "Expected peer identity metadata is missing or invalid.", bundleAvailable }
		if cfg.PeerIdentity != peerName { return false, "The peer identity in tunnel settings does not match the generated peer certificate.", bundleAvailable }
		if err := verifyCredentialSet(caPEM, serverPEM, keyPEM, nil, nil, serverName, "", ""); err != nil {
			return false, "Gateway certificates failed validation: " + err.Error(), bundleAvailable
		}
		return true, "Gateway credentials are installed and validated.", bundleAvailable
	}

	caPEM, err := readCredentialFile(credentialPath("ca.crt"), false)
	if err != nil { return false, "Import a peer bundle from a configured Gateway before starting the tunnel.", false }
	serverPEM, err := readCredentialFile(credentialPath("server.crt"), false)
	if err != nil { return false, "The imported Gateway server certificate is missing.", false }
	clientPEM, err := readCredentialFile(credentialPath("client.crt"), false)
	if err != nil { return false, "The imported Dialer client certificate is missing.", false }
	keyPEM, err := readCredentialFile(credentialPath("client.key"), true)
	if err != nil { return false, "The imported Dialer private key is missing or has unsafe permissions.", false }
	serverName, err := readCredentialText(credentialPath("server-name.txt"))
	if err != nil || !validServerName(serverName) || cfg.ServerName != serverName {
		return false, "The TLS server name must match the identity in the imported Gateway bundle.", false
	}
	peerName, err := readCredentialText(credentialPath("peer-name.txt"))
	if err != nil || !validPKIIdentity(peerName) { return false, "The imported peer identity metadata is missing or invalid.", false }
	if err := verifyCredentialSet(caPEM, serverPEM, nil, clientPEM, keyPEM, serverName, peerName, "dialer"); err != nil {
		return false, "Dialer credentials failed validation: " + err.Error(), false
	}
	return true, "Dialer credentials are installed and validated.", false
}

func readCredentialFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("credential is not a regular file")
	}
	perm := info.Mode().Perm()
	if perm&0022 != 0 || (private && perm&0077 != 0) {
		return nil, errors.New("credential permissions are unsafe")
	}
	if private && perm != 0600 { return nil, errors.New("private key must use mode 0600") }
	if info.Size() <= 0 || info.Size() > maxCredentialBytes { return nil, errors.New("credential size is invalid") }
	return os.ReadFile(path)
}

func readCredentialText(path string) (string, error) {
	data, err := readCredentialFile(path, false)
	if err != nil { return "", err }
	value := strings.TrimSpace(string(data))
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n\t /\\") {
		return "", errors.New("invalid credential metadata")
	}
	return value, nil
}

func validPKIIdentity(value string) bool {
	if len(value) < 1 || len(value) > 64 { return false }
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func parseCredentialCert(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifyCredentialSet(caPEM, serverPEM, serverKeyPEM, clientPEM, clientKeyPEM []byte, serverName, peerName, role string) error {
	ca, err := parseCredentialCert(caPEM)
	if err != nil { return errors.New("CA certificate is invalid") }
	if !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		time.Now().Before(ca.NotBefore) || !time.Now().Before(ca.NotAfter) {
		return errors.New("CA certificate is not currently valid for certificate signing")
	}
	serverCert, err := parseCredentialCert(serverPEM)
	if err != nil { return errors.New("server certificate is invalid") }
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := serverCert.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: time.Now(), DNSName: serverName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return errors.New("server certificate does not match the TLS name or configured CA")
	}
	if len(serverKeyPEM) > 0 {
		if _, err := tls.X509KeyPair(serverPEM, serverKeyPEM); err != nil {
			return errors.New("server private key does not match the server certificate")
		}
	}
	if len(clientPEM) > 0 || len(clientKeyPEM) > 0 {
		clientCert, err := parseCredentialCert(clientPEM)
		if err != nil { return errors.New("client certificate is invalid") }
		if clientCert.Subject.CommonName != peerName { return errors.New("client certificate identity does not match the bundle metadata") }
		if _, err := clientCert.Verify(x509.VerifyOptions{
			Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			return errors.New("client certificate does not validate for client authentication")
		}
		if _, err := tls.X509KeyPair(clientPEM, clientKeyPEM); err != nil {
			return errors.New("client private key does not match the client certificate")
		}
	}
	_ = role
	return nil
}

func createDialerBundle(files map[string][]byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	peerName := strings.TrimSpace(string(files["peer-name.txt"]))
	if !validPKIIdentity(peerName) { return nil, errors.New("invalid peer identity") }
	names := []string{"ca.crt", "server.crt", "server-name.txt", "peer-name.txt", "peer-" + peerName + ".crt", "peer-" + peerName + ".key"}
	for _, name := range names {
		data, ok := files[name]
		if !ok || len(data) == 0 || len(data) > maxCredentialBytes {
			_ = writer.Close()
			return nil, fmt.Errorf("missing or invalid bundle file: %s", name)
		}
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		entry, err := writer.CreateHeader(header)
		if err != nil { _ = writer.Close(); return nil, err }
		if _, err := entry.Write(data); err != nil { _ = writer.Close(); return nil, err }
	}
	if err := writer.Close(); err != nil { return nil, err }
	if buffer.Len() > maxPeerBundleBytes { return nil, errors.New("peer bundle exceeds the maximum size") }
	return buffer.Bytes(), nil
}

func parseDialerBundle(data []byte) (dialerBundle, error) {
	var out dialerBundle
	if len(data) == 0 || len(data) > maxPeerBundleBytes { return out, errors.New("bundle size must be between 1 byte and 1 MiB") }
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil { return out, errors.New("uploaded bundle is not a valid ZIP archive") }
	files := make(map[string][]byte, len(reader.File))
	for _, entry := range reader.File {
		if entry.FileInfo().IsDir() || entry.Name == "" || strings.ContainsAny(entry.Name, "/\\") ||
			entry.Name == "." || entry.Name == ".." || strings.Contains(entry.Name, "..") {
			return out, errors.New("bundle contains an unsafe path")
		}
		if _, exists := files[entry.Name]; exists { return out, errors.New("bundle contains duplicate filenames") }
		if entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > maxCredentialBytes {
			return out, errors.New("bundle contains an invalid or oversized file")
		}
		f, err := entry.Open()
		if err != nil { return out, errors.New("bundle could not be read") }
		content, readErr := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(content) == 0 || len(content) > maxCredentialBytes {
			return out, errors.New("bundle contains an invalid or oversized file")
		}
		files[entry.Name] = content
	}
	out.PeerName = strings.TrimSpace(string(files["peer-name.txt"]))
	out.ServerName = strings.TrimSpace(string(files["server-name.txt"]))
	if !validPKIIdentity(out.PeerName) || !validServerName(out.ServerName) { return out, errors.New("bundle metadata is invalid") }
	expected := map[string]bool{
		"ca.crt": true, "server.crt": true, "server-name.txt": true, "peer-name.txt": true,
		"peer-" + out.PeerName + ".crt": true, "peer-" + out.PeerName + ".key": true,
	}
	if len(files) != len(expected) { return out, errors.New("bundle contains unexpected files") }
	for name := range files {
		if !expected[name] { return out, errors.New("bundle contains unexpected files") }
	}
	out.CACert, out.ServerCert = files["ca.crt"], files["server.crt"]
	out.ClientCert, out.ClientKey = files["peer-"+out.PeerName+".crt"], files["peer-"+out.PeerName+".key"]
	if err := verifyCredentialSet(out.CACert, out.ServerCert, nil, out.ClientCert, out.ClientKey, out.ServerName, out.PeerName, "dialer"); err != nil {
		return dialerBundle{}, err
	}
	return out, nil
}

func (m *Controller) GenerateGatewayCredentials(ctx context.Context, serverName string) error {
	if m.role != RoleGateway { return errors.New("credential generation is available only on the Gateway panel") }
	if !validServerName(serverName) { return errors.New("server identity must be a valid DNS name or IP address") }
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() { return errors.New("another management operation is in progress") }
	defer m.speedRunMu.Unlock()
	state, _, err := m.readServiceState(ctx)
	if err != nil { return errors.New("the Gateway endpoint must be installed before generating credentials") }
	if state == "active" || state == "activating" { return errors.New("stop the tunnel service before generating credentials") }
	cfg, _, err := m.readConfiguration()
	if err != nil { return errors.New("configure the endpoint settings before generating credentials") }
	if !validPKIIdentity(cfg.PeerIdentity) {
		return errors.New("peer identity must contain 1-64 letters, digits, dots, underscores or hyphens")
	}
	for _, name := range []string{"ca.crt", "server.crt", "server.key", "server-name.txt", "peer-name.txt"} {
		if _, err := os.Lstat(credentialPath(name)); err == nil {
			return errors.New("Gateway credentials already exist; refusing to overwrite them")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("could not safely inspect existing Gateway credential files")
		}
	}
	if _, err := os.Lstat(peerBundlePath); err == nil {
		return errors.New("a Dialer bundle already exists; download and preserve it before trying again")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not safely inspect the existing Dialer bundle")
	}
	if err := os.MkdirAll(credentialDir, 0750); err != nil { return errors.New("could not prepare the protected credential directory") }
	dirInfo, err := os.Lstat(credentialDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential directory is not a safe directory")
	}
	work, err := os.MkdirTemp("/var/lib/pqtunnel-manager", "pki-work-")
	if err != nil { return errors.New("could not create a protected temporary PKI workspace") }
	_ = os.Chmod(work, 0700)
	defer os.RemoveAll(work)
	if _, err := m.runner.Run(ctx, pkiCommandPath, "init", "--out", work, "--server-name", serverName); err != nil {
		return errors.New("could not generate Gateway PKI material")
	}
	if _, err := m.runner.Run(ctx, pkiCommandPath, "issue-peer", "--out", work, "--name", cfg.PeerIdentity); err != nil {
		return errors.New("could not issue the Dialer peer certificate")
	}
	readWork := func(name string, private bool) ([]byte, error) {
		path := filepath.Join(work, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 { return nil, errors.New("generated PKI output is missing or unsafe") }
		if private && info.Mode().Perm() != 0600 { return nil, errors.New("generated private key does not have mode 0600") }
		if info.Size() <= 0 || info.Size() > maxCredentialBytes { return nil, errors.New("generated PKI output has an invalid size") }
		return os.ReadFile(path)
	}
	caPEM, err := readWork("ca.crt", false); if err != nil { return err }
	serverPEM, err := readWork("server.crt", false); if err != nil { return err }
	serverKeyPEM, err := readWork("server.key", true); if err != nil { return err }
	clientPEM, err := readWork("peer-"+cfg.PeerIdentity+".crt", false); if err != nil { return err }
	clientKeyPEM, err := readWork("peer-"+cfg.PeerIdentity+".key", true); if err != nil { return err }
	if err := verifyCredentialSet(caPEM, serverPEM, serverKeyPEM, clientPEM, clientKeyPEM, serverName, cfg.PeerIdentity, "dialer"); err != nil {
		return fmt.Errorf("generated credential validation failed: %w", err)
	}
	files := map[string][]byte{
		"ca.crt": caPEM, "server.crt": serverPEM, "server-name.txt": []byte(serverName + "\n"),
		"peer-name.txt": []byte(cfg.PeerIdentity + "\n"),
		"peer-"+cfg.PeerIdentity+".crt": clientPEM, "peer-"+cfg.PeerIdentity+".key": clientKeyPEM,
	}
	bundle, err := createDialerBundle(files)
	if err != nil { return errors.New("could not create the Dialer credential bundle") }
	toInstall := []struct { name string; data []byte; mode os.FileMode }{
		{"ca.crt", caPEM, 0644}, {"server.crt", serverPEM, 0644}, {"server.key", serverKeyPEM, 0600},
		{"server-name.txt", []byte(serverName + "\n"), 0644}, {"peer-name.txt", []byte(cfg.PeerIdentity + "\n"), 0644},
	}
	written := make([]string, 0, len(toInstall))
	for _, item := range toInstall {
		path := credentialPath(item.name)
		if err := atomicWrite(path, item.data, item.mode); err != nil {
			for _, old := range written { _ = os.Remove(old) }
			return errors.New("could not install the generated Gateway credentials")
		}
		written = append(written, path)
	}
	if err := atomicWrite(peerBundlePath, bundle, 0600); err != nil {
		for _, old := range written { _ = os.Remove(old) }
		return errors.New("could not save the Dialer bundle")
	}
	return nil
}

func (m *Controller) ExportDialerBundle() ([]byte, error) {
	if m.role != RoleGateway { return nil, errors.New("Dialer bundles are available only on the Gateway panel") }
	data, err := readCredentialFile(peerBundlePath, true)
	if err != nil { return nil, errors.New("no Dialer bundle is ready; generate Gateway credentials first") }
	if len(data) > maxPeerBundleBytes { return nil, errors.New("Dialer bundle exceeds the maximum size") }
	return data, nil
}

func (m *Controller) ImportDialerBundle(ctx context.Context, data []byte) error {
	if m.role != RoleDialer { return errors.New("credential import is available only on the Dialer panel") }
	bundle, err := parseDialerBundle(data)
	if err != nil { return err }
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.speedRunMu.TryLock() { return errors.New("another management operation is in progress") }
	defer m.speedRunMu.Unlock()
	state, _, err := m.readServiceState(ctx)
	if err != nil { return errors.New("the Dialer endpoint must be installed before importing credentials") }
	if state == "active" || state == "activating" { return errors.New("stop the tunnel service before importing credentials") }
	cfg, original, err := m.readConfiguration()
	if err != nil { return errors.New("configure the Dialer endpoint settings before importing credentials") }
	for _, name := range []string{"ca.crt", "server.crt", "client.crt", "client.key", "server-name.txt", "peer-name.txt"} {
		if _, err := os.Lstat(credentialPath(name)); err == nil {
			return errors.New("Dialer credential files already exist; refusing to overwrite them")
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("could not safely inspect existing Dialer credential files")
		}
	}
	cfg.ServerName = bundle.ServerName
	if cfg.ServerAddress == "192.0.2.1:8443" || cfg.ServerAddress == "" {
		cfg.ServerAddress = net.JoinHostPort(bundle.ServerName, "8443")
	}
	changes, err := m.configurationChanges(cfg)
	if err != nil { return fmt.Errorf("imported peer settings are incompatible with the current Dialer config: %w", err) }
	entries, err := parseEnvFile(original)
	if err != nil { return errors.New("current Dialer configuration uses unsupported syntax") }
	updated, err := updateEnvFile(original, entries, changes)
	if err != nil { return errors.New("could not prepare the Dialer config update") }
	state, _, err = m.readServiceState(ctx)
	if err != nil || state == "active" { return errors.New("could not verify that the Dialer service is stopped; no credentials were imported") }
	if err := m.writeBackup(original); err != nil { return errors.New("could not create the protected config backup") }
	if err := os.MkdirAll(credentialDir, 0750); err != nil { return errors.New("could not prepare the protected credential directory") }
	dirInfo, err := os.Lstat(credentialDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 { return errors.New("credential directory is not a safe directory") }
	toInstall := []struct { name string; data []byte; mode os.FileMode }{
		{"ca.crt", bundle.CACert, 0644}, {"server.crt", bundle.ServerCert, 0644},
		{"client.crt", bundle.ClientCert, 0644}, {"client.key", bundle.ClientKey, 0600},
		{"server-name.txt", []byte(bundle.ServerName + "\n"), 0644}, {"peer-name.txt", []byte(bundle.PeerName + "\n"), 0644},
	}
	written := make([]string, 0, len(toInstall))
	for _, item := range toInstall {
		path := credentialPath(item.name)
		if err := atomicWrite(path, item.data, item.mode); err != nil {
			for _, old := range written { _ = os.Remove(old) }
			return errors.New("could not install imported credential files")
		}
		written = append(written, path)
	}
	if err := atomicWrite(m.configPath, updated, os.FileMode(0640)); err != nil {
		for _, old := range written { _ = os.Remove(old) }
		return errors.New("could not write the Dialer configuration")
	}
	return nil
}
