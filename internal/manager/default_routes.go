package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/hatinati2/PQTunnel/internal/adminapi"
)

const defaultRouteApprovalPath = "/var/lib/pqtunnel-manager/default-route-approval"

func defaultRoutePrefixes(role Role, cfg adminapi.TunnelConfiguration) string {
	if role == RoleGateway {
		return cfg.LocalPrefixes
	}
	return cfg.RemotePrefixes
}

func requiresDefaultRouteReview(role Role, cfg adminapi.TunnelConfiguration) bool {
	prefixes, err := parseCanonicalPrefixesWithDefault(defaultRoutePrefixes(role, cfg), true)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

func defaultRouteApprovalDigest(role Role, cfg adminapi.TunnelConfiguration) string {
	// Bind the approval to the full endpoint configuration, including the port
	// allowlist. Any later edit invalidates the old approval automatically.
	value := string(role) + "\x00" +
		cfg.ListenAddress + "\x00" +
		cfg.PeerPrefixes + "\x00" +
		cfg.LocalPrefixes + "\x00" +
		cfg.PeerIdentity + "\x00" +
		cfg.ServerAddress + "\x00" +
		cfg.ServerName + "\x00" +
		cfg.RemotePrefixes + "\x00" +
		cfg.AllowedDstPorts
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (m *Controller) defaultRoutesApproved(cfg adminapi.TunnelConfiguration) bool {
	if !requiresDefaultRouteReview(m.role, cfg) {
		return true
	}
	info, err := os.Lstat(defaultRouteApprovalPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return false
	}
	data, err := os.ReadFile(defaultRouteApprovalPath)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == defaultRouteApprovalDigest(m.role, cfg)
}

func (m *Controller) saveDefaultRouteApproval(cfg adminapi.TunnelConfiguration, allowed bool) error {
	if !requiresDefaultRouteReview(m.role, cfg) {
		err := os.Remove(defaultRouteApprovalPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("could not clear the old default-route approval")
		}
		return nil
	}
	if !allowed {
		if m.defaultRoutesApproved(cfg) {
			return nil
		}
		return errors.New("default-route prefixes require explicit confirmation in the settings form")
	}
	if info, err := os.Lstat(filepath.Dir(defaultRouteApprovalPath)); err != nil ||
		!info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("manager state directory is missing or has unsafe permissions")
	}
	return atomicWrite(defaultRouteApprovalPath, []byte(defaultRouteApprovalDigest(m.role, cfg)+"\n"), 0600)
}
