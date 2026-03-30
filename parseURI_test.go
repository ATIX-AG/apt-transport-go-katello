package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func shortRepoHash(location string) string {
	sum := sha256.Sum256([]byte(location))
	return hex.EncodeToString(sum[:])[:16]
}

func hostFromLocation(location string) string {
	parts := strings.SplitN(location, "/", 2)
	return parts[0]
}

func buildAliasedKatelloURI(entitlement string, location string, repoID string, hash string, suffix string) string {
	if hash == "" {
		hash = shortRepoHash(location)
	}
	uri := fmt.Sprintf(
		"katello://%s;repopath=%s@%s/%s/%s",
		entitlement,
		url.QueryEscape(location),
		hostFromLocation(location),
		hash,
		repoID,
	)
	if suffix != "" {
		uri += "/" + suffix
	}
	return uri
}

func Test_parseURI(t *testing.T) {
	tests := []struct {
		name           string
		inputURI       string
		expectedURL    string
		expectedEnt    string
		expectedCACert string
		expectedCert   string
		expectedKey    string
		expectErr      bool
	}{
		{
			name: "Valid URI with repopath metadata",
			inputURI: buildAliasedKatelloURI(
				"7561127256828274694",
				"repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/",
				"Example-Saltstack-for-Debian-and-Ubuntu",
				"",
				"dists/default/Release",
			),
			expectedURL:    "https://repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/dists/default/Release",
			expectedEnt:    "7561127256828274694",
			expectedCACert: "/etc/rhsm/ca/katello-server-ca.pem",
			expectedCert:   "/etc/pki/entitlement/7561127256828274694.pem",
			expectedKey:    "/etc/pki/entitlement/7561127256828274694-key.pem",
			expectErr:      false,
		},
		{
			name: "Hash mismatch is accepted (no hash check)",
			inputURI: buildAliasedKatelloURI(
				"7561127256828274694",
				"repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/",
				"Example-Saltstack-for-Debian-and-Ubuntu",
				"deadbeefdeadbeef",
				"dists/default/Release",
			),
			expectedURL:    "https://repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/dists/default/Release",
			expectedEnt:    "7561127256828274694",
			expectedCACert: "/etc/rhsm/ca/katello-server-ca.pem",
			expectedCert:   "/etc/pki/entitlement/7561127256828274694.pem",
			expectedKey:    "/etc/pki/entitlement/7561127256828274694-key.pem",
			expectErr:      false,
		},
		{
			name: "Repo ID segment is ignored for URL reconstruction",
			inputURI: buildAliasedKatelloURI(
				"7561127256828274694",
				"repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/",
				"totally-different-repo-id",
				"",
				"dists/default/Release",
			),
			expectedURL:    "https://repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/dists/default/Release",
			expectedEnt:    "7561127256828274694",
			expectedCACert: "/etc/rhsm/ca/katello-server-ca.pem",
			expectedCert:   "/etc/pki/entitlement/7561127256828274694.pem",
			expectedKey:    "/etc/pki/entitlement/7561127256828274694-key.pem",
			expectErr:      false,
		},
		{
			name: "No alias suffix keeps repopath unchanged",
			inputURI: buildAliasedKatelloURI(
				"7561127256828274694",
				"repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/",
				"Example-Saltstack-for-Debian-and-Ubuntu",
				"",
				"",
			),
			expectedURL:    "https://repo-host.example/pulp/content/ORG/development/Saltstack_for_Debian_and_Ubuntu_RCV/short/01dscwjc/",
			expectedEnt:    "7561127256828274694",
			expectedCACert: "/etc/rhsm/ca/katello-server-ca.pem",
			expectedCert:   "/etc/pki/entitlement/7561127256828274694.pem",
			expectedKey:    "/etc/pki/entitlement/7561127256828274694-key.pem",
			expectErr:      false,
		},
		{
			name:           "Valid legacy format with entitlement",
			inputURI:       "katello://12345@myserver.com/path",
			expectedURL:    "https://myserver.com/path",
			expectedEnt:    "12345",
			expectedCACert: "/etc/rhsm/ca/katello-server-ca.pem",
			expectedCert:   "/etc/pki/entitlement/12345.pem",
			expectedKey:    "/etc/pki/entitlement/12345-key.pem",
			expectErr:      false,
		},
		{
			name:      "Invalid URI without userinfo",
			inputURI:  "katello://myserver.com/path",
			expectErr: true,
		},
		{
			name:      "Invalid URI with malformed repopath encoding",
			inputURI:  "katello://12345;repopath=%ZZ@myserver.com/5c0118de8cb1007/repo-id/dists/default/Release",
			expectErr: true,
		},
		{
			name:      "Invalid URI with extra userinfo section",
			inputURI:  "katello://12345;repopath=myserver.com%2Fpulp%2Fdeb%2Frepo;extra@myserver.com/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Invalid URI with empty metadata key",
			inputURI:  "katello://12345;=myserver.com%2Fpulp%2Fdeb%2Frepo@myserver.com/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Invalid URI with metadata missing equals",
			inputURI:  "katello://12345;repopath@myserver.com/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Invalid URI metadata without alias separator",
			inputURI:  "katello://12345;repopath=myserver.com%2Fpulp%2Fdeb%2Frepo",
			expectErr: true,
		},
		{
			name:      "Invalid URI with incomplete alias path",
			inputURI:  "katello://12345;repopath=myserver.com%2Fpulp%2Fdeb%2Frepo@myserver.com/5c0118de8cb1007",
			expectErr: true,
		},
		{
			name:      "Invalid URI with empty alias host",
			inputURI:  "katello://12345;repopath=myserver.com%2Fpulp%2Fdeb%2Frepo@/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Unsupported metadata field is rejected",
			inputURI:  "katello://12345;foo=bar@myserver.com/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Duplicate repopath metadata is rejected",
			inputURI:  "katello://12345;repopath=one;repopath=two@myserver.com/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Missing entitlement is rejected",
			inputURI:  "katello://;repopath=myserver.com%2Fpulp%2Fdeb%2Frepo@myserver.com/5c0118de8cb1007/repo-id",
			expectErr: true,
		},
		{
			name:      "Invalid scheme",
			inputURI:  "ftp://myserver.com/path",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &katelloMethod{}
			gotURL, err := k.parseURI(tt.inputURI)

			if (err != nil) != tt.expectErr {
				t.Errorf("parseURI() error = %v, wantErr %v", err, tt.expectErr)
				return
			}
			if tt.expectErr {
				return
			}

			if gotURL != tt.expectedURL {
				t.Errorf("parseURI() got = %v, want %v", gotURL, tt.expectedURL)
			}
			if k.entitlement != tt.expectedEnt {
				t.Errorf("parseURI() entitlement = %v, want %v", k.entitlement, tt.expectedEnt)
			}
			if k.sslCACert != tt.expectedCACert {
				t.Errorf("parseURI() sslCACert = %v, want %v", k.sslCACert, tt.expectedCACert)
			}
			if k.sslCert != tt.expectedCert {
				t.Errorf("parseURI() sslCert = %v, want %v", k.sslCert, tt.expectedCert)
			}
			if k.sslKey != tt.expectedKey {
				t.Errorf("parseURI() sslKey = %v, want %v", k.sslKey, tt.expectedKey)
			}
		})
	}
}
