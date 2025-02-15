package main

import (
	"testing"
)

// Test_parseURI tests the parseURI function.
func Test_parseURI(t *testing.T) {
	tests := []struct {
		name         string
		inputURI     string
		expectedURL  string
		expectedEnt  string
		expectedCACert string
		expectedCert string
		expectedKey  string
		expectErr    bool
	}{
		{
			name:        "Valid URI with entitlement",
			inputURI:    "katello://12345@myserver.com/path",
			expectedURL: "https://myserver.com/path",
			expectedEnt: "12345",
			expectedCACert: "/etc/rhsm/ca/katello-server-ca.pem",
			expectedCert: "/etc/pki/entitlement/12345.pem",
			expectedKey: "/etc/pki/entitlement/12345-key.pem",
			expectErr:   false,
		},
		{
			name:        "Valid URI without entitlement",
			inputURI:    "katello://myserver.com/path",
			expectedURL: "http://myserver.com/path",
			expectedEnt: "",
			expectedCACert: "",
			expectedCert: "",
			expectedKey: "",
			expectErr:   false,
		},
		{
			name:      "Invalid URI format",
			inputURI:  "http://myserver.com/path",
			expectErr: true,
		},
		{
			name:      "Invalid scheme",
			inputURI:  "ftp://myserver.com/path",
			expectErr: true,
		},
		{
			name:      "Empty URI",
			inputURI:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new instance of katelloMethod
			k := &katelloMethod{}

			// Step 1: Call parseURI()
			gotURL, err := k.parseURI(tt.inputURI)

			// Step 2: Check for expected error
			if (err != nil) != tt.expectErr {
				t.Errorf("parseURI() error = %v, wantErr %v", err, tt.expectErr)
				return
			}

			// Step 3: If error is expected, stop further checks
			if tt.expectErr {
				return
			}

			// Step 4: Validate the returned URL
			if gotURL != tt.expectedURL {
				t.Errorf("parseURI() got = %v, want %v", gotURL, tt.expectedURL)
			}

			// Step 5: Validate the stored entitlement
			if k.entitlement != tt.expectedEnt {
				t.Errorf("parseURI() entitlement = %v, want %v", k.entitlement, tt.expectedEnt)
			}

			// Step 6: Validate SSL certificate settings
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

