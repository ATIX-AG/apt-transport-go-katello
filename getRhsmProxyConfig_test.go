package main

import (
	"os"
	"testing"
)

// createTempRhsmConfig creates a temporary rhsm.conf file for testing.
func createTempRhsmConfig(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "rhsm.conf")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(content)
	if err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

// Test_getRhsmProxyConfig tests the getRhsmProxyConfig function.
func Test_getRhsmProxyConfig(t *testing.T) {
	tests := []struct {
		name       string
		configData string
		want       string
		wantErr    bool
	}{
		{
			name: "Valid Proxy Config",
			configData: `
			[server]
			hostname = subscription.rhsm.redhat.com

			[proxy]
			proxy_hostname = proxy.example.com
			proxy_scheme = https
			proxy_port = 8080
			proxy_user = admin
			proxy_password = secret123
			`,
			want: "https://admin:secret123@proxy.example.com:8080",
		},
		{
			name: "No Proxy Configured",
			configData: `
			[server]
			hostname = subscription.rhsm.redhat.com
			`,
			want: "",
		},
		{
			name: "Proxy Without User and Password",
			configData: `
			[proxy]
			proxy_hostname = proxy.example.com
			proxy_port = 3128
			`,
			want: "http://proxy.example.com:3128",
		},
		{
			name: "Proxy Without Port",
			configData: `
			[proxy]
			proxy_hostname = proxy.example.com
			`,
			want: "http://proxy.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file with config data
			filePath, err := createTempRhsmConfig(tt.configData)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(filePath) // Cleanup temp file

			got, err := getRhsmProxyConfig(filePath)

			if (err != nil) != tt.wantErr {
				t.Errorf("getRhsmProxyConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getRhsmProxyConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

