package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"gopkg.in/ini.v1"
)

// pkgAcquireMethod provides a base structure similar to the Python class
type pkgAcquireMethod struct {
	eof bool
}

// NewPkgAcquireMethod initializes
func NewPkgAcquireMethod() *pkgAcquireMethod {
	return &pkgAcquireMethod{}
}

// getNextMsg parses messages from stdin similar to Apt’s protocol
func (p *pkgAcquireMethod) getNextMsg() (map[string]string, error) {
	if p.eof {
		return nil, nil
	}

	reader := bufio.NewReader(os.Stdin)
	result := make(map[string]string)

	// Read first meaningful line
	line, err := reader.ReadString('\n')
	for line == "\n" {
		line, err = reader.ReadString('\n')
	}
	if err != nil {
		p.eof = true
		return nil, err
	}

	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid message format")
	}
	result["_number"] = strings.TrimSpace(parts[0])
	result["_text"] = strings.TrimSpace(parts[1])

	// Read remaining headers
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			p.eof = true
			return result, err
		}
		if line == "\n" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, nil
}

// dictToMsg formats a dictionary as an HTTP-like message
func dictToMsg(msg map[string]string) string {
	var result strings.Builder
	for key, value := range msg {
		if value != "" {
			result.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	return result.String()
}

// status prints a status message
func (p *pkgAcquireMethod) status(msg map[string]string) {
	fmt.Println("102 Status\n" + dictToMsg(msg))
}

// uriStart signals the start of a URI fetch
func (p *pkgAcquireMethod) uriStart(msg map[string]string) {
	fmt.Println("200 URI Start\n" + dictToMsg(msg))
}

// uriDone signals the successful completion of a URI fetch
func (p *pkgAcquireMethod) uriDone(msg map[string]string) {
	fmt.Println("201 URI Done\n" + dictToMsg(msg))
}

// uriFailure signals a URI fetch failure
func (p *pkgAcquireMethod) uriFailure(msg map[string]string) {
	fmt.Println("400 URI Failure\n" + dictToMsg(msg))
}

// Run loops through requests on stdin
func (p *pkgAcquireMethod) Run() int {
	for {
		msg, err := p.getNextMsg()
		if err != nil || msg == nil {
			return 0
		}

		if msg["_number"] == "600" {
			km := NewKatelloMethod()
			err := km.Fetch(msg)
			if err != nil {
				km.Fail(err.Error())
			}
		} else {
			return 100
		}
	}
}

// katelloMethod extends pkgAcquireMethod with Katello-specific logic
type katelloMethod struct {
	*pkgAcquireMethod
	entitlement   string
	uri           string
	url           string
	filename      string
	notRegistered string
	sslCACert     string
	sslCert       string
	sslKey        string
}

// NewKatelloMethod initializes a new Katello method
func NewKatelloMethod() *katelloMethod {
	return &katelloMethod{
		pkgAcquireMethod: NewPkgAcquireMethod(),
		notRegistered:    "This system is not registered",
	}
}

// Fail handles failures
func (k *katelloMethod) Fail(message string) {
	k.uriFailure(map[string]string{"URI": k.uri, "Message": message})
}

// parseURI extracts entitlement and constructs the correct URL
func (k *katelloMethod) parseURI(uri string) (string, error) {
	re := regexp.MustCompile(`^katello://((?P<entitlement>.*?)@)?(?P<url>.*)$`)
	match := re.FindStringSubmatch(uri)
	if match == nil {
		return "", fmt.Errorf("protocol mismatch")
	}

	entitlement := match[2]
	k.entitlement = entitlement
	protocol := "http://"
	if entitlement != "" {
		protocol = "https://"
		k.sslCACert = "/etc/rhsm/ca/katello-server-ca.pem"
		k.sslCert = fmt.Sprintf("/etc/pki/entitlement/%s.pem", entitlement)
		k.sslKey = fmt.Sprintf("/etc/pki/entitlement/%s-key.pem", entitlement)
	}

	return protocol + match[3], nil
}

// Reads RHSM proxy configuration from `/etc/rhsm/rhsm.conf`
func getRhsmProxyConfig() (string, error) {
	cfg, err := ini.Load("/etc/rhsm/rhsm.conf")
	if err != nil {
		return "", fmt.Errorf("failed to read rhsm.conf: %v", err)
	}

	serverSection := cfg.Section("server")
	proxyHostname := serverSection.Key("proxy_hostname").String()
	if proxyHostname == "" {
		return "", nil // No proxy configured
	}

	proxyURL := &url.URL{
		Scheme: "http",
		Host:   proxyHostname,
	}

	if proxyScheme := serverSection.Key("proxy_scheme").String(); proxyScheme != "" {
		proxyURL.Scheme = proxyScheme
	}

	if proxyPort := serverSection.Key("proxy_port").String(); proxyPort != "" {
		proxyURL.Host = fmt.Sprintf("%s:%s", proxyHostname, proxyPort)
	}

	if proxyUser := serverSection.Key("proxy_user").String(); proxyUser != "" {
		if proxyPassword := serverSection.Key("proxy_password").String(); proxyPassword != "" {
			proxyURL.User = url.UserPassword(proxyUser, proxyPassword)
		} else {
			proxyURL.User = url.User(proxyUser)
		}
	}

	return proxyURL.String(), nil
}

// Fetch fetches a file from a remote server
func (k *katelloMethod) Fetch(msg map[string]string) error {
	k.uri = msg["URI"]
	k.url, _ = k.parseURI(msg["URI"])
	k.filename = msg["Filename"]

	// Load CA certificate
	caCert, err := os.ReadFile(k.sslCACert)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(k.sslCert, k.sslKey)
	if err != nil {
		return fmt.Errorf("failed to load client cert and key: %v", err)
	}

	// Create CA pool and add our CA certificate
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}

	// Get RHSM proxy configuration
	proxyURL, err := getRhsmProxyConfig()
	if err != nil {
		return fmt.Errorf("failed to get RHSM proxy config: %v", err)
	}

	// Create HTTP transport with TLS and proxy settings
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(parsedProxyURL)
	}

	// Create HTTP client with custom transport
	client := &http.Client{
		Transport: transport,
	}

	// Perform GET request
	resp, err := client.Get(k.url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	k.status(map[string]string{"URI": k.uri, "Message": "Waiting for headers"})

	if resp.StatusCode != 200 {
		k.uriFailure(map[string]string{
			"URI":        k.uri,
			"Message":    fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
			"FailReason": fmt.Sprintf("HttpError%d", resp.StatusCode),
		})
		return nil
	}

	// Start transfer
	k.uriStart(map[string]string{
		"URI":           k.uri,
		"Size":          resp.Header.Get("Content-Length"),
		"Last-Modified": resp.Header.Get("Last-Modified"),
	})

	// Save to file and compute hashes
	file, err := os.Create(k.filename)
	if err != nil {
		return err
	}
	defer file.Close()

	hashSHA256 := sha256.New()
	hashMD5 := md5.New()
	writer := io.MultiWriter(file, hashSHA256, hashMD5)

	_, err = io.Copy(writer, resp.Body)
	if err != nil {
		return err
	}

	// Report success
	k.uriDone(map[string]string{
		"URI":           k.uri,
		"Filename":      k.filename,
		"Size":          resp.Header.Get("Content-Length"),
		"Last-Modified": resp.Header.Get("Last-Modified"),
		"MD5-Hash":      hex.EncodeToString(hashMD5.Sum(nil)),
		"MD5Sum-Hash":   hex.EncodeToString(hashMD5.Sum(nil)),
		"SHA256-Hash":   hex.EncodeToString(hashSHA256.Sum(nil)),
	})
	return nil
}

func main() {
	// Handle KeyboardInterrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nInterrupted. Exiting...")
		os.Exit(0)
	}()

  fmt.Println("100 Capabilities\nVersion: 1.0\nSingle-Instance: true\n") //nolint:govet

	// Run the main method
	method := NewKatelloMethod()
	ret := method.Run()
	os.Exit(ret)
}
