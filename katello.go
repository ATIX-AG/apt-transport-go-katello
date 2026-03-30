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
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
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
			fmt.Fprintf(&result, "%s: %s\n", key, value)
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
			debugf("run loop end: err=%v msg_nil=%t", err, msg == nil)
			return 0
		}
		debugf("run message: number=%q text=%q uri=%q file=%q", msg["_number"], msg["_text"], msg["URI"], msg["Filename"])

		if msg["_number"] == "600" {
			km := NewKatelloMethod()
			err := km.fetch(msg)
			if err != nil {
				debugf("fetch failed: uri=%q err=%v", km.uri, err)
				km.fail(err.Error())
			}
		} else {
			debugf("unexpected message number: %q", msg["_number"])
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
func (k *katelloMethod) fail(message string) {
	k.uriFailure(map[string]string{"URI": k.uri, "Message": message})
}

const (
	katelloURIPrefix      = "katello://"
	repoPathMetadataField = "repopath"
)

// parseKatelloUserInfo parses "<entitlement>;repopath=<encoded-repopath>".
func parseKatelloUserInfo(userInfo string) (string, string, error) {
	if userInfo == "" {
		return "", "", fmt.Errorf("missing katello user info")
	}
	userInfoSections := strings.SplitN(userInfo, ";", 3)
	if len(userInfoSections) != 2 {
		return "", "", fmt.Errorf("invalid katello user info format")
	}

	entitlementID := userInfoSections[0]
	if entitlementID == "" {
		return "", "", fmt.Errorf("missing entitlement ID in katello user info")
	}

	repoPathAssignment := userInfoSections[1]
	encodedRepoPath, hadPrefix := strings.CutPrefix(repoPathAssignment, repoPathMetadataField+"=")
	if !hadPrefix {
		return "", "", fmt.Errorf("invalid katello repo path assignment format: %q", repoPathAssignment)
	}
	if encodedRepoPath == "" {
		return "", "", fmt.Errorf("no repo path provided via: %q", repoPathAssignment)
	}

	return entitlementID, encodedRepoPath, nil
}

// parseAliasSuffix validates "<fqdn>/<hash>/<repo-id>[/<suffix>]" and returns only the optional suffix.
// in:  "repo.example/5c0118de8cb1007/Repo-Id"
// out: ""
// in:  "repo.example/5c0118de8cb1007/Repo-Id/dists/stable/Release"
// out: "/dists/stable/Release"
func parseAliasSuffix(location string) (string, error) {
	parts := strings.SplitN(location, "/", 4)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("invalid uri alias path")
	}

	if len(parts) == 3 {
		return "", nil
	}
	return "/" + parts[3], nil
}

// resolveAliasedLocation rebuilds the real backend path from alias location + decoded repopath.
// in:  location="repo.example/5c0118de8cb1007/Repo-Id", repoPath="repo.example/pulp/content/ORG/prod/repo/"
// out: "repo.example/pulp/content/ORG/prod/repo/"
// in:  location="repo.example/5c0118de8cb1007/Repo-Id/pool/main/a/app.deb", repoPath="repo.example/pulp/content/ORG/prod/repo/"
// out: "repo.example/pulp/content/ORG/prod/repo/pool/main/a/app.deb"
func resolveAliasedLocation(location string, repoPath string) (string, error) {
	if repoPath == "" {
		return "", fmt.Errorf("empty repopath")
	}

	suffix, err := parseAliasSuffix(location)
	if err != nil {
		return "", err
	}

	if suffix == "" {
		return repoPath, nil
	}
	return strings.TrimRight(repoPath, "/") + suffix, nil
}

// parseURI supports these formats:
// - New:    katello://<entitlement>;repopath=<url-encoded "<fqdn>/<full-path>">@<fqdn>/<hash16>/<readable-repo-id>
// - Legacy: katello://<entitlement>@<fqdn>/<full-path>
// For the new format, the alias part after '@' is used only to extract the apt-requested suffix.
func (k *katelloMethod) parseURI(uri string) (string, error) {
	debugf("parseURI in: %q", uri)
	if !strings.HasPrefix(uri, katelloURIPrefix) {
		return "", fmt.Errorf("protocol mismatch")
	}
	withoutPrefix := strings.TrimPrefix(uri, katelloURIPrefix)
	if withoutPrefix == "" {
		return "", fmt.Errorf("protocol mismatch")
	}

	userInfoAndLocation := strings.SplitN(withoutPrefix, "@", 3)
	if len(userInfoAndLocation) != 2 || userInfoAndLocation[0] == "" || userInfoAndLocation[1] == "" {
		return "", fmt.Errorf("invalid katello uri format")
	}
	userInfo := userInfoAndLocation[0]
	location := userInfoAndLocation[1]

	entitlement := userInfo
	if strings.Contains(userInfo, ";") {
		var encodedRepoPath string
		var err error
		entitlement, encodedRepoPath, err = parseKatelloUserInfo(userInfo)
		if err != nil {
			return "", err
		}

		repoPath, err := url.QueryUnescape(encodedRepoPath)
		if err != nil {
			return "", fmt.Errorf("invalid repopath encoding: %v", err)
		}
		debugf("parseURI decoded repopath: %q", repoPath)
		location, err = resolveAliasedLocation(location, repoPath)
		if err != nil {
			return "", err
		}
	}

	k.entitlement = entitlement
	protocol := "http://"
	if entitlement != "" {
		protocol = "https://"
		k.sslCACert = "/etc/rhsm/ca/katello-server-ca.pem"
		k.sslCert = fmt.Sprintf("/etc/pki/entitlement/%s.pem", entitlement)
		k.sslKey = fmt.Sprintf("/etc/pki/entitlement/%s-key.pem", entitlement)
	}

	resolved := protocol + location
	debugf("parseURI out: entitlement=%q resolved_url=%q", entitlement, resolved)
	return resolved, nil
}

// getRhsmProxyConfig reads /etc/rhsm/rhsm.conf and extracts proxy settings using regex
func getRhsmProxyConfig(configfile string) (proxyConfig string, err error) {
	file, err := os.Open(configfile)
	if err != nil {
		return "", fmt.Errorf("failed to read rhsm.conf: %v", err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close rhsm.conf: %v", closeErr)
		}
	}()

	// Define regex patterns to match proxy settings
	regexPatterns := map[string]*regexp.Regexp{
		"proxy_hostname": regexp.MustCompile(`^\s*proxy_hostname\s*=\s*(.+)\s*$`),
		"proxy_scheme":   regexp.MustCompile(`^\s*proxy_scheme\s*=\s*(.+)\s*$`),
		"proxy_port":     regexp.MustCompile(`^\s*proxy_port\s*=\s*(\d+)\s*$`),
		"proxy_user":     regexp.MustCompile(`^\s*proxy_user\s*=\s*(.+)\s*$`),
		"proxy_password": regexp.MustCompile(`^\s*proxy_password\s*=\s*(.+)\s*$`),
	}

	// Store extracted values
	config := map[string]string{}

	// Read file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue // Skip empty lines and comments
		}

		// Check for matching patterns
		for key, pattern := range regexPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 1 {
				config[key] = matches[1]
			}
		}
	}

	// Handle scanner errors
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading rhsm.conf: %v", err)
	}

	// Ensure proxy_hostname is set (otherwise, no proxy)
	proxyHostname, exists := config["proxy_hostname"]
	if !exists || proxyHostname == "" {
		debugf("proxy config: no proxy configured")
		return "", nil // No proxy configured
	}

	// Construct proxy URL
	proxyURL := &url.URL{
		Scheme: "http", // Default scheme
		Host:   proxyHostname,
	}

	// Override scheme if found
	if proxyScheme, ok := config["proxy_scheme"]; ok {
		proxyURL.Scheme = proxyScheme
	}

	// Append port if available
	if proxyPort, ok := config["proxy_port"]; ok {
		proxyURL.Host = fmt.Sprintf("%s:%s", proxyHostname, proxyPort)
	}

	// Append user credentials if available
	if proxyUser, ok := config["proxy_user"]; ok {
		if proxyPassword, ok := config["proxy_password"]; ok {
			proxyURL.User = url.UserPassword(proxyUser, proxyPassword)
		} else {
			proxyURL.User = url.User(proxyUser)
		}
	}

	result := proxyURL.String()
	debugf("proxy config resolved: %q", result)
	return result, nil
}

// ReadFile function that works in both Go 1.15 and later versions
func ReadFile(filename string) ([]byte, error) {
	// FIXME: use the os.ReadFile if everything is on Go 1.16+
	// return os.ReadFile(filename)

	// Go 1.15 and earlier (fallback to ioutil.ReadFile)
	return ioutil.ReadFile(filename)
}

// Fetch fetches a file from a remote server
func (k *katelloMethod) fetch(msg map[string]string) (err error) {
	k.uri = msg["URI"]
	k.url, err = k.parseURI(msg["URI"])
	if err != nil {
		return err
	}
	k.filename = msg["Filename"]
	debugf("fetch start: uri=%q url=%q file=%q", k.uri, k.url, k.filename)

	// Load CA certificate
	caCert, err := ReadFile(k.sslCACert)
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
	proxyURL, err := getRhsmProxyConfig("/etc/rhsm/rhsm.conf")
	if err != nil {
		return fmt.Errorf("failed to get RHSM proxy config: %v", err)
	}
	debugf("fetch proxy: %q", proxyURL)

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
	defer func() {
		closeErr := resp.Body.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close response body: %v", closeErr)
		}
	}()

	k.status(map[string]string{"URI": k.uri, "Message": "Waiting for headers"})
	debugf("fetch response: status=%d status_text=%q", resp.StatusCode, resp.Status)

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
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close output file %q: %v", k.filename, closeErr)
		}
	}()

	hashSHA256 := sha256.New()
	hashMD5 := md5.New()
	writer := io.MultiWriter(file, hashSHA256, hashMD5)

	written, err := io.Copy(writer, resp.Body)
	if err != nil {
		return err
	}
	debugf("fetch copied bytes: %d", written)

	md5Hash := hex.EncodeToString(hashMD5.Sum(nil))
	sha256Hash := hex.EncodeToString(hashSHA256.Sum(nil))

	// Report success
	k.uriDone(map[string]string{
		"URI":           k.uri,
		"Filename":      k.filename,
		"Size":          resp.Header.Get("Content-Length"),
		"Last-Modified": resp.Header.Get("Last-Modified"),
		"MD5-Hash":      md5Hash,
		"MD5Sum-Hash":   md5Hash,
		"SHA256-Hash":   sha256Hash,
	})
	debugf("fetch done: md5=%s sha256=%s", md5Hash, sha256Hash)
	return nil
}

func main() {
	debugf("method startup")

	// Handle KeyboardInterrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		debugf("interrupt received")
		fmt.Println("\nInterrupted. Exiting...")
		os.Exit(0)
	}()

	output := "100 Capabilities\n" +
		"Version: 1.0\n" +
		"Single-Instance: true\n"
	fmt.Println(output)

	// Run the main method
	method := NewKatelloMethod()
	ret := method.Run()
	debugf("method exit code: %d", ret)
	os.Exit(ret)
}
