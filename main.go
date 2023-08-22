package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/skratchdot/open-golang/open"
)

type vaultOidcAuth struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		AuthURL string `json:"auth_url"`
	} `json:"data"`
	WrapInfo any `json:"wrap_info"`
	Warnings any `json:"warnings"`
	Auth     any `json:"auth"`
}

type vaultLogin struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		Metadata      struct {
			Username string `json:"username"`
		} `json:"metadata"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		EntityID      string `json:"entity_id"`
		TokenType     string `json:"token_type"`
		Orphan        bool   `json:"orphan"`
	} `json:"auth"`
}

type authObject struct {
	Addr           string `json:"addr"`
	Namespace      string `json:"namespace"`
	OidcMountName  string `json:"auth_path"`
	Role           string `json:"auth_role"`
	Insecure       bool   `json:"insecure"`
	RedirectURI    string `json:"redirect_uri"`
	CallbackPath   string `json:"callback_path"`
	AuthUrlReqPath string `json:"url_path"`
	LocalState     string `json:"local_state"`
	LocalNonce     string `json:"local_nonce"`
	AuthUrl        string `json:"auth_url"`
	Token          string `json:"token"`
	RemoteCode     string `json:"remote_code"`
	RemoteState    string `json:"remote_state"`
	AppRoleMount   string `json:"app_role_mount"`
	AppRoleName    string `json:"app_role_name"`
	AppRoleTTL     string `json:"app_role_ttl"`
}

type SecretIDResponse struct {
	RequestID     string `json:"request_id"`
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		SecretID         string `json:"secret_id"`
		SecretIDAccessor string `json:"secret_id_accessor"`
		SecretIDNumUses  int    `json:"secret_id_num_uses"`
		SecretIDTTL      int    `json:"secret_id_ttl"`
	} `json:"data"`
	WrapInfo any `json:"wrap_info"`
	Warnings any `json:"warnings"`
	Auth     any `json:"auth"`
}

func main() {

	var vaultAddr string
	fmt.Print("Vault Address [https://vault-test.cso.att.com:8200]: ")
	fmt.Scanln(&vaultAddr)
	if vaultAddr == "" {
		vaultAddr = "https://vault-test.cso.att.com:8200"
	}

	var vaultNamespace string
	fmt.Print("Vault Namespace [5GMobility]: ")
	fmt.Scanln(&vaultNamespace)
	if vaultNamespace == "" {
		vaultNamespace = "5GMobility"
	}

	var oidcMountName string
	fmt.Print("OIDC Auth Method Name [oidc]: ")
	fmt.Scanln(&oidcMountName)
	if oidcMountName == "" {
		oidcMountName = "oidc"
	}

	var appRoleMount string
	fmt.Print("App Role Mount Path [5g/approle]: ")
	fmt.Scanln(&appRoleMount)
	if appRoleMount == "" {
		appRoleMount = "5g/approle"
	}

	var appRoleName string
	fmt.Print("App Role Mount Path [auth.demo.role]: ")
	fmt.Scanln(&appRoleName)
	if appRoleName == "" {
		appRoleName = "auth.demo.role"
	}

	var appRoleTTL string
	fmt.Print("App Role Mount Path [30s]: ")
	fmt.Scanln(&appRoleTTL)
	if appRoleTTL == "" {
		appRoleTTL = "30s"
	}

	oidcAuthMethodPath := fmt.Sprintf("auth/%s/oidc", oidcMountName)

	// parse vault URL scheme to determine TLS settings
	insecure := false
	parsedVaultAddr, err := url.Parse(vaultAddr)
	if parsedVaultAddr.Scheme == "http" {
		insecure = true
		fmt.Println("using insecure transport!")
	}

	var authData authObject
	authData.Addr = vaultAddr
	authData.Namespace = vaultNamespace
	authData.OidcMountName = oidcMountName
	authData.Role = "default_role"
	authData.Insecure = insecure
	authData.RedirectURI = "http://localhost:8250/oidc/callback"
	authData.CallbackPath = fmt.Sprintf("%s/callback", oidcAuthMethodPath)
	authData.AuthUrlReqPath = fmt.Sprintf("%s/auth_url", oidcAuthMethodPath)
	authData.AppRoleMount = appRoleMount
	authData.AppRoleName = appRoleName
	authData.AppRoleTTL = appRoleTTL

	authData.getVaultAuthUrl()

	server := &http.Server{Addr: authData.RedirectURI}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authData.RemoteCode = r.URL.Query().Get("code")
		authData.RemoteState = r.URL.Query().Get("state")

		if authData.LocalState != authData.RemoteState {
			fmt.Println("state mismatch")
			io.WriteString(w, "Error: state mismatch\n")
			cleanup(server)
			return
		}

		if authData.RemoteCode == "" {
			fmt.Println("error: Url Param 'code' is missing")
			io.WriteString(w, "Error: could not find 'code' URL parameter\n")
			cleanup(server)
			return
		}

		if err != nil {
			fmt.Println("error: could not get access token")
			io.WriteString(w, "Error: could not retrieve access token\n")
			cleanup(server)
			return
		}

		authData.getVaultToken()

		// return an indication of success to the caller
		io.WriteString(w, `
		<html>
			<body>
				<h1>Login successful!</h1>
				<h2>You can close this window and return to the CLI.</h2>
			</body>
		</html>`)

		fmt.Println("Successfully logged into Vault via OIDC.")

		// close the HTTP server
		cleanup(server)
	})

	// parse the redirect URL for the port number
	u, err := url.Parse(authData.RedirectURI)
	if err != nil {
		log.Fatalf("error: bad redirect URL: %s\n", err)
	}

	// set up a listener on the redirect port
	port := fmt.Sprintf(":%s", u.Port())
	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("error opening port %s for server: %s\n", port, err)
	}

	err = open.Start(authData.AuthUrl)
	if err != nil {
		log.Fatalf("error opening browser to callback URL: %v\n", err)
	}

	server.Serve(l)
	authData.getSecretId()
}

func cleanup(server *http.Server) {
	go server.Close()
}

func (a *authObject) getVaultAuthUrl() {
	payload := map[string]string{
		"role":         a.Role,
		"redirect_uri": a.RedirectURI,
	}

	json_data, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("error marshalling payload for Vault query: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: a.Insecure}

	// Retrieve Vault OIDC auth_url
	req, err := http.NewRequest("POST", a.Addr+"/v1/"+a.AuthUrlReqPath, bytes.NewReader(json_data))
	if a.Namespace != "" {
		req.Header.Add("X-VAULT-NAMESPACE", a.Namespace)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("error retrieving auth_url from Vault: %v\n", err)
	}

	var result vaultOidcAuth
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		log.Fatalf("error decoding response from Vault (auth_url request): %v\n", err)
	}

	a.AuthUrl = result.Data.AuthURL
	parsedAuthUrl, err := url.Parse(a.AuthUrl)
	a.LocalNonce = parsedAuthUrl.Query().Get("nonce")
	a.LocalState = parsedAuthUrl.Query().Get("state")
}

func (a *authObject) getVaultToken() {
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: a.Insecure}

	// auth to Vault and get token
	req, err := http.NewRequest("GET", a.Addr+"/v1/"+a.CallbackPath+"?code="+a.RemoteCode+"&state="+a.RemoteState+"&nonce="+a.LocalNonce, nil)
	if err != nil {
		log.Fatalf("error constructing auth request to Vault: %v\n", err)
	}
	if a.Namespace != "" {
		req.Header.Set("X-VAULT-NAMESPACE", a.Namespace)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("error authenticating with Vault: %v\n", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("error authenticating with Vault: %v\n", resp.Status)
	}

	var result vaultLogin
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		log.Fatalf("error unmarshalling Vault auth response: %v\n", err)
	}

	a.Token = result.Auth.ClientToken
}

func (a *authObject) getSecretId() {
	// POST: /auth/approle/role/:role_name/secret-id
	payload := map[string]string{
		"role": a.AppRoleName,
		"ttl":  a.AppRoleTTL,
	}

	json_data, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("error marshalling payload for AppRole Secret ID request: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: a.Insecure}

	// Request new Secret ID
	req, err := http.NewRequest("POST", a.Addr+"/v1/auth/"+a.AppRoleMount+"/role/"+a.AppRoleName+"/secret-id", bytes.NewReader(json_data))
	if a.Namespace != "" {
		req.Header.Add("X-VAULT-NAMESPACE", a.Namespace)
	}
	req.Header.Add("X-VAULT-TOKEN", a.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("error retrieving secret ID from Vault: %v\n", err)
	}

	var result SecretIDResponse
	err = json.NewDecoder(resp.Body).Decode(&result)

	fmt.Printf("New Secret ID for AppRole %s: %s (TTL: %v)\n", a.AppRoleName, result.Data.SecretID, result.Data.SecretIDTTL)
}
