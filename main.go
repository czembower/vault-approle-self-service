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
	"os"
	"strconv"
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
	WrapSecretId   bool   `json:"wrap_secret_id"`
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
	WrapInfo struct {
		Accessor         string `json:"accessor"`
		Creation_Path    string `json:"creation_path"`
		Creation_Time    string `json:"creation_time"`
		Token            string `json:"token"`
		TTL              int    `json:"ttl"`
		Wrapped_Accessor string `json:"wrapped_accessor"`
	} `json:"wrap_info"`
	Warnings any `json:"warnings"`
	Auth     any `json:"auth"`
}

type UnwrapSecret struct {
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
	dec := 1
	fmt.Println("[1] Generate new AppRole Secret ID")
	fmt.Println("[2] Unwrap Secret ID from token")
	fmt.Print("Make a selection [1]: ")
	fmt.Scanln(&dec)

	var authData authObject

	fmt.Print("Vault Address [https://127.0.0.1:8200]: ")
	fmt.Scanln(&authData.Addr)
	if authData.Addr == "" {
		authData.Addr = "https://127.0.0.1:8200"
	}

	// parse vault URL scheme to determine TLS settings
	authData.Insecure = false
	parsedVaultAddr, err := url.Parse(authData.Addr)
	if parsedVaultAddr.Scheme == "http" {
		authData.Insecure = true
		fmt.Println("using insecure transport!")
	}

	if dec == 2 {
		fmt.Print("Wrapping Token: ")
		fmt.Scanln(&authData.Token)
		if authData.Token == "" {
			log.Fatal("error: You must enter a valid wrapping token")
		}
		authData.unwrapSecret()
	}

	fmt.Print("Vault Namespace [root]: ")
	fmt.Scanln(&authData.Namespace)
	if authData.Namespace == "" {
		authData.Namespace = "root"
	}

	fmt.Print("OIDC Auth Method Name [oidc]: ")
	fmt.Scanln(&authData.OidcMountName)
	if authData.OidcMountName == "" {
		authData.OidcMountName = "oidc"
	}

	fmt.Print("App Role Mount Path [approle]: ")
	fmt.Scanln(&authData.AppRoleMount)
	if authData.AppRoleMount == "" {
		authData.AppRoleMount = "approle"
	}

	fmt.Print("Vault Role [my-role]: ")
	fmt.Scanln(&authData.AppRoleName)
	if authData.AppRoleName == "" {
		authData.AppRoleName = "my-role"
	}

	fmt.Print("App Role Secret ID TTL [24h]: ")
	fmt.Scanln(&authData.AppRoleTTL)
	if authData.AppRoleTTL == "" {
		authData.AppRoleTTL = "24h"
	}

	var wrapSecretIdString string
	fmt.Print("Wrap Secret ID? [true]: ")
	fmt.Scanln(&wrapSecretIdString)
	if wrapSecretIdString == "" {
		wrapSecretIdString = "true"
	}
	authData.WrapSecretId, _ = strconv.ParseBool(wrapSecretIdString)

	oidcAuthMethodPath := fmt.Sprintf("auth/%s/oidc", authData.OidcMountName)
	authData.RedirectURI = "http://localhost:8250/oidc/callback"
	authData.CallbackPath = fmt.Sprintf("%s/callback", oidcAuthMethodPath)
	authData.AuthUrlReqPath = fmt.Sprintf("%s/auth_url", oidcAuthMethodPath)

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

		loginSuccess := fmt.Sprintf(`
		<html>
			<body>
				<center>
				<br><br><br>
				<table width=200 border=0>
				<tr>
				<td width=50></td>
				<td align=center width=100>
				<img src="https://www.datocms-assets.com/2885/1620159869-brandvaultprimaryattributedcolor.svg" />
				</td>
				<td>
				<img height=25 src="https://upload.wikimedia.org/wikipedia/commons/thumb/3/3b/Eo_circle_green_checkmark.svg/2048px-Eo_circle_green_checkmark.svg.png" />
				</td>
				</tr>
				<tr>
				<td width=50></td>
				<td colspan=2>
				<h2>Login successful</h2>
				<h3>You can close this window and return to the CLI.</h3>
				</td>
				</tr>
				<tr height=600>
				<td colspan=3>
				<font size="2">
				Authorization: %s
				</font>
				</td>
				</tr>
				</center>
			</body>
		</html>`, authData.RemoteCode)

		// return an indication of success to the caller
		io.WriteString(w, loginSuccess)

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
	payload := map[string]string{
		"ttl": a.AppRoleTTL,
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

	if a.WrapSecretId {
		req.Header.Add("X-Vault-Wrap-TTL", "24h")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("error retrieving secret ID from Vault: %v\n", err)
	}

	var result SecretIDResponse
	err = json.NewDecoder(resp.Body).Decode(&result)

	if a.WrapSecretId {
		fmt.Printf("New wrapping token for %s Secret ID: %s (Wrapped Secret ID validity period: %d hours)\n", a.AppRoleName, result.WrapInfo.Token, result.WrapInfo.TTL/60/60)
	} else {
		fmt.Printf("New Secret ID for AppRole %s: %s (TTL: %v)\n", a.AppRoleName, result.Data.SecretID, result.Data.SecretIDTTL)
	}
}

func (a *authObject) unwrapSecret() {
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: a.Insecure}

	req, err := http.NewRequest("POST", a.Addr+"/v1/sys/wrapping/unwrap", nil)
	if a.Namespace != "" {
		req.Header.Add("X-VAULT-NAMESPACE", a.Namespace)
	}
	req.Header.Add("X-VAULT-TOKEN", a.Token)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("error retrieving unwrapped secret: %v\n", err)
	}

	var result UnwrapSecret
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		log.Fatalf("error unmarshalling Vault response: %v\n", err)
	}

	if len(result.Data.SecretID) != 36 {
		log.Println("An error has occurred. Please make sure you have entered a valid response-wrapped secret.")
	}

	fmt.Printf("Secret ID: %s\n", result.Data.SecretID)

	os.Exit(0)
}
