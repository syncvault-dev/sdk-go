// Package syncvault provides a zero-knowledge sync SDK for Go applications.
package syncvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultServerURL = "https://api.syncvault.dev"
	pbkdf2Iterations = 100000
	keyLength        = 32
	saltLength       = 16
	nonceLength      = 12
)

// Client is the SyncVault SDK client.
type Client struct {
	appToken    string
	serverURL   string
	redirectURI string
	token       string
	password    string
	httpClient  *http.Client
}

// Config holds the configuration for creating a new Client.
type Config struct {
	AppToken    string
	ServerURL   string
	RedirectURI string
}

// User represents a SyncVault user.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// FileInfo represents file metadata.
type FileInfo struct {
	Path      string `json:"path"`
	UpdatedAt string `json:"updatedAt"`
}

// PutOptions contains optional parameters for Put operations.
type PutOptions struct {
	// UpdatedAt is used for Last-Write-Wins conflict resolution.
	// If server has newer data, Put will fail with ErrConflictStale.
	UpdatedAt *string
}

// ConflictError is returned when server has newer data (LWW conflict).
type ConflictError struct {
	ServerUpdatedAt string
}

func (e *ConflictError) Error() string {
	return "conflict: server has newer data"
}

// New creates a new SyncVault client.
func New(config Config) (*Client, error) {
	if config.AppToken == "" {
		return nil, errors.New("appToken is required")
	}

	serverURL := config.ServerURL
	if serverURL == "" {
		serverURL = defaultServerURL
	}

	return &Client{
		appToken:    config.AppToken,
		serverURL:   serverURL,
		redirectURI: config.RedirectURI,
		httpClient:  &http.Client{},
	}, nil
}

// GetAuthURL generates the OAuth authorization URL.
func (c *Client) GetAuthURL(state string) (string, error) {
	if c.redirectURI == "" {
		return "", errors.New("redirectURI is required for OAuth flow")
	}

	params := url.Values{}
	params.Set("app_token", c.appToken)
	params.Set("redirect_uri", c.redirectURI)
	if state != "" {
		params.Set("state", state)
	}

	return fmt.Sprintf("%s/api/oauth/authorize?%s", c.serverURL, params.Encode()), nil
}

// ExchangeCode exchanges an authorization code for an access token.
func (c *Client) ExchangeCode(code, password string) (*User, error) {
	payload := map[string]string{
		"code":         code,
		"app_token":    c.appToken,
		"redirect_uri": c.redirectURI,
	}

	var response struct {
		AccessToken string `json:"access_token"`
		User        User   `json:"user"`
	}

	if err := c.request("POST", "/api/oauth/token", payload, &response); err != nil {
		return nil, err
	}

	c.token = response.AccessToken
	c.password = password

	return &response.User, nil
}

// prepareAuthPassword hashes the password for authentication
func prepareAuthPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Auth authenticates a user directly.
func (c *Client) Auth(username, password string) (*User, error) {
	payload := map[string]string{
		"username": username,
		"password": prepareAuthPassword(password),
	}

	var response struct {
		Token string `json:"token"`
		User  User   `json:"user"`
	}

	if err := c.request("POST", "/api/user/auth/login", payload, &response); err != nil {
		return nil, err
	}

	c.token = response.Token
	c.password = password

	return &response.User, nil
}

// Register creates a new user account.
func (c *Client) Register(username, password string) (*User, error) {
	payload := map[string]string{
		"username": username,
		"password": prepareAuthPassword(password),
	}

	var response struct {
		Token string `json:"token"`
		User  User   `json:"user"`
	}

	if err := c.request("POST", "/api/user/auth/register", payload, &response); err != nil {
		return nil, err
	}

	c.token = response.Token
	c.password = password

	return &response.User, nil
}

// SetAuth manually sets the authentication state.
func (c *Client) SetAuth(token, password string) {
	c.token = token
	c.password = password
}

// GetToken returns the current access token.
func (c *Client) GetToken() string {
	return c.token
}

// Put stores encrypted data at the given path.
func (c *Client) Put(path string, data interface{}) error {
	return c.PutWithOptions(path, data, nil)
}

// PutWithOptions stores encrypted data at the given path with optional LWW conflict resolution.
func (c *Client) PutWithOptions(path string, data interface{}, opts *PutOptions) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	encrypted, err := c.encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	payload := map[string]string{
		"path": path,
		"data": encrypted,
	}

	if opts != nil && opts.UpdatedAt != nil {
		payload["updatedAt"] = *opts.UpdatedAt
	}

	var response map[string]interface{}
	return c.request("POST", "/api/sync/put", payload, &response)
}

// Get retrieves and decrypts data from the given path.
func (c *Client) Get(path string, result interface{}) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	var response struct {
		Data string `json:"data"`
	}

	if err := c.request("GET", "/api/sync/get?path="+url.QueryEscape(path), nil, &response); err != nil {
		return err
	}

	return c.decrypt(response.Data, result)
}

// List returns all files for this app.
func (c *Client) List() ([]FileInfo, error) {
	if c.token == "" || c.password == "" {
		return nil, errors.New("not authenticated")
	}

	var response struct {
		Files []FileInfo `json:"files"`
	}

	if err := c.request("GET", "/api/sync/list", nil, &response); err != nil {
		return nil, err
	}

	return response.Files, nil
}

// Delete removes a file.
func (c *Client) Delete(path string) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	payload := map[string]string{"path": path}
	var response map[string]interface{}
	return c.request("POST", "/api/sync/delete", payload, &response)
}

// GetMetadata retrieves unencrypted app metadata for the current user.
func (c *Client) GetMetadata(result interface{}) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	var response struct {
		Metadata json.RawMessage `json:"metadata"`
	}

	if err := c.request("GET", "/api/sync/metadata", nil, &response); err != nil {
		return err
	}

	return json.Unmarshal(response.Metadata, result)
}

// SetMetadata sets the app metadata for the current user (replaces all metadata).
func (c *Client) SetMetadata(metadata interface{}) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	payload := map[string]interface{}{"metadata": metadata}
	var response map[string]interface{}
	return c.request("POST", "/api/sync/metadata", payload, &response)
}

// UpdateMetadata merges new metadata with existing metadata.
func (c *Client) UpdateMetadata(metadata interface{}) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	payload := map[string]interface{}{"metadata": metadata}
	var response map[string]interface{}
	return c.request("PATCH", "/api/sync/metadata", payload, &response)
}

// GetEntitlements retrieves entitlements for the current user (read-only, set by developer backend).
func (c *Client) GetEntitlements(result interface{}) error {
	if c.token == "" || c.password == "" {
		return errors.New("not authenticated")
	}

	var response struct {
		Entitlements json.RawMessage `json:"entitlements"`
	}

	if err := c.request("GET", "/api/sync/entitlements", nil, &response); err != nil {
		return err
	}

	return json.Unmarshal(response.Entitlements, result)
}

// QuotaInfo represents user storage quota information.
type QuotaInfo struct {
	QuotaBytes *int64 `json:"quotaBytes"`
	UsedBytes  int64  `json:"usedBytes"`
	Unlimited  bool   `json:"unlimited"`
}

// GetQuota retrieves the user's storage quota information.
func (c *Client) GetQuota() (*QuotaInfo, error) {
	if c.token == "" || c.password == "" {
		return nil, errors.New("not authenticated")
	}

	var response QuotaInfo
	if err := c.request("GET", "/api/sync/quota", nil, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// IsAuthenticated checks if the client is authenticated.
func (c *Client) IsAuthenticated() bool {
	return c.token != "" && c.password != ""
}

// Logout clears the authentication state.
func (c *Client) Logout() {
	c.token = ""
	c.password = ""
}

func (c *Client) request(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.serverURL+path, bodyReader)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Token", c.appToken)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error           string `json:"error"`
			Code            string `json:"code"`
			ServerUpdatedAt string `json:"serverUpdatedAt"`
		}
		if decodeErr := json.NewDecoder(resp.Body).Decode(&errResp); decodeErr != nil {
			return fmt.Errorf("request failed with status %d", resp.StatusCode)
		}
		
		// Handle LWW conflict
		if resp.StatusCode == 409 && errResp.Code == "CONFLICT_STALE" {
			return &ConflictError{ServerUpdatedAt: errResp.ServerUpdatedAt}
		}
		
		if errResp.Error != "" {
			return errors.New(errResp.Error)
		}
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}

	return nil
}

func (c *Client) deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keyLength, sha256.New)
}

func (c *Client) encrypt(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := c.deriveKey(c.password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, jsonData, nil)

	// Format: salt + nonce + ciphertext
	result := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}

func (c *Client) decrypt(encryptedBase64 string, result interface{}) error {
	data, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return err
	}

	if len(data) < saltLength+nonceLength {
		return errors.New("invalid encrypted data")
	}

	salt := data[:saltLength]
	nonce := data[saltLength : saltLength+nonceLength]
	ciphertext := data[saltLength+nonceLength:]

	key := c.deriveKey(c.password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, result)
}

// ServerClient is the SyncVault SDK client for server-side operations.
// It allows backend applications to write data on behalf of users.
type ServerClient struct {
appToken    string
secretToken string
serverURL   string
httpClient  *http.Client
}

// NewServerClient creates a new ServerClient.
func NewServerClient(appToken, secretToken, serverURL string) *ServerClient {
if serverURL == "" {
serverURL = defaultServerURL
}
return &ServerClient{
appToken:    appToken,
secretToken: secretToken,
serverURL:   serverURL,
httpClient:  &http.Client{},
}
}

func (c *ServerClient) request(method, path string, body interface{}, target interface{}) error {
var bodyReader io.Reader
if body != nil {
jsonBody, err := json.Marshal(body)
if err != nil {
return err
}
bodyReader = bytes.NewBuffer(jsonBody)
}

req, err := http.NewRequest(method, c.serverURL+path, bodyReader)
if err != nil {
return err
}

req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-App-Token", c.appToken)
req.Header.Set("X-Secret-Token", c.secretToken)

resp, err := c.httpClient.Do(req)
if err != nil {
return err
}
defer resp.Body.Close()

if resp.StatusCode >= 400 {
var errResp struct {
Error string `json:"error"`
}
if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
return fmt.Errorf("request failed with status %d", resp.StatusCode)
}
return errors.New(errResp.Error)
}

if target != nil {
return json.NewDecoder(resp.Body).Decode(target)
}

return nil
}

// GetUserPublicKey retrieves the public key for a user.
func (c *ServerClient) GetUserPublicKey(userID string) (string, error) {
var resp struct {
PublicKey string `json:"publicKey"`
}
if err := c.request("GET", fmt.Sprintf("/api/server/user/%s/public-key", userID), nil, &resp); err != nil {
return "", err
}
return resp.PublicKey, nil
}

// PutForUser writes encrypted data to a user's vault.
func (c *ServerClient) PutForUser(userID, path, encryptedData string) error {
payload := map[string]string{
"path": path,
"data": encryptedData,
}
return c.request("POST", fmt.Sprintf("/api/server/user/%s/put", userID), payload, nil)
}

// ListForUser lists files in a user's vault.
func (c *ServerClient) ListForUser(userID string) ([]FileInfo, error) {
var resp struct {
Files []FileInfo `json:"files"`
}
if err := c.request("GET", fmt.Sprintf("/api/server/user/%s/list", userID), nil, &resp); err != nil {
return nil, err
}
return resp.Files, nil
}

// EncryptForUser encrypts data using hybrid encryption (RSA-OAEP + AES-GCM) for a user.
func (c *ServerClient) EncryptForUser(data interface{}, publicKeyPEM string) (string, error) {
// 1. Generate AES key and IV
aesKey := make([]byte, 32)
iv := make([]byte, 12)
if _, err := rand.Read(aesKey); err != nil {
return "", err
}
if _, err := rand.Read(iv); err != nil {
return "", err
}

// 2. Serialize data and encrypt with AES-GCM
jsonData, err := json.Marshal(data)
if err != nil {
return "", err
}

block, err := aes.NewCipher(aesKey)
if err != nil {
return "", err
}
gcm, err := cipher.NewGCM(block)
if err != nil {
return "", err
}

// Sign data in typical GCM fashion (ciphertext + tag appended)
ciphertext := gcm.Seal(nil, iv, jsonData, nil)

// Separate tag from ciphertext (Go appends tag at the end)
tagSize := gcm.Overhead()
if len(ciphertext) < tagSize {
return "", errors.New("ciphertext too short")
}
rawCiphertext := ciphertext[:len(ciphertext)-tagSize]
authTag := ciphertext[len(ciphertext)-tagSize:]

// 3. Encrypt AES key with RSA-OAEP
block2, _ := pem.Decode([]byte(publicKeyPEM))
if block2 == nil {
return "", errors.New("failed to parse PEM block containing the public key")
}
pub, err := x509.ParsePKIXPublicKey(block2.Bytes)
if err != nil {
return "", err
}
rsaPub, ok := pub.(*rsa.PublicKey)
if !ok {
return "", errors.New("key is not of type *rsa.PublicKey")
}

encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
if err != nil {
return "", err
}

// 4. Pack: encryptedAesKey (256) + iv (12) + authTag (16) + ciphertext
var combined bytes.Buffer
combined.Write(encryptedAESKey)
combined.Write(iv)
combined.Write(authTag)
combined.Write(rawCiphertext)

return base64.StdEncoding.EncodeToString(combined.Bytes()), nil
}

// WriteForUser encrypts and writes data for a user in one step.
func (c *ServerClient) WriteForUser(userID, path string, data interface{}) error {
pubKey, err := c.GetUserPublicKey(userID)
if err != nil {
return err
}
encrypted, err := c.EncryptForUser(data, pubKey)
if err != nil {
return err
}
return c.PutForUser(userID, path, encrypted)
}

// DecryptFromServer decrypts data encrypted by ServerClient.
// privateKeyPEM should be the user's unencrypted private key in PEM format.
func DecryptFromServer(encryptedBase64, privateKeyPEM string) (interface{}, error) {
combined, err := base64.StdEncoding.DecodeString(encryptedBase64)
if err != nil {
return nil, err
}

rsaKeySize := 256 // 2048-bit RSA
aesIvLength := 12
authTagLength := 16
minLength := rsaKeySize + aesIvLength + authTagLength

if len(combined) < minLength {
return nil, errors.New("invalid encrypted data: too short")
}

encryptedAESKey := combined[:rsaKeySize]
iv := combined[rsaKeySize : rsaKeySize+aesIvLength]
authTag := combined[rsaKeySize+aesIvLength : rsaKeySize+aesIvLength+authTagLength]
ciphertext := combined[rsaKeySize+aesIvLength+authTagLength:]

// Parse Private Key
block, _ := pem.Decode([]byte(privateKeyPEM))
if block == nil {
return nil, errors.New("failed to parse PEM block containing the private key")
}

// Try parsing as PKCS8 first (standard), then PKCS1
var privKey interface{}
privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
if err != nil {
privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
if err != nil {
return nil, fmt.Errorf("failed to parse private key: %v", err)
}
}

rsaPriv, ok := privKey.(*rsa.PrivateKey)
if !ok {
return nil, errors.New("key is not of type *rsa.PrivateKey")
}

// Decrypt AES Key
aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, encryptedAESKey, nil)
if err != nil {
return nil, fmt.Errorf("failed to decrypt AES key: %v", err)
}

// Decrypt Data
blockAES, err := aes.NewCipher(aesKey)
if err != nil {
return nil, err
}
gcm, err := cipher.NewGCM(blockAES)
if err != nil {
return nil, err
}

// Reassemble ciphertext + tag for Go's Open
fullCiphertext := append(ciphertext, authTag...)
plaintext, err := gcm.Open(nil, iv, fullCiphertext, nil)
if err != nil {
return nil, fmt.Errorf("failed to decrypt data: %v", err)
}

var result interface{}
if err := json.Unmarshal(plaintext, &result); err != nil {
return nil, err
}

return result, nil
}
