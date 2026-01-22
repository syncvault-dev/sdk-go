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

// ServerClient is used by app backends to write data on behalf of users.
// Requires server_write OAuth scope to be granted by users.
type ServerClient struct {
	appToken    string
	secretToken string
	serverURL   string
	httpClient  *http.Client
}

// ServerConfig holds the configuration for creating a ServerClient.
type ServerConfig struct {
	AppToken    string
	SecretToken string
	ServerURL   string
}

// ServerFileInfo represents file metadata from server listing.
type ServerFileInfo struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	UpdatedAt string `json:"updatedAt"`
}

// ServerPutResponse represents the response from a server put operation.
type ServerPutResponse struct {
	Success   bool   `json:"success"`
	Path      string `json:"path"`
	UserID    string `json:"userId"`
	Size      int64  `json:"size"`
	UpdatedAt string `json:"updatedAt"`
}

// NewServerClient creates a new server-side SyncVault client.
func NewServerClient(config ServerConfig) (*ServerClient, error) {
	if config.AppToken == "" {
		return nil, errors.New("appToken is required")
	}
	if config.SecretToken == "" {
		return nil, errors.New("secretToken is required for server-side operations")
	}

	serverURL := config.ServerURL
	if serverURL == "" {
		serverURL = defaultServerURL
	}

	return &ServerClient{
		appToken:    config.AppToken,
		secretToken: config.SecretToken,
		serverURL:   serverURL,
		httpClient:  &http.Client{},
	}, nil
}

// GetUserPublicKey retrieves the user's public key for encryption.
func (c *ServerClient) GetUserPublicKey(userID string) (string, error) {
	var response struct {
		PublicKey string `json:"publicKey"`
		UserID    string `json:"userId"`
	}

	if err := c.request("GET", "/api/server/user/"+userID+"/public-key", nil, &response); err != nil {
		return "", err
	}

	return response.PublicKey, nil
}

// EncryptForUser encrypts data with the user's public key using hybrid encryption.
// Uses RSA-OAEP to encrypt an AES-GCM key, then encrypts the data with AES-GCM.
func (c *ServerClient) EncryptForUser(data interface{}, publicKeyBase64 string) (string, error) {
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("public key is not RSA")
	}

	// JSON encode the data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	// Generate a random AES key (256-bit)
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt data with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	encryptedData := gcm.Seal(nil, iv, jsonData, nil)

	// Encrypt AES key with RSA-OAEP
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublicKey, aesKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt AES key: %w", err)
	}

	// Pack: encryptedAESKey (256 bytes for 2048-bit RSA) + iv (12 bytes) + encryptedData
	result := make([]byte, 0, len(encryptedAESKey)+len(iv)+len(encryptedData))
	result = append(result, encryptedAESKey...)
	result = append(result, iv...)
	result = append(result, encryptedData...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// PutForUser writes pre-encrypted data to a user's storage.
// Data must be encrypted with EncryptForUser() first.
func (c *ServerClient) PutForUser(userID, path, encryptedData string) (*ServerPutResponse, error) {
	payload := map[string]string{
		"path": path,
		"data": encryptedData,
	}

	var response ServerPutResponse
	if err := c.request("POST", "/api/server/user/"+userID+"/put", payload, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// WriteForUser encrypts and stores data for a user in one call.
func (c *ServerClient) WriteForUser(userID, path string, data interface{}) (*ServerPutResponse, error) {
	publicKey, err := c.GetUserPublicKey(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user public key: %w", err)
	}

	encrypted, err := c.EncryptForUser(data, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return c.PutForUser(userID, path, encrypted)
}

// ListForUser returns all files for a user in this app.
func (c *ServerClient) ListForUser(userID string) ([]ServerFileInfo, error) {
	var response struct {
		Files []ServerFileInfo `json:"files"`
	}

	if err := c.request("GET", "/api/server/user/"+userID+"/list", nil, &response); err != nil {
		return nil, err
	}

	return response.Files, nil
}

func (c *ServerClient) request(method, path string, body interface{}, result interface{}) error {
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
		if decodeErr := json.NewDecoder(resp.Body).Decode(&errResp); decodeErr != nil {
			return fmt.Errorf("request failed with status %d", resp.StatusCode)
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

// DecryptFromServer decrypts data that was encrypted by an app server using hybrid encryption.
// This is used by the client to decrypt data written via ServerClient.WriteForUser().
func DecryptFromServer(encryptedBase64, privateKeyBase64 string, result interface{}) error {
	// Decode the encrypted data
	combined, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// RSA-OAEP encrypted AES key is 256 bytes for 2048-bit RSA
	const rsaKeySize = 256
	const aesIVLength = 12

	if len(combined) < rsaKeySize+aesIVLength {
		return errors.New("invalid encrypted data: too short")
	}

	encryptedAESKey := combined[:rsaKeySize]
	iv := combined[rsaKeySize : rsaKeySize+aesIVLength]
	ciphertext := combined[rsaKeySize+aesIVLength:]

	// Decode and parse the private key
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("private key is not RSA")
	}

	// Decrypt the AES key with RSA-OAEP
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAESKey, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// Decrypt the data with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	return json.Unmarshal(plaintext, result)
}
