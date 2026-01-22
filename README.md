# SyncVault Go SDK

Zero-knowledge sync SDK for Go applications.

## Installation

```bash
go get github.com/syncvault-dev/sdk-go
```

## Quick Start (OAuth Flow)

```go
package main

import (
    "fmt"
    "log"

    syncvault "github.com/syncvault-dev/sdk-go"
)

func main() {
    client, err := syncvault.New(syncvault.Config{
        AppToken:    "your_app_token",
        RedirectURI: "http://localhost:8080/callback",
        ServerURL:   "https://api.syncvault.io", // optional
    })
    if err != nil {
        log.Fatal(err)
    }

    // Step 1: Get OAuth URL and redirect user
    authURL, err := client.GetAuthURL("")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Redirect user to:", authURL)

    // Step 2: After callback, exchange code for token
    // code := r.URL.Query().Get("code") // from callback
    code := "authorization_code_from_callback"
    password := "user_encryption_password"

    user, err := client.ExchangeCode(code, password)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Logged in as:", user.Username)

    // Step 3: Use the SDK
    err = client.Put("data.json", map[string]string{"hello": "world"})
    if err != nil {
        log.Fatal(err)
    }

    var data map[string]string
    err = client.Get("data.json", &data)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Data:", data)
}
```

## Quick Start (Direct Auth)

```go
package main

import (
    "fmt"
    "log"

    syncvault "github.com/syncvault-dev/sdk-go"
)

func main() {
    client, err := syncvault.New(syncvault.Config{
        AppToken:  "your_app_token",
        ServerURL: "https://api.syncvault.io",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Authenticate directly
    user, err := client.Auth("username", "password")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Logged in as:", user.Username)

    // Store data
    note := map[string]interface{}{
        "title":   "My Note",
        "content": "Hello, World!",
    }
    err = client.Put("notes/note1.json", note)
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve data
    var retrieved map[string]interface{}
    err = client.Get("notes/note1.json", &retrieved)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Retrieved:", retrieved)

    // List files
    files, err := client.List()
    if err != nil {
        log.Fatal(err)
    }
    for _, f := range files {
        fmt.Println("File:", f.Path, "Updated:", f.UpdatedAt)
    }

    // Delete
    err = client.Delete("notes/note1.json")
    if err != nil {
        log.Fatal(err)
    }
}
```

## API Reference

### New(config)

Create a new SyncVault client.

```go
client, err := syncvault.New(syncvault.Config{
    AppToken:    "required",
    ServerURL:   "optional, defaults to http://localhost:3000",
    RedirectURI: "required for OAuth",
})
```

### OAuth Methods

- `GetAuthURL(state string)` - Generate OAuth authorization URL
- `ExchangeCode(code, password string)` - Exchange code for access token
- `SetAuth(token, password string)` - Set auth state manually

### Direct Auth

- `Auth(username, password string)` - Authenticate user
- `Register(username, password string)` - Register new user

### Data Operations

- `Put(path string, data interface{})` - Store encrypted data
- `Get(path string, result interface{})` - Retrieve and decrypt data
- `List()` - List all files
- `Delete(path string)` - Delete a file

### Metadata Operations (Preferences)

Metadata is for unencrypted app preferences like theme, timezone, language (up to 10KB).

```go
// Set preferences (replaces all)
err := client.SetMetadata(map[string]any{
    "theme": "dark",
    "timezone": "UTC",
    "language": "en",
})

// Get preferences
var prefs map[string]any
err := client.GetMetadata(&prefs)

// Update preferences (shallow merge)
err := client.UpdateMetadata(map[string]any{
    "language": "es",
})
```

- `GetMetadata(result interface{})` - Get user preferences
- `SetMetadata(metadata interface{})` - Replace all preferences
- `UpdateMetadata(metadata interface{})` - Merge with existing preferences

### Entitlements Operations

Entitlements are read-only data set by the developer's backend. Use them for subscription status, feature flags, etc.

```go
// Get entitlements (set by developer backend)
var entitlements map[string]any
err := client.GetEntitlements(&entitlements)
fmt.Println(entitlements["plan"]) // "premium"
```

- `GetEntitlements(result interface{})` - Get user entitlements (read-only)

### Quota Operations

```go
// Get storage quota info
quota, err := client.GetQuota()
fmt.Println(quota.UsedBytes)   // bytes used
fmt.Println(quota.QuotaBytes)  // limit (nil if unlimited)
fmt.Println(quota.Unlimited)   // true if no limit
```

- `GetQuota()` - Get user storage quota information

### State

- `IsAuthenticated()` - Check auth state
- `Logout()` - Clear auth state

## Encryption

Data is encrypted using AES-256-GCM with keys derived via PBKDF2 (100,000 iterations).

**Note:** Metadata (preferences) and entitlements are NOT encrypted. Only use them for non-sensitive information.

## Offline Support

The SDK supports offline-first sync with local caching and automatic retry.

### Basic Usage

```go
client, err := syncvault.NewOfflineClient(
    syncvault.Config{
        AppToken: "your_app_token",
    },
    syncvault.OfflineConfig{
        CacheDir:       "", // defaults to ~/.syncvault/cache
        RetryInterval:  30 * time.Second,
        MaxRetries:     10,
        EnableAutoSync: true,
    },
)
if err != nil {
    log.Fatal(err)
}

// Authenticate
client.Auth("username", "password")

// Put - queues if offline, syncs when online
err = client.Put("data.json", myData)

// Get - returns cached data if offline
err = client.Get("data.json", &myData)

// Check pending operations
if client.HasPendingChanges() {
    fmt.Println("Pending:", client.PendingCount())
}
```

### Callbacks

```go
client.OnSyncSuccess(func(op *syncvault.PendingOperation) {
    fmt.Println("Synced:", op.Path)
})

client.OnSyncError(func(op *syncvault.PendingOperation, err error) {
    fmt.Println("Failed:", op.Path, err)
})
```

### Manual Sync

```go
// Manually trigger sync
client.SyncPending()

// Stop auto-sync
client.StopAutoSync()

// Clear cache/queue
client.GetStore().ClearCache()
client.GetStore().ClearQueue()
```

## Server-Side Write (App Backends)

Apps can write encrypted data on behalf of users using `ServerClient`. This requires:
1. Developer enables `server_write` in app settings (dev dashboard)
2. User grants the `server_write` OAuth scope

### How It Works

1. **Developer** enables `serverWriteEnabled` for the app in developer dashboard
2. User authorizes your app with the `server_write` scope
3. A RSA key pair is generated **per-app** - public key stored on server, private key stored locally by user
4. Your backend encrypts data with the user's public key
5. Only the user can decrypt with their private key

**Important:** The server can **never read** user data. It can only store pre-encrypted blobs.

### Backend Setup

```go
package main

import (
    "fmt"
    "log"
    "time"

    syncvault "github.com/syncvault-dev/sdk-go"
)

func main() {
    // Create server client (for backend use only)
    server, err := syncvault.NewServerClient(syncvault.ServerConfig{
        AppToken:    "your_app_token",
        SecretToken: "your_secret_token",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Write data for a user (encrypts automatically)
    result, err := server.WriteForUser(userID, "inbox/email-123.json", map[string]interface{}{
        "subject":   "Hello",
        "body":      "World",
        "timestamp": time.Now().Unix(),
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Wrote:", result.Path)

    // Or manually encrypt and write
    publicKey, _ := server.GetUserPublicKey(userID)
    encrypted, _ := server.EncryptForUser(data, publicKey)
    server.PutForUser(userID, "path/to/file.json", encrypted)

    // List user's files (paths only, cannot read content)
    files, _ := server.ListForUser(userID)
    for _, f := range files {
        fmt.Println(f.Path, f.Size)
    }
}
```

### Client-Side Decryption

Users decrypt server-written data using their private key:

```go
// The private key was stored locally during OAuth consent (per-app)
privateKey := loadPrivateKeyFromStorage(appToken)

// Get the encrypted data from the server
// (raw data, not through the normal client.Get which uses password-based decryption)

// Decrypt with private key
var email map[string]interface{}
err := syncvault.DecryptFromServer(encryptedData, privateKey, &email)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Subject:", email["subject"])
```

**Note:** If your app hasn't enabled `serverWriteEnabled`, the `server_write` scope will be silently ignored.
