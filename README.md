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

### Metadata Operations

Metadata is unencrypted JSON data (up to 10KB) stored on the server. Unlike encrypted sync data, metadata can be read by developers for automation and analytics.

```go
// Set metadata (replaces all)
err := client.SetMetadata(map[string]any{
    "plan": "premium",
    "theme": "dark",
})

// Get metadata
var meta map[string]any
err := client.GetMetadata(&meta)

// Update metadata (shallow merge)
err := client.UpdateMetadata(map[string]any{
    "lastSync": time.Now().Format(time.RFC3339),
})
```

- `GetMetadata(result interface{})` - Get user metadata
- `SetMetadata(metadata interface{})` - Replace all metadata
- `UpdateMetadata(metadata interface{})` - Merge with existing metadata

### State

- `IsAuthenticated()` - Check auth state
- `Logout()` - Clear auth state

## Encryption

Data is encrypted using AES-256-GCM with keys derived via PBKDF2 (100,000 iterations).

**Note:** Metadata is NOT encrypted and is stored as plain JSON on the server. Only use metadata for non-sensitive information like preferences, feature flags, or sync timestamps.
