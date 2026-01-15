// Package syncvault provides offline sync capabilities with local caching and auto-retry.
package syncvault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OperationType represents the type of sync operation
type OperationType string

const (
	OpPut    OperationType = "put"
	OpDelete OperationType = "delete"
)

// PendingOperation represents a queued offline operation
type PendingOperation struct {
	ID        string        `json:"id"`
	Type      OperationType `json:"type"`
	Path      string        `json:"path"`
	Data      string        `json:"data,omitempty"` // encrypted data for put
	CreatedAt time.Time     `json:"createdAt"`
	Retries   int           `json:"retries"`
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Path      string    `json:"path"`
	Data      string    `json:"data"` // encrypted
	UpdatedAt time.Time `json:"updatedAt"`
}

// OfflineStore handles local caching and offline queue
type OfflineStore struct {
	cacheDir string
	mu       sync.RWMutex
	cache    map[string]*CacheEntry
	queue    []*PendingOperation
}

// OfflineConfig configures offline behavior
type OfflineConfig struct {
	CacheDir       string        // Directory for cache storage
	RetryInterval  time.Duration // Interval between retries (default: 30s)
	MaxRetries     int           // Max retries per operation (default: 10)
	EnableAutoSync bool          // Auto-sync when online (default: true)
}

// NewOfflineStore creates a new offline store
func NewOfflineStore(config OfflineConfig) (*OfflineStore, error) {
	if config.CacheDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		config.CacheDir = filepath.Join(homeDir, ".syncvault", "cache")
	}

	if err := os.MkdirAll(config.CacheDir, 0700); err != nil {
		return nil, err
	}

	store := &OfflineStore{
		cacheDir: config.CacheDir,
		cache:    make(map[string]*CacheEntry),
		queue:    make([]*PendingOperation, 0),
	}

	// Load persisted data
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// GetCached returns cached data for a path
func (s *OfflineStore) GetCached(path string) (*CacheEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.cache[path]
	return entry, ok
}

// SetCache stores data in cache
func (s *OfflineStore) SetCache(path, data string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[path] = &CacheEntry{
		Path:      path,
		Data:      data,
		UpdatedAt: time.Now(),
	}
	s.persist()
}

// RemoveCache removes an item from cache
func (s *OfflineStore) RemoveCache(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cache, path)
	s.persist()
}

// QueueOperation adds an operation to the offline queue
func (s *OfflineStore) QueueOperation(op *PendingOperation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op.ID = generateOpID()
	op.CreatedAt = time.Now()
	s.queue = append(s.queue, op)
	s.persist()
}

// GetPendingOperations returns all pending operations
func (s *OfflineStore) GetPendingOperations() []*PendingOperation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PendingOperation, len(s.queue))
	copy(result, s.queue)
	return result
}

// RemoveOperation removes a completed operation from queue
func (s *OfflineStore) RemoveOperation(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, op := range s.queue {
		if op.ID == id {
			s.queue = append(s.queue[:i], s.queue[i+1:]...)
			break
		}
	}
	s.persist()
}

// IncrementRetry increments retry count for an operation
func (s *OfflineStore) IncrementRetry(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, op := range s.queue {
		if op.ID == id {
			op.Retries++
			break
		}
	}
	s.persist()
}

// HasPendingOperations returns true if there are queued operations
func (s *OfflineStore) HasPendingOperations() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.queue) > 0
}

// ClearQueue removes all pending operations
func (s *OfflineStore) ClearQueue() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = make([]*PendingOperation, 0)
	s.persist()
}

// ClearCache removes all cached data
func (s *OfflineStore) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]*CacheEntry)
	s.persist()
}

func (s *OfflineStore) load() error {
	// Load cache
	cachePath := filepath.Join(s.cacheDir, "cache.json")
	if data, err := os.ReadFile(cachePath); err == nil {
		if err := json.Unmarshal(data, &s.cache); err != nil {
			return err
		}
	}

	// Load queue
	queuePath := filepath.Join(s.cacheDir, "queue.json")
	if data, err := os.ReadFile(queuePath); err == nil {
		if err := json.Unmarshal(data, &s.queue); err != nil {
			return err
		}
	}

	return nil
}

func (s *OfflineStore) persist() {
	// Persist cache
	cachePath := filepath.Join(s.cacheDir, "cache.json")
	if data, err := json.Marshal(s.cache); err == nil {
		os.WriteFile(cachePath, data, 0600)
	}

	// Persist queue
	queuePath := filepath.Join(s.cacheDir, "queue.json")
	if data, err := json.Marshal(s.queue); err == nil {
		os.WriteFile(queuePath, data, 0600)
	}
}

func generateOpID() string {
	return time.Now().Format("20060102150405.000000000")
}

// OfflineClient wraps Client with offline support
type OfflineClient struct {
	*Client
	store         *OfflineStore
	config        OfflineConfig
	syncTicker    *time.Ticker
	stopSync      chan struct{}
	onSyncError   func(op *PendingOperation, err error)
	onSyncSuccess func(op *PendingOperation)
}

// NewOfflineClient creates a client with offline support
func NewOfflineClient(config Config, offlineConfig OfflineConfig) (*OfflineClient, error) {
	client, err := New(config)
	if err != nil {
		return nil, err
	}

	store, err := NewOfflineStore(offlineConfig)
	if err != nil {
		return nil, err
	}

	if offlineConfig.RetryInterval == 0 {
		offlineConfig.RetryInterval = 30 * time.Second
	}
	if offlineConfig.MaxRetries == 0 {
		offlineConfig.MaxRetries = 10
	}

	oc := &OfflineClient{
		Client:   client,
		store:    store,
		config:   offlineConfig,
		stopSync: make(chan struct{}),
	}

	if offlineConfig.EnableAutoSync {
		oc.StartAutoSync()
	}

	return oc, nil
}

// OnSyncError sets callback for sync errors
func (oc *OfflineClient) OnSyncError(fn func(op *PendingOperation, err error)) {
	oc.onSyncError = fn
}

// OnSyncSuccess sets callback for successful syncs
func (oc *OfflineClient) OnSyncSuccess(fn func(op *PendingOperation)) {
	oc.onSyncSuccess = fn
}

// Put stores data, queuing for later if offline
func (oc *OfflineClient) Put(path string, data interface{}) error {
	encrypted, err := oc.encrypt(data)
	if err != nil {
		return err
	}

	// Try online first
	err = oc.Client.Put(path, data)
	if err == nil {
		oc.store.SetCache(path, encrypted)
		return nil
	}

	// If network error, queue for later
	if isNetworkError(err) {
		oc.store.SetCache(path, encrypted)
		oc.store.QueueOperation(&PendingOperation{
			Type: OpPut,
			Path: path,
			Data: encrypted,
		})
		return nil
	}

	return err
}

// Get retrieves data, falling back to cache if offline
func (oc *OfflineClient) Get(path string, result interface{}) error {
	// Try online first
	err := oc.Client.Get(path, result)
	if err == nil {
		// Update cache with fresh data
		if encrypted, err := oc.encrypt(result); err == nil {
			oc.store.SetCache(path, encrypted)
		}
		return nil
	}

	// If network error, try cache
	if isNetworkError(err) {
		if entry, ok := oc.store.GetCached(path); ok {
			return oc.decrypt(entry.Data, result)
		}
		return errors.New("offline and no cached data available")
	}

	return err
}

// Delete removes data, queuing for later if offline
func (oc *OfflineClient) Delete(path string) error {
	err := oc.Client.Delete(path)
	if err == nil {
		oc.store.RemoveCache(path)
		return nil
	}

	if isNetworkError(err) {
		oc.store.RemoveCache(path)
		oc.store.QueueOperation(&PendingOperation{
			Type: OpDelete,
			Path: path,
		})
		return nil
	}

	return err
}

// StartAutoSync starts background sync of pending operations
func (oc *OfflineClient) StartAutoSync() {
	if oc.syncTicker != nil {
		return
	}

	oc.syncTicker = time.NewTicker(oc.config.RetryInterval)
	go func() {
		for {
			select {
			case <-oc.syncTicker.C:
				oc.SyncPending()
			case <-oc.stopSync:
				return
			}
		}
	}()
}

// StopAutoSync stops background sync
func (oc *OfflineClient) StopAutoSync() {
	if oc.syncTicker != nil {
		oc.syncTicker.Stop()
		close(oc.stopSync)
		oc.syncTicker = nil
	}
}

// SyncPending attempts to sync all pending operations
func (oc *OfflineClient) SyncPending() {
	ops := oc.store.GetPendingOperations()
	for _, op := range ops {
		if op.Retries >= oc.config.MaxRetries {
			oc.store.RemoveOperation(op.ID)
			if oc.onSyncError != nil {
				oc.onSyncError(op, errors.New("max retries exceeded"))
			}
			continue
		}

		var err error
		switch op.Type {
		case OpPut:
			err = oc.syncPut(op)
		case OpDelete:
			err = oc.syncDelete(op)
		}

		if err == nil {
			oc.store.RemoveOperation(op.ID)
			if oc.onSyncSuccess != nil {
				oc.onSyncSuccess(op)
			}
		} else if isNetworkError(err) {
			oc.store.IncrementRetry(op.ID)
		} else {
			// Non-network error, remove from queue
			oc.store.RemoveOperation(op.ID)
			if oc.onSyncError != nil {
				oc.onSyncError(op, err)
			}
		}
	}
}

func (oc *OfflineClient) syncPut(op *PendingOperation) error {
	payload := map[string]string{
		"path": op.Path,
		"data": op.Data,
	}
	var response map[string]interface{}
	return oc.request("POST", "/api/sync/put", payload, &response)
}

func (oc *OfflineClient) syncDelete(op *PendingOperation) error {
	payload := map[string]string{"path": op.Path}
	var response map[string]interface{}
	return oc.request("POST", "/api/sync/delete", payload, &response)
}

// GetStore returns the offline store for direct access
func (oc *OfflineClient) GetStore() *OfflineStore {
	return oc.store
}

// HasPendingChanges returns true if there are unsync'd operations
func (oc *OfflineClient) HasPendingChanges() bool {
	return oc.store.HasPendingOperations()
}

// PendingCount returns the number of pending operations
func (oc *OfflineClient) PendingCount() int {
	return len(oc.store.GetPendingOperations())
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	// Check for common network error patterns
	msg := err.Error()
	return containsAny(msg, []string{
		"connection refused",
		"no such host",
		"network is unreachable",
		"timeout",
		"i/o timeout",
		"connection reset",
		"EOF",
		"dial tcp",
	})
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
