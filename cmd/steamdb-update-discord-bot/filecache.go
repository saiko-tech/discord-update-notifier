package main

import (
	"bytes"
	"os"
	"sync"

	"go.uber.org/zap"
)

// CacheEntry represents a cached file with its data
type CacheEntry struct {
	Data []byte
}

// FileCache stores file contents in memory to reduce GCS operations
type FileCache struct {
	cache map[string]CacheEntry
	mu    sync.RWMutex
}

// NewFileCache creates a new file cache
func NewFileCache() *FileCache {
	return &FileCache{
		cache: make(map[string]CacheEntry),
	}
}

// Get retrieves a file from cache or reads it from disk
func (fc *FileCache) Get(path string) ([]byte, error) {
	fc.mu.RLock()
	entry, exists := fc.cache[path]
	fc.mu.RUnlock()

	if exists {
		zap.S().Debugw("file cache hit", "path", path)
		return entry.Data, nil
	}

	zap.S().Debugw("file cache miss", "path", path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fc.mu.Lock()
	fc.cache[path] = CacheEntry{
		Data: data,
	}
	fc.mu.Unlock()

	return data, nil
}

// Set stores a file in cache and writes it to disk
func (fc *FileCache) Set(path string, data []byte) error {
	if bytes.Equal(fc.cache[path].Data, data) {
		return nil // skip if not changed
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return err
	}

	fc.mu.Lock()
	fc.cache[path] = CacheEntry{
		Data: data,
	}
	fc.mu.Unlock()

	return nil
}

// Invalidate removes a file from cache
func (fc *FileCache) Invalidate(path string) {
	fc.mu.Lock()
	delete(fc.cache, path)
	fc.mu.Unlock()
}
