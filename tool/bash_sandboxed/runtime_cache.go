package bash_sandboxed

import (
	"encoding/json"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"time"
)

// Runtime path detection (e.g. `go env`, `pnpm store path`) spawns subprocesses
// that can take hundreds of milliseconds. The PreToolUse hook runs as a fresh
// process on every tool call, so an in-process cache cannot amortize that cost;
// results are persisted to a small JSON file instead. Entries carry the
// environment variables that influence the detected paths and expire after
// runtimeDetectCacheTTL, so a changed environment or relocated store is picked
// up promptly.

// runtimeDetectCacheTTL bounds how long a persisted detection result is reused.
const runtimeDetectCacheTTL = time.Hour

type runtimeCacheEntry struct {
	Paths     []string          `json:"paths"`
	ExpiresAt time.Time         `json:"expires_at"`
	Env       map[string]string `json:"env,omitempty"`
}

type runtimeCacheFile struct {
	Entries map[string]runtimeCacheEntry `json:"entries"`
}

// runtimeCachePath returns the persistent cache file location, or "" when no
// user cache directory is available (caching is then skipped).
func runtimeCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "lite-sandbox", "runtime-paths.json")
}

// envFingerprint captures the current values of the environment variables that
// influence a runtime's detected paths, so cache entries are invalidated when
// the environment changes.
func envFingerprint(keys []string) map[string]string {
	fp := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			fp[k] = v
		}
	}
	return fp
}

// cachedDetect returns the detection result for name from the persistent cache
// when it is fresh and was produced under the same environment, otherwise runs
// detect and refreshes the cache. Empty results are returned but not cached, so
// a transient detection failure does not stick for the full TTL.
func cachedDetect(name string, envKeys []string, detect func() []string) []string {
	cachePath := runtimeCachePath()
	if cachePath == "" {
		return detect()
	}
	fp := envFingerprint(envKeys)
	cache := loadRuntimeCache(cachePath)
	if e, ok := cache.Entries[name]; ok && time.Now().Before(e.ExpiresAt) && maps.Equal(e.Env, fp) {
		return e.Paths
	}
	paths := detect()
	if len(paths) == 0 {
		return paths
	}
	cache.Entries[name] = runtimeCacheEntry{
		Paths:     paths,
		ExpiresAt: time.Now().Add(runtimeDetectCacheTTL),
		Env:       fp,
	}
	saveRuntimeCache(cachePath, cache)
	return paths
}

// loadRuntimeCache reads the cache file, returning an empty cache on any error
// (missing file, corrupt JSON) so callers always get a usable value.
func loadRuntimeCache(path string) runtimeCacheFile {
	cache := runtimeCacheFile{Entries: map[string]runtimeCacheEntry{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return cache
	}
	if err := json.Unmarshal(data, &cache); err != nil || cache.Entries == nil {
		cache.Entries = map[string]runtimeCacheEntry{}
	}
	return cache
}

// saveRuntimeCache writes the cache atomically (temp file + rename) so
// concurrent hook processes never observe a partially written file. Failures
// are logged and otherwise ignored; the cache is purely an optimization.
func saveRuntimeCache(path string, cache runtimeCacheFile) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		slog.Debug("failed to create runtime cache directory", "error", err)
		return
	}
	data, err := json.Marshal(cache)
	if err != nil {
		slog.Debug("failed to marshal runtime cache", "error", err)
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runtime-paths-*.json")
	if err != nil {
		slog.Debug("failed to create runtime cache temp file", "error", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		slog.Debug("failed to write runtime cache", "error", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		slog.Debug("failed to replace runtime cache", "error", err)
	}
}
