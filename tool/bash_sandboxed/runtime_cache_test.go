package bash_sandboxed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// setCacheDir points the runtime cache at a file in a temp directory. The
// explicit override is required for hermeticity: os.UserCacheDir ignores
// XDG_CACHE_HOME on macOS, so redirecting via env cache dirs is not portable.
func setCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LITE_SANDBOX_RUNTIME_CACHE", filepath.Join(dir, "runtime-paths.json"))
	return dir
}

func TestCachedDetect_CachesResult(t *testing.T) {
	setCacheDir(t)

	calls := 0
	detect := func() []string {
		calls++
		return []string{"/some/path"}
	}

	got := cachedDetect("testrt", nil, detect)
	if !reflect.DeepEqual(got, []string{"/some/path"}) {
		t.Fatalf("first call returned %v", got)
	}
	got = cachedDetect("testrt", nil, detect)
	if !reflect.DeepEqual(got, []string{"/some/path"}) {
		t.Fatalf("second call returned %v", got)
	}
	if calls != 1 {
		t.Fatalf("detect ran %d times, want 1 (second call should hit the cache)", calls)
	}
}

func TestCachedDetect_EnvChangeInvalidates(t *testing.T) {
	setCacheDir(t)
	t.Setenv("LITE_SANDBOX_TEST_ENV", "a")

	calls := 0
	detect := func() []string {
		calls++
		return []string{"/some/path"}
	}

	cachedDetect("testrt", []string{"LITE_SANDBOX_TEST_ENV"}, detect)
	t.Setenv("LITE_SANDBOX_TEST_ENV", "b")
	cachedDetect("testrt", []string{"LITE_SANDBOX_TEST_ENV"}, detect)
	if calls != 2 {
		t.Fatalf("detect ran %d times, want 2 (env change should invalidate)", calls)
	}
}

func TestCachedDetect_ExpiryInvalidates(t *testing.T) {
	setCacheDir(t)

	calls := 0
	detect := func() []string {
		calls++
		return []string{"/some/path"}
	}

	cachedDetect("testrt", nil, detect)

	// Rewrite the entry as already expired.
	path := runtimeCachePath()
	cache := loadRuntimeCache(path)
	e := cache.Entries["testrt"]
	e.ExpiresAt = time.Now().Add(-time.Minute)
	cache.Entries["testrt"] = e
	saveRuntimeCache(path, cache)

	cachedDetect("testrt", nil, detect)
	if calls != 2 {
		t.Fatalf("detect ran %d times, want 2 (expired entry should re-detect)", calls)
	}
}

func TestCachedDetect_EmptyResultNotCached(t *testing.T) {
	setCacheDir(t)

	calls := 0
	detect := func() []string {
		calls++
		return nil
	}

	cachedDetect("testrt", nil, detect)
	cachedDetect("testrt", nil, detect)
	if calls != 2 {
		t.Fatalf("detect ran %d times, want 2 (empty results must not be cached)", calls)
	}
}

func TestCachedDetect_CorruptCacheFile(t *testing.T) {
	setCacheDir(t)

	path := runtimeCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := cachedDetect("testrt", nil, func() []string { return []string{"/p"} })
	if !reflect.DeepEqual(got, []string{"/p"}) {
		t.Fatalf("got %v, want detection result despite corrupt cache", got)
	}

	// The rewritten file must be valid JSON.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cache runtimeCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatalf("cache file is not valid JSON after rewrite: %v", err)
	}
}
