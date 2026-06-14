package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectDockerSocket_DockerHost(t *testing.T) {
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "unix:///custom/docker.sock")
	if got := DetectDockerSocket(); got != "/custom/docker.sock" {
		t.Fatalf("DOCKER_HOST not honored: got %q", got)
	}

	// tcp:// is not a unix socket; detection must ignore it and fall back.
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
	if got := DetectDockerSocket(); got != DefaultDockerSocket {
		t.Fatalf("tcp DOCKER_HOST should fall back to default, got %q", got)
	}
}

func TestDetectDockerSocket_Context(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")

	// Active context "orbstack" -> ~/.docker/contexts/meta/<sha256(name)>/meta.json
	const ctxName = "orbstack"
	const sock = "/Users/alex/.orbstack/run/docker.sock"

	dockerDir := filepath.Join(home, ".docker")
	if err := os.MkdirAll(dockerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(`{"currentContext":"`+ctxName+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte(ctxName))
	metaDir := filepath.Join(dockerDir, "contexts", "meta", hex.EncodeToString(digest[:]))
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := `{"Name":"` + ctxName + `","Endpoints":{"docker":{"Host":"unix://` + sock + `"}}}`
	if err := os.WriteFile(filepath.Join(metaDir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := DetectDockerSocket(); got != sock {
		t.Fatalf("context endpoint not resolved: got %q want %q", got, sock)
	}
}

func TestUpstreamSocket_ExplicitWins(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///should/not/be/used.sock")
	d := &DockerConfig{SocketPath: "/explicit/docker.sock"}
	if got := d.UpstreamSocket(); got != "/explicit/docker.sock" {
		t.Fatalf("explicit socket_path should win, got %q", got)
	}
}
