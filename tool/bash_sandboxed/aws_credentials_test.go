package bash_sandboxed

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const testCredNote = "lite-sandbox: AWS credentials for profile \"dev\" are unavailable"

// credNotes returns a reporter that reports testCredNote for any since at or
// before failAt, like an IMDS server whose fetch failed at failAt.
func credNotes(failAt time.Time) func(time.Time) []string {
	return func(since time.Time) []string {
		if failAt.Before(since) {
			return nil
		}
		return []string{testCredNote}
	}
}

// TestExecute_AWSCredentialNote: a credential failure recorded while a command
// ran is explained after its output, for a failing command (in the error the
// MCP server shows) and for one that exited 0 anyway.
func TestExecute_AWSCredentialNote(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.SetAWSCredentialNotes(credNotes(time.Now().Add(time.Hour))) // "during" every command below

	out, err := s.Execute(context.Background(), `echo 'Unable to locate credentials' >&2; exit 253`, workDir, []string{workDir}, []string{workDir})
	var failed *CommandFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("want CommandFailedError, got %v", err)
	}
	if !strings.Contains(err.Error(), testCredNote) || !strings.Contains(out, testCredNote) {
		t.Errorf("note missing from failure:\nerr: %v\nout: %q", err, out)
	}
	if !strings.HasPrefix(out, "Unable to locate credentials\n\n") {
		t.Errorf("note should follow the command's own output, got %q", out)
	}

	out, err = s.Execute(context.Background(), `echo ok`, workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, testCredNote) {
		t.Errorf("note missing from a command that exited 0: %q", out)
	}
}

// TestExecute_AWSCredentialNote_OnlyDuringCommand: a failure from before the
// command started (an earlier command, or the startup pre-warm) is not
// reported, nor is anything when no IMDS server is running.
func TestExecute_AWSCredentialNote_OnlyDuringCommand(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	out, err := s.Execute(context.Background(), `echo ok`, workDir, []string{workDir}, []string{workDir})
	if err != nil || out != "ok\n" {
		t.Fatalf("no reporter: out %q err %v", out, err)
	}

	s.SetAWSCredentialNotes(credNotes(time.Now().Add(-time.Minute)))
	out, err = s.Execute(context.Background(), `echo ok`, workDir, []string{workDir}, []string{workDir})
	if err != nil || out != "ok\n" {
		t.Fatalf("stale failure should not be reported: out %q err %v", out, err)
	}
}

// TestExecute_AWSCredentialNote_ValidationErrorUntouched: a command refused
// before it ran fetched nothing, so it gets no note.
func TestExecute_AWSCredentialNote_ValidationErrorUntouched(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.SetAWSCredentialNotes(credNotes(time.Now().Add(time.Hour)))
	_, err := s.Execute(context.Background(), `definitely-not-a-command`, workDir, []string{workDir}, []string{workDir})
	if err == nil || strings.Contains(err.Error(), testCredNote) {
		t.Fatalf("validation error should carry no note, got %v", err)
	}
}

func TestBackground_AWSCredentialNote(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	defer s.Close()
	s.SetAWSCredentialNotes(credNotes(time.Now().Add(time.Hour)))
	proc, err := s.ExecuteBackground(`echo started`, workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := s.ListBackground()
		if len(st) == 1 && st[0].Status != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background process did not finish")
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, err := os.ReadFile(proc.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), testCredNote) {
		t.Errorf("note missing from background output: %q", b)
	}
}

// TestAWSBaseEnv_MetadataTimeout: brokered mode raises botocore's 1s IMDS
// timeout so a cold credential fetch on the host is waited for, unless the
// environment already chose a timeout.
func TestAWSBaseEnv_MetadataTimeout(t *testing.T) {
	clearAWSRegionEnv(t)
	t.Setenv("AWS_METADATA_SERVICE_TIMEOUT", "")
	os.Unsetenv("AWS_METADATA_SERVICE_TIMEOUT")

	if got := awsBaseEnv([]string{"PATH=/bin"}, "", ""); slices.ContainsFunc(got, func(kv string) bool {
		return strings.HasPrefix(kv, "AWS_METADATA_SERVICE_TIMEOUT=")
	}) {
		t.Errorf("no timeout without IMDS, got %v", got)
	}
	if got := awsBaseEnv([]string{"PATH=/bin"}, "http://ep/", ""); !slices.Contains(got, "AWS_METADATA_SERVICE_TIMEOUT="+awsMetadataTimeoutSeconds) {
		t.Errorf("expected timeout injected, got %v", got)
	}

	t.Setenv("AWS_METADATA_SERVICE_TIMEOUT", "5")
	got := awsBaseEnv([]string{"PATH=/bin", "AWS_METADATA_SERVICE_TIMEOUT=5"}, "http://ep/", "")
	if slices.Contains(got, "AWS_METADATA_SERVICE_TIMEOUT="+awsMetadataTimeoutSeconds) {
		t.Errorf("an explicit timeout should be kept, got %v", got)
	}
}
