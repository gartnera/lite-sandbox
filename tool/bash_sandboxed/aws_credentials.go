package bash_sandboxed

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// AWS clients report every failure to get credentials from the brokered IMDS
// server the same way — the AWS CLI and boto3 say "Unable to locate
// credentials", having discarded the server's error — so an agent cannot tell
// an expired SSO session on the host from a sandbox restriction, and tends to
// retry or work around it. The IMDS servers record why a fetch failed; after a
// command runs, the sandbox asks for failures recorded while it ran and
// appends a note saying what went wrong and what the user must do on the host.

// SetAWSCredentialNotes installs (or clears, with nil) the function that
// reports brokered AWS credential failures recorded at or after a time, one
// agent-facing note per failing profile. The IMDS lifecycle owns the servers
// and provides it.
func (s *Sandbox) SetAWSCredentialNotes(fn func(since time.Time) []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.awsCredNotes = fn
}

// awsCredentialNote returns the notes for credential failures since the given
// time, joined into one block, or "" when there were none.
func (s *Sandbox) awsCredentialNote(since time.Time) string {
	s.mu.RLock()
	fn := s.awsCredNotes
	s.mu.RUnlock()
	if fn == nil {
		return ""
	}
	return strings.Join(fn(since), "\n")
}

// withAWSCredentialNote appends the credential note for failures since the
// given time (if any) to a finished command's output, and to the output a
// CommandFailedError carries, so it reaches the agent whether or not the
// command exited non-zero (`aws … || true` still saw no credentials).
func (s *Sandbox) withAWSCredentialNote(since time.Time, output string, err error) (string, error) {
	note := s.awsCredentialNote(since)
	if note == "" {
		return output, err
	}
	output = appendNote(output, note)
	var failed *CommandFailedError
	switch {
	case errors.As(err, &failed):
		failed.Output = appendNote(failed.Output, note)
	case err != nil:
		err = fmt.Errorf("%w\n%s", err, note)
	}
	return output, err
}

// writeAWSCredentialNote writes the credential note for failures since the
// given time (if any) to w, for callers that stream output (background
// processes, the interactive shell).
func (s *Sandbox) writeAWSCredentialNote(since time.Time, w io.Writer) {
	if note := s.awsCredentialNote(since); note != "" {
		fmt.Fprintf(w, "\n%s\n", note)
	}
}

func appendNote(output, note string) string {
	if output != "" && !strings.HasSuffix(output, "\n") {
		output += "\n"
	}
	return output + "\n" + note + "\n"
}

// awsMetadataTimeoutSeconds is the per-request IMDS timeout injected for
// botocore-based clients (AWS CLI v1/v2, boto3) as AWS_METADATA_SERVICE_TIMEOUT.
// botocore's default is 1 second with a single attempt, but the first request
// for a profile can wait on a network round trip on the host (SSO
// GetRoleCredentials, an SSO token refresh, STS AssumeRole); when it takes
// longer the client gives up and reports no credentials. It matches the IMDS
// server's own deadline for a credential fetch.
const awsMetadataTimeoutSeconds = "30"
