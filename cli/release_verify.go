package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchExpectedSha256 downloads the `<asset>.sha256` sidecar the release
// workflow publishes alongside every CLI package and worker image tarball,
// and returns the hex digest it contains. The sidecar is a tiny text file
// (either a bare hex digest, or the standard `sha256sum` two-column format
// "<hex>  <filename>") so we only need the first whitespace-delimited token.
//
// Verification is fail-closed: callers treat a missing/unreadable sidecar
// the same as a hash mismatch and refuse to install. `openbin update` and
// the first-run worker-image fetch both self-replace/execute what they
// download, so trusting bytes off the wire on TLS alone isn't enough — a
// compromised release pipeline or a tampered asset on GitHub's CDN would
// otherwise be installed and run with no second check.
func fetchExpectedSha256(assetURL string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(assetURL + ".sha256")
	if err != nil {
		return "", fmt.Errorf("fetch checksum for %s: %w", assetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch checksum for %s: HTTP %d", assetURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read checksum for %s: %w", assetURL, err)
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 || len(fields[0]) != hex.EncodedLen(sha256.Size) {
		return "", fmt.Errorf("checksum file for %s is malformed", assetURL)
	}
	return strings.ToLower(fields[0]), nil
}

// verifySha256 hex-encodes the SHA-256 digest of got and compares it against
// want (case-insensitive). Returns a descriptive error on mismatch so the
// caller can abort the install instead of running/loading tampered bytes.
func verifySha256(got []byte, want string) error {
	sum := sha256.Sum256(got)
	gotHex := hex.EncodeToString(sum[:])
	if !strings.EqualFold(gotHex, want) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s — refusing to install a tampered download", want, gotHex)
	}
	return nil
}
