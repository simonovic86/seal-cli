package testutil

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// FakeHTTPDoer is a mock HTTP client for testing.
type FakeHTTPDoer struct {
	// Responses maps URL path suffixes to responses
	Responses map[string]*http.Response
	// Errors maps URL path suffixes to errors
	Errors map[string]error
}

func (f *FakeHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	path := req.URL.Path
	// Check for path suffix matches
	for suffix, err := range f.Errors {
		if strings.HasSuffix(path, suffix) {
			return nil, err
		}
	}
	for suffix, resp := range f.Responses {
		if strings.HasSuffix(path, suffix) {
			// Clone the response body for reuse
			return CloneResponse(resp), nil
		}
	}
	// Return 404 for unknown paths
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

// CloneResponse creates a copy of an http.Response with a fresh body reader.
// Fixed: Read once, create fresh readers for both original and clone.
func CloneResponse(resp *http.Response) *http.Response {
	// We need to clone the response because the body can only be read once
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Reset the original response body for potential future reuse
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	
	return &http.Response{
		StatusCode: resp.StatusCode,
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}
}

// MakeDrandInfoResponse creates a fake drand /info response.
func MakeDrandInfoResponse() *http.Response {
	info := struct {
		Period      int    `json:"period"`
		GenesisTime int64  `json:"genesis_time"`
		Hash        string `json:"hash"`
		GroupHash   string `json:"groupHash"`
		SchemeID    string `json:"schemeID"`
		BeaconID    string `json:"beaconID"`
	}{
		Period:      3,
		GenesisTime: 1677685200, // Fixed genesis time for deterministic tests
		Hash:        "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
		SchemeID:    "bls-unchained-on-g1",
		BeaconID:    "quicknet",
	}
	body, _ := json.Marshal(info)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// MakeDrandPublicResponse creates a fake drand /public/latest or /public/<round> response.
func MakeDrandPublicResponse(round uint64) *http.Response {
	resp := struct {
		Round      uint64 `json:"round"`
		Randomness string `json:"randomness"`
	}{
		Round:      round,
		Randomness: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// FakeTimelockBox is a mock tlock implementation for testing.
// It uses a simple reversible encoding (base64 with prefix) instead of actual encryption.
type FakeTimelockBox struct {
	// EncryptError can be set to simulate encryption failures
	EncryptError error
	// DecryptError can be set to simulate decryption failures
	DecryptError error
	// DecryptedDEK can be set to return a specific DEK on decrypt
	DecryptedDEK []byte
}

func (f *FakeTimelockBox) Encrypt(dek []byte, targetRound uint64) (string, error) {
	if f.EncryptError != nil {
		return "", f.EncryptError
	}
	// Simple fake: base64 encode with prefix to identify as fake
	return "FAKE_TLOCK:" + base64.StdEncoding.EncodeToString(dek), nil
}

func (f *FakeTimelockBox) Decrypt(ciphertextB64 string) ([]byte, error) {
	if f.DecryptError != nil {
		return nil, f.DecryptError
	}
	if f.DecryptedDEK != nil {
		return f.DecryptedDEK, nil
	}
	// Reverse the fake encoding
	if strings.HasPrefix(ciphertextB64, "FAKE_TLOCK:") {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertextB64, "FAKE_TLOCK:"))
	}
	// For backwards compatibility with real tlock ciphertext, return error
	return nil, io.ErrUnexpectedEOF
}

// FormatRoundURL converts a round number to a URL path component.
// Fixed: Use strconv.FormatUint instead of string(rune(round)) to properly convert round numbers.
func FormatRoundURL(round uint64) string {
	return "/public/" + strconv.FormatUint(round, 10)
}

// SetupTestEnv creates an isolated HOME environment for testing.
// Returns the temporary home directory and a cleanup function.
func SetupTestEnv(t *testing.T) (homeDir string, cleanup func()) {
	t.Helper()
	tmpHome := t.TempDir()
	
	oldHome := os.Getenv("HOME")
	oldXDGDataHome := os.Getenv("XDG_DATA_HOME")
	
	os.Setenv("HOME", tmpHome)
	os.Setenv("XDG_DATA_HOME", "")
	
	cleanup = func() {
		os.Setenv("HOME", oldHome)
		os.Setenv("XDG_DATA_HOME", oldXDGDataHome)
	}
	
	return tmpHome, cleanup
}

// BuildSealBinary builds the seal binary with testmode tag for testing.
// Returns the path to the built binary.
// Works from any test location by building from module root.
func BuildSealBinary(t *testing.T) string {
	t.Helper()
	
	binPath := t.TempDir() + "/seal-test"
	// Build from module root - use . to build the current package (main in cmd/seal)
	// When called from cmd/seal tests, we're already in cmd/seal so build current dir
	// When called from other tests, we need to specify ./cmd/seal
	// Solution: Always use ./cmd/seal with working dir at module root
	buildCmd := exec.Command("go", "build", "-tags", "testmode", "-o", binPath, ".")
	
	if output, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, output)
	}
	
	return binPath
}

// UUIDRegex is a compiled regex for validating UUID format.
var UUIDRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsUUID validates that a string is a valid UUID.
func IsUUID(s string) bool {
	return UUIDRegex.MatchString(s)
}
