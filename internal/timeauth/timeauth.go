package timeauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/drand/tlock"
	thttp "github.com/drand/tlock/networks/http"
)

// TimeAuthority is an external, verifiable source of truth for time-based unlocking.
type TimeAuthority interface {
	// Name returns the identifier for this time authority.
	Name() string

	// Lock creates a time-locked key reference for the given unlock time.
	// Returns an opaque key reference that can later be used to determine unlock eligibility.
	Lock(unlockTime time.Time) (KeyReference, error)

	// CanUnlock determines whether the unlock time has been reached.
	// Returns true if unlocking is permitted, false otherwise.
	CanUnlock(ref KeyReference, now time.Time) (bool, error)
}

// PlaceholderAuthority is a no-op time authority for testing and development.
// It never permits unlocking and does not support time-lock encryption.
type PlaceholderAuthority struct{}

func (p *PlaceholderAuthority) Name() string {
	return "placeholder"
}

func (p *PlaceholderAuthority) RoundAt(unlockTime time.Time) (uint64, error) {
	// Placeholder doesn't use rounds
	return 0, nil
}

func (p *PlaceholderAuthority) TimeLockEncrypt(data []byte, targetRound uint64) (string, error) {
	// Placeholder doesn't support time-lock encryption
	// Return empty string to indicate no tlock support (preserves old behavior)
	return "", nil
}

func (p *PlaceholderAuthority) TimeLockDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error) {
	// Placeholder doesn't support time-lock decryption
	// This should never be called since items without DEKTlockB64 don't materialize
	return nil, fmt.Errorf("placeholder authority does not support time-lock decryption")
}

func (p *PlaceholderAuthority) CanUnlock(ctx context.Context, targetRound uint64) (bool, error) {
	// Always returns false - no unlocking permitted
	return false, nil
}

// Lock creates a time-locked key reference for the given unlock time.
// Deprecated: For backward compatibility with old tests.
func (p *PlaceholderAuthority) Lock(unlockTime time.Time) (KeyReference, error) {
	// Return a dummy key reference
	return KeyReference("placeholder-key-ref"), nil
}

// CanUnlockRef checks if unlocking is permitted for a key reference.
// Deprecated: For backward compatibility with old tests.
func (p *PlaceholderAuthority) CanUnlockRef(ref KeyReference, now time.Time) (bool, error) {
	// Always returns false - no unlocking permitted
	return false, nil
}

// DrandKeyReference contains drand-specific information for time-locked keys.
type DrandKeyReference struct {
	Network     string `json:"network"`
	TargetRound uint64 `json:"target_round"`
}

// HTTPDoer is an interface for making HTTP requests.
// This allows injecting mock HTTP clients for testing.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// TimelockBox abstracts tlock encryption/decryption for testing.
type TimelockBox interface {
	// Encrypt time-locks the DEK to the target round.
	// Returns base64-encoded ciphertext.
	Encrypt(dek []byte, targetRound uint64) (string, error)

	// Decrypt decrypts the tlock ciphertext.
	// Ciphertext is base64-encoded.
	Decrypt(ciphertextB64 string) ([]byte, error)
}

// DrandAuthority is a time authority based on the drand public randomness beacon.
type DrandAuthority struct {
	NetworkName string
	BaseURL     string
	ChainHash   string
	HTTPClient  HTTPDoer    // injectable HTTP client
	Timelock    TimelockBox // injectable tlock implementation
	info        *DrandInfo  // cached network info
}

type DrandInfo struct {
	Period      int    `json:"period"`
	GenesisTime int64  `json:"genesis_time"`
	Hash        string `json:"hash"`
	GroupHash   string `json:"groupHash"`
	SchemeID    string `json:"schemeID"`
	BeaconID    string `json:"beaconID"`
}

type drandPublicResponse struct {
	Round      uint64 `json:"round"`
	Randomness string `json:"randomness"`
}

func (d *DrandAuthority) Name() string {
	return "drand"
}

// RoundAt calculates the drand round number for a given unlock time.
func (d *DrandAuthority) RoundAt(unlockTime time.Time) (uint64, error) {
	// Fetch network info to get period and genesis time
	info, err := d.FetchInfo()
	if err != nil {
		return 0, fmt.Errorf("failed to fetch drand info: %w", err)
	}

	// Calculate target round for the unlock time
	// Round number = (unix_time - genesis_time) / period
	unlockUnix := unlockTime.Unix()
	elapsedSeconds := unlockUnix - info.GenesisTime

	if elapsedSeconds < 0 {
		return 0, fmt.Errorf("unlock time is before drand genesis")
	}

	targetRound := uint64(elapsedSeconds) / uint64(info.Period)

	// Round up to ensure we're at or after the unlock time
	if uint64(elapsedSeconds)%uint64(info.Period) != 0 {
		targetRound++
	}

	return targetRound, nil
}

// TimeLockEncrypt encrypts data using tlock to the specified round.
func (d *DrandAuthority) TimeLockEncrypt(data []byte, targetRound uint64) (string, error) {
	return d.Timelock.Encrypt(data, targetRound)
}

// TimeLockDecrypt decrypts time-locked data using drand randomness.
func (d *DrandAuthority) TimeLockDecrypt(ctx context.Context, ciphertextB64 string) ([]byte, error) {
	return d.Timelock.Decrypt(ciphertextB64)
}

// CanUnlock checks if the target round has been reached.
func (d *DrandAuthority) CanUnlock(ctx context.Context, targetRound uint64) (bool, error) {
	currentRound, err := d.fetchLatestRound()
	if err != nil {
		return false, fmt.Errorf("failed to fetch latest round: %w", err)
	}

	return currentRound >= targetRound, nil
}

// Lock creates a time-locked key reference for the given unlock time.
// Deprecated: Use RoundAt() for new code. Kept for backward compatibility.
func (d *DrandAuthority) Lock(unlockTime time.Time) (KeyReference, error) {
	targetRound, err := d.RoundAt(unlockTime)
	if err != nil {
		return "", err
	}

	// Create key reference
	ref := DrandKeyReference{
		Network:     d.NetworkName,
		TargetRound: targetRound,
	}

	refJSON, err := json.Marshal(ref)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key reference: %w", err)
	}

	return KeyReference(refJSON), nil
}

// CanUnlockRef checks if unlocking is permitted for a key reference.
// Deprecated: For backward compatibility with old Lock/CanUnlock pattern.
func (d *DrandAuthority) CanUnlockRef(ref KeyReference, now time.Time) (bool, error) {
	// Parse key reference
	var drandRef DrandKeyReference
	if err := json.Unmarshal([]byte(ref), &drandRef); err != nil {
		return false, fmt.Errorf("invalid drand key reference: %w", err)
	}

	// Verify network matches
	if drandRef.Network != d.NetworkName {
		return false, fmt.Errorf("network mismatch: expected %s, got %s", d.NetworkName, drandRef.Network)
	}

	// Use the new CanUnlock method
	return d.CanUnlock(context.Background(), drandRef.TargetRound)
}

func (d *DrandAuthority) FetchInfo() (*DrandInfo, error) {
	// Return cached info if available
	if d.info != nil {
		return d.info, nil
	}

	url := d.BaseURL + "/info"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("drand info request failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info DrandInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	d.info = &info
	return &info, nil
}

func (d *DrandAuthority) fetchLatestRound() (uint64, error) {
	url := d.BaseURL + "/public/latest"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("drand latest round request failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var publicResp drandPublicResponse
	if err := json.Unmarshal(body, &publicResp); err != nil {
		return 0, err
	}

	return publicResp.Round, nil
}

func (d *DrandAuthority) fetchRoundRandomness(round uint64) ([]byte, error) {
	url := fmt.Sprintf("%s/public/%d", d.BaseURL, round)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("drand round %d request failed: %d", round, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var publicResp drandPublicResponse
	if err := json.Unmarshal(body, &publicResp); err != nil {
		return nil, err
	}

	// Decode hex-encoded randomness
	randomness, err := hex.DecodeString(publicResp.Randomness)
	if err != nil {
		return nil, fmt.Errorf("failed to decode randomness: %w", err)
	}

	return randomness, nil
}

// RealTimelockBox implements TimelockBox using the actual tlock library.
type RealTimelockBox struct {
	BaseURL   string
	ChainHash string
}

// Encrypt time-locks the DEK using tlock.
func (r *RealTimelockBox) Encrypt(dek []byte, targetRound uint64) (string, error) {
	network, err := thttp.NewNetwork(r.BaseURL, r.ChainHash)
	if err != nil {
		return "", fmt.Errorf("failed to create tlock network: %w", err)
	}

	var tlockCiphertext bytes.Buffer
	dekReader := bytes.NewReader(dek)

	if err := tlock.New(network).Encrypt(&tlockCiphertext, dekReader, targetRound); err != nil {
		return "", fmt.Errorf("failed to tlock encrypt DEK: %w", err)
	}

	return base64.StdEncoding.EncodeToString(tlockCiphertext.Bytes()), nil
}

// Decrypt decrypts the tlock ciphertext.
func (r *RealTimelockBox) Decrypt(ciphertextB64 string) ([]byte, error) {
	tlockCiphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tlock ciphertext: %w", err)
	}

	network, err := thttp.NewNetwork(r.BaseURL, r.ChainHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create tlock network: %w", err)
	}

	var dekBuffer bytes.Buffer
	tlockReader := bytes.NewReader(tlockCiphertext)

	if err := tlock.New(network).Decrypt(&dekBuffer, tlockReader); err != nil {
		return nil, err
	}

	return dekBuffer.Bytes(), nil
}

// drandQuicknetChainHash is the chain hash for drand quicknet.
const drandQuicknetChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

// NewDrandAuthority creates a drand authority for the quicknet network.
func NewDrandAuthority() *DrandAuthority {
	return NewDrandAuthorityWithDeps(http.DefaultClient, nil)
}

// NewDrandAuthorityWithDeps creates a drand authority with injectable dependencies.
func NewDrandAuthorityWithDeps(httpClient HTTPDoer, timelock TimelockBox) *DrandAuthority {
	baseURL := "https://api.drand.sh/" + drandQuicknetChainHash

	if timelock == nil {
		timelock = &RealTimelockBox{
			BaseURL:   "https://api.drand.sh",
			ChainHash: drandQuicknetChainHash,
		}
	}

	return &DrandAuthority{
		NetworkName: "quicknet",
		BaseURL:     baseURL,
		ChainHash:   drandQuicknetChainHash,
		HTTPClient:  httpClient,
		Timelock:    timelock,
	}
}
