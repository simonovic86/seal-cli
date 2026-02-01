//go:build testmode

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// testModeHTTPDoer is a mock HTTP client for test mode.
type testModeHTTPDoer struct{}

func (t *testModeHTTPDoer) Do(req *http.Request) (*http.Response, error) {
	path := req.URL.Path

	// Handle /info endpoint
	if strings.HasSuffix(path, "/info") {
		info := drandInfo{
			Period:      3,
			GenesisTime: 1677685200,
			Hash:        drandQuicknetChainHash,
			SchemeID:    "bls-unchained-on-g1",
			BeaconID:    "quicknet",
		}
		body, _ := json.Marshal(info)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(body)),
		}, nil
	}

	// Handle /public/latest endpoint
	if strings.HasSuffix(path, "/public/latest") {
		// Calculate current round based on real time
		// Genesis: 1677685200 (2023-03-01 13:00:00 UTC), Period: 3 seconds
		genesisTime := int64(1677685200)
		period := int64(3)
		now := time.Now().Unix()
		currentRound := uint64((now - genesisTime) / period)
		
		resp := drandPublicResponse{
			Round:      currentRound,
			Randomness: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		}
		body, _ := json.Marshal(resp)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(body)),
		}, nil
	}

	// Default: return 404
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

// testModeTimelockBox is a fake tlock implementation for test mode.
type testModeTimelockBox struct{}

func (t *testModeTimelockBox) Encrypt(dek []byte, targetRound uint64) (string, error) {
	return "TESTMODE_TLOCK:" + base64.StdEncoding.EncodeToString(dek), nil
}

func (t *testModeTimelockBox) Decrypt(ciphertextB64 string) ([]byte, error) {
	if strings.HasPrefix(ciphertextB64, "TESTMODE_TLOCK:") {
		return base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertextB64, "TESTMODE_TLOCK:"))
	}
	return nil, io.ErrUnexpectedEOF
}

// newDefaultDrandAuthority creates a DrandAuthority for test mode.
func newDefaultDrandAuthority() *DrandAuthority {
	return NewDrandAuthorityWithDeps(&testModeHTTPDoer{}, &testModeTimelockBox{})
}
