package seal

import (
	"net/http"

	"seal/internal/testutil"
	"seal/internal/timeauth"
)

// newTestDrandAuthority creates a test drand authority.
// This is duplicated in seal tests to avoid import cycles.
func newTestDrandAuthority(currentRound uint64) *timeauth.DrandAuthority {
	fakeHTTP := &testutil.FakeHTTPDoer{
		Responses: map[string]*http.Response{
			"/info":          testutil.MakeDrandInfoResponse(),
			"/public/latest": testutil.MakeDrandPublicResponse(currentRound),
		},
	}
	return timeauth.NewDrandAuthorityWithDeps(fakeHTTP, &testutil.FakeTimelockBox{})
}
