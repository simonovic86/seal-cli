//go:build !testmode

package main

import "net/http"

// newDefaultDrandAuthority creates a DrandAuthority for production use.
func newDefaultDrandAuthority() *DrandAuthority {
	return NewDrandAuthorityWithDeps(http.DefaultClient, nil)
}
