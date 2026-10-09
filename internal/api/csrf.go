// SPDX-License-Identifier: Apache-2.0

package api

import (
	"mime"
	"net/http"
	"slices"
	"strings"
)

// simpleTypes are the content types a cross-site form can send without a CORS preflight.
var simpleTypes = []string{"application/x-www-form-urlencoded", "multipart/form-data", "text/plain"}

// csrf guards an API handler against cross-site requests (docs/04-security.md, "Human
// authentication and sessions", CSRF): Go's CrossOriginProtection refuses requests a browser
// marks as cross-site, and on every request that is not a GET or HEAD an Origin, if present, must
// be one of the controller's origins, and the content type must be one a form cannot send.
func (s *Server) csrf(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	return cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && s.o.Origins != nil {
			allowed, err := s.o.Origins(r.Context())
			if err != nil || !slices.Contains(allowed, strings.TrimSuffix(origin, "/")) {
				http.Error(w, "api: cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || slices.Contains(simpleTypes, ct) {
			http.Error(w, "api: unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		next.ServeHTTP(w, r)
	}))
}
