// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
)

// ControlHandler receives challenge updates over HTTP, standing in for the control session when
// the controller runs in another process. In rpmgr the update travels in the mutually
// authenticated control session; here a bearer token on loopback replaces that authentication.
func ControlHandler(g *Gateway, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		got := []byte(r.Header.Get("Authorization"))
		if token == "" || subtle.ConstantTimeCompare(got, []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		var u ChallengeUpdate
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&u); err != nil {
			http.Error(w, "bad update", http.StatusBadRequest)
			return
		}
		if err := g.ApplyChallenge(r.Context(), u); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
