// SPDX-License-Identifier: Apache-2.0

package apisvc_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/gen/rpmgr/v1/rpmgrv1connect"
	"github.com/felix-homelab/rpmgr/internal/api"
)

// TestRequestSize (docs/03-connections.md, "Timeouts, keepalive and backoff"): a request message
// above api.MaxRequestBytes is refused before it is handled, also when it is sent compressed and
// small on the wire, and also to a caller that is not signed in; one below the limit reaches the
// method's own checks.
func TestRequestSize(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	b := e.browser()
	plain := rpmgrv1connect.NewAuthServiceClient(&http.Client{Transport: b}, e.url)
	gzipped := rpmgrv1connect.NewAuthServiceClient(&http.Client{Transport: b}, e.url, connect.WithSendGzip())
	login := func(c rpmgrv1connect.AuthServiceClient, n int) error {
		_, err := c.Login(ctx, connect.NewRequest(&rpmgrv1.LoginRequest{Email: "ada@example.com", Password: strings.Repeat("a", n)}))
		return err
	}
	for name, c := range map[string]rpmgrv1connect.AuthServiceClient{"plain": plain, "gzip": gzipped} {
		if err := login(c, api.MaxRequestBytes+1); code(err) != connect.CodeResourceExhausted {
			t.Errorf("%s, above the limit: %v", name, err)
		}
		if err := login(c, api.MaxRequestBytes-1024); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s, below the limit: %v", name, err)
		}
	}
}
