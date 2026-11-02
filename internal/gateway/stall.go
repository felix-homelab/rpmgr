// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/felix-homelab/rpmgr/internal/tunnel"
)

// stallAfter is how long a relayed stream may copy no byte in either direction before the gateway
// logs it once at debug level (docs/03-connections.md, "Observability"); a test shortens it.
var stallAfter = 30 * time.Second

// watchStall logs a stream of route that has copied no byte in either direction for after: one
// debug line with the route, target, connector and the stream's byte counts, once per stream, and
// none for a stream that is moving. It costs a timer per stream and nothing per byte, and arms
// none when debug logging is off. The returned function ends the watch when the relay returns.
func watchStall(ctx context.Context, logger *slog.Logger, st tunnel.Stream, route, target string, after time.Duration) (stop func()) {
	ts, ok := st.(*trackedStream)
	if !ok || after <= 0 || !logger.Enabled(ctx, slog.LevelDebug) {
		return func() {}
	}
	var (
		mu    sync.Mutex
		timer *time.Timer
		ended bool
	)
	check := func() {
		mu.Lock()
		defer mu.Unlock()
		if ended {
			return
		}
		idle := ts.d.now().Sub(time.Unix(0, ts.last.Load()))
		if idle < after {
			timer.Reset(after - idle)
			return
		}
		logger.Debug("stream stalled", "route", route, "target", target, "connector", ts.d.connector,
			"idle", idle.Round(time.Millisecond), "bytes_from_client", ts.nIn.Load(), "bytes_to_client", ts.nOut.Load())
		// Not re-armed: one line per stream.
	}
	mu.Lock()
	timer = time.AfterFunc(after, check)
	mu.Unlock()
	return func() {
		mu.Lock()
		ended = true
		timer.Stop()
		mu.Unlock()
	}
}
