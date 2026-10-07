// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// WatchEvery is how often the connector looks at its policy file; SIGHUP, which `rpmgr policy`
// sends through `systemctl reload`, reloads it at once (docs/03-connections.md, "Timeouts,
// keepalive and backoff").
const WatchEvery = 2 * time.Second

// Watcher keeps the policy in force: it reloads the file when it changes and on SIGHUP, and tells
// the connector, which re-evaluates its routes' readiness without a new revision.
type Watcher struct {
	path     string
	onChange func(*Policy, error)
	every    time.Duration
	cur      atomic.Pointer[Policy]

	mu   sync.Mutex
	last fileState
}

type fileState struct {
	exists  bool
	size    int64
	modTime time.Time
	mode    os.FileMode
}

func stat(path string) fileState {
	st, err := os.Stat(path)
	if err != nil {
		return fileState{}
	}
	return fileState{exists: true, size: st.Size(), modTime: st.ModTime(), mode: st.Mode()}
}

// NewWatcher loads the policy at path; onChange, which may be nil, gets every policy loaded after
// a change, with the error of a file that does not load.
func NewWatcher(path string, onChange func(*Policy, error)) *Watcher {
	w := &Watcher{path: path, onChange: onChange, every: WatchEvery}
	w.mu.Lock()
	w.last = stat(path)
	w.mu.Unlock()
	p, _ := Load(path)
	w.cur.Store(p)
	return w
}

// Current returns the policy in force.
func (w *Watcher) Current() *Policy { return w.cur.Load() }

// Reload loads the file again and reports the new policy.
func (w *Watcher) Reload() {
	w.mu.Lock()
	w.last = stat(w.path)
	w.mu.Unlock()
	p, err := Load(w.path)
	w.cur.Store(p)
	if w.onChange != nil {
		w.onChange(p, err)
	}
}

// Run reloads on SIGHUP and when the file changed, until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	t := time.NewTicker(w.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			w.Reload()
		case <-t.C:
			w.mu.Lock()
			changed := stat(w.path) != w.last
			w.mu.Unlock()
			if changed {
				w.Reload()
			}
		}
	}
}
