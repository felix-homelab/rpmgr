// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	rpmgrv1 "github.com/felix-homelab/rpmgr/gen/rpmgr/v1"
	"github.com/felix-homelab/rpmgr/internal/controller"
	"github.com/felix-homelab/rpmgr/internal/release"
	"github.com/felix-homelab/rpmgr/internal/settings"
)

// stepClock is a clock the test moves forward.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *stepClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// woken reports whether the release check was asked to run, taking the request.
func woken(c *controller.ReleaseChecks) bool {
	select {
	case <-c.Wakes():
		return true
	default:
		return false
	}
}

// TestReleaseChecks (#890): "Check now" wakes the release check once, joins a check asked for or
// running, and is refused for a gap after the last check started and while the release source
// limits the rate; each check records when it ended and how: ok, failed with its error (the mirror
// keeping what it had), or off. A build that checks for no releases refuses it.
func TestReleaseChecks(t *testing.T) {
	e := newMirrorEnv(t, "1.4.2")
	e.releases["1.4.2"] = signedRelease(t, "1.4.2", 87, release.Stable)
	clock := &stepClock{now: relNow}
	e.o.Mirror.Now = clock.Now
	checks := controller.NewReleaseChecks(e.o.Mirror)
	e.o.Checks = checks

	if st := checks.Status(); st.GetRunning() || st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_UNSPECIFIED || st.GetCheckTime() != nil {
		t.Errorf("before the first check: %v", st)
	}
	st, wait, err := checks.CheckNow()
	if err != nil || wait != 0 || !st.GetRunning() || !woken(checks) {
		t.Fatalf("check now: %v %v %v", st, wait, err)
	}
	if st, wait, err := checks.CheckNow(); err != nil || wait != 0 || !st.GetRunning() || woken(checks) {
		t.Errorf("asked again before it ran: %v %v %v, or it woke the check twice", st, wait, err)
	}
	clock.add(time.Second)
	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Fatal(err)
	}
	st = checks.Status()
	if st.GetRunning() || st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OK || !st.GetCheckTime().AsTime().Equal(relNow.Add(time.Second)) ||
		st.GetError() != "" || e.lister.asked != 1 {
		t.Errorf("after the check: %v, listed %d times", st, e.lister.asked)
	}

	// Within the gap after the start, a check is refused and nothing is woken.
	clock.add(30 * time.Second)
	if _, wait, err := checks.CheckNow(); err != nil || wait != 30*time.Second || woken(checks) {
		t.Errorf("within the gap: wait %v, %v", wait, err)
	}

	// A failed check is recorded with its error; a rate limit refuses checks until it ends.
	clock.add(controller.ReleaseCheckGap)
	if _, wait, err := checks.CheckNow(); err != nil || wait != 0 || !woken(checks) {
		t.Fatalf("after the gap: wait %v, %v", wait, err)
	}
	e.lister.err = &release.RateLimitedError{Until: clock.Now().Add(40 * time.Minute)}
	if err := controller.CheckRelease(e.sys, e.o); err == nil {
		t.Fatal("a rate-limited check succeeded")
	}
	st = checks.Status()
	if st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED || st.GetError() == "" || st.GetRunning() {
		t.Errorf("a failed check: %v", st)
	}
	if !e.o.Mirror.Complete("1.4.2") {
		t.Error("a failed check lost the mirror's own version")
	}
	clock.add(2 * time.Minute)
	if _, wait, err := checks.CheckNow(); err != nil || wait != 38*time.Minute || woken(checks) {
		t.Errorf("while rate limited: wait %v, %v", wait, err)
	}

	// A source that is down fails the check with its error; the next succeeds again.
	clock.add(time.Hour)
	e.lister.err = errors.New("dial tcp: no route to host")
	if err := controller.CheckRelease(e.sys, e.o); err == nil {
		t.Fatal("a check of a source that is down succeeded")
	}
	if st := checks.Status(); st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_FAILED || !strings.Contains(st.GetError(), "no route to host") {
		t.Errorf("a source that is down: %v", st)
	}

	// With the release check off, a check keeps only what rollouts need and records "off".
	if _, err := settings.UpdateInstance(e.sys, e.db, &rpmgrv1.InstanceSettings{ReleaseCheck: new(false)},
		&fieldmaskpb.FieldMask{Paths: []string{"release_check"}}, 0); err != nil {
		t.Fatal(err)
	}
	if err := controller.CheckRelease(e.sys, e.o); err != nil {
		t.Fatal(err)
	}
	if st := checks.Status(); st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OFF || st.GetError() != "" {
		t.Errorf("switched off: %v", st)
	}

	// A check that ctx ends records nothing but that it no longer runs.
	ctx, cancel := context.WithCancel(e.sys)
	cancel()
	_ = controller.CheckRelease(ctx, e.o)
	if st := checks.Status(); st.GetRunning() || st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OFF {
		t.Errorf("a cancelled check: %v", st)
	}

	for _, m := range []*release.Mirror{{Version: "dev", Roots: e.o.Mirror.Roots}, {Version: "1.4.2"}} {
		none := controller.NewReleaseChecks(m)
		if _, _, err := none.CheckNow(); !errors.Is(err, release.ErrDevelopment) {
			t.Errorf("%s with %d roots: check now %v", m.Version, len(m.Roots), err)
		}
		if st := none.Status(); st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_NONE {
			t.Errorf("%s with %d roots: %v", m.Version, len(m.Roots), st)
		}
	}
	var unset *controller.ReleaseChecks
	unset.Wake()
	if _, _, err := unset.CheckNow(); !errors.Is(err, release.ErrDevelopment) {
		t.Errorf("no release check: %v", err)
	}
}

// TestReleaseCheck_CheckNow: the running release check starts a check at once when asked to.
func TestReleaseCheck_CheckNow(t *testing.T) {
	e := newMirrorEnv(t, "1.4.2")
	e.releases["1.4.2"] = signedRelease(t, "1.4.2", 87, release.Stable)
	clock := &stepClock{now: relNow}
	e.o.Mirror.Now = clock.Now
	checks := controller.NewReleaseChecks(e.o.Mirror)
	lister := &countingLister{}
	e.o.Lister, e.o.Wake, e.o.Checks = lister, checks.Wakes(), checks
	ctx, cancel := context.WithCancel(e.sys)
	done := make(chan struct{})
	go func() { controller.ReleaseCheck(ctx, e.o); close(done) }()
	defer func() { cancel(); <-done }()
	ended := func(n int32) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if lister.asked.Load() >= n && !checks.Status().GetRunning() {
				return
			}
		}
		t.Fatalf("%d checks, want %d", lister.asked.Load(), n)
	}
	ended(1)
	clock.add(controller.ReleaseCheckGap)
	if _, wait, err := checks.CheckNow(); err != nil || wait != 0 {
		t.Fatalf("check now: %v %v", wait, err)
	}
	ended(2)
	if st := checks.Status(); st.GetOutcome() != rpmgrv1.ReleaseCheckOutcome_RELEASE_CHECK_OUTCOME_OK {
		t.Errorf("after check now: %v", st)
	}
}
