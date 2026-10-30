// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/alerts"
	"github.com/felix-homelab/rpmgr/internal/apisvc"
	"github.com/felix-homelab/rpmgr/internal/authz"
	"github.com/felix-homelab/rpmgr/internal/events"
	"github.com/felix-homelab/rpmgr/internal/lease"
	"github.com/felix-homelab/rpmgr/internal/mail"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
	"github.com/felix-homelab/rpmgr/internal/store/ent"
	"github.com/felix-homelab/rpmgr/internal/store/ent/event"
	"github.com/felix-homelab/rpmgr/internal/store/ent/mailjob"
	"github.com/felix-homelab/rpmgr/internal/store/ent/membership"
	"github.com/felix-homelab/rpmgr/internal/store/ent/user"
)

// The timing of the mail job (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	MailEvery     = 30 * time.Second
	MailRetryFrom = time.Minute
	MailRetryCap  = time.Hour
	MailGiveUp    = 6 * time.Hour
	MailPerPass   = 20
)

// mailTypes are the events that are e-mailed: an alert firing and resolving, and a webhook
// endpoint disabled for failing (D139, D143).
var mailTypes = []string{"alert.fire", "alert.resolve", "webhook.disable"}

// MailOptions configure the mail job.
type MailOptions struct {
	DB     *store.DB
	Leases *lease.Leases
	Mailer apisvc.Mailer
	// PublicURL is the controller's address, the link in every mail.
	PublicURL string
	Now       func() time.Time
	Logger    *slog.Logger
}

// MailJob is the singleton job that e-mails the events of mailTypes through the instance's relay:
// it makes one mail job for each event, sends it to the org's Owners and Admins (the Instance
// Admins for an instance event) and retries a failure with a doubling delay until MailGiveUp, when
// it logs and gives up. Nothing here runs in the transaction of the alert or the delivery, so a
// failed mail blocks neither.
func MailJob(o MailOptions) lease.Job {
	return lease.Job{Name: "mail", Reason: "e-mail the alerts", Every: MailEvery,
		Run: func(ctx context.Context, l lease.Lease) error { return runMail(ctx, o, l) }}
}

// mailResult is what a pass did to one mail job.
type mailResult struct {
	job      *ent.MailJob
	state    mailjob.State
	done     []string
	attempts int
	next     time.Time
}

func runMail(ctx context.Context, o MailOptions, l lease.Lease) error {
	now := o.Now().UTC()
	c := o.DB.ReadClient()
	if err := enqueueMails(ctx, o, l, now); err != nil {
		return err
	}
	due, err := c.MailJob.Query().Where(mailjob.StateEQ(mailjob.StatePending), mailjob.NextAttemptAtLTE(now)).
		Order(ent.Asc(mailjob.FieldNextAttemptAt)).Limit(MailPerPass).All(ctx)
	if err != nil {
		return err
	}
	var results []mailResult
	if len(due) > 0 {
		configured, err := o.Mailer.Configured(ctx)
		if err != nil {
			return err
		}
		for _, j := range due {
			r := mailResult{job: j, state: mailjob.StateSkipped, done: j.Done, attempts: j.Attempts}
			if configured {
				r = sendMail(ctx, o, j, now)
			}
			results = append(results, r)
		}
	}
	return store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
		if err := o.Leases.Fence(ctx, tx, l); err != nil {
			return err
		}
		for _, r := range results {
			if r.next.IsZero() {
				r.next = now
			}
			if err := tx.MailJob.UpdateOne(r.job).SetState(r.state).SetDone(r.done).SetAttempts(r.attempts).
				SetNextAttemptAt(r.next).Exec(ctx); err != nil {
				return err
			}
		}
		_, err := tx.MailJob.Delete().Where(mailjob.CreatedAtLT(now.Add(-events.Keep))).Exec(ctx)
		return err
	})
}

// enqueueMails makes a mail job for each event of mailTypes within MailGiveUp that has none; the
// unique event ID keeps a lease takeover from making two.
func enqueueMails(ctx context.Context, o MailOptions, l lease.Lease, now time.Time) error {
	c := o.DB.ReadClient()
	evs, err := c.Event.Query().Where(event.TypeIn(mailTypes...), event.TsGTE(now.Add(-MailGiveUp))).
		Order(ent.Asc(event.FieldTs)).Limit(500).All(ctx)
	if err != nil || len(evs) == 0 {
		return err
	}
	ids := make([]string, len(evs))
	for i, e := range evs {
		ids[i] = e.ID
	}
	have, err := c.MailJob.Query().Where(mailjob.EventIDIn(ids...)).Select(mailjob.FieldEventID).Strings(ctx)
	if err != nil {
		return err
	}
	var fresh []*ent.Event
	for _, e := range evs {
		if !slices.Contains(have, e.ID) {
			fresh = append(fresh, e)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	return store.WriteTx(ctx, o.DB, func(tx *ent.Tx) error {
		if err := o.Leases.Fence(ctx, tx, l); err != nil {
			return err
		}
		for _, e := range fresh {
			cr := tx.MailJob.Create().SetEventID(e.ID).SetState(mailjob.StatePending).SetNextAttemptAt(now).SetCreatedAt(e.Ts)
			if e.OrgID != nil {
				cr.SetOrgID(*e.OrgID)
			}
			if err := cr.Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

// sendMail sends j's mail to the recipients that did not get it yet. A mail that is no longer
// wanted (the org turned alert e-mails off, the event or its recipients are gone) is skipped.
func sendMail(ctx context.Context, o MailOptions, j *ent.MailJob, now time.Time) mailResult {
	r := mailResult{job: j, state: mailjob.StateSkipped, done: j.Done, attempts: j.Attempts}
	fail := func(err error) mailResult {
		r.attempts++
		r.state, r.next = mailjob.StatePending, now.Add(mailBackoff(r.attempts))
		if now.Sub(j.CreatedAt) >= MailGiveUp {
			r.state = mailjob.StateGivenUp
			o.Logger.Warn("giving up on an alert e-mail", "event", j.EventID, "attempts", r.attempts, "error", err)
		} else {
			o.Logger.Info("an alert e-mail failed, will retry", "event", j.EventID, "attempts", r.attempts, "error", err)
		}
		return r
	}
	c := o.DB.ReadClient()
	e, err := c.Event.Get(ctx, j.EventID)
	if ent.IsNotFound(err) {
		return r
	} else if err != nil {
		return fail(err)
	}
	org := ""
	if j.OrgID != nil {
		org = *j.OrgID
	}
	// Alert e-mails follow the org's setting; the e-mail of a disabled webhook endpoint does not,
	// as it asks for a person's action.
	if org != "" && strings.HasPrefix(e.Type, "alert.") {
		s, _, err := settings.Org(ctx, c, org)
		if err != nil {
			return fail(err)
		}
		if !s.GetAlertEmail() {
			return r
		}
	}
	to, err := mailRecipients(ctx, c, org)
	if err != nil {
		return fail(err)
	}
	if len(to) == 0 {
		return r
	}
	orgName := ""
	if org != "" {
		if or, err := c.Org.Get(ctx, org); err == nil {
			orgName = or.Name
		}
	}
	msg := alertMail(e, orgName, o.PublicURL)
	var firstErr error
	for _, addr := range to {
		if slices.Contains(r.done, addr) {
			continue
		}
		msg.To = addr
		if err := o.Mailer.Send(ctx, msg); err != nil {
			firstErr = err
			continue
		}
		r.done = append(r.done, addr)
	}
	if firstErr != nil {
		return fail(firstErr)
	}
	r.state = mailjob.StateSent
	return r
}

// mailBackoff is the delay after the n-th failed attempt: MailRetryFrom, doubling to MailRetryCap.
func mailBackoff(n int) time.Duration {
	d := MailRetryFrom
	for i := 1; i < n && d < MailRetryCap; i++ {
		d *= 2
	}
	return min(d, MailRetryCap)
}

// mailRecipients are the e-mail addresses of the active Owners and Admins of org, or, for an
// instance event, of the active Instance Admins; sorted, without duplicates.
func mailRecipients(ctx context.Context, c *ent.Client, org string) ([]string, error) {
	var out []string
	if org == "" {
		us, err := c.User.Query().Where(user.InstanceAdmin(true), user.StatusEQ(user.StatusActive)).All(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range us {
			out = append(out, u.Email)
		}
	} else {
		ms, err := c.Membership.Query().Where(membership.OrgID(org),
			membership.RoleIn(membership.Role(authz.RoleOwner), membership.Role(authz.RoleAdmin))).WithUser().All(ctx)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if u := m.Edges.User; u != nil && u.Status == user.StatusActive {
				out = append(out, u.Email)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// alertMail is the mail of e: the envelope's facts and a link, never a secret or another org's
// data. A webhook endpoint is named by its ID, as its URL may hold the receiver's token.
func alertMail(e *ent.Event, orgName, publicURL string) mail.Message {
	var subject string
	switch e.Type {
	case "webhook.disable":
		subject = "Webhook endpoint disabled"
	default:
		kind, _, _ := strings.Cut(e.Summary, ":")
		state := "firing"
		if e.Type == "alert.resolve" {
			state = "resolved"
		}
		subject = alerts.Title(kind) + " " + state
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", e.Summary)
	if orgName != "" {
		fmt.Fprintf(&b, "Organisation: %s\n", orgName)
	}
	fmt.Fprintf(&b, "%s: %s (%s)\nTime: %s\n\n", e.SubjectType, firstNonEmpty(e.SubjectName, e.SubjectID), e.SubjectID, e.Ts.UTC().Format(time.RFC3339))
	if e.Type == "webhook.disable" {
		b.WriteString("The events of the time it was disabled are not sent again. An Owner or Admin enables it again\nonce the receiver works.\n\n")
	}
	fmt.Fprintf(&b, "Open rpmgr: %s\n", strings.TrimRight(publicURL, "/")+"/")
	return mail.Message{Subject: "[rpmgr] " + strings.NewReplacer("\r", "", "\n", "").Replace(subject), Body: b.String()}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
