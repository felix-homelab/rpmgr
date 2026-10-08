// SPDX-License-Identifier: Apache-2.0

package apisvc

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/felix-homelab/rpmgr/internal/mail"
	"github.com/felix-homelab/rpmgr/internal/secret"
	"github.com/felix-homelab/rpmgr/internal/settings"
	"github.com/felix-homelab/rpmgr/internal/store"
)

// Mailer sends the controller's e-mails.
type Mailer interface {
	// Configured reports whether there is a relay to send through.
	Configured(ctx context.Context) (bool, error)
	Send(ctx context.Context, m mail.Message) error
}

// Relay is the Mailer of the instance settings' relay, read at every send.
type Relay struct {
	DB      *store.DB
	Sys     context.Context
	Sealer  *secret.Sealer
	RootCAs *x509.CertPool // tests
}

// Configured implements Mailer.
func (r *Relay) Configured(context.Context) (bool, error) {
	inst, _, err := settings.Instance(r.Sys, r.DB.ReadClient())
	if err != nil {
		return false, err
	}
	return inst.GetSmtp().GetServer() != "", nil
}

// Send implements Mailer.
func (r *Relay) Send(ctx context.Context, m mail.Message) error {
	inst, _, err := settings.Instance(r.Sys, r.DB.ReadClient())
	if err != nil {
		return err
	}
	pw, err := settings.InstanceSecret(r.Sys, r.DB.ReadClient(), r.Sealer, settings.SMTPPassword)
	if err != nil {
		return err
	}
	return mail.Send(ctx, mail.Relay{Settings: inst.GetSmtp(), Password: pw, RootCAs: r.RootCAs}, m)
}

// resetMail is the e-mail with a password-reset link.
func resetMail(to, link string, ttl time.Duration) mail.Message {
	return mail.Message{To: to, Subject: "Reset your rpmgr password", Body: fmt.Sprintf(
		"Someone asked to reset the password of your rpmgr account. If it was you, set a new one here within %s:\n\n%s\n\n"+
			"If it was not you, ignore this e-mail; your password stays as it is.\n", hours(ttl), link)}
}

// invitationMail is the e-mail with an invitation link.
func invitationMail(to, org, role, link string, ttl time.Duration) mail.Message {
	return mail.Message{To: to, Subject: "Your invitation to " + strings.NewReplacer("\r", "", "\n", "").Replace(org) + " on rpmgr",
		Body: fmt.Sprintf("You are invited to join %s on rpmgr as %s. Accept within %s:\n\n%s\n", org, role, hours(ttl), link)}
}

func hours(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%d days", d/(24*time.Hour))
	}
	return fmt.Sprintf("%d hours", d/time.Hour)
}
