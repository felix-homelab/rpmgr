// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/felix-homelab/rpmgr/internal/events"
)

// eventReferenceFile is the generated reference of event types, relative to this package.
const eventReferenceFile = "../../docs/guide/reference/events.md"

// eventReferenceRegenerate is the command that regenerates eventReferenceFile, from the repository
// root. It shares the -update flag of the command-line reference.
const eventReferenceRegenerate = "go test ./cmd/rpmgr -run TestEventReference -update"

// TestEventReference: the committed reference of event types is the catalog of internal/events as
// renderEventReference renders it, so that a new API method or status event cannot leave it
// behind.
func TestEventReference(t *testing.T) {
	got := renderEventReference(events.Catalog())
	if *updateCLIReference {
		if err := os.WriteFile(eventReferenceFile, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(eventReferenceFile)
	if err != nil {
		t.Fatalf("%v; generate it with: %s", err, eventReferenceRegenerate)
	}
	if line, same := firstDifferentLine(string(want), got); !same {
		t.Errorf("%s does not match the event types of the code (first difference at line %d); regenerate it with: %s",
			eventReferenceFile, line, eventReferenceRegenerate)
	}
}

// TestEventCatalog: the catalog holds the types the documentation names, each once, and none that
// is no event.
func TestEventCatalog(t *testing.T) {
	seen := map[string]events.Type{}
	for _, e := range events.Catalog() {
		if _, dup := seen[e.Type]; dup {
			t.Errorf("event type %q is listed twice", e.Type)
		}
		seen[e.Type] = e
		if e.Resource == "" || e.Verb == "" || e.Type != e.Resource+"."+e.Verb {
			t.Errorf("event type %q is not <resource>.<verb>", e.Type)
		}
		if !e.Status && e.Method == "" {
			t.Errorf("event type %q has neither a method nor a status", e.Type)
		}
	}
	for _, want := range []string{"route.create", "route.update", "route_target.create", "webhook_secret.rotate",
		"token.create", "audit.export", "route.status", "webhook.test", "alert.fire"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("event type %q is missing from the catalog", want)
		}
	}
	// Signing in and out, a step-up, a reset-link request, a test send and a live log are no events
	// of their own; a read never is.
	for _, not := range []string{"auth.login", "auth.logout", "up.step", "password_reset.request", "session.login",
		"agent.logs_open", "logs.stream", "route.get", "route.list", "instance_audit.export", "api_token.create"} {
		if _, ok := seen[not]; ok {
			t.Errorf("%q is in the catalog but is no event", not)
		}
	}
	if len(seen) < len(events.StatusEvents) {
		t.Errorf("the catalog has %d types, fewer than the %d status events", len(seen), len(events.StatusEvents))
	}
}

// TestRenderEventReference: the renderer's rules on a small catalog: groups by resource in order,
// an acronym in capitals, a status event's own meaning and link, and an unknown scope shown as such.
func TestRenderEventReference(t *testing.T) {
	got := renderEventReference([]events.Type{
		{Type: "agent.connect", Resource: "agent", Verb: "connect", Meaning: "Connected.", Scope: "org", Status: true},
		{Type: "dns_name.create", Resource: "dns_name", Verb: "create", Method: "m", Scope: "org"},
		{Type: "route.cancel", Resource: "route", Verb: "cancel", Method: "m"},
		{Type: "route.set", Resource: "route", Verb: "set", Method: "m", Scope: "instance"},
	})
	for _, want := range []string{
		"## agent\n", "## dns_name\n", "## route\n",
		"| `agent.connect` | Connected. | org | [07](../../07-api.md#webhooks-phase-2) |",
		"| `dns_name.create` | DNS name created. | org |  |",
		"| `route.cancel` | Route cancelled. | varies |  |",
		"| `route.set` | Route set. | instance |  |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered page lacks %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "## agent\n") > strings.Index(got, "## dns_name\n") || strings.Index(got, "## dns_name\n") > strings.Index(got, "## route\n") {
		t.Errorf("groups are not in order:\n%s", got)
	}
}

// eventAcronyms are the words of a resource name written in capitals.
var eventAcronyms = map[string]string{"api": "API", "dns": "DNS", "ca": "CA", "smtp": "SMTP", "totp": "TOTP"}

// eventPast are the verbs whose past participle is not the verb with -d or -ed.
var eventPast = map[string]string{"set": "set", "cancel": "cancelled", "sync": "synced"}

// eventMeaning derives what an event of a method means from its type: "Route target created."
func eventMeaning(resource, verb string) string {
	words := strings.Split(resource, "_")
	for i, w := range words {
		if a, ok := eventAcronyms[w]; ok {
			words[i] = a
		}
	}
	if resource == "me" {
		words = []string{"own profile"}
	}
	noun := strings.Join(words, " ")
	past, ok := eventPast[verb]
	switch {
	case ok:
	case strings.HasSuffix(verb, "e"):
		past = verb + "d"
	case strings.HasSuffix(verb, "y"):
		past = verb[:len(verb)-1] + "ied"
	default:
		past = verb + "ed"
	}
	return strings.ToUpper(noun[:1]) + noun[1:] + " " + past + "."
}

// eventLink is the link of a status event: the webhooks section of 07, which names its events.
const eventLink = "[07](../../07-api.md#webhooks-phase-2)"

// renderEventReference renders the reference page from the catalog, in groups by resource.
func renderEventReference(catalog []events.Type) string {
	var b strings.Builder
	b.WriteString(`# Event reference

This page lists every type of event that a webhook receives and that an audit entry causes. It is
for you when you need the exact name to put in an endpoint's event filter; the task pages
([Webhooks](../operations/webhooks.md), [Audit log](../operations/audit-log.md)) explain what to do
with them, and the envelope of an event is in [07](../../07-api.md#webhooks-phase-2).

<!-- Generated from the API services and the status events of internal/events by TestEventReference. Do not edit by hand. -->

## How to read this page

- Every change that the audit log records as a success is an event. Its type is
  ` + "`<resource>.<verb>`" + `, made from the name of the API method: ` + "`UpdateRoute`" + ` of the route service is
  ` + "`route.update`" + `, ` + "`CreateRouteTarget`" + ` is ` + "`route_target.create`" + `, and a method that is a verb alone takes
  the name of its service. The audit log names the same change by the method, and the event's type is
  that name in this form.
- Status events report a state rather than a change you made, such as a route's status or an agent
  going offline. They are marked with a link to where they are described.
- Signing in and out, a step-up, asking for a reset link, the use of a token and the use of a
  system scope are not events. Neither is a read.
- Changes that the controller or the command line make outside the API are events too, under the
  name of their audit action; they are not generated here.
- An endpoint names the types it wants, or a prefix such as ` + "`route.*`" + ` for every type of one
  resource; naming none means all of them. A name that is not in the table is not
  refused when you save the endpoint, so check it against this page.
- Scope says whose endpoints can receive the event: ` + "`org`" + ` is the organisation's, ` + "`instance`" + `
  the instance endpoints'. A scope of ` + "`varies`" + ` means that it depends on the request.
`)
	last := ""
	for _, e := range catalog {
		if e.Resource != last {
			last = e.Resource
			fmt.Fprintf(&b, "\n## %s\n\n| Type | Meaning | Scope | See |\n|---|---|---|---|\n", e.Resource)
		}
		meaning, scope, link := e.Meaning, e.Scope, ""
		if e.Status {
			link = eventLink
			if strings.HasPrefix(e.Type, "alert.") {
				link = "[10](../../10-operations.md#suggested-alerts)"
			}
		} else {
			meaning = eventMeaning(e.Resource, e.Verb)
		}
		if scope == "" {
			scope = "varies"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", e.Type, meaning, scope, link)
		if e.Type == "alert.resolve" {
			b.WriteString("\nThe kind of an alert starts the event's summary; the kinds are listed in the suggested\n" +
				"alerts of [10](../../10-operations.md#suggested-alerts).\n")
		}
	}
	return b.String()
}
