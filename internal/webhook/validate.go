// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The limits of an endpoint's settings (docs/03-connections.md, "Timeouts, keepalive and backoff").
const (
	MaxURL        = 2048 // bytes of a receiver's URL
	MaxEventTypes = 32   // event types an endpoint names
	MaxEventType  = 64   // bytes of one event type
)

// eventType is an event type or a prefix of one: lower-case words joined by dots and underscores,
// the last one optionally a star, as in route.update or route.*.
var eventType = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(\.\*)?$`)

// ValidateURL checks a receiver's URL as it is set: https, a host, no credentials, no fragment, at
// most MaxURL bytes. The guard checks the addresses it resolves to when it dials, not here.
func ValidateURL(raw string) error {
	switch {
	case raw == "":
		return errors.New("webhook: the url is empty")
	case len(raw) > MaxURL:
		return fmt.Errorf("webhook: the url is longer than %d bytes", MaxURL)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return errors.New("webhook: the url does not parse")
	case u.Scheme != "https":
		return errors.New("webhook: the url must start with https://")
	case u.Hostname() == "":
		return errors.New("webhook: the url names no host")
	case u.User != nil:
		return errors.New("webhook: the url must not hold credentials")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("webhook: the url must not have a fragment")
	}
	return nil
}

// ValidateEventTypes checks the event types an endpoint names, by name or by prefix such as
// route.*; none is valid and means all. Duplicates are refused.
func ValidateEventTypes(types []string) error {
	if len(types) > MaxEventTypes {
		return fmt.Errorf("webhook: more than %d event types", MaxEventTypes)
	}
	seen := map[string]bool{}
	for _, t := range types {
		switch {
		case len(t) > MaxEventType || !eventType.MatchString(t):
			return fmt.Errorf("webhook: %q is not an event type or a prefix such as route.*", t)
		case seen[t]:
			return fmt.Errorf("webhook: the event type %q is named twice", t)
		}
		seen[t] = true
	}
	return nil
}
