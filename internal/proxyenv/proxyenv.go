// SPDX-License-Identifier: Apache-2.0

// Package proxyenv reads the proxy variables that the outbound connections of every role follow
// (docs/10-operations.md, "Controller outbound connections"; docs/03-connections.md, "Transports
// and fallback"): HTTPS_PROXY, else ALL_PROXY, for TLS connections and https:// URLs; HTTP_PROXY,
// else ALL_PROXY, for http:// URLs; NO_PROXY exempts hosts, and loopback addresses always go
// direct. Each variable is also read in lower case, which the upper-case one overrides. A value
// without a scheme is an http:// proxy, as net/http reads it. A value that is no proxy URL the
// caller can use is an error that names the variable, never the value, which may hold credentials.
package proxyenv

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/http/httpproxy"
)

// Lookup returns the name and the value of a variable, the upper-case name first, or two empty
// strings when neither is set.
func Lookup(getenv func(string) string, name string) (string, string) {
	for _, n := range []string{name, strings.ToLower(name)} {
		if v := getenv(n); v != "" {
			return n, v
		}
	}
	return "", ""
}

// NoProxy returns NO_PROXY, or no_proxy.
func NoProxy(getenv func(string) string) string {
	_, v := Lookup(getenv, "NO_PROXY")
	return v
}

// Proxy is the proxy one variable names.
type Proxy struct {
	Var string // the variable it came from, such as HTTPS_PROXY or all_proxy
	URL *url.URL
}

// For returns the proxy of connections to scheme's URLs, "https" or "http", and whether there is
// one; kinds are the proxy schemes the caller can use, such as "http" and "socks5".
func For(getenv func(string) string, scheme string, kinds ...string) (Proxy, bool, error) {
	name, raw := Lookup(getenv, strings.ToUpper(scheme)+"_PROXY")
	if raw == "" {
		name, raw = Lookup(getenv, "ALL_PROXY")
	}
	if raw == "" {
		return Proxy{}, false, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !slices.Contains(kinds, u.Scheme) {
		return Proxy{}, false, fmt.Errorf("%s is not %s URL with a host", name, schemes(kinds))
	}
	return Proxy{Var: name, URL: u}, true, nil
}

// schemes lists proxy kinds as "an http://, socks5:// or socks5h://".
func schemes(kinds []string) string {
	s := make([]string, len(kinds))
	for i, k := range kinds {
		s[i] = k + "://"
	}
	article := "a "
	if strings.HasPrefix(s[0], "http") {
		article = "an "
	}
	if len(s) == 1 {
		return article + s[0]
	}
	return article + strings.Join(s[:len(s)-1], ", ") + " or " + s[len(s)-1]
}

// Requests returns the Proxy function of an http.Transport: https:// URLs go through HTTPS_PROXY,
// else ALL_PROXY, and http:// URLs through HTTP_PROXY, else ALL_PROXY, each an http://, https://,
// socks5:// or socks5h:// proxy, unless NO_PROXY exempts the host.
func Requests(getenv func(string) string) (func(*http.Request) (*url.URL, error), error) {
	cfg := httpproxy.Config{NoProxy: NoProxy(getenv)}
	for _, s := range []struct {
		scheme string
		to     *string
	}{{"https", &cfg.HTTPSProxy}, {"http", &cfg.HTTPProxy}} {
		p, ok, err := For(getenv, s.scheme, "http", "https", "socks5", "socks5h")
		if err != nil {
			return nil, err
		}
		if ok {
			*s.to = p.URL.String()
		}
	}
	use := cfg.ProxyFunc()
	return func(r *http.Request) (*url.URL, error) { return use(r.URL) }, nil
}

var fromEnvironment = sync.OnceValues(func() (func(*http.Request) (*url.URL, error), error) { return Requests(os.Getenv) })

// FromEnvironment is Requests of the process's environment, read once, in place of
// http.ProxyFromEnvironment. With a variable that is no proxy URL, every request fails with
// Requests' error.
func FromEnvironment(r *http.Request) (*url.URL, error) {
	use, err := fromEnvironment()
	if err != nil {
		return nil, err
	}
	return use(r)
}
