// SPDX-License-Identifier: Apache-2.0

// Package installsh writes the controller's /install.sh (docs/04-security.md, "Install scripts"):
// a POSIX shell script that installs a gateway or a connector from the controller's /dl/ mirror,
// with the binary's release root keys embedded to verify what it downloads.
package installsh

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"text/template"

	"github.com/felix-homelab/rpmgr/internal/release"
)

//go:embed install.sh.tmpl
var text string

var script = template.Must(template.New("install.sh").Parse(text))

type root struct{ ID, PEM string }

// Render returns the install script of a release version, which trusts roots.
func Render(version string, roots []release.PublicKey) ([]byte, error) {
	if !release.Releasable(version) {
		return nil, release.ErrDevelopment
	}
	if len(roots) == 0 {
		return nil, errors.New("installsh: this build has no release root keys")
	}
	data := struct {
		Version string
		Roots   []root
	}{Version: version}
	for _, k := range roots {
		der, err := x509.MarshalPKIXPublicKey(k.Key)
		if err != nil {
			return nil, err
		}
		data.Roots = append(data.Roots, root{ID: hex.EncodeToString(k.ID[:]), PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	}
	var b bytes.Buffer
	if err := script.Execute(&b, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// unavailable is the script served when there is none: run by `curl … | sh`, it says why and
// fails, where an error page would leave sh with no input and exit 0.
func unavailable(reason string) []byte {
	return []byte("#!/bin/sh\necho 'rpmgr install: this controller serves no install script: " +
		strings.ReplaceAll(reason, "'", "") + "' >&2\nexit 1\n")
}

// Handler serves GET /install.sh.
func Handler(version string, roots []release.PublicKey) http.Handler {
	body, err := Render(version, roots)
	if err != nil {
		body = unavailable(err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache") // it names the controller's version, which upgrades change
		_, _ = w.Write(body)
	})
}
