// SPDX-License-Identifier: Apache-2.0

// Package installsh writes rpmgr's install scripts (docs/04-security.md, "Install scripts"): the
// controller's /install.sh, a POSIX shell script that installs a gateway or a connector from the
// controller's /dl/ mirror, and the global deploy/install.sh, which installs the binary of a
// GitHub release. Both embed the release root keys and share the verification of what they
// download (verify.sh.tmpl).
package installsh

// The repository's copy of the global install script, with the compiled-in release root keys.
//go:generate go run ../../tools/installscript -o ../../deploy/install.sh

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"text/template"

	"github.com/felix-homelab/rpmgr/internal/release"
)

//go:embed *.sh.tmpl
var files embed.FS

var scripts = template.Must(template.ParseFS(files, "*.sh.tmpl"))

type root struct{ ID, PEM string }

// Render returns the controller's install script of a release version, which trusts roots.
func Render(version string, roots []release.PublicKey) ([]byte, error) {
	if !release.Releasable(version) {
		return nil, release.ErrDevelopment
	}
	return render("install.sh.tmpl", version, roots)
}

// RenderGlobal returns the global install script, which trusts roots: pinned to a release version,
// as the release attaches it, or with version "" the copy in the repository, deploy/install.sh,
// which installs the latest release unless told otherwise.
func RenderGlobal(version string, roots []release.PublicKey) ([]byte, error) {
	if version != "" && !release.Releasable(version) {
		return nil, release.ErrDevelopment
	}
	return render("global.sh.tmpl", version, roots)
}

func render(name, version string, roots []release.PublicKey) ([]byte, error) {
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
	if err := scripts.ExecuteTemplate(&b, name, data); err != nil {
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
