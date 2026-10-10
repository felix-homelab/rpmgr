// SPDX-License-Identifier: Apache-2.0

// Command releasemanifest drafts and checks the release manifest that the signer signs offline
// (RELEASING.md, "Release process"; docs/04-security.md, "Release signing"). It is a release tool
// and not part of the rpmgr binary:
//
//	releasemanifest draft -version <v> -dir <dir> [-previous <manifest>] [-seq <n>] [-floor <v>] [-issued <time>]
//	releasemanifest check -dir <dir> [-previous <manifest>] <manifest>
//
// The artifacts are the files of dir named rpmgr-<version>-<os>-<arch>[-<variant>], without an
// extension; other files are ignored. draft writes the unsigned manifest of those artifacts to
// standard output, as compact JSON: by default with seq one above the previous manifest's and its
// floor, or seq 1 and the version itself as the floor for the first release, and the channel that
// the version implies. check reports whether a manifest is well-formed and exactly as draft writes
// it, lists exactly the artifacts of dir with their sizes and SHA-256, and has a higher seq than
// the previous manifest.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/felix-homelab/rpmgr/internal/release"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "draft" && os.Args[1] != "check" {
		fmt.Fprintln(os.Stderr, "usage: releasemanifest draft|check … (see the package documentation)")
		os.Exit(2)
	}
	var err error
	if os.Args[1] == "draft" {
		err = draft(os.Args[2:], os.Stdout, time.Now)
	} else {
		err = check(os.Args[2:], os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasemanifest:", err)
		os.Exit(1)
	}
}

func draft(args []string, w io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("draft", flag.ContinueOnError)
	version := fs.String("version", "", "the release version, without a leading v")
	dir := fs.String("dir", "", "the directory of the artifacts")
	previous := fs.String("previous", "", "the manifest of the last published release; none for the first")
	seq := fs.Uint64("seq", 0, "the manifest's seq (default one above the previous manifest's)")
	floor := fs.String("floor", "", "the version floor (default the previous manifest's)")
	issued := fs.String("issued", "", "the issue time, RFC 3339 (default now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *version == "" || *dir == "" {
		return errors.New("draft needs -version and -dir, and no arguments")
	}
	m := release.Manifest{Seq: *seq, Version: *version, Floor: *floor, Channel: release.Stable, IssuedAt: now().UTC().Truncate(time.Second)}
	if semver.Prerelease("v"+*version) != "" {
		m.Channel = release.Prerelease
	}
	if *issued != "" {
		t, err := time.Parse(time.RFC3339, *issued)
		if err != nil {
			return err
		}
		m.IssuedAt = t.UTC()
	}
	if *previous != "" {
		prev, err := readManifest(*previous)
		if err != nil {
			return err
		}
		if m.Seq == 0 {
			m.Seq = prev.Seq + 1
		}
		if m.Floor == "" {
			m.Floor = prev.Floor
		}
	}
	if m.Seq == 0 {
		m.Seq = 1
	}
	if m.Floor == "" {
		m.Floor = m.Version
	}
	var err error
	if m.Artifacts, err = artifacts(*dir, m.Version); err != nil {
		return err
	}
	if err := m.Check(); err != nil {
		return fmt.Errorf("%w; a floor above the version is lowered only deliberately, with -floor", err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func check(args []string, warn io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	dir := fs.String("dir", "", "the directory of the artifacts")
	previous := fs.String("previous", "", "the manifest of the last published release; none for the first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *dir == "" {
		return errors.New("check needs -dir and the manifest")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := readManifest(fs.Arg(0))
	if err != nil {
		return err
	}
	// Install scripts read the manifest with grep (internal/installsh), so its form is fixed.
	if canonical, _ := json.Marshal(m); !bytes.Equal(bytes.TrimSuffix(b, []byte("\n")), canonical) {
		return errors.New("the manifest is not in the compact form that draft writes")
	}
	files, err := artifacts(*dir, m.Version)
	if err != nil {
		return err
	}
	if len(files) != len(m.Artifacts) {
		return fmt.Errorf("the manifest lists %d artifacts, the directory holds %d", len(m.Artifacts), len(files))
	}
	for _, a := range m.Artifacts {
		name := release.ArtifactName(m.Version, a)
		f, err := os.Open(filepath.Join(*dir, name)) //nolint:gosec // G304: the release manager's directory
		if err != nil {
			return err
		}
		err = a.Check(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if *previous != "" {
		prev, err := readManifest(*previous)
		if err != nil {
			return err
		}
		if m.Seq <= prev.Seq {
			return fmt.Errorf("seq %d is not above the previous manifest's %d", m.Seq, prev.Seq)
		}
		if semver.Compare("v"+m.Floor, "v"+prev.Floor) < 0 {
			_, _ = fmt.Fprintf(warn, "note: the floor is lowered from %s to %s\n", prev.Floor, m.Floor)
		}
	}
	return nil
}

// readManifest reads a manifest and checks that it is well-formed.
func readManifest(path string) (*release.Manifest, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the release manager's file
	if err != nil {
		return nil, err
	}
	var m release.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := m.Check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// artifacts returns the artifacts of version in dir, with their sizes and SHA-256, in the order of
// their names.
func artifacts(dir, version string) ([]release.Artifact, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	prefix := "rpmgr-" + version + "-"
	var out []release.Artifact
	for _, de := range des {
		rest, ok := strings.CutPrefix(de.Name(), prefix)
		if !ok || strings.Contains(rest, ".") || !de.Type().IsRegular() {
			continue
		}
		parts := strings.Split(rest, "-")
		a := release.Artifact{Variant: "full"}
		switch len(parts) {
		case 2:
			a.OS, a.Arch = parts[0], parts[1]
		case 3:
			a.OS, a.Arch, a.Variant = parts[0], parts[1], parts[2]
		}
		if a.OS == "" || len(parts) == 3 && a.Variant == "full" {
			return nil, fmt.Errorf("%s is not named rpmgr-<version>-<os>-<arch>[-<variant>]", de.Name())
		}
		if a.SHA256, a.Size, err = digest(filepath.Join(dir, de.Name())); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no artifact of version %s", dir, version)
	}
	return out, nil
}

func digest(path string) (string, int64, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the release manager's directory
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}
