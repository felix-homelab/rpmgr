#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# rpmgr install script for a first installation from a GitHub release (docs/10-operations.md,
# "Install paths"; docs/04-security.md, "Install scripts"). It downloads the release for this
# host, verifies it with OpenSSL >= 3 as the controller's /install.sh does: root key (below) ->
# signing-key statement -> release manifest -> SHA-256 and size of the binary, then installs the
# binary, the user rpmgr and its directories, and offers to run `rpmgr setup`. Running it again
# upgrades the binary and leaves the user, the directories and the configuration as they are.
# This copy installs the latest release unless --version names one.
#
#   curl -fsSLO https://github.com/felix-homelab/rpmgr/releases/latest/download/install.sh
#   sudo sh install.sh [--version <version>] [--prerelease] [--no-setup] [--dir <directory>]
#     [--verify-only]
set -eu

PINNED=''
REPO=felix-homelab/rpmgr
# Where releases come from; other values serve a mirror, or a test (https only).
GITHUB=${RPMGR_INSTALL_GITHUB:-https://github.com}
API=${RPMGR_INSTALL_API:-https://api.github.com}
BIN=/usr/local/bin/rpmgr

die() { echo "rpmgr install: $*" >&2; exit 1; }
say() { echo "rpmgr install: $*" >&2; }

usage() {
  cat <<'EOF'
Usage: sh install.sh [--version <version>] [--prerelease] [--no-setup] [--dir <directory>]
         [--verify-only]

Installs rpmgr from its GitHub release, verified with the release root keys in this script, to
/usr/local/bin/rpmgr, with the user rpmgr, /etc/rpmgr and /var/lib/rpmgr; then offers to run
"rpmgr setup". Run as root.

  --version <version>  install this version, e.g. 0.1.0 (default: this script's, else the latest)
  --prerelease         without --version, take the latest release including pre-releases
  --no-setup           do not offer to run "rpmgr setup"
  --dir <directory>    download into this directory and keep the files (default: a temporary one)
  --verify-only        download and verify the release, install nothing; needs no root
EOF
}

version=$PINNED prerelease=0 setup=1 dir='' verify_only=0
while [ $# -gt 0 ]; do
  case $1 in
    --version) [ $# -ge 2 ] || die "--version needs a version"; version=${2#v}; shift 2 ;;
    --prerelease) prerelease=1; shift ;;
    --no-setup) setup=0; shift ;;
    --dir) [ $# -ge 2 ] || die "--dir needs a directory"; dir=$2; shift 2 ;;
    --verify-only) verify_only=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done
case $GITHUB in https://*) ;; *) die "RPMGR_INSTALL_GITHUB must be an https:// URL" ;; esac
case $API in https://*) ;; *) die "RPMGR_INSTALL_API must be an https:// URL" ;; esac
case $version in '' | [0-9]*.[0-9]*.[0-9]*) ;; *) die "--version $version is not a release version such as 0.1.0" ;; esac
case $version in *[!0-9A-Za-z.-]*) die "--version $version is not a release version such as 0.1.0" ;; esac

case $(uname -s) in
  Linux) ;;
  *) die "rpmgr installs on Linux only; this is $(uname -s) (Windows and macOS connectors come in Phase 2)" ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  armv7l | armv7) arch=arm ;;
  riscv64) arch=riscv64 ;;
  *) die "no rpmgr build for linux/$(uname -m); there are builds for x86_64, aarch64, armv7l and riscv64" ;;
esac
if command -v curl >/dev/null 2>&1; then
  get() { curl -fsSL --proto =https --proto-redir =https --tlsv1.2 --retry 2 --max-time 600 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  get() { wget -q --https-only -O "$2" "$1"; }
else
  die "curl or wget is needed"
fi
for tool in openssl sed grep date dd od wc head cut tr; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is needed"
done
v=$(openssl version 2>/dev/null) || die "openssl does not run"
case $v in
  "OpenSSL "[3-9].* | "OpenSSL "[1-9][0-9].*) ;;
  *) die "OpenSSL 3.0 or later is needed to verify the release; found: $v" ;;
esac

if [ -n "$dir" ]; then
  mkdir -p "$dir" || die "cannot create --dir $dir"
  tmp=$(cd "$dir" && pwd)
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
fi
umask 077

# The latest release, or with --prerelease the latest one including pre-releases.
if [ -z "$version" ]; then
  if [ "$prerelease" = 1 ]; then
    get "$API/repos/$REPO/releases?per_page=20" "$tmp/releases.json" || die "cannot list the releases at $API"
  else
    get "$API/repos/$REPO/releases/latest" "$tmp/releases.json" || die "cannot find the latest release at $API"
  fi
  version=$(tr -d '\n' <"$tmp/releases.json" | grep -o '"tag_name": *"v[0-9][^"]*"' | head -n 1 | sed 's/.*"v\([^"]*\)"$/\1/')
  [ -n "$version" ] || die "no release found at $API/repos/$REPO"
fi
VERSION=$version

# The release root keys, by minisign key ID (bytes as in signatures).

cat >"$tmp/root-071ad9e309d58574.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+9l67LBLDn9xUIhPPfsnk4mlbxrpvejUitJIfdZQn78=
-----END PUBLIC KEY-----
EOF
cat >"$tmp/root-d5589a02f18fc6e4.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhUpw06whx3yBPLScnoiCI4aCWOju0rw5xSOfDPwGcMw=
-----END PUBLIC KEY-----
EOF

b64d() { tr -d '\n' | openssl base64 -d -A; }
hex() { od -An -v -tx1 | tr -d ' \n'; }
size() { wc -c <"$1" | tr -d ' '; }

# verify <signature file> <data file> <key prefix>: checks a minisign signature (prehashed, ED)
# with the key "<key prefix>-<key ID>.pem" its key ID names, and prints that key ID.
verify() {
  sigf=$1 data=$2 prefix=$3
  [ "$(wc -l <"$sigf" | tr -d ' ')" = 4 ] || die "$sigf is not a minisign signature file"
  case $(sed -n 1p "$sigf") in "untrusted comment: "*) ;; *) die "$sigf has no untrusted comment" ;; esac
  case $(sed -n 3p "$sigf") in "trusted comment: "*) ;; *) die "$sigf has no trusted comment" ;; esac
  sed -n 2p "$sigf" | b64d >"$tmp/sig" 2>/dev/null || die "$sigf is malformed"
  sed -n 4p "$sigf" | b64d >"$tmp/global" 2>/dev/null || die "$sigf is malformed"
  [ "$(size "$tmp/sig")" = 74 ] && [ "$(size "$tmp/global")" = 64 ] || die "$sigf is malformed"
  [ "$(head -c 2 "$tmp/sig")" = ED ] || die "$sigf is not a prehashed (ED) minisign signature"
  id=$(dd if="$tmp/sig" bs=1 skip=2 count=8 2>/dev/null | hex)
  key="$prefix-$id.pem"
  [ -f "$key" ] || die "$sigf is signed with an unknown key $id"
  dd if="$tmp/sig" bs=1 skip=10 count=64 of="$tmp/sig64" 2>/dev/null
  openssl dgst -blake2b512 -binary "$data" >"$tmp/hash"
  openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$tmp/hash" -sigfile "$tmp/sig64" >/dev/null 2>&1 ||
    die "the signature of $(basename "$data") does not verify"
  { cat "$tmp/sig64"; sed -n 3p "$sigf" | sed 's/^trusted comment: //' | tr -d '\n'; } >"$tmp/trusted"
  openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$tmp/trusted" -sigfile "$tmp/global" >/dev/null 2>&1 ||
    die "the trusted comment of $(basename "$data") does not verify"
  echo "$id"
}

# field <file> <key>: a JSON string field of a one-line document; refuses two or none.
field() {
  n=$(grep -o "\"$2\":\"[^\"]*\"" "$1" | wc -l | tr -d ' ')
  [ "$n" = 1 ] || die "$(basename "$1") has $n $2 fields"
  grep -o "\"$2\":\"[^\"]*\"" "$1" | sed "s/^\"$2\":\"//; s/\"\$//"
}

# verify_release checks the downloaded release in $tmp and sets $seq, the manifest's.
verify_release() {
  # 1. The statement, signed by a root key, names the signing key and is valid now.
  verify "$tmp/signing-key.json.minisig" "$tmp/signing-key.json" "$tmp/root" >/dev/null
  [ "$(grep -o '"statement":1[,}]' "$tmp/signing-key.json" | wc -l | tr -d ' ')" = 1 ] || die "the signing-key statement is not of format 1"
  signer=$(field "$tmp/signing-key.json" signer)
  now=$(date -u +%s)
  nb=$(date -u -d "$(field "$tmp/signing-key.json" not_before)" +%s) || die "bad not_before"
  na=$(date -u -d "$(field "$tmp/signing-key.json" not_after)" +%s) || die "bad not_after"
  [ "$now" -ge "$nb" ] && [ "$now" -lt "$na" ] || die "the signing-key statement is not valid now"
  [ $((na - nb)) -le $((366 * 86400)) ] || die "the signing-key statement is valid for more than 12 months"
  printf %s "$signer" | b64d >"$tmp/signer" 2>/dev/null || die "the signing key is malformed"
  [ "$(size "$tmp/signer")" = 42 ] && [ "$(head -c 2 "$tmp/signer")" = Ed ] || die "the signing key is not a minisign Ed25519 key"
  sid=$(dd if="$tmp/signer" bs=1 skip=2 count=8 2>/dev/null | hex)
  # An Ed25519 SubjectPublicKeyInfo: its 12-byte DER prefix, then the key.
  { printf '\060\052\060\005\006\003\053\145\160\003\041\000'; dd if="$tmp/signer" bs=1 skip=10 count=32 2>/dev/null; } >"$tmp/signer.der"
  openssl pkey -pubin -inform DER -in "$tmp/signer.der" -out "$tmp/signing-$sid.pem" 2>/dev/null || die "the signing key is malformed"

  # 2. The manifest, signed by that key, is of this version and lists the binary.
  verify "$tmp/manifest.json.minisig" "$tmp/manifest.json" "$tmp/signing" >/dev/null
  [ "$(field "$tmp/manifest.json" version)" = "$VERSION" ] || die "the manifest is not of version $VERSION"
  seq=$(grep -o '"seq":[0-9]*' "$tmp/manifest.json" | cut -d: -f2)
  [ -n "$seq" ] || die "the manifest has no seq"
  entry=$(grep -o "{\"os\":\"linux\",\"arch\":\"$arch\",\"variant\":\"full\",\"sha256\":\"[0-9a-f]*\",\"size\":[0-9]*}" "$tmp/manifest.json") ||
    die "the manifest lists no full build for linux/$arch"
  want_sum=$(echo "$entry" | sed 's/.*"sha256":"\([0-9a-f]*\)".*/\1/')
  want_size=$(echo "$entry" | sed 's/.*"size":\([0-9]*\)}/\1/')

  # 3. The binary has the manifest's size and SHA-256.
  [ "$(size "$tmp/$artifact")" = "$want_size" ] || die "the binary's size does not match the manifest"
  [ "$(openssl dgst -sha256 -r "$tmp/$artifact" | cut -d' ' -f1)" = "$want_sum" ] || die "the binary's SHA-256 does not match the manifest"
  say "verified rpmgr $VERSION (manifest $seq)"
}

say "downloading rpmgr $VERSION for linux/$arch from $GITHUB/$REPO"
artifact="rpmgr-$VERSION-linux-$arch"
for f in signing-key.json signing-key.json.minisig manifest.json manifest.json.minisig "$artifact"; do
  get "$GITHUB/$REPO/releases/download/v$VERSION/$f" "$tmp/$f" || die "cannot download $f of rpmgr $VERSION"
done
verify_release
[ "$verify_only" = 0 ] || exit 0

# Install only what verified; an upgrade replaces the binary in one rename.
[ "$(id -u)" = 0 ] || die "run as root: sudo sh install.sh"
for tool in install useradd id; do command -v "$tool" >/dev/null 2>&1 || die "$tool is needed"; done
id rpmgr >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/rpmgr --shell /usr/sbin/nologin rpmgr
install -d -m 0755 /etc/rpmgr
install -d -m 0750 -o rpmgr -g rpmgr /var/lib/rpmgr
install -d -m 0755 "$(dirname "$BIN")"
install -m 0755 "$tmp/$artifact" "$BIN.new"
mv -f "$BIN.new" "$BIN"
"$BIN" version --verbose || die "the installed $BIN does not run"
say "installed rpmgr $VERSION to $BIN"
for unit in rpmgr-controller rpmgr-all-in-one rpmgr-gateway rpmgr-connector; do
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$unit" 2>/dev/null; then
    say "$unit runs the previous binary until: systemctl restart $unit"
  fi
done

next() {
  say "next: set up this host's role with: sudo rpmgr setup"
}
if [ "$setup" = 0 ]; then
  next
  exit 0
fi
if ! "$BIN" setup --help >/dev/null 2>&1; then
  say "rpmgr $VERSION has no setup command; set up the role as docs/10-operations.md, \"Install\", describes:"
  say "  rpmgr all-in-one init --public-url https://<name>, or rpmgr controller init, or rpmgr enroll"
  exit 0
fi
# Asked only when standard input is the terminal: piped into sudo-rs, Ubuntu's sudo since 25.10, the
# terminal passes nothing typed on, so the question would wait for good. Without a terminal, nothing
# is asked. (A subshell: a failed redirection of the special built-in ":" would end the script.)
if [ ! -t 0 ] || ! (: </dev/tty) 2>/dev/null; then
  next
  exit 0
fi
printf 'Run rpmgr setup now? [Y/n] ' >/dev/tty
read -r answer </dev/tty || answer=n
case $answer in
  '' | [Yy] | [Yy][Ee][Ss]) umask 022; exec "$BIN" setup </dev/tty >/dev/tty 2>&1 ;; # not this script's 077
  *) next ;;
esac
