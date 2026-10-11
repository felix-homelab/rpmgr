#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks that a pull-request title is a Conventional Commit header of at most 72 characters
# (CONTRIBUTING.md, "Commits" and "Pull requests"). With --bot, for the dependency bot's titles and
# commits, the subject may start with a capital letter and the line may be longer (D65); the type
# and the scope are checked as for everyone.
#
# Usage: check-pr-title.sh [--bot] "<title>"
set -euo pipefail
export LC_ALL=C.UTF-8
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

bot=false
if [[ ${1-} == --bot ]]; then
  bot=true
  shift
fi
title=${1-}
types='feat|fix|perf|refactor|docs|test|build|ci|chore|revert'
scopes='controller|gateway|connector|tunnel|pki|policy|authz|store|api|web|dns|acme|ota|importer|cli|ops|design|adr|deps|release'
header="^(${types})(\\((${scopes})\\))?!?: [^ ]"

if [[ -z $title ]]; then
  fail "the PR title is empty"
  finish
fi
if ! $bot && ((${#title} > 72)); then
  fail "the PR title has ${#title} characters; the limit is 72"
fi
if [[ ! $title =~ $header ]]; then
  fail "the PR title must start with '<type>(<scope>)!: ' where type is one of ${types//|/, }" \
    "and the optional scope one of ${scopes//|/, } (got: '$title')"
else
  subject=${title#*: }
  if ! $bot && [[ ! $subject =~ ^[a-z0-9\`] ]]; then
    fail "the subject must start with a lowercase letter, a digit or a backtick (got: '$subject')"
  fi
  if [[ $subject == *. ]]; then
    fail "the subject must not end with a period"
  fi
  if [[ $subject =~ [[:space:]]$ || $subject =~ [[:space:]]{2} ]]; then
    fail "the subject has trailing or repeated whitespace"
  fi
fi
finish
