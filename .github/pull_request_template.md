<!--
Title: a Conventional Commit header, at most 72 characters, e.g. `feat(dns): publish route hostnames`.
The merge commit on main records it. Rules: CONTRIBUTING.md.
-->

## What and why

<!-- What changes for users or for the design, and why. -->

Closes #

## How it was tested

<!-- Commands, test names, manual checks. Include error cases and edge conditions. -->

## Not verified

<!-- Anything that could not be run or checked here. Write "Nothing" if everything was verified. -->

## Breaking changes and upgrade notes

<!-- "None", or what users must do. Breaking changes also need `!` in the title and a `BREAKING CHANGE:` footer. -->

## Checklist

- [ ] Title is a Conventional Commit header; branch name follows CONTRIBUTING.md
- [ ] Every commit is signed off (`git commit -s`, DCO); new source files have an SPDX header
- [ ] One logical change, within the size limits (or the reason is given above)
- [ ] Tests cover error cases and edge conditions, not only the happy path
- [ ] Documentation updated per the feature documentation checklist (or not needed)
- [ ] `CHANGELOG.md` entry under `Unreleased`, or the `no-changelog` label
- [ ] Security impact considered; security-sensitive changes labelled `security-sensitive`
- [ ] New dependencies justified
