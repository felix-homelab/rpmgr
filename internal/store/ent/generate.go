// SPDX-License-Identifier: Apache-2.0

// Package ent holds the Ent client generated from ./schema (docs/06-data-model.md). Regenerate it
// with `go generate ./internal/store/ent`; the generated code is committed.
package ent

// The generator is a tool dependency in go.mod. golang.org/x/tools is raised there above Ent's own
// requirement, because the version Ent v0.14.6 requires cannot load packages with Go 1.27 (S5).
//
//go:generate go tool ent generate --feature privacy,entql,intercept,sql/versioned-migration,sql/execquery ./schema
