// SPDX-License-Identifier: Apache-2.0

// Package ent holds the generated Ent client of the S5 spike. Regenerate with `go generate ./ent`.
package ent

// The generator is pinned as a tool in go.mod. golang.org/x/tools is raised there above Ent's own
// requirement, because the version Ent v0.14.6 requires cannot load packages with Go 1.27
// ("package "context" without types was imported").
//
//go:generate go tool ent generate --feature privacy,entql,intercept,sql/versioned-migration,sql/execquery ./schema
