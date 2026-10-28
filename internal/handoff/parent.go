// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"io"
	"os"
	"time"
)

// Socket is one listening socket the old process hands over.
type Socket struct {
	// Name says what it serves, for logs.
	Name string
	// File is a duplicate of the socket, as (*net.TCPListener).File returns one. Start does not
	// close it; the caller does once Start returned.
	File *os.File
}

// Config is one hand-off as the old process starts it. It always starts the binary this process
// was started from, at its path (os.Executable), which an update replaced; nothing names another
// binary. The zero value passes this process's arguments and environment.
type Config struct {
	// Args are its arguments without the program name; nil for this process's.
	Args []string
	// Env is its environment; nil for this process's. Env itself is set by Start.
	Env []string
	// Generation is the new process's generation, one more than this one's.
	Generation uint64
	// Stdout and Stderr default to this process's.
	Stdout, Stderr io.Writer

	bin    string        // tests: their copy of the binary; else the one this process runs
	rule   *binaryRule   // tests: their own files instead of root's
	window time.Duration // tests: a shorter readiness window
}

// Child is a new process that reported ready and was told to take over.
type Child struct {
	// Pid is its process ID.
	Pid int
	// Generation is its generation.
	Generation uint64
	// Pipe is the status pipe to it.
	Pipe *Pipe

	exited chan struct{}
	err    error
}

// Exited is closed once the new process exited; Err then says how.
func (c *Child) Exited() <-chan struct{} { return c.exited }

// Err returns how the new process exited, once Exited is closed.
func (c *Child) Err() error { <-c.exited; return c.err }

// binaryRule is the check of the binary a hand-off starts (docs/04-security.md, "Socket
// hand-off"): a regular file owned by root that neither its group nor others may write, in
// directories that follow the same rule, up to /. Tests own their files and stop below /tmp.
type binaryRule struct {
	uid  uint32 // the owner every file and directory must have: root
	stop string // the last directory checked: /
}

var rootRule = binaryRule{uid: 0, stop: "/"}
