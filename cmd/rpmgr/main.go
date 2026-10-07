// SPDX-License-Identifier: Apache-2.0

// Command rpmgr runs every role of rpmgr (controller, gateway, connector, all-in-one) and its
// administration commands (docs/02-architecture.md, docs/16-cli.md).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/felix-homelab/rpmgr/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Main(ctx, commands(), os.Args[1:], &cli.Env{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Getenv: os.Getenv,
	})
	stop()
	os.Exit(code)
}
