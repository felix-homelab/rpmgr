// SPDX-License-Identifier: Apache-2.0

// Command s10 is the prototype of spike S10 (docs/spikes/S10.md, ADR-0022): a model gateway that
// hands its listening sockets to a re-executed binary, a load generator with model connectors, and
// the experiments behind the facts the design rests on. It is never merged; see README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "handoff":
		err = handoffCmd(os.Args[2:])
	case "load":
		err = load(os.Args[2:])
	case "reuseport":
		err = reuseport(os.Args[2:])
	case "sharedqueue":
		err = sharedQueue(os.Args[2:])
	case "sqlite":
		err = sqliteRun(os.Args[2:])
	case "bincheck":
		err = binCheckCmd(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "s10:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: s10 serve|handoff|load|reuseport|sharedqueue|sqlite|bincheck [flags]")
	os.Exit(2)
}
