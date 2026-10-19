// SPDX-License-Identifier: Apache-2.0

// Command s9 is the harness of spike S9: how controller replicas share session ownership
// (docs/13-roadmap.md, row S9). Each question runs as a subcommand that starts its replicas as
// separate processes (the "replica" subcommand), drives simulated agents from this process, and
// writes its raw results to results/.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"replica":  runReplica,
		"facts":    runFacts,
		"q1":       runQ1,
		"q2":       runQ2,
		"q3":       runQ3,
		"q4-fs":    runQ4FS,
		"q4-s3":    runQ4S3,
		"q4-ship":  runQ4Ship,
		"q5":       runQ5,
		"pki":      runPKI,
		"s3-facts": runS3Facts,
	}
	f := cmds[os.Args[1]]
	if f == nil {
		usage()
	}
	if err := f(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "s9:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: s9 replica|facts|q1|q2|q3|q4-fs|q4-s3|q5|s3-facts|pki [flags]")
	os.Exit(2)
}
