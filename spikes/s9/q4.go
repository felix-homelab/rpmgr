// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/felix-homelab/rpmgr/internal/revlog"
)

// runQ4Ship is one shipper process: it appends n entries to its local revocation log and ships
// after each append, as a replica does, then ships until nothing is left.
func runQ4Ship(args []string) error {
	fs := flag.NewFlagSet("q4-ship", flag.ExitOnError)
	kind := fs.String("kind", "fs", "fs | s3")
	dir := fs.String("dir", "", "filesystem sink directory")
	bucket := fs.String("bucket", "", "S3 bucket")
	prefix := fs.String("prefix", "sink/", "S3 key prefix")
	logPath := fs.String("log", "", "the local revocation log")
	replica := fs.String("replica", "", "replica name")
	n := fs.Int("n", 500, "entries")
	unconditional := fs.Bool("unconditional", false, "S3 negative control: PUT without If-None-Match")
	_ = fs.Parse(args)
	ctx := context.Background()
	l, err := revlog.Open(*logPath, nil)
	if err != nil {
		return err
	}
	var s3s *s3Sink
	if *kind == "s3" {
		s3s = &s3Sink{c: s3Client(), bucket: *bucket, prefix: *prefix, unconditional: *unconditional}
	}
	ship := func() error {
		if s3s != nil {
			return s3s.ship(ctx, *logPath, *replica)
		}
		left, err := revlog.Sink{Dir: *dir}.Ship(*logPath, *replica)
		if err == nil && len(left) > 0 {
			err = fmt.Errorf("%d left", len(left))
		}
		return err
	}
	errs := 0
	for i := range *n {
		if _, err := l.Append(revlog.Entry{Kind: revlog.CertificateRevoked, Subject: fmt.Sprintf("%s-%04d", *replica, i)}); err != nil {
			return err
		}
		if err := ship(); err != nil {
			errs++
		}
		time.Sleep(time.Duration(rand.IntN(3)) * time.Millisecond) //nolint:gosec // jitter
	}
	for range 100 {
		if err := ship(); err == nil {
			break
		}
		errs++
	}
	if s3s != nil {
		fmt.Printf("%s: taken=%d conflicts=%d errors=%d\n", *replica, s3s.Taken, s3s.Conflicts, errs)
	} else {
		fmt.Printf("%s: errors=%d\n", *replica, errs)
	}
	return nil
}

// race starts two shipper processes with args and waits for both.
func race(r *report, mk func(replica string) []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	outs := make([]bytes.Buffer, 2)
	errs := make([]error, 2)
	for i, rep := range []string{"r1", "r2"} {
		wg.Go(func() {
			cmd := exec.Command(self, append([]string{"q4-ship", "-replica", rep}, mk(rep)...)...) //nolint:gosec // own binary
			cmd.Stdout, cmd.Stderr = &outs[i], &outs[i]
			errs[i] = cmd.Run()
		})
	}
	wg.Wait()
	for i := range outs {
		r.printf("    shipper: %s", strings.TrimSpace(outs[i].String()))
		if errs[i] != nil {
			return errs[i]
		}
	}
	return nil
}

// exactlyOnce checks that the sink holds every local entry of both replicas once.
func exactlyOnce(sink []revlog.SinkEntry, logs map[string]string) (missing, dup int, err error) {
	seen := map[string]int{}
	for _, e := range sink {
		seen[e.Replica+"/"+e.Entry.Hash]++
	}
	for rep, path := range logs {
		local, err := revlog.Read(path)
		if err != nil {
			return 0, 0, err
		}
		for _, e := range local {
			switch seen[rep+"/"+e.Hash] {
			case 0:
				missing++
			case 1:
			default:
				dup++
			}
		}
	}
	return missing, dup, nil
}

// runQ4FS: two shipper processes race on a filesystem sink (tmpfs and the host's disk).
func runQ4FS(args []string) error {
	fs := flag.NewFlagSet("q4-fs", flag.ExitOnError)
	rounds := fs.Int("rounds", 5, "rounds per filesystem")
	n := fs.Int("n", 500, "entries per shipper")
	disk := fs.String("disk", filepath.Join(resultsDir(), "logs"), "a directory on the host's disk")
	_ = fs.Parse(args)
	r, err := newReport("q4-fs")
	if err != nil {
		return err
	}
	defer r.close()
	pass := true
	for _, base := range []string{"/dev/shm", *disk} {
		for round := range *rounds {
			dir, err := os.MkdirTemp(base, "s9-q4-")
			if err != nil {
				return err
			}
			sinkDir := filepath.Join(dir, "sink")
			if err := os.Mkdir(sinkDir, 0o750); err != nil {
				return err
			}
			logs := map[string]string{"r1": filepath.Join(dir, "r1.log"), "r2": filepath.Join(dir, "r2.log")}
			t := time.Now()
			if err := race(r, func(rep string) []string {
				return []string{"-kind", "fs", "-dir", sinkDir, "-log", logs[rep], "-n", fmt.Sprint(*n)}
			}); err != nil {
				return err
			}
			sink, err := revlog.Sink{Dir: sinkDir}.Read()
			if err != nil {
				pass = r.verdict(false, "%s round %d: the sink does not verify: %v", base, round+1, err) && pass
				continue
			}
			missing, dup, err := exactlyOnce(sink, logs)
			if err != nil {
				return err
			}
			pass = r.verdict(len(sink) == 2**n && missing == 0 && dup == 0,
				"%s round %d (%s): %d sink entries 1..%d, chain verified, missing %d, duplicate %d", fsType(base), round+1,
				time.Since(t).Round(time.Millisecond), len(sink), len(sink), missing, dup) && pass
			_ = os.RemoveAll(dir)
		}
	}
	r.printf("Q4 filesystem overall: %v", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return nil
}

func fsType(dir string) string {
	b, err := exec.Command("stat", "-f", "-c", "%T", dir).Output() //nolint:gosec // spike
	if err != nil {
		return dir
	}
	return dir + " (" + strings.TrimSpace(string(b)) + ")"
}

// runQ4S3: two shipper processes race on an S3 sink, with If-None-Match: *, then without it as
// the negative control.
func runQ4S3(args []string) error {
	fs := flag.NewFlagSet("q4-s3", flag.ExitOnError)
	rounds := fs.Int("rounds", 5, "rounds")
	n := fs.Int("n", 500, "entries per shipper")
	_ = fs.Parse(args)
	ctx := context.Background()
	r, err := newReport("q4-s3")
	if err != nil {
		return err
	}
	defer r.close()
	c := s3Client()
	bucket := "s9-sink"
	if err := ensureBucket(ctx, c, bucket); err != nil {
		return err
	}
	pass := true
	for _, unconditional := range []bool{false, true} {
		for round := range *rounds {
			if unconditional && round > 0 {
				break
			}
			prefix := fmt.Sprintf("run-%d/", time.Now().UnixNano())
			dir, err := os.MkdirTemp("", "s9-q4s3-")
			if err != nil {
				return err
			}
			logs := map[string]string{"r1": filepath.Join(dir, "r1.log"), "r2": filepath.Join(dir, "r2.log")}
			t := time.Now()
			if err := race(r, func(rep string) []string {
				return []string{"-kind", "s3", "-bucket", bucket, "-prefix", prefix, "-log", logs[rep], "-n", fmt.Sprint(*n),
					fmt.Sprintf("-unconditional=%v", unconditional)}
			}); err != nil {
				return err
			}
			reader := &s3Sink{c: c, bucket: bucket, prefix: prefix}
			sink, rerr := reader.read(ctx)
			missing, dup, err := exactlyOnce(sink, logs)
			if err != nil {
				return err
			}
			label := "If-None-Match: *"
			if unconditional {
				label = "negative control, plain PUT"
				r.verdict(rerr != nil || missing > 0 || dup > 0,
					"%s: the race is detected: verify error %v, missing %d, duplicate %d — expected", label, rerr, missing, dup)
				continue
			}
			pass = r.verdict(rerr == nil && len(sink) == 2**n && missing == 0 && dup == 0,
				"%s round %d (%s): %d sink objects, chain verified (%v), missing %d, duplicate %d", label, round+1,
				time.Since(t).Round(time.Millisecond), len(sink), rerr, missing, dup) && pass
			_ = os.RemoveAll(dir)
		}
	}
	r.printf("Q4 S3 overall: %v", map[bool]string{true: "PASS", false: "FAIL"}[pass])
	return nil
}

// runS3Facts re-checks conditional create on the pinned MinIO: a second If-None-Match: * PUT is
// refused with 412, and of two racing ones exactly one wins.
func runS3Facts(args []string) error {
	fs := flag.NewFlagSet("s3-facts", flag.ExitOnError)
	rounds := fs.Int("rounds", 500, "racing rounds")
	_ = fs.Parse(args)
	ctx := context.Background()
	r, err := newReport("facts-s3")
	if err != nil {
		return err
	}
	defer r.close()
	c := s3Client()
	bucket := "s9-facts"
	if err := ensureBucket(ctx, c, bucket); err != nil {
		return err
	}
	put := func(key, body string, cond bool) error {
		in := &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader(body)}
		if cond {
			in.IfNoneMatch = aws.String("*")
		}
		_, err := c.PutObject(ctx, in)
		return err
	}
	get := func(key string) string {
		o, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		if err != nil {
			return "error: " + err.Error()
		}
		defer func() { _ = o.Body.Close() }()
		b, _ := io.ReadAll(o.Body)
		return string(b)
	}
	key := fmt.Sprintf("once-%d", time.Now().UnixNano())
	e1, e2 := put(key, "first", true), put(key, "second", true)
	r.verdict(e1 == nil && statusOf(e2) == 412 && get(key) == "first",
		"If-None-Match: * creates (%v), a second is refused with %d, the object keeps its body (%q)", e1, statusOf(e2), get(key))
	for _, cond := range []bool{true, false} {
		wins, conflicts, other := 0, 0, 0
		bad := 0
		for i := range *rounds {
			k := fmt.Sprintf("race-%v-%d-%d", cond, time.Now().UnixNano(), i)
			var wg sync.WaitGroup
			res := make([]error, 2)
			for j := range 2 {
				wg.Go(func() { res[j] = put(k, fmt.Sprintf("writer-%d", j), cond) })
			}
			wg.Wait()
			ok := 0
			winner := -1
			for j, e := range res {
				switch statusOf(e) {
				case 0:
					if e == nil {
						ok++
						winner = j
					} else {
						other++
					}
				case 412:
				case 409:
					conflicts++
				default:
					other++
				}
			}
			wins += ok
			if cond && (ok != 1 || get(k) != fmt.Sprintf("writer-%d", winner)) {
				bad++
			}
		}
		if cond {
			r.verdict(bad == 0 && other == 0, "%d rounds of two racing If-None-Match: * PUTs: exactly one wins every round (%d wins, %d 409 conflicts, %d other errors, %d bad rounds)",
				*rounds, wins, conflicts, other, bad)
		} else {
			r.printf("negative control: %d rounds of two racing plain PUTs: %d succeed (both, overwriting)", *rounds, wins)
		}
	}
	return nil
}
