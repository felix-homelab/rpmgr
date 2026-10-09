// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"slices"
	"sort"
	"strings"
)

// The tables compare the transports with each other and with a direct TCP connection, cell by
// cell, as spike S1 did (docs/spikes/S1.md):
//
//   - single-stream throughput: 1 stream, loss 0 %, up and down (higher is better);
//   - 32-stream goodput at 1 % loss, up and down (higher is better);
//   - connection-setup latency p99 at loss 0 % (lower is better);
//   - CPU per Gbit/s: gateway plus connector CPU seconds per Gbit delivered at loss 0 % (lower is
//     better);
//   - HTTP/2 requests per second and their p99 latency through an http route.
//
// Each cell is the median over repetitions. The targets are those of docs/03-connections.md,
// "Targets [T]"; regressions are reported against a baseline with the 10 % margin of
// RELEASING.md, report-only for v0.x (D49).
const regressionMargin = 0.10

type metric struct {
	name         string
	higherBetter bool
	match        func(r Record) bool
	value        func(r Record) float64
}

var metrics = []metric{
	{"Single-stream throughput (Mbit/s)", true,
		func(r Record) bool { return isTput(r) && r.Streams == 1 && r.LossPct == 0 },
		func(r Record) float64 { return r.GoodputMbps }},
	{"32-stream goodput at 1 % loss (Mbit/s)", true,
		func(r Record) bool { return isTput(r) && r.Streams == 32 && r.LossPct == 1 },
		func(r Record) float64 { return r.GoodputMbps }},
	{"Connection-setup latency p99 (ms)", false,
		func(r Record) bool { return r.Workload == "setup" && r.LossPct == 0 },
		func(r Record) float64 { return r.P99ms }},
	{"CPU per Gbit/s (CPU s per Gbit)", false,
		func(r Record) bool { return isTput(r) && r.LossPct == 0 && r.CPUPerGbit > 0 },
		func(r Record) float64 { return r.CPUPerGbit }},
	{"HTTP/2 requests per second", true,
		func(r Record) bool { return r.Workload == "http" },
		func(r Record) float64 { return r.RPS }},
	{"HTTP/2 request latency p99 (ms)", false,
		func(r Record) bool { return r.Workload == "http" },
		func(r Record) float64 { return r.P99ms }},
}

func isTput(r Record) bool { return r.Workload == "up" || r.Workload == "down" }

// cellKey identifies one measurement cell independent of the system.
type cellKey struct {
	Testbed  string
	GSO      string
	RTT      float64
	Loss     float64
	Workload string
	Streams  int
}

func (k cellKey) String() string {
	s := fmt.Sprintf("%s RTT %g ms loss %g %% %s", k.Testbed, k.RTT, k.Loss, k.Workload)
	if k.Streams > 0 {
		s += fmt.Sprintf(" ×%d", k.Streams)
	}
	if k.GSO != "" {
		s += " GSO " + k.GSO
	}
	return s
}

func keyOf(r Record) cellKey {
	return cellKey{r.Testbed, r.GSO, r.RTTms, r.LossPct, r.Workload, r.Streams}
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := slices.Clone(v)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func cmdSummarize(args []string) error {
	fs := flag.NewFlagSet("summarize", flag.ContinueOnError)
	in := fs.String("in", "results.jsonl", "results file")
	baseline := fs.String("baseline", "", "results of the last release on the same runners, for the regression check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	recs, err := readResults(*in)
	if err != nil {
		return err
	}
	var base []Record
	if *baseline != "" {
		if base, err = readResults(*baseline); err != nil {
			return err
		}
	}
	return summarize(os.Stdout, recs, base)
}

func readResults(path string) ([]Record, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's results file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readRecords(f)
}

func readRecords(r io.Reader) ([]Record, error) {
	var recs []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for line := 1; sc.Scan(); line++ {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		recs = append(recs, rec)
	}
	return recs, sc.Err()
}

// medians groups records by cell and system and returns the median of value per group.
func medians(recs []Record, match func(Record) bool, value func(Record) float64) map[cellKey]map[string]float64 {
	vals := map[cellKey]map[string][]float64{}
	for _, r := range recs {
		if !match(r) {
			continue
		}
		k := keyOf(r)
		if vals[k] == nil {
			vals[k] = map[string][]float64{}
		}
		vals[k][r.System] = append(vals[k][r.System], value(r))
	}
	out := map[cellKey]map[string]float64{}
	for k, bySys := range vals {
		out[k] = map[string]float64{}
		for sys, v := range bySys {
			out[k][sys] = median(v)
		}
	}
	return out
}

func sortedKeys(m map[cellKey]map[string]float64) []cellKey {
	keys := slices.Collect(maps.Keys(m))
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	return keys
}

func summarize(w io.Writer, recs, base []Record) error {
	if len(recs) == 0 {
		return errors.New("bench: no measurements")
	}
	testbeds := map[string]bool{}
	for _, r := range recs {
		testbeds[r.Testbed] = true
	}
	for _, tb := range slices.Sorted(maps.Keys(testbeds)) {
		if !strings.HasPrefix(tb, "ref-") {
			fmt.Fprintf(w, "> **Not the reference testbed** (%s): runner measurements (D49), not the reference run (VB-20).\n\n", tb)
		}
	}
	for _, m := range metrics {
		cells := medians(recs, m.match, m.value)
		if len(cells) == 0 {
			continue
		}
		fmt.Fprintf(w, "### %s\n\n| Cell | direct | QUIC | TCP + h2 | QUIC ÷ h2 |\n|---|---|---|---|---|\n", m.name)
		for _, k := range sortedKeys(cells) {
			c := cells[k]
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", k, num(c, "direct"), num(c, "quic"), num(c, "h2"), ratio(c))
		}
		fmt.Fprintln(w)
	}
	others(w, recs)
	targets(w, recs)
	if base != nil {
		regressions(w, recs, base)
	}
	return nil
}

// others lists the workloads that compare no transports cell by cell.
func others(w io.Writer, recs []Record) {
	var rows []string
	for _, r := range recs {
		var what, result string
		switch r.Workload {
		case "udp":
			what = fmt.Sprintf("UDP, %d B at %d/s", r.Size, r.Rate)
			result = fmt.Sprintf("%.0f /s back, loss %.2f %%, %.0f %% on the oversize path", r.PPS, r.UDPLossPct, r.OversizeShare*100)
		case "changes":
			what = fmt.Sprintf("1 change/s, %d routes", r.Routes)
			result = fmt.Sprintf("apply p50 %.2f s, p99 %.2f s; %d of %d held connections lost", r.ApplyP50s, r.ApplyP99s, r.Lost, r.Conns)
		case "kill-gateway", "kill-controller":
			what = strings.Replace(r.Workload, "kill-", "SIGKILL ", 1) + " under load"
			result = fmt.Sprintf("answers again after %.1f s; %d of %d held connections lost", r.RecoveryS, r.Lost, r.Conns)
		case "idle":
			what = fmt.Sprintf("%d idle connectors", r.Connectors)
			result = fmt.Sprintf("gateway %.0f MiB (%.0f MiB without them), %.3f CPU s/s", r.MemoryMiB["gateway"], r.MemoryMiB["gateway_without"],
				r.CPUs["gateway"]/r.DurationS)
		case "vb18":
			what = "VB-18: new connections to a blocked connector"
			result = fmt.Sprintf("%.0f %% before, %.0f %% while its session is blocked", r.Share["before"]*100, r.Share["blocked"]*100)
		default:
			continue
		}
		rows = append(rows, fmt.Sprintf("| %s RTT %g ms loss %g %% | %s | %s | %s |", r.Testbed, r.RTTms, r.LossPct, what, r.System, result))
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(w, "### Other workloads\n\n| Cell | Workload | System | Result |\n|---|---|---|---|\n%s\n\n", strings.Join(rows, "\n"))
}

// targets checks the targets of docs/03-connections.md, "Targets [T]".
func targets(w io.Writer, recs []Record) {
	fmt.Fprintf(w, "### Targets (03)\n\n| Target | Cell | Value | Met |\n|---|---|---|---|\n")
	single := medians(recs, metrics[0].match, metrics[0].value)
	for _, k := range sortedKeys(single) {
		c := single[k]
		for _, sys := range []string{"quic", "h2"} {
			if d, ok := c["direct"]; ok && d > 0 {
				share := c[sys] / d
				fmt.Fprintf(w, "| Single stream against direct (%s) | %s | %.0f %% | %s |\n", sys, k, share*100, yes(share >= 0.8))
			}
		}
	}
	multi := medians(recs, metrics[1].match, metrics[1].value)
	for _, k := range sortedKeys(multi) {
		if c := multi[k]; c["h2"] > 0 {
			r := c["quic"] / c["h2"]
			fmt.Fprintf(w, "| 32 streams at 1 %% loss: QUIC against h2 | %s | %.2f × | %s |\n", k, r, yes(r >= 1.5))
		}
	}
	setup := medians(recs, metrics[2].match, metrics[2].value)
	for _, k := range sortedKeys(setup) {
		c := setup[k]
		d, ok := c["direct"]
		if !ok {
			continue
		}
		for _, sys := range []string{"quic", "h2"} {
			if q, ok := c[sys]; ok {
				added := q - d
				fmt.Fprintf(w, "| Added setup latency p99 (%s) | %s | %+.2f ms | %s |\n", sys, k, added, yes(added <= k.RTT+2))
			}
		}
	}
	for _, r := range recs {
		if r.Workload != "changes" {
			continue
		}
		routes := ""
		if r.Routes < 1000 {
			routes = fmt.Sprintf(", %d routes, not 1 000", r.Routes)
		}
		fmt.Fprintf(w, "| Snapshot apply p99 (%s%s) | %s RTT %g ms | %.2f s | %s |\n", r.System, routes, r.Testbed, r.RTTms, r.ApplyP99s, yes(r.ApplyP99s <= 2))
		fmt.Fprintf(w, "| Resets on unchanged routes during changes (%s) | %s RTT %g ms | %d | %s |\n", r.System, r.Testbed, r.RTTms, r.Lost, yes(r.Lost == 0))
	}
	fmt.Fprintln(w)
}

// regressions compares each cell with the baseline's and lists those more than the margin worse.
func regressions(w io.Writer, recs, base []Record) {
	fmt.Fprintf(w, "### Regression check against the baseline (report-only for v0.x, D49)\n\n"+
		"| Metric | Cell | System | Baseline | Now | Change |\n|---|---|---|---|---|---|\n")
	found := 0
	for _, m := range metrics {
		now, then := medians(recs, m.match, m.value), medians(base, m.match, m.value)
		for _, k := range sortedKeys(now) {
			for _, sys := range []string{"direct", "quic", "h2"} {
				v, ok1 := now[k][sys]
				b, ok2 := then[k][sys]
				if !ok1 || !ok2 || b == 0 {
					continue
				}
				change := (v - b) / b
				worse := change < -regressionMargin
				if !m.higherBetter {
					worse = change > regressionMargin
				}
				if worse {
					found++
					fmt.Fprintf(w, "| %s | %s | %s | %.3g | %.3g | %+.0f %% |\n", m.name, k, sys, b, v, change*100)
				}
			}
		}
	}
	if found == 0 {
		fmt.Fprintf(w, "| — | no cell more than %.0f %% worse | | | | |\n", regressionMargin*100)
	}
	fmt.Fprintln(w)
}

func num(c map[string]float64, sys string) string {
	v, ok := c[sys]
	if !ok {
		return "—"
	}
	return fmt.Sprintf("%.3g", v)
}

func ratio(c map[string]float64) string {
	q, okQ := c["quic"]
	h, okH := c["h2"]
	if !okQ || !okH || h == 0 {
		return "—"
	}
	return fmt.Sprintf("%.2f", q/h)
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "**no**"
}
