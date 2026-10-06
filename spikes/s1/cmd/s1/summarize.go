// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
)

// The D19 rule names four metrics and "the transport that wins more of the four". The cells and
// the aggregation below make it computable; they were fixed in docs/spikes/S1.md before any
// reference-testbed run:
//
//   - M1 single-stream throughput: 1 stream, loss 0 %, RTT {1, 80} ms, up and down (higher wins);
//   - M2 32-stream goodput at 1 % loss: 32 streams, RTT {1, 80} ms, up and down (higher wins);
//   - M3 connection-setup latency p99: loss 0 %, RTT {1, 80} ms (lower wins);
//   - M4 CPU per Gbit/s: gateway plus connector CPU seconds per Gbit delivered, RTT 1 ms, loss 0 %,
//     1 and 32 streams, up and down (lower wins).
//
// Each cell is the median over repetitions. Per metric, the QUIC/h2 ratios of all cells and all
// testbeds (x86-64, arm64, Raspberry Pi 5) are combined by geometric mean, oriented so that a
// value above 1 favours QUIC. A transport wins a metric when that mean favours it by at least 5 %;
// otherwise the metric is a tie. The default is the transport with more wins; a tie keeps QUIC.
const winMargin = 1.05

type metric struct {
	name         string
	higherBetter bool
	match        func(r Record) bool
	value        func(r Record) float64
}

var metrics = []metric{
	{"M1 single-stream throughput (Mbit/s)", true,
		func(r Record) bool { return isTput(r) && r.Streams == 1 && r.LossPct == 0 && inRTT(r) },
		func(r Record) float64 { return r.GoodputMbps }},
	{"M2 32-stream goodput at 1 % loss (Mbit/s)", true,
		func(r Record) bool { return isTput(r) && r.Streams == 32 && r.LossPct == 1 && inRTT(r) },
		func(r Record) float64 { return r.GoodputMbps }},
	{"M3 connection-setup latency p99 (ms)", false,
		func(r Record) bool { return r.Workload == "setup" && r.LossPct == 0 && inRTT(r) },
		func(r Record) float64 { return r.P99ms }},
	{"M4 CPU per Gbit/s (CPU s per Gbit)", false,
		func(r Record) bool { return isTput(r) && r.RTTms == 1 && r.LossPct == 0 && r.CPUPerGbit > 0 },
		func(r Record) float64 { return r.CPUPerGbit }},
}

func isTput(r Record) bool { return r.Workload == "up" || r.Workload == "down" }
func inRTT(r Record) bool  { return r.RTTms == 1 || r.RTTms == 80 }

// cellKey identifies one measurement cell independent of the system.
type cellKey struct {
	Testbed  string
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
	return s
}

func keyOf(r Record) cellKey {
	return cellKey{r.Testbed, r.RTTms, r.LossPct, r.Workload, r.Streams}
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func cmdSummarize(args []string) error {
	fs := flag.NewFlagSet("summarize", flag.ExitOnError)
	in := fs.String("in", "results.jsonl", "results file")
	_ = fs.Parse(args)
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	recs, err := readRecords(f)
	if err != nil {
		return err
	}
	return summarize(os.Stdout, recs)
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
	keys := make([]cellKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	return keys
}

// Verdict is the outcome of the D19 rule.
type Verdict struct {
	Wins      map[string]int // "quic", "h2"
	PerMetric []string       // "quic", "h2" or "tie"
	Default   string
}

func applyRule(recs []Record) (Verdict, []float64, error) {
	v := Verdict{Wins: map[string]int{}}
	var gms []float64
	for _, m := range metrics {
		cells := medians(recs, m.match, m.value)
		var logSum float64
		var n int
		for _, k := range sortedKeys(cells) {
			q, okQ := cells[k]["quic"]
			h, okH := cells[k]["h2"]
			if !okQ || !okH || q <= 0 || h <= 0 {
				continue
			}
			ratio := q / h
			if !m.higherBetter {
				ratio = h / q
			}
			logSum += math.Log(ratio)
			n++
		}
		if n == 0 {
			return v, nil, fmt.Errorf("no cell with both transports for %s", m.name)
		}
		gm := math.Exp(logSum / float64(n))
		gms = append(gms, gm)
		switch {
		case gm >= winMargin:
			v.Wins["quic"]++
			v.PerMetric = append(v.PerMetric, "quic")
		case gm <= 1/winMargin:
			v.Wins["h2"]++
			v.PerMetric = append(v.PerMetric, "h2")
		default:
			v.PerMetric = append(v.PerMetric, "tie")
		}
	}
	v.Default = "quic"
	if v.Wins["h2"] > v.Wins["quic"] {
		v.Default = "h2"
	}
	return v, gms, nil
}

func summarize(w io.Writer, recs []Record) error {
	testbeds := map[string]bool{}
	for _, r := range recs {
		testbeds[r.Testbed] = true
	}
	for tb := range testbeds {
		if !strings.HasPrefix(tb, "ref-") {
			fmt.Fprintf(w, "> **Not the reference testbed** (%s): these numbers do not decide the rule (D37).\n\n", tb)
		}
	}
	for _, m := range metrics {
		cells := medians(recs, m.match, m.value)
		fmt.Fprintf(w, "### %s\n\n| Cell | direct | QUIC | TCP + h2 | QUIC ÷ h2 |\n|---|---|---|---|---|\n", m.name)
		for _, k := range sortedKeys(cells) {
			c := cells[k]
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", k, num(c, "direct"), num(c, "quic"), num(c, "h2"), ratio(c))
		}
		fmt.Fprintln(w)
	}
	targets(w, recs)
	v, gms, err := applyRule(recs)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "### D19 rule\n\n| Metric | Geometric mean, oriented (> 1 favours QUIC) | Winner |\n|---|---|---|\n")
	for i, m := range metrics {
		fmt.Fprintf(w, "| %s | %.3f | %s |\n", m.name, gms[i], v.PerMetric[i])
	}
	fmt.Fprintf(w, "\nWins: QUIC %d, TCP + h2 %d → default transport: **%s**\n", v.Wins["quic"], v.Wins["h2"], v.Default)
	return nil
}

// targets checks the [T] targets of docs/03-connections.md#targets-t.
func targets(w io.Writer, recs []Record) {
	fmt.Fprintf(w, "### Targets (03)\n\n| Target | Cell | Value | Met |\n|---|---|---|---|\n")
	single := medians(recs, metrics[0].match, metrics[0].value)
	for _, k := range sortedKeys(single) {
		c := single[k]
		for _, sys := range []string{"quic", "h2"} {
			if d, ok := c["direct"]; ok && d > 0 {
				share := c[sys] / d
				fmt.Fprintf(w, "| Single stream ≥ 80 %% of direct (%s) | %s | %.0f %% | %s |\n", sys, k, share*100, yes(share >= 0.8))
			}
		}
	}
	multi := medians(recs, metrics[1].match, metrics[1].value)
	for _, k := range sortedKeys(multi) {
		c := multi[k]
		if c["h2"] > 0 {
			r := c["quic"] / c["h2"]
			fmt.Fprintf(w, "| 32 streams at 1 %% loss: QUIC ≥ 1.5 × h2 | %s | %.2f × | %s |\n", k, r, yes(r >= 1.5))
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
			added := c[sys] - d
			fmt.Fprintf(w, "| Added setup p99 ≤ RTT + 2 ms (%s) | %s | %+.2f ms | %s |\n", sys, k, added, yes(added <= k.RTT+2))
		}
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
