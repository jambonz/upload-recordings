// Command procmon samples one process's CPU time and resident memory from
// /proc once a second and, when told to stop, prints a JSON summary including
// CPU time per thread. Run it in the server's PID namespace
// (docker run --pid container:<server>), where the server is PID 1.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const hz = 100 // USER_HZ

type thread struct {
	Tid     int     `json:"tid"`
	Name    string  `json:"name"`
	CPUSecs float64 `json:"cpu_secs"`
}

type summary struct {
	Label        string    `json:"label"`
	WallSecs     float64   `json:"wall_secs"`
	CPUSecs      float64   `json:"cpu_secs"` // user+system over the run
	UserSecs     float64   `json:"user_secs"`
	SysSecs      float64   `json:"sys_secs"`
	AvgCPUPct    float64   `json:"avg_cpu_pct"`   // of one core
	PeakCPUPct   float64   `json:"peak_cpu_pct"`  // busiest 1 s sample
	StartRSSMB   float64   `json:"start_rss_mb"`  // idle, before load
	MedianRSSMB  float64   `json:"median_rss_mb"` // steady state
	PeakRSSMB    float64   `json:"peak_rss_mb"`   // VmHWM
	EndRSSMB     float64   `json:"end_rss_mb"`
	Threads      int       `json:"threads"`
	BusiestPct   float64   `json:"busiest_thread_share_pct"` // share of all CPU used by one thread
	TopThreads   []thread  `json:"top_threads"`
	CPUPctSeries []float64 `json:"cpu_pct_series"`
	RSSMBSeries  []float64 `json:"rss_mb_series"`
}

func cpuTicks(statPath string) (user, sys float64, name string, ok bool) {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return
	}
	s := string(b)
	open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 {
		return
	}
	f := strings.Fields(s[close+2:])
	if len(f) < 13 {
		return
	}
	u, _ := strconv.ParseFloat(f[11], 64)
	k, _ := strconv.ParseFloat(f[12], 64)
	return u / hz, k / hz, s[open+1 : close], true
}

func statusMB(pid int, field string) float64 {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, field+":") {
			kb, _ := strconv.ParseFloat(strings.Fields(line)[1], 64)
			return kb / 1024
		}
	}
	return 0
}

func main() {
	pid := flag.Int("pid", 1, "process to watch")
	label := flag.String("label", "", "label copied into the summary")
	out := flag.String("out", "", "file to write the summary to (default stdout)")
	flag.Parse()

	stat := fmt.Sprintf("/proc/%d/stat", *pid)
	u0, s0, _, ok := cpuTicks(stat)
	if !ok {
		fmt.Fprintln(os.Stderr, "procmon: cannot read", stat)
		os.Exit(1)
	}
	sum := summary{Label: *label, StartRSSMB: statusMB(*pid, "VmRSS")}
	start := time.Now()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(time.Second)
	prev, prevAt := u0+s0, start
	var threads []thread
	sample := func() {
		u, s, _, ok := cpuTicks(stat)
		if !ok {
			return
		}
		now := time.Now()
		sum.CPUPctSeries = append(sum.CPUPctSeries, (u+s-prev)/now.Sub(prevAt).Seconds()*100)
		sum.RSSMBSeries = append(sum.RSSMBSeries, statusMB(*pid, "VmRSS"))
		prev, prevAt = u+s, now
		sum.UserSecs, sum.SysSecs = u-u0, s-s0
		sum.PeakRSSMB = statusMB(*pid, "VmHWM")
		// Threads come and go; keep the latest view of each.
		tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/stat", *pid))
		cur := threads[:0:0]
		for _, t := range tasks {
			tu, ts, name, ok := cpuTicks(t)
			if !ok {
				continue
			}
			tid, _ := strconv.Atoi(filepath.Base(filepath.Dir(t)))
			cur = append(cur, thread{tid, name, tu + ts})
		}
		if len(cur) > 0 {
			threads = cur
		}
	}
loop:
	for {
		select {
		case <-tick.C:
			sample()
		case <-stop:
			sample()
			break loop
		}
	}
	sum.WallSecs = time.Since(start).Seconds()
	sum.CPUSecs = sum.UserSecs + sum.SysSecs
	sum.AvgCPUPct = sum.CPUSecs / sum.WallSecs * 100
	for _, p := range sum.CPUPctSeries {
		sum.PeakCPUPct = max(sum.PeakCPUPct, p)
	}
	if n := len(sum.RSSMBSeries); n > 0 {
		sorted := append([]float64(nil), sum.RSSMBSeries...)
		sort.Float64s(sorted)
		sum.MedianRSSMB = sorted[n/2]
		sum.EndRSSMB = sum.RSSMBSeries[n-1]
	}
	sort.Slice(threads, func(i, j int) bool { return threads[i].CPUSecs > threads[j].CPUSecs })
	sum.Threads = len(threads)
	total := 0.0
	for _, t := range threads {
		total += t.CPUSecs
	}
	if total > 0 && len(threads) > 0 {
		sum.BusiestPct = threads[0].CPUSecs / total * 100
	}
	sum.TopThreads = threads[:min(len(threads), 6)]
	b, _ := json.Marshal(sum)
	if *out != "" {
		os.WriteFile(*out, append(b, '\n'), 0o644)
		return
	}
	fmt.Println(string(b))
}
