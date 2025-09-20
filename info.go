// go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	CLR_RESET = "\033[0m"
	CLR_DIM   = "\033[2m"
	CLR_BOLD  = "\033[1m"

	FG_RED    = "\033[31m"
	FG_GREEN  = "\033[32m"
	FG_YELLOW = "\033[33m"
	FG_BLUE   = "\033[34m"
	FG_CYAN   = "\033[36m"
	FG_WHITE  = "\033[37m"
)

type cpuSnap struct {
	user, nice, sys, idle, iowait, irq, softirq, steal, guest, guestNice uint64
}
type cpuAll struct {
	total cpuSnap
	cores []cpuSnap // cpu0, cpu1, ...
}

type netSnap struct {
	iface            string
	rxBytes, txBytes uint64
}

func main() {
	// Static info
	model := boardModel()

	// State
	prevAll := readCPUAll() // total + per-core
	prevNet := pickPrimaryIface()
	prevNet = readNetSnap(prevNet.iface)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		start := time.Now()

		// CPU (total + cores)
		curAll := readCPUAll()
		totPct, iowPct := cpuPercent(prevAll.total, curAll.total)
		corePcts := make([]float64, len(curAll.cores))
		for i := range curAll.cores {
			if i < len(prevAll.cores) {
				p, _ := cpuPercent(prevAll.cores[i], curAll.cores[i])
				corePcts[i] = p
			}
		}
		prevAll = curAll

		// Optional per-core frequency (cheap read; may be empty if not exposed)
		coreMHz := readCoreFreqMHz()

		load1, load5, load15 := readLoad()
		memTotal, memAvail, swapTotal, swapFree := readMem()
		usedMem := memTotal - memAvail
		swapUsed := swapTotal - swapFree

		rootUsage := diskUsage("/")

		if prevNet.iface == "" {
			prevNet = pickPrimaryIface()
		}
		curNet := readNetSnap(prevNet.iface)
		rxRate := float64(curNet.rxBytes - prevNet.rxBytes)
		txRate := float64(curNet.txBytes - prevNet.txBytes)
		prevNet = curNet

		tempC := readTempC()
		throt := throttledFlags() // "N/A" if vcgencmd missing
		up := uptime()
		ip := localIPv4()

		// Render
		clearScreen()
		fmt.Println(CLR_BOLD+"Raspberry Pi System Metrics"+CLR_RESET, dimf(" (updates every 1s)"))
		fmt.Println(dimf(model))
		fmt.Println(strings.Repeat("─", 60))

		// CPU total
		fmt.Printf("%sCPU%s  : %s%5.1f%%%s  %s(iowait %4.1f%%)%s   Load: %s%.2f %.2f %.2f%s\n",
			FG_CYAN, CLR_RESET, colorPct(totPct), totPct, CLR_RESET,
			CLR_DIM, iowPct, CLR_RESET,
			FG_WHITE, load1, load5, load15, CLR_RESET)

		// Per-core utilization
		if len(corePcts) > 0 {
			fmt.Print(FG_CYAN, "Cores", CLR_RESET, ": ")
			for i, p := range corePcts {
				fmt.Printf("%s%02d%s:%s%4.0f%%%s  ",
					CLR_DIM, i, CLR_RESET, colorPct(p), p, CLR_RESET)
				if (i+1)%8 == 0 && i+1 < len(corePcts) {
					fmt.Print("\n          ")
				}
			}
			fmt.Println()

			// Optional per-core frequency (MHz), only if lengths match
			if len(coreMHz) == len(corePcts) && len(coreMHz) > 0 {
				fmt.Print(FG_CYAN, "Freq ", CLR_RESET, ": ")
				for i, mhz := range coreMHz {
					lab := fmt.Sprintf("%4dMHz", mhz)
					col := FG_GREEN
					if mhz > 1800 {
						col = FG_YELLOW
					}
					if mhz > 2300 {
						col = FG_RED
					} // Pi 5 turbo territory
					fmt.Printf("%s%02d%s:%s%s%s  ", CLR_DIM, i, CLR_RESET, col, lab, CLR_RESET)
					if (i+1)%8 == 0 && i+1 < len(coreMHz) {
						fmt.Print("\n          ")
					}
				}
				fmt.Println()
			}
		}

		// Temp + throttle
		fmt.Printf("%sTherm%s: %s%5.1f°C%s   Throttle: %s\n",
			FG_CYAN, CLR_RESET, colorTemp(tempC), tempC, CLR_RESET, throt)

		// Mem / Swap
		fmt.Printf("%sMem%s  : %s / %s used   %sSwap%s: %s / %s used\n",
			FG_CYAN, CLR_RESET, colorMemFrac(usedMem, memTotal, humanBytes(usedMem)),
			humanBytes(memTotal),
			FG_CYAN, CLR_RESET,
			colorSwapFrac(swapUsed, swapTotal, humanBytes(swapUsed)),
			humanBytes(swapTotal),
		)

		// Disk
		fmt.Printf("%sDisk%s : / %s used of %s (%s)\n",
			FG_CYAN, CLR_RESET,
			colorDiskFrac(rootUsage.Used, rootUsage.Total, humanBytes(rootUsage.Used)),
			humanBytes(rootUsage.Total),
			colorDiskFrac(rootUsage.Used, rootUsage.Total, fmt.Sprintf("%.0f%%", rootUsage.Pct*100.0)),
		)

		// Net
		if prevNet.iface != "" {
			fmt.Printf("%sNet%s  : %s  ↓ %s/s  ↑ %s/s\n",
				FG_CYAN, CLR_RESET, prevNet.iface,
				humanBits(rxRate*8), humanBits(txRate*8))
		} else {
			fmt.Printf("%sNet%s  : %s\n", FG_CYAN, CLR_RESET, dimf("no active interface"))
		}

		// Uptime & IP
		fmt.Printf("%sSys%s  : Uptime %s   IP: %s\n",
			FG_CYAN, CLR_RESET, up, ip)

		// Footer
		fmt.Println(strings.Repeat("─", 60))
		fmt.Print(dimf("q to quit"))
		if time.Since(start) < 200*time.Millisecond {
			time.Sleep(50 * time.Millisecond)
		}
		<-ticker.C
	}
}

/********** CPU helpers (total + per-core) **********/

func readCPUAll() cpuAll {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuAll{}
	}
	defer f.Close()

	var out cpuAll
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "cpu ") {
			out.total = parseCPUStatLine(line)
		} else if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			out.cores = append(out.cores, parseCPUStatLine(line))
		} else {
			// ignore other lines
		}
	}
	return out
}

func parseCPUStatLine(line string) cpuSnap {
	fields := strings.Fields(line)
	var v [10]uint64
	for i := 0; i < len(v) && i+1 < len(fields); i++ {
		v[i], _ = parseUint(fields[i+1])
	}
	return cpuSnap{
		user: v[0], nice: v[1], sys: v[2], idle: v[3],
		iowait: v[4], irq: v[5], softirq: v[6],
		steal: v[7], guest: v[8], guestNice: v[9],
	}
}

func cpuPercent(a, b cpuSnap) (totalPct float64, iowPct float64) {
	du := float64(b.user - a.user)
	dn := float64(b.nice - a.nice)
	ds := float64(b.sys - a.sys)
	dd := float64(b.idle - a.idle)
	diow := float64(b.iowait - a.iowait)
	di := float64(b.irq - a.irq)
	dsi := float64(b.softirq - a.softirq)
	dst := float64(b.steal - a.steal)
	total := du + dn + ds + dd + diow + di + dsi + dst
	if total <= 0 {
		return 0, 0
	}
	busy := du + dn + ds + diow + di + dsi + dst
	return 100.0 * busy / total, 100.0 * diow / total
}

// localIPv4 returns the first non-loopback IPv4 address it finds.
func localIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ipv4 := ip.To4()
			if ipv4 != nil {
				return ipv4.String()
			}
		}
	}
	return "unknown"
}

/********** Board model + frequencies **********/

func boardModel() string {
	if b, err := os.ReadFile("/proc/device-tree/model"); err == nil {
		s := strings.TrimRight(string(b), "\x00\n ")
		if s != "" {
			return s
		}
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "Unknown"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Model") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "Unknown"
}

func readCoreFreqMHz() []int {
	paths, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")
	freqs := make([]int, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		hz, err := strconv.ParseInt(s, 10, 64)
		if err != nil || hz <= 0 {
			freqs = append(freqs, 0)
			continue
		}
		// file is in kHz on most systems; convert to MHz
		// If it's already in Hz, the division still lands us in MHz.
		mhz := int(hz / 1000)
		if mhz == 0 {
			mhz = int(hz / 1_000_000)
		}
		freqs = append(freqs, mhz)
	}
	return freqs
}

/********** Parsing helpers **********/

func readLoad() (float64, float64, float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fs := strings.Fields(string(b))
	if len(fs) < 3 {
		return 0, 0, 0
	}
	l1, _ := strconv.ParseFloat(fs[0], 64)
	l5, _ := strconv.ParseFloat(fs[1], 64)
	l15, _ := strconv.ParseFloat(fs[2], 64)
	return l1, l5, l15
}

func readMem() (memTotal, memAvail, swapTotal, swapFree uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line == "" && err != nil {
			break
		}
		if strings.HasPrefix(line, "MemTotal:") {
			memTotal = parseKiBLine(line)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			memAvail = parseKiBLine(line)
		} else if strings.HasPrefix(line, "SwapTotal:") {
			swapTotal = parseKiBLine(line)
		} else if strings.HasPrefix(line, "SwapFree:") {
			swapFree = parseKiBLine(line)
		}
		if err == io.EOF {
			break
		}
	}
	// KiB -> bytes
	memTotal *= 1024
	memAvail *= 1024
	swapTotal *= 1024
	swapFree *= 1024
	return
}

func parseKiBLine(line string) uint64 {
	fs := strings.Fields(line)
	if len(fs) < 2 {
		return 0
	}
	val, _ := parseUint(fs[1])
	return val
}

type diskInfo struct {
	Total, Used uint64
	Pct         float64
}

func diskUsage(path string) diskInfo {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return diskInfo{}
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	used := total - free
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total)
	}
	return diskInfo{Total: total, Used: used, Pct: pct}
}

func pickPrimaryIface() netSnap {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return netSnap{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for i := 0; sc.Scan(); i++ {
		if i < 2 {
			continue // skip headers
		}
		line := sc.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		return netSnap{iface: iface}
	}
	return netSnap{}
}

func readNetSnap(iface string) netSnap {
	if iface == "" {
		return netSnap{}
	}
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return netSnap{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for i := 0; sc.Scan(); i++ {
		if i < 2 {
			continue
		}
		line := sc.Text()
		if !strings.Contains(line, iface+":") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			break
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			break
		}
		rxB, _ := parseUint(fields[0])
		txB, _ := parseUint(fields[8])
		return netSnap{iface: iface, rxBytes: rxB, txBytes: txB}
	}
	return netSnap{iface: iface}
}

func readTempC() float64 {
	matches, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, p := range matches {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(raw))
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		if v > 1000 {
			return v / 1000.0
		}
		return v
	}
	return 0
}

func throttledFlags() string {
	path, err := exec.LookPath("vcgencmd")
	if err != nil {
		return dimf("N/A (vcgencmd not found)")
	}
	out, err := exec.Command(path, "get_throttled").Output()
	if err != nil {
		return dimf("N/A (vcgencmd error)")
	}
	// Example: "throttled=0x0\n"
	s := strings.TrimSpace(string(out))
	if !strings.Contains(s, "0x") {
		return s
	}
	hex := s[strings.Index(s, "0x")+2:]
	val, _ := strconv.ParseUint(hex, 16, 64)
	if val == 0 {
		return colorOK("0x0 (no throttling)")
	}
	return colorWarn(fmt.Sprintf("0x%x", val))
}

func uptime() string {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "unknown"
	}
	fs := strings.Fields(string(b))
	if len(fs) == 0 {
		return "unknown"
	}
	secs, _ := strconv.ParseFloat(fs[0], 64)
	d := time.Duration(secs) * time.Second
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	return fmt.Sprintf("%dd %dh %dm", days, h, m)
}

/********** Formatting **********/

func colorPct(v float64) string {
	switch {
	case v < 40:
		return FG_GREEN
	case v < 75:
		return FG_YELLOW
	default:
		return FG_RED
	}
}

func colorTemp(v float64) string {
	switch {
	case v < 60:
		return FG_GREEN
	case v < 75:
		return FG_YELLOW
	default:
		return FG_RED
	}
}

func colorOK(s string) string   { return FG_GREEN + s + CLR_RESET }
func colorWarn(s string) string { return FG_YELLOW + s + CLR_RESET }

func colorMemFrac(used, total uint64, label string) string {
	p := frac(used, total)
	return colorByPct(label, p)
}
func colorSwapFrac(used, total uint64, label string) string {
	p := frac(used, total)
	return colorByPct(label, p)
}
func colorDiskFrac(used, total uint64, label string) string {
	p := frac(used, total)
	return colorByPct(label, p)
}

func colorByPct(label string, p float64) string {
	switch {
	case p < 0.6:
		return FG_GREEN + label + CLR_RESET
	case p < 0.85:
		return FG_YELLOW + label + CLR_RESET
	default:
		return FG_RED + label + CLR_RESET
	}
}

func frac(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanBits(bitsPerSec float64) string {
	const unit = 1000.0
	if bitsPerSec < unit {
		return fmt.Sprintf("%.0f b", bitsPerSec)
	}
	div, exp := unit, 0
	for n := bitsPerSec / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cb", bitsPerSec/div, "kMGTPE"[exp])
}

func parseUint(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(s), 10, 64)
}

func dimf(s string) string { return CLR_DIM + s + CLR_RESET }

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}
