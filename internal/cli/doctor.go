package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DoctorResult holds the pass/fail result for one probe.
type DoctorResult struct {
	Name   string
	Pass   bool
	Detail string
}

// Doctor runs all pre-flight probes and prints a report to w.
// Returns an error if any CRITICAL probe fails.
func Doctor(ctx context.Context, cfg Config, w io.Writer) error {
	probes := []func(context.Context, Config) DoctorResult{
		probeOS,
		probeKernelVersion,
		probeTPROXYModule,
		probeIPTables,
		probeControlPlane,
		probeAgentAdmin,
	}

	anyFail := false
	for _, p := range probes {
		r := p(ctx, cfg)
		icon := "✓"
		if !r.Pass {
			icon = "✗"
			anyFail = true
		}
		fmt.Fprintf(w, "  %s  %-40s %s\n", icon, r.Name, r.Detail)
	}
	fmt.Fprintln(w)
	if anyFail {
		return fmt.Errorf("doctor: one or more probes failed")
	}
	return nil
}

func probeOS(_ context.Context, _ Config) DoctorResult {
	pass := runtime.GOOS == "linux"
	detail := runtime.GOOS
	if !pass {
		detail += " (Meridian data plane requires Linux)"
	}
	return DoctorResult{"OS", pass, detail}
}

func probeKernelVersion(_ context.Context, _ Config) DoctorResult {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return DoctorResult{"Kernel version", false, fmt.Sprintf("uname -r: %v", err)}
	}
	ver := strings.TrimSpace(string(out))
	// Require >= 5.10 (minimum for TC BPF + TPROXY + SOCKMAP).
	pass := kernelAtLeast(ver, 5, 10)
	detail := ver
	if !pass {
		detail += " (need >= 5.10)"
	}
	return DoctorResult{"Kernel >= 5.10", pass, detail}
}

func probeTPROXYModule(_ context.Context, _ Config) DoctorResult {
	// Check /proc/net/xt_TPROXY or try modprobe.
	if _, err := os.Stat("/proc/net/xt_TPROXY"); err == nil {
		return DoctorResult{"TPROXY module", true, "present (proc)"}
	}
	if out, err := exec.Command("modprobe", "--dry-run", "xt_TPROXY").CombinedOutput(); err == nil {
		return DoctorResult{"TPROXY module", true, "loadable"}
	} else {
		_ = out
	}
	// Last resort: check if it is built-in.
	if data, err := os.ReadFile("/lib/modules/" + kernelRelease() + "/modules.builtin"); err == nil {
		if strings.Contains(string(data), "xt_TPROXY") {
			return DoctorResult{"TPROXY module", true, "built-in"}
		}
	}
	return DoctorResult{"TPROXY module", false, "not found (CONFIG_NETFILTER_XT_TARGET_TPROXY required)"}
}

func probeIPTables(_ context.Context, _ Config) DoctorResult {
	if _, err := exec.LookPath("iptables"); err != nil {
		return DoctorResult{"iptables", false, "not found in PATH"}
	}
	out, err := exec.Command("iptables", "--version").Output()
	if err != nil {
		return DoctorResult{"iptables", false, fmt.Sprintf("%v", err)}
	}
	return DoctorResult{"iptables", true, strings.TrimSpace(string(out))}
}

func probeControlPlane(_ context.Context, cfg Config) DoctorResult {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(cfg.ControlAddr + "/status")
	if err != nil {
		return DoctorResult{"Control plane reachable", false, fmt.Sprintf("%v", err)}
	}
	resp.Body.Close()
	return DoctorResult{"Control plane reachable", resp.StatusCode < 500,
		fmt.Sprintf("HTTP %d at %s", resp.StatusCode, cfg.ControlAddr)}
}

func probeAgentAdmin(_ context.Context, cfg Config) DoctorResult {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(cfg.AgentAddr + "/healthz")
	if err != nil {
		return DoctorResult{"Agent admin reachable", false, fmt.Sprintf("%v", err)}
	}
	resp.Body.Close()
	return DoctorResult{"Agent admin reachable", resp.StatusCode == 200,
		fmt.Sprintf("HTTP %d at %s", resp.StatusCode, cfg.AgentAddr)}
}

func kernelRelease() string {
	out, _ := exec.Command("uname", "-r").Output()
	return strings.TrimSpace(string(out))
}

// kernelAtLeast reports whether verStr is >= major.minor.
func kernelAtLeast(verStr string, major, minor int) bool {
	var maj, min int
	_, _ = fmt.Sscanf(verStr, "%d.%d", &maj, &min)
	return maj > major || (maj == major && min >= minor)
}
