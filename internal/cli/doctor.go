// Pre-flight diagnostics for the Meridian data plane.
//
// `meridian doctor` answers one question: can this host run the agent's eBPF
// data path? Every probe reads the host through the Env seam, so the decision
// logic is pure and unit-testable (T1) on any OS without root; only HostEnv
// touches the real kernel.
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

// CheckStatus is the verdict of a single probe.
type CheckStatus string

const (
	// StatusOK means the requirement is satisfied.
	StatusOK CheckStatus = "OK"
	// StatusWarn means the requirement is satisfied in a degraded or
	// unverifiable way: the data path will probably work, but something
	// deserves attention. Warnings do not fail `meridian doctor`.
	StatusWarn CheckStatus = "WARN"
	// StatusFail means the requirement is not satisfied and the data path
	// cannot come up. Any failure fails `meridian doctor`.
	StatusFail CheckStatus = "FAIL"
)

// CheckResult is one line of the doctor report.
type CheckResult struct {
	Name   string
	Status CheckStatus
	Detail string
}

// Env is the seam between the checks and the host. Tests supply stubs; real
// runs use HostEnv. All fields must be non-nil.
type Env struct {
	// GOOS is the host operating system (runtime.GOOS).
	GOOS string
	// KernelRelease returns the running kernel release (`uname -r`).
	KernelRelease func() (string, error)
	// ReadFile reads a file, typically under /proc or /sys.
	ReadFile func(path string) ([]byte, error)
	// Run executes a command and reports whether it succeeded.
	Run func(ctx context.Context, name string, args ...string) error
	// HTTPGet GETs url and returns the response status code.
	HTTPGet func(url string) (int, error)
}

// probeTimeout bounds each external command and HTTP probe so doctor always
// terminates promptly on a wedged host.
const probeTimeout = 3 * time.Second

// HostEnv returns an Env wired to the real host.
func HostEnv() Env {
	return Env{
		GOOS: runtime.GOOS,
		KernelRelease: func() (string, error) {
			out, err := exec.Command("uname", "-r").Output()
			if err != nil {
				return "", fmt.Errorf("uname -r: %w", err)
			}
			return strings.TrimSpace(string(out)), nil
		},
		ReadFile: os.ReadFile,
		Run: func(ctx context.Context, name string, args ...string) error {
			ctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			return exec.CommandContext(ctx, name, args...).Run()
		},
		HTTPGet: func(url string) (int, error) {
			client := &http.Client{Timeout: probeTimeout}
			resp, err := client.Get(url)
			if err != nil {
				return 0, err
			}
			defer resp.Body.Close()
			return resp.StatusCode, nil
		},
	}
}

// DoctorCheck runs the pre-flight probes against the real host, prints the
// report to w, and returns a non-nil error if any check failed.
func DoctorCheck(ctx context.Context, cfg Config, w io.Writer) error {
	return DoctorCheckWithEnv(ctx, cfg, HostEnv(), w)
}

// DoctorCheckWithEnv is DoctorCheck against an explicit Env (the test seam).
func DoctorCheckWithEnv(ctx context.Context, cfg Config, env Env, w io.Writer) error {
	results := RunChecks(ctx, cfg, env)
	if err := printReport(results, w); err != nil {
		return err
	}
	return reportFailure(results)
}

// RunChecks runs every probe and returns the results in report order. It never
// short-circuits: a broken host should get the full picture in one pass.
func RunChecks(ctx context.Context, cfg Config, env Env) []CheckResult {
	osResult := checkHostOS(env)

	// The kernel probes are meaningless off Linux; report them as skipped
	// rather than pretending to have an answer.
	kernelChecks := []func() CheckResult{
		func() CheckResult { return checkKernel(env) },
		func() CheckResult { return checkBPFFS(env) },
		func() CheckResult { return checkCgroupV2(env) },
		func() CheckResult { return checkTPROXY(ctx, env) },
		func() CheckResult { return checkCapabilities(env) },
	}
	skipped := []string{nameKernel, nameBPFFS, nameCgroupV2, nameTPROXY, nameCapabilities}

	results := make([]CheckResult, 0, len(kernelChecks)+3)
	results = append(results, osResult)
	for i, check := range kernelChecks {
		if env.GOOS != "linux" {
			results = append(results, skip(skipped[i], env.GOOS))
			continue
		}
		results = append(results, check())
	}
	return append(results,
		checkReachable(env, "control plane reachable", cfg.ControlAddr+"/status"),
		checkReachable(env, "agent admin reachable", cfg.AgentAddr+"/healthz"),
	)
}

// skip reports a probe that cannot run on this host.
func skip(name, goos string) CheckResult {
	return CheckResult{name, StatusWarn, "skipped: requires Linux (host is " + goos + ")"}
}

// printReport writes the human-readable report.
func printReport(results []CheckResult, w io.Writer) error {
	if _, err := fmt.Fprintf(w, "meridian doctor — data plane pre-flight\n\n"); err != nil {
		return err
	}
	var ok, warn, fail int
	for _, r := range results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		default:
			fail++
		}
		if _, err := fmt.Fprintf(w, "  %-7s %-34s %s\n", "["+string(r.Status)+"]", r.Name, r.Detail); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "\n%d ok, %d warning(s), %d failure(s)\n", ok, warn, fail)
	return err
}

// reportFailure returns an error if any check failed. Warnings are tolerated.
func reportFailure(results []CheckResult) error {
	var failed []string
	for _, r := range results {
		if r.Status == StatusFail {
			failed = append(failed, r.Name)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("doctor: %d check(s) failed: %s", len(failed), strings.Join(failed, ", "))
}
