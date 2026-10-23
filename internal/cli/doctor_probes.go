package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Check names, shared by the probes and the non-Linux skip path.
const (
	nameHostOS       = "host OS"
	nameKernel       = "kernel >= 5.8 (BPF ringbuf)"
	nameBPFFS        = "bpffs at /sys/fs/bpf"
	nameCgroupV2     = "cgroup v2 at /sys/fs/cgroup"
	nameTPROXY       = "xt_TPROXY available"
	nameCapabilities = "effective capabilities"
)

// Kernel floors. 5.8 introduced the BPF ring buffer (BPF_MAP_TYPE_RINGBUF) and
// CAP_BPF, so it is a hard requirement. 5.10 is the version the project builds
// and tests against (see docs/subsystems/01-ebpf.md); anything between the two
// is expected to work but is untested.
const (
	kernelRingbufMajor = 5
	kernelRingbufMinor = 8
	kernelTestedMajor  = 5
	kernelTestedMinor  = 10
)

// Capability bit positions from <linux/capability.h>.
const (
	capNetAdmin = 12
	capSysAdmin = 21
	capBPF      = 39
)

// Filesystem paths the probes read.
const (
	procMounts     = "/proc/mounts"
	procSelfStatus = "/proc/self/status"
	procModules    = "/proc/modules"
	bpffsPath      = "/sys/fs/bpf"
	cgroupPath     = "/sys/fs/cgroup"
	tproxyModule   = "xt_TPROXY"
)

// checkHostOS reports whether this host can run the data plane at all.
func checkHostOS(env Env) CheckResult {
	if env.GOOS != "linux" {
		return CheckResult{nameHostOS, StatusFail,
			env.GOOS + " (the Meridian data plane requires Linux; use the Lima VM — see docs/TESTING_GUIDE.md)"}
	}
	return CheckResult{nameHostOS, StatusOK, "linux"}
}

// checkKernel reports whether the running kernel supports the BPF ring buffer.
func checkKernel(env Env) CheckResult {
	release, err := env.KernelRelease()
	if err != nil {
		return CheckResult{nameKernel, StatusFail, fmt.Sprintf("cannot determine kernel release: %v", err)}
	}
	major, minor, err := parseKernelVersion(release)
	if err != nil {
		return CheckResult{nameKernel, StatusFail, fmt.Sprintf("unparseable kernel release %q: %v", release, err)}
	}
	switch {
	case !atLeast(major, minor, kernelRingbufMajor, kernelRingbufMinor):
		return CheckResult{nameKernel, StatusFail, fmt.Sprintf(
			"%s (need >= %d.%d for BPF_MAP_TYPE_RINGBUF)",
			release, kernelRingbufMajor, kernelRingbufMinor)}
	case !atLeast(major, minor, kernelTestedMajor, kernelTestedMinor):
		return CheckResult{nameKernel, StatusWarn, fmt.Sprintf(
			"%s (ring buffer present; %d.%d+ is the tested baseline)",
			release, kernelTestedMajor, kernelTestedMinor)}
	default:
		return CheckResult{nameKernel, StatusOK, release}
	}
}

// checkBPFFS reports whether bpffs is mounted at /sys/fs/bpf, which the agent
// needs in order to pin maps and programs across restarts.
func checkBPFFS(env Env) CheckResult {
	mounts, err := readMounts(env)
	if err != nil {
		return CheckResult{nameBPFFS, StatusFail, err.Error()}
	}
	for _, m := range mounts {
		if m.Point == bpffsPath && m.Type == "bpf" {
			return CheckResult{nameBPFFS, StatusOK, "mounted (" + m.Type + ")"}
		}
	}
	return CheckResult{nameBPFFS, StatusFail,
		"not mounted (run: mount -t bpf bpf " + bpffsPath + ")"}
}

// checkCgroupV2 reports whether the unified cgroup hierarchy is mounted where
// the agent expects it. cgroup v2 is required for cgroup/connect4 attachment
// and for CONFIG_SOCK_CGROUP_DATA-based identity lookup.
func checkCgroupV2(env Env) CheckResult {
	mounts, err := readMounts(env)
	if err != nil {
		return CheckResult{nameCgroupV2, StatusFail, err.Error()}
	}
	elsewhere := ""
	for _, m := range mounts {
		if m.Type != "cgroup2" {
			continue
		}
		if m.Point == cgroupPath {
			return CheckResult{nameCgroupV2, StatusOK, "cgroup2 at " + cgroupPath}
		}
		if elsewhere == "" {
			elsewhere = m.Point
		}
	}
	if elsewhere != "" {
		return CheckResult{nameCgroupV2, StatusWarn, fmt.Sprintf(
			"cgroup2 mounted at %s, not %s (hybrid hierarchy; set the agent's cgroup root explicitly)",
			elsewhere, cgroupPath)}
	}
	return CheckResult{nameCgroupV2, StatusFail,
		"no cgroup2 mount (boot with systemd.unified_cgroup_hierarchy=1)"}
}

// checkTPROXY reports whether the xt_TPROXY target is usable: already loaded,
// built into the kernel, or loadable on demand.
func checkTPROXY(ctx context.Context, env Env) CheckResult {
	if data, err := env.ReadFile(procModules); err == nil && moduleLoaded(string(data), tproxyModule) {
		return CheckResult{nameTPROXY, StatusOK, "loaded"}
	}
	if release, err := env.KernelRelease(); err == nil {
		builtin := "/lib/modules/" + release + "/modules.builtin"
		if data, err := env.ReadFile(builtin); err == nil &&
			strings.Contains(string(data), "/"+tproxyModule+".ko") {
			return CheckResult{nameTPROXY, StatusOK, "built-in"}
		}
	}
	if err := env.Run(ctx, "modprobe", "--dry-run", tproxyModule); err == nil {
		return CheckResult{nameTPROXY, StatusOK, "loadable (modprobe --dry-run)"}
	}
	return CheckResult{nameTPROXY, StatusFail,
		"not loaded, built-in, or loadable (CONFIG_NETFILTER_XT_TARGET_TPROXY required)"}
}

// checkCapabilities reports whether this process holds the capabilities the
// agent needs: CAP_NET_ADMIN (TC/qdisc, iptables) plus CAP_BPF (or the older
// CAP_SYS_ADMIN) to load programs and create maps.
//
// The verdict describes the *invoking* process. Run `sudo meridian doctor` to
// check the privileges the agent will actually have.
func checkCapabilities(env Env) CheckResult {
	data, err := env.ReadFile(procSelfStatus)
	if err != nil {
		return CheckResult{nameCapabilities, StatusFail,
			fmt.Sprintf("cannot read %s: %v", procSelfStatus, err)}
	}
	caps, err := parseCapEff(string(data))
	if err != nil {
		return CheckResult{nameCapabilities, StatusFail, err.Error()}
	}

	hasNetAdmin := caps&(1<<capNetAdmin) != 0
	hasBPF := caps&(1<<capBPF) != 0
	hasSysAdmin := caps&(1<<capSysAdmin) != 0

	var missing []string
	if !hasNetAdmin {
		missing = append(missing, "CAP_NET_ADMIN")
	}
	if !hasBPF && !hasSysAdmin {
		missing = append(missing, "CAP_BPF (or CAP_SYS_ADMIN)")
	}
	if len(missing) > 0 {
		return CheckResult{nameCapabilities, StatusFail, fmt.Sprintf(
			"missing %s (re-run as root: sudo meridian doctor)", strings.Join(missing, ", "))}
	}
	if !hasBPF {
		return CheckResult{nameCapabilities, StatusWarn,
			"CAP_NET_ADMIN + CAP_SYS_ADMIN (CAP_BPF absent; works, but grant CAP_BPF for least privilege)"}
	}
	return CheckResult{nameCapabilities, StatusOK, "CAP_BPF + CAP_NET_ADMIN present"}
}

// checkReachable probes an HTTP endpoint. A control plane or agent that is not
// running yet is a warning, not a failure: doctor is a pre-flight check and is
// expected to run before the data plane is up.
func checkReachable(env Env, name, url string) CheckResult {
	code, err := env.HTTPGet(url)
	if err != nil {
		return CheckResult{name, StatusWarn, fmt.Sprintf("not reachable at %s: %v", url, err)}
	}
	if code >= 500 {
		return CheckResult{name, StatusWarn, fmt.Sprintf("HTTP %d at %s", code, url)}
	}
	return CheckResult{name, StatusOK, fmt.Sprintf("HTTP %d at %s", code, url)}
}

// mount is one entry of /proc/mounts.
type mount struct {
	Source string
	Point  string
	Type   string
	Opts   string
}

// readMounts returns the parsed mount table.
func readMounts(env Env) ([]mount, error) {
	data, err := env.ReadFile(procMounts)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", procMounts, err)
	}
	return parseMounts(string(data)), nil
}

// parseMounts parses /proc/mounts, skipping lines that are too short to be
// mount entries. Mount points are octal-escaped by the kernel.
func parseMounts(content string) []mount {
	lines := strings.Split(content, "\n")
	mounts := make([]mount, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mounts = append(mounts, mount{
			Source: unescapeMount(fields[0]),
			Point:  unescapeMount(fields[1]),
			Type:   fields[2],
			Opts:   fields[3],
		})
	}
	return mounts
}

// unescapeMount decodes the \OOO octal escapes the kernel writes for space,
// tab, newline and backslash in mount paths.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// moduleLoaded reports whether /proc/modules lists name as a loaded module.
// Only the first field of each line is the module's own name; later fields
// list the modules that depend on it.
func moduleLoaded(procModulesContent, name string) bool {
	for _, line := range strings.Split(procModulesContent, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == name {
			return true
		}
	}
	return false
}

// parseCapEff extracts the effective capability mask from /proc/<pid>/status.
func parseCapEff(statusContent string) (uint64, error) {
	for _, line := range strings.Split(statusContent, "\n") {
		value, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		caps, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("unparseable CapEff %q: %v", strings.TrimSpace(value), err)
		}
		return caps, nil
	}
	return 0, fmt.Errorf("no CapEff line in %s", procSelfStatus)
}

// parseKernelVersion extracts major and minor from a `uname -r` release string
// such as "5.15.0-182-generic".
func parseKernelVersion(release string) (int, int, error) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("want major.minor, got %q", release)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("bad major version in %q", release)
	}
	// The minor component may carry a suffix, e.g. "10-custom".
	minorDigits := parts[1]
	for i, r := range minorDigits {
		if r < '0' || r > '9' {
			minorDigits = minorDigits[:i]
			break
		}
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return 0, 0, fmt.Errorf("bad minor version in %q", release)
	}
	return major, minor, nil
}

// atLeast compares two major.minor pairs.
func atLeast(gotMajor, gotMinor, wantMajor, wantMinor int) bool {
	return gotMajor > wantMajor || (gotMajor == wantMajor && gotMinor >= wantMinor)
}
