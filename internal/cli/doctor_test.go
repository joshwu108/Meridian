package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// T1 (unit, no root, any OS): every probe reads the host through the Env seam,
// so the checks below run identically on macOS and Linux.

const (
	mountsFull = "" +
		"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0\n" +
		"bpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0\n"

	statusAllCaps = "Name:\tmeridian\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nSeccomp:\t0\n"
	statusNoCaps  = "Name:\tmeridian\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n"
)

// capsHex renders an effective-capability mask holding exactly the given bits.
func capsHex(bits ...uint) string {
	var mask uint64
	for _, b := range bits {
		mask |= 1 << b
	}
	return "CapEff:\t" + hex16(mask) + "\n"
}

func hex16(v uint64) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		out[i] = digits[v&0xf]
		v >>= 4
	}
	return string(out)
}

// healthyEnv returns an Env describing a host that passes every check.
func healthyEnv() Env {
	files := map[string]string{
		"/proc/mounts":      mountsFull,
		"/proc/self/status": statusAllCaps,
		"/proc/modules":     "xt_TPROXY 20480 1 - Live 0x0000000000000000\nnf_tproxy_ipv4 16384 1 xt_TPROXY, Live 0x0\n",
		"/lib/modules/5.15.0-182/modules.builtin": "kernel/net/ipv4/netfilter/nf_defrag_ipv4.ko\n",
	}
	return Env{
		GOOS:          "linux",
		KernelRelease: func() (string, error) { return "5.15.0-182-generic", nil },
		ReadFile: func(path string) ([]byte, error) {
			if s, ok := files[path]; ok {
				return []byte(s), nil
			}
			return nil, errors.New("no such file or directory")
		},
		Run:     func(context.Context, string, ...string) error { return nil },
		HTTPGet: func(string) (int, error) { return 200, nil },
	}
}

// withFile returns a copy of env whose ReadFile serves content at path
// (content == "" removes the file). env is never mutated.
func withFile(env Env, path, content string) Env {
	base := env.ReadFile
	next := env
	next.ReadFile = func(p string) ([]byte, error) {
		if p == path {
			if content == "" {
				return nil, errors.New("no such file or directory")
			}
			return []byte(content), nil
		}
		return base(p)
	}
	return next
}

// find returns the result whose name contains sub.
func find(t *testing.T, results []CheckResult, sub string) CheckResult {
	t.Helper()
	for _, r := range results {
		if strings.Contains(r.Name, sub) {
			return r
		}
	}
	t.Fatalf("no check matching %q in %v", sub, names(results))
	return CheckResult{}
}

func names(results []CheckResult) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, r.Name)
	}
	return out
}

func TestRunChecksHealthyHost(t *testing.T) {
	results := RunChecks(context.Background(), DefaultConfig(), healthyEnv())
	if len(results) == 0 {
		t.Fatal("no checks ran")
	}
	for _, r := range results {
		if r.Status != StatusOK {
			t.Errorf("check %q = %s (%s), want OK", r.Name, r.Status, r.Detail)
		}
		if r.Detail == "" {
			t.Errorf("check %q has empty detail", r.Name)
		}
	}
}

func TestCheckKernel(t *testing.T) {
	tests := []struct {
		name    string
		release string
		err     error
		want    CheckStatus
	}{
		{"modern kernel", "6.8.0-45-generic", nil, StatusOK},
		{"exactly minimum recommended", "5.10.0", nil, StatusOK},
		{"ringbuf ok but below recommended", "5.8.0", nil, StatusWarn},
		{"below ringbuf minimum", "5.4.0-200-generic", nil, StatusFail},
		{"ancient", "4.19.0", nil, StatusFail},
		{"unparseable", "not-a-version", nil, StatusFail},
		{"uname failed", "", errors.New("boom"), StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := healthyEnv()
			env.KernelRelease = func() (string, error) { return tc.release, tc.err }
			got := checkKernel(env)
			if got.Status != tc.want {
				t.Errorf("checkKernel(%q) = %s (%s), want %s", tc.release, got.Status, got.Detail, tc.want)
			}
		})
	}
}

func TestCheckBPFFS(t *testing.T) {
	tests := []struct {
		name   string
		mounts string
		want   CheckStatus
	}{
		{"mounted", mountsFull, StatusOK},
		{"mountpoint with escaped space", "bpf /sys/fs/bpf\\040x bpf rw 0 0\n", StatusFail},
		{"wrong fstype at path", "tmpfs /sys/fs/bpf tmpfs rw 0 0\n", StatusFail},
		{"not mounted", "sysfs /sys sysfs rw 0 0\n", StatusFail},
		{"unreadable", "", StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkBPFFS(withFile(healthyEnv(), "/proc/mounts", tc.mounts))
			if got.Status != tc.want {
				t.Errorf("checkBPFFS = %s (%s), want %s", got.Status, got.Detail, tc.want)
			}
		})
	}
}

func TestCheckCgroupV2(t *testing.T) {
	tests := []struct {
		name   string
		mounts string
		want   CheckStatus
	}{
		{"unified at /sys/fs/cgroup", mountsFull, StatusOK},
		{"unified elsewhere (hybrid)", "" +
			"tmpfs /sys/fs/cgroup tmpfs ro 0 0\n" +
			"cgroup2 /sys/fs/cgroup/unified cgroup2 rw 0 0\n", StatusWarn},
		{"v1 only", "cgroup /sys/fs/cgroup/net_cls cgroup rw,net_cls 0 0\n", StatusFail},
		{"unreadable", "", StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCgroupV2(withFile(healthyEnv(), "/proc/mounts", tc.mounts))
			if got.Status != tc.want {
				t.Errorf("checkCgroupV2 = %s (%s), want %s", got.Status, got.Detail, tc.want)
			}
		})
	}
}

func TestCheckTPROXY(t *testing.T) {
	loadedElsewhere := "nf_tproxy_ipv4 16384 0 - Live 0x0\n"

	t.Run("loaded", func(t *testing.T) {
		if got := checkTPROXY(context.Background(), healthyEnv()); got.Status != StatusOK {
			t.Errorf("got %s (%s), want OK", got.Status, got.Detail)
		}
		if got := checkTPROXY(context.Background(), healthyEnv()); !strings.Contains(got.Detail, "loaded") {
			t.Errorf("detail %q should say the module is loaded", got.Detail)
		}
	})

	t.Run("built-in", func(t *testing.T) {
		env := withFile(healthyEnv(), "/proc/modules", loadedElsewhere)
		env = withFile(env, "/lib/modules/5.15.0-182-generic/modules.builtin",
			"kernel/net/netfilter/xt_TPROXY.ko\n")
		env.Run = func(context.Context, string, ...string) error { return errors.New("not executed") }
		got := checkTPROXY(context.Background(), env)
		if got.Status != StatusOK || !strings.Contains(got.Detail, "built-in") {
			t.Errorf("got %s (%s), want OK built-in", got.Status, got.Detail)
		}
	})

	t.Run("loadable via modprobe", func(t *testing.T) {
		env := withFile(healthyEnv(), "/proc/modules", loadedElsewhere)
		var ran []string
		env.Run = func(_ context.Context, name string, args ...string) error {
			ran = append(ran, name+" "+strings.Join(args, " "))
			return nil
		}
		got := checkTPROXY(context.Background(), env)
		if got.Status != StatusOK || !strings.Contains(got.Detail, "loadable") {
			t.Errorf("got %s (%s), want OK loadable", got.Status, got.Detail)
		}
		if len(ran) != 1 || !strings.Contains(ran[0], "modprobe --dry-run xt_TPROXY") {
			t.Errorf("ran %v, want a modprobe --dry-run xt_TPROXY probe", ran)
		}
	})

	t.Run("absent", func(t *testing.T) {
		env := withFile(healthyEnv(), "/proc/modules", loadedElsewhere)
		env.Run = func(context.Context, string, ...string) error { return errors.New("exit status 1") }
		got := checkTPROXY(context.Background(), env)
		if got.Status != StatusFail {
			t.Errorf("got %s (%s), want FAIL", got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "CONFIG_NETFILTER_XT_TARGET_TPROXY") {
			t.Errorf("detail %q should name the kernel config option", got.Detail)
		}
	})
}

func TestCheckCapabilities(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   CheckStatus
	}{
		{"root with full set", statusAllCaps, StatusOK},
		{"exactly CAP_BPF + CAP_NET_ADMIN", capsHex(capBPF, capNetAdmin), StatusOK},
		{"CAP_SYS_ADMIN substitutes for CAP_BPF", capsHex(capSysAdmin, capNetAdmin), StatusWarn},
		{"missing CAP_NET_ADMIN", capsHex(capBPF), StatusFail},
		{"missing BPF caps", capsHex(capNetAdmin), StatusFail},
		{"unprivileged", statusNoCaps, StatusFail},
		{"no CapEff line", "Name:\tmeridian\nUid:\t0\t0\t0\t0\n", StatusFail},
		{"unparseable CapEff", "CapEff:\tnot-hex\n", StatusFail},
		{"unreadable", "", StatusFail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCapabilities(withFile(healthyEnv(), "/proc/self/status", tc.status))
			if got.Status != tc.want {
				t.Errorf("checkCapabilities = %s (%s), want %s", got.Status, got.Detail, tc.want)
			}
		})
	}

	t.Run("names the missing capability", func(t *testing.T) {
		got := checkCapabilities(withFile(healthyEnv(), "/proc/self/status", capsHex(capBPF)))
		if !strings.Contains(got.Detail, "CAP_NET_ADMIN") {
			t.Errorf("detail %q should name CAP_NET_ADMIN", got.Detail)
		}
	})
}

func TestRunChecksNonLinuxHostSkipsKernelProbes(t *testing.T) {
	env := healthyEnv()
	env.GOOS = "darwin"
	results := RunChecks(context.Background(), DefaultConfig(), env)

	os := find(t, results, "host OS")
	if os.Status != StatusFail {
		t.Errorf("host OS = %s, want FAIL on darwin", os.Status)
	}
	for _, sub := range []string{"kernel", "bpffs", "cgroup", "TPROXY", "capabilities"} {
		r := find(t, results, sub)
		if r.Status != StatusWarn {
			t.Errorf("check %q = %s (%s), want WARN (skipped) on darwin", r.Name, r.Status, r.Detail)
		}
		if !strings.Contains(r.Detail, "darwin") {
			t.Errorf("check %q detail %q should name the host OS", r.Name, r.Detail)
		}
	}
	// Reachability does not depend on the kernel, so it still runs.
	if r := find(t, results, "control plane"); r.Status != StatusOK {
		t.Errorf("control plane = %s (%s), want OK", r.Status, r.Detail)
	}
}

func TestReachabilityChecksWarnButDoNotFail(t *testing.T) {
	env := healthyEnv()
	env.HTTPGet = func(string) (int, error) { return 0, errors.New("connection refused") }

	results := RunChecks(context.Background(), DefaultConfig(), env)
	for _, sub := range []string{"control plane", "agent admin"} {
		if r := find(t, results, sub); r.Status != StatusWarn {
			t.Errorf("check %q = %s (%s), want WARN", r.Name, r.Status, r.Detail)
		}
	}
	if err := reportFailure(results); err != nil {
		t.Errorf("warnings alone must not fail doctor: %v", err)
	}
}

func TestReachabilityServerError(t *testing.T) {
	env := healthyEnv()
	env.HTTPGet = func(string) (int, error) { return 503, nil }
	if r := find(t, RunChecks(context.Background(), DefaultConfig(), env), "control plane"); r.Status != StatusWarn {
		t.Errorf("HTTP 503 = %s (%s), want WARN", r.Status, r.Detail)
	}
}

func TestDoctorCheckWithEnvOutputAndExitStatus(t *testing.T) {
	t.Run("healthy host", func(t *testing.T) {
		var sb strings.Builder
		if err := DoctorCheckWithEnv(context.Background(), DefaultConfig(), healthyEnv(), &sb); err != nil {
			t.Fatalf("DoctorCheckWithEnv on healthy host: %v", err)
		}
		out := sb.String()
		if !strings.Contains(out, "[OK]") {
			t.Errorf("output missing [OK] markers:\n%s", out)
		}
		if strings.Contains(out, "[FAIL]") {
			t.Errorf("healthy host reported a failure:\n%s", out)
		}
	})

	t.Run("broken host", func(t *testing.T) {
		env := withFile(healthyEnv(), "/proc/mounts", "sysfs /sys sysfs rw 0 0\n")
		var sb strings.Builder
		err := DoctorCheckWithEnv(context.Background(), DefaultConfig(), env, &sb)
		if err == nil {
			t.Fatal("want error when a check fails")
		}
		out := sb.String()
		if !strings.Contains(out, "[FAIL]") {
			t.Errorf("output missing [FAIL] marker:\n%s", out)
		}
		// Every check still runs and prints, even after one fails.
		if got := strings.Count(out, "["); got < 8 {
			t.Errorf("want all checks printed, got %d lines:\n%s", got, out)
		}
	})
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		ver          string
		major, minor int
		wantErr      bool
	}{
		{"5.15.0-182-generic", 5, 15, false},
		{"6.1.0", 6, 1, false},
		{"5.10", 5, 10, false},
		{"5.10.1-custom", 5, 10, false},
		{"4.19.0-26-amd64", 4, 19, false},
		{"5", 0, 0, true},
		{"", 0, 0, true},
		{"not-a-version", 0, 0, true},
		{"x.10.0", 0, 0, true},
		{"5.x.0", 0, 0, true},
		{"5..0", 0, 0, true},
	}
	for _, tc := range tests {
		maj, min, err := parseKernelVersion(tc.ver)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseKernelVersion(%q) err = %v, wantErr %v", tc.ver, err, tc.wantErr)
			continue
		}
		if err == nil && (maj != tc.major || min != tc.minor) {
			t.Errorf("parseKernelVersion(%q) = %d.%d, want %d.%d", tc.ver, maj, min, tc.major, tc.minor)
		}
	}
}

func TestAtLeast(t *testing.T) {
	tests := []struct {
		ver          string
		major, minor int
		want         bool
	}{
		{"5.15.0-182", 5, 10, true},
		{"5.10.0", 5, 10, true},
		{"5.9.0", 5, 10, false},
		{"4.19.0", 5, 10, false},
		{"6.1.0", 5, 10, true},
		{"5.10.1-custom", 5, 10, true},
		{"5.8.0", 5, 8, true},
		{"5.7.19", 5, 8, false},
	}
	for _, tc := range tests {
		maj, min, err := parseKernelVersion(tc.ver)
		if err != nil {
			t.Fatalf("parseKernelVersion(%q): %v", tc.ver, err)
		}
		if got := atLeast(maj, min, tc.major, tc.minor); got != tc.want {
			t.Errorf("atLeast(%s >= %d.%d) = %v, want %v", tc.ver, tc.major, tc.minor, got, tc.want)
		}
	}
}

func TestParseMounts(t *testing.T) {
	mounts := parseMounts("" +
		"bpf /sys/fs/bpf bpf rw,mode=700 0 0\n" +
		"cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n" +
		"tmpfs /run/user/1000\\040(x) tmpfs rw 0 0\n" +
		"malformed line\n" +
		"\n")
	if len(mounts) != 3 {
		t.Fatalf("got %d mounts, want 3: %+v", len(mounts), mounts)
	}
	if mounts[0].Point != "/sys/fs/bpf" || mounts[0].Type != "bpf" {
		t.Errorf("mounts[0] = %+v", mounts[0])
	}
	if want := "/run/user/1000 (x)"; mounts[2].Point != want {
		t.Errorf("mounts[2].Point = %q, want %q (octal escapes decoded)", mounts[2].Point, want)
	}
}

func TestHostEnvIsWired(t *testing.T) {
	env := HostEnv()
	if env.GOOS == "" || env.KernelRelease == nil || env.ReadFile == nil || env.Run == nil || env.HTTPGet == nil {
		t.Fatalf("HostEnv() has unset fields: %+v", env)
	}
}
