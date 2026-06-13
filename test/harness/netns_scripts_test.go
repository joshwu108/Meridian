package harness

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupNetnsDryRun(t *testing.T) {
	out := runScript(t, "setup_netns.sh", "mrdn-test")
	assertContainsInOrder(t, out,
		"+ ip netns add mrdn-test",
		"+ ip netns exec mrdn-test ip link set lo up",
	)
}

func TestCreateVethPairDryRun(t *testing.T) {
	out := runScript(t, "create_veth_pair.sh",
		"mrdn-test",
		"mh-test",
		"mp-test",
		"169.254.10.1/30",
		"169.254.10.2/30",
	)
	assertContainsInOrder(t, out,
		"+ ip link add mh-test type veth peer name mp-test",
		"+ ip link set mp-test netns mrdn-test",
		"+ ip addr add 169.254.10.1/30 dev mh-test",
		"+ ip link set mh-test up",
		"+ ip netns exec mrdn-test ip addr add 169.254.10.2/30 dev mp-test",
		"+ ip netns exec mrdn-test ip link set mp-test up",
		"+ ip netns exec mrdn-test ip link set lo up",
		"+ tc qdisc replace dev mh-test clsact",
	)
}

func TestCleanupNetnsDryRun(t *testing.T) {
	out := runScript(t, "cleanup_netns.sh", "mrdn-test", "mh-test")
	assertContainsInOrder(t, out,
		"+ tc qdisc del dev mh-test clsact",
		"+ ip link del mh-test",
		"+ ip netns del mrdn-test",
	)
}

func TestScriptsUsageValidation(t *testing.T) {
	scripts := []string{"setup_netns.sh", "create_veth_pair.sh", "cleanup_netns.sh"}
	for _, script := range scripts {
		script := script
		t.Run(script, func(t *testing.T) {
			cmd := exec.Command("bash", scriptPath(t, script))
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected usage failure for %s, got success (output=%q)", script, string(out))
			}
			if !strings.Contains(string(out), "Usage:") {
				t.Fatalf("expected usage output for %s, got: %q", script, string(out))
			}
		})
	}
}

func runScript(t *testing.T, scriptName string, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{scriptPath(t, scriptName)}, args...)
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Env = append(cmd.Environ(), "DRY_RUN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script %s failed: %v\noutput:\n%s", scriptName, err, string(out))
	}
	return string(out)
}

func scriptPath(t *testing.T, scriptName string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(currentFile), "..", "..", "scripts", "netns", scriptName)
}

func assertContainsInOrder(t *testing.T, got string, parts ...string) {
	t.Helper()
	cursor := 0
	for _, part := range parts {
		idx := strings.Index(got[cursor:], part)
		if idx < 0 {
			t.Fatalf("missing expected output %q in:\n%s", part, got)
		}
		cursor += idx + len(part)
	}
}
