package harness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

// TestHarnessFixtureDoesNotInvokeScripts pins the C-4/D-4 decision: the Go
// harness is the single authoritative netns fixture, and the bash scripts are
// debug-only. If a fixture file ever started shelling out to scripts/netns/*.sh
// we would be back to two divergent sources of truth on the CI path. This test
// inspects string literals in every non-test harness source (comments and
// docstrings are intentionally ignored — they may name the scripts) and fails
// if any literal points at the scripts, keeping them off the CI fixture path.
func TestHarnessFixtureDoesNotInvokeScripts(t *testing.T) {
	dir := harnessDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read harness dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// Comments are excluded so a doc comment can still name the scripts.
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, banned := range []string{"scripts/netns", ".sh"} {
				if strings.Contains(val, banned) {
					t.Errorf("%s has string literal %q referencing %q: the harness "+
						"must not invoke the debug scripts (C-4/D-4 — harness is the "+
						"authoritative fixture)", name, val, banned)
				}
			}
			return true
		})
	}
}

// TestScriptsCarryDebugOnlyBanner asserts every netns script declares itself
// debug-only and names the harness as authoritative, so the divergence the
// banner prevents cannot silently return.
func TestScriptsCarryDebugOnlyBanner(t *testing.T) {
	scripts := []string{"setup_netns.sh", "create_veth_pair.sh", "cleanup_netns.sh"}
	for _, script := range scripts {
		script := script
		t.Run(script, func(t *testing.T) {
			body, err := os.ReadFile(scriptPath(t, script))
			if err != nil {
				t.Fatalf("read %s: %v", script, err)
			}
			src := string(body)
			for _, want := range []string{"DEBUG-ONLY", "AUTHORITATIVE"} {
				if !strings.Contains(src, want) {
					t.Errorf("%s is missing the %q banner marker", script, want)
				}
			}
		})
	}
}

func harnessDir(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(currentFile)
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
