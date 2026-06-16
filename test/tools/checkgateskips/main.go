// Command checkgateskips is the MER-44 gate skip-integrity guard. It reads
// test/gates/manifest.txt and fails if any armed=yes gate skips or fails.
//
// Gates are grouped by (build-tags, package) and each group is run in a SINGLE
// `go test -parallel 1` process — the same way the canonical `make test-bpf` /
// `make test-integration` targets run, which is what makes them reliable. The
// previous one-process-per-gate approach respawned privileged tests dozens of
// times in rapid succession; the two-node integration tests leak RunID-scoped
// netns + fixed host veths/underlay subnets between processes, so back-to-back
// gate processes collided and flaked non-deterministically (MER-68). Running a
// package's gates together, serialized, lets each test's own t.Cleanup tear down
// its kernel state before the next starts — no leak, no flake.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type gateEntry struct {
	armed    bool
	tags     string
	pkg      string
	testName string
}

type groupKey struct {
	tags string
	pkg  string
}

type gateGroup struct {
	key   groupKey
	gates []gateEntry
}

type gateResult struct {
	ran    bool
	skips  int
	failed bool
}

type jsonEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
	Output string `json:"Output"`
}

func main() {
	manifest := flag.String("manifest", "test/gates/manifest.txt", "gate manifest path")
	flag.Parse()

	entries, err := parseManifest(*manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "checkgateskips: %v\n", err)
		os.Exit(2)
	}

	var failures int
	for _, group := range groupGates(entries) {
		results, runErr := runGroup(group)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "checkgateskips: group %s (%s): %v\n",
				group.key.pkg, displayTags(group.key.tags), runErr)
			failures += len(group.gates)
			continue
		}
		for _, entry := range group.gates {
			res := results[entry.testName]
			switch {
			case !res.ran:
				fmt.Fprintf(os.Stderr,
					"checkgateskips: FAIL gate %q (%s): did not run (no match in package output)\n",
					entry.testName, entry.pkg)
				failures++
			case res.skips > 0:
				fmt.Fprintf(os.Stderr,
					"checkgateskips: FAIL gate %q (%s): %d skip(s) — armed gates must not skip (MER-44)\n",
					entry.testName, entry.pkg, res.skips)
				failures++
			case res.failed:
				fmt.Fprintf(os.Stderr,
					"checkgateskips: FAIL gate %q (%s): test failed (not a skip, but gate is red)\n",
					entry.testName, entry.pkg)
				failures++
			default:
				fmt.Printf("checkgateskips: OK   gate %q (%s): 0 skips\n", entry.testName, entry.pkg)
			}
		}
	}

	if failures > 0 {
		os.Exit(1)
	}
}

func parseManifest(path string) ([]gateEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []gateEntry
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("%s:%d: want 4 fields, got %d", path, lineNo, len(fields))
		}
		tags := fields[1]
		if tags == "''" {
			tags = ""
		}
		entries = append(entries, gateEntry{
			armed:    strings.EqualFold(fields[0], "yes"),
			tags:     tags,
			pkg:      fields[2],
			testName: fields[3],
		})
	}
	return entries, scanner.Err()
}

// groupGates buckets armed gates by (tags, pkg) in first-seen order so each
// package's gates run together in one process.
func groupGates(entries []gateEntry) []gateGroup {
	var order []groupKey
	byKey := make(map[groupKey]*gateGroup)
	for _, e := range entries {
		if !e.armed || e.pkg == "" {
			continue
		}
		key := groupKey{tags: e.tags, pkg: e.pkg}
		g, ok := byKey[key]
		if !ok {
			g = &gateGroup{key: key}
			byKey[key] = g
			order = append(order, key)
		}
		g.gates = append(g.gates, e)
	}
	groups := make([]gateGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, *byKey[key])
	}
	return groups
}

// isPrivileged reports whether a gate group needs root (it loads BPF / creates
// netns). These run with -exec=sudo, exactly as the canonical make targets do.
func isPrivileged(tags string) bool {
	return tags == "bpf" || tags == "integration"
}

// runGroup runs the group's package as ONE `go test -parallel 1` process — the
// whole package, with NO -run filter, exactly as the canonical `make test-bpf` /
// `make test-integration` targets do (those are reliable 10/10; a -run subset is
// not, because it changes which tests run and the order in which shared host
// resources — fixed underlay subnets, host veths, ports — are set up and torn
// down). The armed gates are then attributed from the combined -json output.
func runGroup(group gateGroup) (map[string]gateResult, error) {
	names := make([]string, len(group.gates))
	for i, g := range group.gates {
		names[i] = g.testName
	}

	args := []string{"test", "-json", "-count=1", "-parallel", "1"}
	if group.key.tags != "" {
		args = append(args, "-tags="+group.key.tags)
	}
	if isPrivileged(group.key.tags) {
		args = append(args, "-exec=sudo", "-timeout=10m")
	}
	args = append(args, group.key.pkg)

	cmd := exec.Command("go", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()

	results := classifyGroup(bytes.NewReader(out.Bytes()), names)

	// If no armed gate ran at all and the command errored, the package failed to
	// build/start — surface it (fail closed) rather than silently passing.
	if runErr != nil && !anyRan(results) {
		return nil, fmt.Errorf("package did not run (build/setup error): go %s: %w\n%s",
			strings.Join(args, " "), runErr, out.String())
	}
	return results, nil
}

// classifyGroup attributes `go test -json` events to each gate by exact name or
// subtest prefix ("Name/sub"). It is the fail-closed core: a genuine t.Skip is a
// skip and a genuine failure is a failure.
func classifyGroup(r io.Reader, names []string) map[string]gateResult {
	res := make(map[string]gateResult, len(names))
	for _, n := range names {
		res[n] = gateResult{}
	}
	dec := json.NewDecoder(r)
	for {
		var ev jsonEvent
		if decErr := dec.Decode(&ev); decErr != nil {
			break
		}
		if ev.Test == "" {
			continue
		}
		for _, n := range names {
			if ev.Test != n && !strings.HasPrefix(ev.Test, n+"/") {
				continue
			}
			gr := res[n]
			switch ev.Action {
			case "run":
				gr.ran = true
			case "skip":
				gr.skips++
			case "fail":
				gr.failed = true
			}
			res[n] = gr
		}
	}
	return res
}

func anyRan(results map[string]gateResult) bool {
	for _, r := range results {
		if r.ran {
			return true
		}
	}
	return false
}

func displayTags(tags string) string {
	if tags == "" {
		return "no tags"
	}
	return "tags=" + tags
}
