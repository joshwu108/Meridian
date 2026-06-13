// Command checkgateskips is the MER-44 gate skip-integrity guard. It reads
// test/gates/manifest.txt and fails if any armed=yes gate reports skips in
// go test -json output.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
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
	for _, entry := range entries {
		if !entry.armed || entry.pkg == "" {
			continue
		}
		skips, testFailed, err := runGate(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checkgateskips: gate %q: %v\n", entry.testName, err)
			failures++
			continue
		}
		if skips > 0 {
			fmt.Fprintf(os.Stderr,
				"checkgateskips: FAIL gate %q (%s): %d skip(s) — armed gates must not skip (MER-44)\n",
				entry.testName, entry.pkg, skips)
			failures++
			continue
		}
		if testFailed {
			fmt.Fprintf(os.Stderr,
				"checkgateskips: FAIL gate %q (%s): test failed (not a skip, but gate is red)\n",
				entry.testName, entry.pkg)
			failures++
			continue
		}
		fmt.Printf("checkgateskips: OK   gate %q (%s): 0 skips\n", entry.testName, entry.pkg)
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

func runGate(entry gateEntry) (skips int, testFailed bool, err error) {
	args := []string{"test", "-json", "-count=1"}
	if entry.tags != "" {
		args = append(args, "-tags="+entry.tags)
	}
	if entry.tags == "bpf" || entry.tags == "integration" {
		args = append(args, "-exec=sudo")
	}
	args = append(args, entry.pkg, "-run", fmt.Sprintf("^%s$", entry.testName))

	cmd := exec.Command("go", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()

	dec := json.NewDecoder(&out)
	for {
		var ev jsonEvent
		if decErr := dec.Decode(&ev); decErr != nil {
			break
		}
		switch ev.Action {
		case "skip":
			if strings.Contains(ev.Test, entry.testName) {
				skips++
			}
		case "fail":
			if strings.Contains(ev.Test, entry.testName) {
				testFailed = true
			}
		}
	}

	if runErr != nil {
		if skips == 0 && !testFailed {
			return 0, true, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), runErr, out.String())
		}
	}
	return skips, testFailed, nil
}
