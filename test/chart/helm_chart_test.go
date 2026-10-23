// Package chart verifies the rendered Meridian Helm chart. Rendering is
// OS-independent, so these tests live outside the Linux-only eBPF
// integration suite and run as part of the pure-Go unit tests.
package chart

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// chartPath is the Helm chart under test, relative to this package.
const chartPath = "../../deploy/helm/meridian"

// renderChart runs `helm template` on the Meridian chart and returns the
// rendered manifests. Skips the test when no helm binary is in PATH so CI
// without helm stays green (same convention as the etcd store test). A
// non-zero exit is returned as stderr rather than failing, so callers can
// assert on expected template failures.
func renderChart(t *testing.T, sets ...string) (stdout, stderr string, ok bool) {
	t.Helper()
	helmBin, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm binary not in PATH; skipping chart render test")
	}

	args := []string{"template", "meridian", chartPath}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command(helmBin, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err == nil
}

// decodeManifests strictly decodes the control-plane Deployment, its Service
// and the ValidatingWebhookConfiguration out of rendered chart output. Strict
// decoding into the real k8s API types catches misspelled or misplaced fields
// that a plain YAML parse would silently accept.
func decodeManifests(t *testing.T, rendered string) (appsv1.Deployment, corev1.Service, admissionv1.ValidatingWebhookConfiguration) {
	t.Helper()

	var dep appsv1.Deployment
	var svc corev1.Service
	var vwc admissionv1.ValidatingWebhookConfiguration

	for _, doc := range strings.Split(rendered, "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var probe struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &probe); err != nil {
			t.Fatalf("probe document kind: %v", err)
		}

		var target any
		switch probe.Kind {
		case "Deployment":
			target = &dep
		case "Service":
			target = &svc
		case "ValidatingWebhookConfiguration":
			target = &vwc
		default:
			continue
		}
		if err := yaml.UnmarshalStrict([]byte(doc), target); err != nil {
			t.Fatalf("strict decode %s: %v", probe.Kind, err)
		}
	}
	return dep, svc, vwc
}

// controlContainer returns the single control-plane container.
func controlContainer(t *testing.T, dep appsv1.Deployment) corev1.Container {
	t.Helper()
	if len(dep.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected 1 control container, got %d", len(dep.Spec.Template.Spec.Containers))
	}
	return dep.Spec.Template.Spec.Containers[0]
}

// argValue returns the value of a --flag=value style arg.
func argValue(args []string, flag string) string {
	for _, a := range args {
		if strings.HasPrefix(a, flag+"=") {
			return strings.TrimPrefix(a, flag+"=")
		}
	}
	return ""
}

// TestChartWebhookPortChain is the regression test for the :9443 collision
// between the admission webhook and the ADS gRPC listener. It walks the whole
// path the apiserver takes -- ValidatingWebhookConfiguration port -> Service
// port -> named targetPort -> containerPort -> the --webhook-addr the process
// actually binds -- and asserts it lands on a port ADS does not hold.
func TestChartWebhookPortChain(t *testing.T) {
	out, errOut, ok := renderChart(t,
		"webhook.enabled=true",
		"webhook.certSecret=meridian-webhook-certs",
	)
	if !ok {
		t.Fatalf("helm template failed: %s", errOut)
	}

	dep, svc, vwc := decodeManifests(t, out)
	if dep.Name == "" || svc.Name == "" || len(vwc.Webhooks) == 0 {
		t.Fatal("chart did not render Deployment, Service and ValidatingWebhookConfiguration")
	}
	ctr := controlContainer(t, dep)

	// The apiserver dials the control Service on clientConfig.service.port.
	cc := vwc.Webhooks[0].ClientConfig
	if cc.Service == nil || cc.Service.Port == nil {
		t.Fatal("webhook clientConfig.service.port is unset")
	}
	webhookPort := *cc.Service.Port
	if cc.Service.Name != svc.Name {
		t.Fatalf("webhook targets Service %q but chart renders %q", cc.Service.Name, svc.Name)
	}

	// That Service port must exist and point at a named container port.
	var targetPortName string
	for _, p := range svc.Spec.Ports {
		if p.Port == webhookPort {
			targetPortName = p.TargetPort.StrVal
		}
	}
	if targetPortName == "" {
		t.Fatalf("Service exposes no port %d for the webhook; ports = %+v", webhookPort, svc.Spec.Ports)
	}

	// The named container port must resolve back to the same number.
	var containerPort int32
	for _, p := range ctr.Ports {
		if p.Name == targetPortName {
			containerPort = p.ContainerPort
		}
	}
	if containerPort != webhookPort {
		t.Fatalf("targetPort %q resolves to containerPort %d, want %d",
			targetPortName, containerPort, webhookPort)
	}

	// The process must be told to bind exactly that port.
	gotWebhookAddr := argValue(ctr.Args, "--webhook-addr")
	if want := ":9444"; gotWebhookAddr != want {
		t.Errorf("--webhook-addr = %q, want %q", gotWebhookAddr, want)
	}

	// ...and it must not be the port ADS already holds. This is the collision.
	gotADSAddr := argValue(ctr.Args, "--ads-addr")
	if gotADSAddr == gotWebhookAddr {
		t.Errorf("webhook and ADS gRPC share address %q; both cannot bind", gotADSAddr)
	}
	for _, p := range ctr.Ports {
		if p.Name != targetPortName && p.ContainerPort == containerPort {
			t.Errorf("containerPort %d is claimed by both %q and %q", containerPort, p.Name, targetPortName)
		}
	}
}

// TestChartWebhookCertMount asserts the serving certificate the webhook needs
// is mounted read-only at the path the --webhook-cert / --webhook-key flags
// point at. Without this the server refuses to start.
func TestChartWebhookCertMount(t *testing.T) {
	out, errOut, ok := renderChart(t,
		"webhook.enabled=true",
		"webhook.certSecret=meridian-webhook-certs",
	)
	if !ok {
		t.Fatalf("helm template failed: %s", errOut)
	}

	dep, _, _ := decodeManifests(t, out)
	ctr := controlContainer(t, dep)

	var mountPath string
	for _, m := range ctr.VolumeMounts {
		if m.Name == "webhook-certs" {
			mountPath = m.MountPath
			if !m.ReadOnly {
				t.Error("webhook-certs mount is not readOnly")
			}
		}
	}
	if mountPath == "" {
		t.Fatal("webhook-certs volumeMount is missing")
	}

	// Both cert flags must resolve inside the mounted directory.
	for _, flag := range []string{"--webhook-cert", "--webhook-key"} {
		got := argValue(ctr.Args, flag)
		if got == "" {
			t.Errorf("%s arg is missing", flag)
			continue
		}
		if filepath.Dir(got) != mountPath {
			t.Errorf("%s = %q, not inside mountPath %q", flag, got, mountPath)
		}
	}

	// main.go requires both flags together, so neither may be dropped.
	if (argValue(ctr.Args, "--webhook-cert") == "") != (argValue(ctr.Args, "--webhook-key") == "") {
		t.Error("--webhook-cert and --webhook-key must be set together")
	}

	var secret *corev1.SecretVolumeSource
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "webhook-certs" {
			secret = v.Secret
		}
	}
	if secret == nil {
		t.Fatal("webhook-certs volume is not backed by a Secret")
	}
	if secret.SecretName != "meridian-webhook-certs" {
		t.Errorf("secretName = %q, want the configured webhook.certSecret", secret.SecretName)
	}
	if secret.DefaultMode == nil || *secret.DefaultMode != 0o400 {
		t.Errorf("defaultMode = %v, want 0400 (private key must not be world-readable)", secret.DefaultMode)
	}
}

// TestChartWebhookDisabled asserts the default render is untouched by the
// webhook wiring: no webhook flags, no webhook port, no cert volume. main.go
// only starts the webhook when both cert flags are present, so the chart must
// not pass them unless the webhook is explicitly enabled.
func TestChartWebhookDisabled(t *testing.T) {
	out, errOut, ok := renderChart(t)
	if !ok {
		t.Fatalf("helm template failed: %s", errOut)
	}

	if strings.Contains(out, "ValidatingWebhookConfiguration") {
		t.Error("webhook config rendered while webhook.enabled=false")
	}

	dep, svc, _ := decodeManifests(t, out)
	ctr := controlContainer(t, dep)

	for _, flag := range []string{"--webhook-addr", "--webhook-cert", "--webhook-key"} {
		if got := argValue(ctr.Args, flag); got != "" {
			t.Errorf("%s = %q passed while webhook is disabled", flag, got)
		}
	}
	for _, p := range ctr.Ports {
		if p.Name == "webhook" {
			t.Error("webhook containerPort declared while webhook is disabled")
		}
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == "webhook" {
			t.Error("webhook Service port declared while webhook is disabled")
		}
	}
	for _, v := range dep.Spec.Template.Spec.Volumes {
		if v.Name == "webhook-certs" {
			t.Error("webhook-certs volume mounted while webhook is disabled")
		}
	}

	// ADS keeps its port when the webhook is off.
	if got, want := argValue(ctr.Args, "--ads-addr"), ":9443"; got != want {
		t.Errorf("--ads-addr = %q, want %q", got, want)
	}
}

// TestChartWebhookRequiresCertSecret asserts the chart fails to render, with
// an actionable message, when the webhook is enabled but no serving-cert
// Secret is named -- rather than shipping a Deployment that crash-loops on a
// missing volume.
func TestChartWebhookRequiresCertSecret(t *testing.T) {
	_, errOut, ok := renderChart(t, "webhook.enabled=true")
	if ok {
		t.Fatal("chart rendered with webhook.enabled=true and no webhook.certSecret; expected failure")
	}
	if !strings.Contains(errOut, "webhook.certSecret") {
		t.Errorf("error message does not name the missing value: %s", errOut)
	}
}

// TestChartWebhookPortOverride asserts the container and Service ports follow
// a custom webhook listen address instead of being hardcoded, including a
// host-qualified form.
func TestChartWebhookPortOverride(t *testing.T) {
	out, errOut, ok := renderChart(t,
		"webhook.enabled=true",
		"webhook.certSecret=meridian-webhook-certs",
		"control.webhookAddr=0.0.0.0:9500",
		"control.service.webhookPort=9500",
	)
	if !ok {
		t.Fatalf("helm template failed: %s", errOut)
	}

	dep, svc, vwc := decodeManifests(t, out)
	ctr := controlContainer(t, dep)

	var containerPort int32
	for _, p := range ctr.Ports {
		if p.Name == "webhook" {
			containerPort = p.ContainerPort
		}
	}
	if containerPort != 9500 {
		t.Errorf("webhook containerPort = %d, want 9500 (derived from control.webhookAddr)", containerPort)
	}

	var svcPort int32
	for _, p := range svc.Spec.Ports {
		if p.Name == "webhook" {
			svcPort = p.Port
		}
	}
	if svcPort != 9500 {
		t.Errorf("webhook Service port = %d, want 9500", svcPort)
	}
	if cc := vwc.Webhooks[0].ClientConfig; cc.Service == nil || *cc.Service.Port != 9500 {
		t.Errorf("webhook clientConfig port did not follow the override")
	}
	if got := argValue(ctr.Args, "--webhook-addr"); got != "0.0.0.0:9500" {
		t.Errorf("--webhook-addr = %q, want 0.0.0.0:9500", got)
	}
}

// TestChartControlPortsFollowValues asserts the REST and ADS container ports
// are derived from their listen addresses too, so a port override cannot
// leave the Service pointing at a port nothing listens on.
func TestChartControlPortsFollowValues(t *testing.T) {
	out, errOut, ok := renderChart(t,
		"control.listenAddr=:8181",
		"control.adsAddr=:9500",
	)
	if !ok {
		t.Fatalf("helm template failed: %s", errOut)
	}

	dep, _, _ := decodeManifests(t, out)
	ctr := controlContainer(t, dep)

	want := map[string]int32{"rest": 8181, "ads-grpc": 9500}
	for _, p := range ctr.Ports {
		if exp, found := want[p.Name]; found && p.ContainerPort != exp {
			t.Errorf("containerPort %q = %d, want %d", p.Name, p.ContainerPort, exp)
		}
	}
}

// TestChartWorkloadSelectorsMatchPodLabels guards the defect that made the
// control-plane Service -- and therefore the admission webhook -- unreachable:
// the pod template set app.kubernetes.io/name twice, so the duplicate key
// silently overwrote the component-qualified value and no longer matched the
// workload selector. The apiserver rejects such a workload outright, and a
// Service selector built the same way matches no pods.
func TestChartWorkloadSelectorsMatchPodLabels(t *testing.T) {
	out, errOut, ok := renderChart(t,
		"webhook.enabled=true",
		"webhook.certSecret=meridian-webhook-certs",
	)
	if !ok {
		t.Fatalf("helm template failed: %s", errOut)
	}

	// A duplicate mapping key is what caused this; strict decoding is what
	// catches it, so assert every workload document decodes strictly.
	dep, svc, _ := decodeManifests(t, out)

	var ds appsv1.DaemonSet
	for _, doc := range strings.Split(out, "\n---\n") {
		if strings.Contains(doc, "kind: DaemonSet") {
			if err := yaml.UnmarshalStrict([]byte(doc), &ds); err != nil {
				t.Fatalf("strict decode DaemonSet: %v", err)
			}
		}
	}
	if ds.Name == "" {
		t.Fatal("chart did not render the agent DaemonSet")
	}

	workloads := []struct {
		kind      string
		selector  map[string]string
		podLabels map[string]string
	}{
		{"Deployment", dep.Spec.Selector.MatchLabels, dep.Spec.Template.Labels},
		{"DaemonSet", ds.Spec.Selector.MatchLabels, ds.Spec.Template.Labels},
	}
	for _, w := range workloads {
		if len(w.selector) == 0 {
			t.Errorf("%s has an empty selector", w.kind)
			continue
		}
		for k, want := range w.selector {
			if got, found := w.podLabels[k]; !found || got != want {
				t.Errorf("%s selector %s=%q does not match pod label %q (found=%v); apiserver would reject this workload",
					w.kind, k, want, got, found)
			}
		}
	}

	// The Service must select the control-plane pods, or nothing reaches the
	// webhook even once the port chain is right.
	if len(svc.Spec.Selector) == 0 {
		t.Fatal("control Service has an empty selector")
	}
	for k, want := range svc.Spec.Selector {
		if got, found := dep.Spec.Template.Labels[k]; !found || got != want {
			t.Errorf("Service selector %s=%q matches no control pod label (got %q, found=%v)",
				k, want, got, found)
		}
	}

	// The agent DaemonSet must not be caught by the control Service.
	matchesAgent := true
	for k, want := range svc.Spec.Selector {
		if ds.Spec.Template.Labels[k] != want {
			matchesAgent = false
		}
	}
	if matchesAgent {
		t.Error("control Service selector also matches agent pods")
	}
}
