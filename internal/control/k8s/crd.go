// MeridianPolicy CRD types and validating admission webhook (CP-5 / Phase 7).
//
// The types are hand-written (no code-gen, no controller-runtime): the dynamic
// client delivers unstructured objects that are converted with
// runtime.DefaultUnstructuredConverter, and the webhook decodes the raw
// AdmissionReview JSON directly. The CRD manifest itself ships with the Helm
// chart (deploy/helm/meridian/crds/meridianpolicy.yaml).
package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// GroupName is the API group of Meridian custom resources.
	GroupName = "meridian.io"
	// Version is the served CRD version.
	Version = "v1alpha1"
	// PolicyKind is the MeridianPolicy kind name.
	PolicyKind = "MeridianPolicy"
	// PolicyResource is the plural resource name of MeridianPolicy.
	PolicyResource = "meridianpolicies"
	// ValidatePath is the admission webhook HTTP path.
	ValidatePath = "/validate-meridianpolicy"
)

// Action names accepted in MeridianPolicySpec.Action.
const (
	PolicyActionNameAllow = "allow"
	PolicyActionNameDeny  = "deny"
)

// Protocol names accepted in MeridianPolicySpec.Protocols.
const (
	ProtocolNameTCP = "tcp"
	ProtocolNameUDP = "udp"
)

// Per-field size limits bounding compiled-rule expansion (sources ×
// destinations × ports × protocols). Mirrored as maxItems in the CRD schema
// (deploy/helm/meridian/crds/meridianpolicy.yaml).
const (
	MaxPolicySources = 64
	MaxPolicyPorts   = 64
)

// PolicyGVR returns the GroupVersionResource for MeridianPolicy, used by the
// dynamic client and informer.
func PolicyGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    GroupName,
		Version:  Version,
		Resource: PolicyResource,
	}
}

// MeridianPolicy is the top-level custom resource. It mirrors
// pkg/wire/policy.go's declarative rule shape: who (sources) may reach which
// workloads (selector) on which ports, with an allow/deny action.
type MeridianPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec MeridianPolicySpec `json:"spec"`
}

// MeridianPolicySpec is the user-facing policy document.
type MeridianPolicySpec struct {
	// Selector picks the destination workloads this policy protects.
	Selector WorkloadSelector `json:"selector"`
	// Sources are SPIFFE IDs allowed (or denied) as traffic sources.
	Sources []string `json:"sources"`
	// Ports are the destination ports the rule applies to.
	Ports []uint16 `json:"ports"`
	// Protocols are the L4 protocols ("tcp", "udp"); empty defaults to tcp.
	Protocols []string `json:"protocols,omitempty"`
	// Action is "allow" or "deny".
	Action string `json:"action"`
}

// WorkloadSelector selects workloads by namespace and (optionally) labels.
type WorkloadSelector struct {
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// ValidatePolicySpec checks a MeridianPolicySpec for structural validity.
// It fails closed: anything not explicitly recognized is an error.
func ValidatePolicySpec(spec MeridianPolicySpec) error {
	switch spec.Action {
	case PolicyActionNameAllow, PolicyActionNameDeny:
	default:
		return fmt.Errorf("spec.action %q: must be %q or %q",
			spec.Action, PolicyActionNameAllow, PolicyActionNameDeny)
	}
	if spec.Selector.Namespace == "" {
		return fmt.Errorf("spec.selector.namespace is required")
	}
	if len(spec.Sources) == 0 {
		return fmt.Errorf("spec.sources must list at least one source SPIFFE ID")
	}
	if len(spec.Sources) > MaxPolicySources {
		return fmt.Errorf("spec.sources has %d entries, max %d", len(spec.Sources), MaxPolicySources)
	}
	for i, src := range spec.Sources {
		if !strings.HasPrefix(src, "spiffe://") || len(src) <= len("spiffe://") {
			return fmt.Errorf("spec.sources[%d] %q: must be a spiffe:// URI", i, src)
		}
	}
	if len(spec.Ports) == 0 {
		return fmt.Errorf("spec.ports must list at least one port")
	}
	if len(spec.Ports) > MaxPolicyPorts {
		return fmt.Errorf("spec.ports has %d entries, max %d", len(spec.Ports), MaxPolicyPorts)
	}
	for i, port := range spec.Ports {
		if port == 0 {
			return fmt.Errorf("spec.ports[%d]: port must be 1-65535", i)
		}
	}
	for i, proto := range spec.Protocols {
		switch proto {
		case ProtocolNameTCP, ProtocolNameUDP:
		default:
			return fmt.Errorf("spec.protocols[%d] %q: unknown protocol, must be %q or %q",
				i, proto, ProtocolNameTCP, ProtocolNameUDP)
		}
	}
	return nil
}

// ValidationWebhook is the validating admission webhook handler for
// MeridianPolicy CREATE/UPDATE. Register it at ValidatePath on the control
// plane's webhook server (TLS termination is the server's concern).
type ValidationWebhook struct {
	logf func(string, ...any)
}

// NewValidationWebhook returns a ready-to-mount handler.
func NewValidationWebhook() *ValidationWebhook {
	return &ValidationWebhook{logf: log.Printf}
}

// maxAdmissionBodyBytes bounds webhook request bodies (defense in depth
// against oversized payloads; real policies are a few KB).
const maxAdmissionBodyBytes = 1 << 20

// ServeHTTP implements http.Handler for the AdmissionReview v1 protocol.
// Protocol errors (bad method, undecodable body) are HTTP errors; policy
// verdicts are always HTTP 200 with .response.allowed set.
func (h *ValidationWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAdmissionBodyBytes))
	if err != nil {
		http.Error(w, "read request body", http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, fmt.Sprintf("decode AdmissionReview: %v", err), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "AdmissionReview has no request", http.StatusBadRequest)
		return
	}

	resp := h.review(review.Request)
	resp.UID = review.Request.UID
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: resp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		h.logf("meridianpolicy webhook: write response: %v", err)
	}
}

// review produces the admission verdict for one request. Fail closed: only
// MeridianPolicy CREATE/UPDATE with a valid spec is allowed through this
// webhook (DELETE carries no object to validate and is always allowed).
func (h *ValidationWebhook) review(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req.Operation == admissionv1.Delete {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	if req.Kind.Group != GroupName || req.Kind.Kind != PolicyKind {
		return denied(fmt.Sprintf("unexpected kind %s/%s, this webhook validates only %s.%s",
			req.Kind.Group, req.Kind.Kind, PolicyKind, GroupName))
	}

	var pol MeridianPolicy
	if err := json.Unmarshal(req.Object.Raw, &pol); err != nil {
		return denied(fmt.Sprintf("decode MeridianPolicy: %v", err))
	}
	if err := ValidatePolicySpec(pol.Spec); err != nil {
		h.logf("meridianpolicy webhook: denied %s/%s: %v", pol.Namespace, pol.Name, err)
		return denied(err.Error())
	}
	return &admissionv1.AdmissionResponse{Allowed: true}
}

func denied(reason string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: reason,
			Reason:  metav1.StatusReasonInvalid,
		},
	}
}
