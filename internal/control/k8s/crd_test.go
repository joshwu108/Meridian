package k8s

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func runtimeRawExtension(raw []byte) runtime.RawExtension {
	return runtime.RawExtension{Raw: raw}
}

func validPolicySpec() MeridianPolicySpec {
	return MeridianPolicySpec{
		Selector: WorkloadSelector{
			Namespace: "payments",
			Labels:    map[string]string{"app": "checkout"},
		},
		Sources: []string{"spiffe://cluster.local/workload/payments/frontend"},
		Ports:   []uint16{8443},
		Action:  PolicyActionNameAllow,
	}
}

func TestValidatePolicySpec(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*MeridianPolicySpec)
		wantErr string // substring; "" means valid
	}{
		{name: "valid allow", mutate: func(s *MeridianPolicySpec) {}},
		{name: "valid deny", mutate: func(s *MeridianPolicySpec) { s.Action = PolicyActionNameDeny }},
		{name: "valid explicit protocols", mutate: func(s *MeridianPolicySpec) {
			s.Protocols = []string{"tcp", "udp"}
		}},
		{name: "unknown action", mutate: func(s *MeridianPolicySpec) { s.Action = "audit" },
			wantErr: "action"},
		{name: "empty action", mutate: func(s *MeridianPolicySpec) { s.Action = "" },
			wantErr: "action"},
		{name: "no ports", mutate: func(s *MeridianPolicySpec) { s.Ports = nil },
			wantErr: "ports"},
		{name: "port zero", mutate: func(s *MeridianPolicySpec) { s.Ports = []uint16{0} },
			wantErr: "port"},
		{name: "no selector namespace", mutate: func(s *MeridianPolicySpec) { s.Selector.Namespace = "" },
			wantErr: "namespace"},
		{name: "no sources", mutate: func(s *MeridianPolicySpec) { s.Sources = nil },
			wantErr: "sources"},
		{name: "non-spiffe source", mutate: func(s *MeridianPolicySpec) {
			s.Sources = []string{"http://cluster.local/frontend"}
		}, wantErr: "spiffe"},
		{name: "empty source entry", mutate: func(s *MeridianPolicySpec) { s.Sources = []string{""} },
			wantErr: "spiffe"},
		{name: "unknown protocol", mutate: func(s *MeridianPolicySpec) { s.Protocols = []string{"sctp"} },
			wantErr: "protocol"},
		{name: "too many sources", mutate: func(s *MeridianPolicySpec) {
			s.Sources = make([]string, MaxPolicySources+1)
			for i := range s.Sources {
				s.Sources[i] = fmt.Sprintf("spiffe://cluster.local/workload/ns/w%d", i)
			}
		}, wantErr: "sources"},
		{name: "too many ports", mutate: func(s *MeridianPolicySpec) {
			s.Ports = make([]uint16, MaxPolicyPorts+1)
			for i := range s.Ports {
				s.Ports[i] = uint16(i + 1)
			}
		}, wantErr: "ports"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := validPolicySpec()
			tt.mutate(&spec)
			err := ValidatePolicySpec(spec)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidatePolicySpec() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidatePolicySpec() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidatePolicySpec() = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// admissionReviewRequest builds an AdmissionReview CREATE/UPDATE request
// wrapping the given policy object.
func admissionReviewRequest(t *testing.T, op admissionv1.Operation, pol MeridianPolicy) []byte {
	t.Helper()
	raw, err := json.Marshal(pol)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid-1"),
			Operation: op,
			Kind: metav1.GroupVersionKind{
				Group: GroupName, Version: Version, Kind: PolicyKind,
			},
			Object: runtimeRawExtension(raw),
		},
	}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	return body
}

func postWebhook(t *testing.T, h http.Handler, body []byte) *admissionv1.AdmissionReview {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, ValidatePath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response == nil {
		t.Fatalf("webhook response has no .response: %s", rec.Body.String())
	}
	return &out
}

func testPolicy(spec MeridianPolicySpec) MeridianPolicy {
	return MeridianPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: GroupName + "/" + Version,
			Kind:       PolicyKind,
		},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-frontend", Namespace: "payments"},
		Spec:       spec,
	}
}

func TestWebhookAllowsValidCreate(t *testing.T) {
	h := NewValidationWebhook()
	body := admissionReviewRequest(t, admissionv1.Create, testPolicy(validPolicySpec()))
	out := postWebhook(t, h, body)
	if !out.Response.Allowed {
		t.Fatalf("valid CREATE denied: %+v", out.Response.Result)
	}
	if out.Response.UID != types.UID("test-uid-1") {
		t.Fatalf("response UID = %q, want request UID echoed", out.Response.UID)
	}
}

func TestWebhookDeniesInvalidCreateAndUpdate(t *testing.T) {
	h := NewValidationWebhook()
	bad := validPolicySpec()
	bad.Action = "shrug"
	for _, op := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update} {
		body := admissionReviewRequest(t, op, testPolicy(bad))
		out := postWebhook(t, h, body)
		if out.Response.Allowed {
			t.Fatalf("invalid %s allowed, want denied", op)
		}
		if out.Response.Result == nil || out.Response.Result.Message == "" {
			t.Fatalf("denial for %s has no reason message", op)
		}
	}
}

func TestWebhookAllowsDelete(t *testing.T) {
	h := NewValidationWebhook()
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("del-1"),
			Operation: admissionv1.Delete,
			Kind:      metav1.GroupVersionKind{Group: GroupName, Version: Version, Kind: PolicyKind},
		},
	}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	out := postWebhook(t, h, body)
	if !out.Response.Allowed {
		t.Fatalf("DELETE denied, want allowed")
	}
}

func TestWebhookRejectsWrongKind(t *testing.T) {
	h := NewValidationWebhook()
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("wrong-kind"),
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
		},
	}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	out := postWebhook(t, h, body)
	if out.Response.Allowed {
		t.Fatalf("unexpected kind allowed, want denied (fail closed)")
	}
}

func TestWebhookRejectsBadRequests(t *testing.T) {
	h := NewValidationWebhook()

	// Non-POST method.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ValidatePath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}

	// Undecodable body.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ValidatePath, strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON status = %d, want 400", rec.Code)
	}

	// Review with no request.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, ValidatePath, strings.NewReader(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty review status = %d, want 400", rec.Code)
	}
}
