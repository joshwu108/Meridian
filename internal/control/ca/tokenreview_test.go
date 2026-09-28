package ca

import (
	"context"
	"errors"
	"strings"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	testAudience = "meridian-control"
	testSAUser   = "system:serviceaccount:meridian-system:meridian-agent"
)

// fakeTokenReviewClient returns a fake clientset whose TokenReview create
// call answers with the given status (after asserting the request shape).
func fakeTokenReviewClient(t *testing.T, status authnv1.TokenReviewStatus) *fake.Clientset {
	t.Helper()
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			create, ok := action.(k8stesting.CreateAction)
			if !ok {
				t.Fatalf("unexpected action %T", action)
			}
			tr, ok := create.GetObject().(*authnv1.TokenReview)
			if !ok {
				t.Fatalf("unexpected object %T", create.GetObject())
			}
			if tr.Spec.Token == "" {
				t.Errorf("TokenReview sent with empty token")
			}
			if len(tr.Spec.Audiences) != 1 || tr.Spec.Audiences[0] != testAudience {
				t.Errorf("TokenReview audiences = %v, want [%s]", tr.Spec.Audiences, testAudience)
			}
			return true, &authnv1.TokenReview{Status: status}, nil
		})
	return cs
}

func authenticatedStatus() authnv1.TokenReviewStatus {
	return authnv1.TokenReviewStatus{
		Authenticated: true,
		Audiences:     []string{testAudience},
		User: authnv1.UserInfo{
			Username: testSAUser,
			Extra: map[string]authnv1.ExtraValue{
				NodeNameExtraKey: {"worker-1"},
			},
		},
	}
}

func TestValidateTokenHappyPath(t *testing.T) {
	auth := NewTokenReviewAuthenticator(fakeTokenReviewClient(t, authenticatedStatus()))
	nodeID, err := auth.ValidateToken(context.Background(), "sa-token", testAudience)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if nodeID != "worker-1" {
		t.Fatalf("nodeID = %q, want %q (from bound-token node-name claim)", nodeID, "worker-1")
	}
}

func TestValidateTokenFailClosed(t *testing.T) {
	unauthenticated := authenticatedStatus()
	unauthenticated.Authenticated = false

	wrongAudience := authenticatedStatus()
	wrongAudience.Audiences = []string{"someone-else"}

	emptyAudiences := authenticatedStatus()
	emptyAudiences.Audiences = nil

	notServiceAccount := authenticatedStatus()
	notServiceAccount.User.Username = "system:admin"

	noNodeName := authenticatedStatus()
	noNodeName.User.Extra = nil

	tests := []struct {
		name    string
		status  authnv1.TokenReviewStatus
		wantErr string
	}{
		{"unauthenticated token", unauthenticated, "not authenticated"},
		{"audience mismatch", wrongAudience, "audience"},
		{"no audiences returned", emptyAudiences, "audience"},
		{"non-serviceaccount principal", notServiceAccount, "serviceaccount"},
		{"missing node-name claim", noNodeName, "node"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewTokenReviewAuthenticator(fakeTokenReviewClient(t, tt.status))
			nodeID, err := auth.ValidateToken(context.Background(), "sa-token", testAudience)
			if err == nil {
				t.Fatalf("ValidateToken = (%q, nil), want error containing %q", nodeID, tt.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTokenRejectsEmptyInputsWithoutAPICall(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("create", "tokenreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			t.Fatalf("TokenReview API called for empty token/audience")
			return true, nil, nil
		})
	auth := NewTokenReviewAuthenticator(cs)

	if _, err := auth.ValidateToken(context.Background(), "", testAudience); err == nil {
		t.Fatalf("empty token accepted, want error")
	}
	if _, err := auth.ValidateToken(context.Background(), "sa-token", ""); err == nil {
		t.Fatalf("empty audience accepted, want error")
	}
}

func TestValidateTokenWrapsAPIError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	apiErr := errors.New("apiserver on fire")
	cs.PrependReactor("create", "tokenreviews",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apiErr
		})
	auth := NewTokenReviewAuthenticator(cs)
	_, err := auth.ValidateToken(context.Background(), "sa-token", testAudience)
	if err == nil {
		t.Fatalf("API error swallowed, want error")
	}
	if !errors.Is(err, apiErr) {
		t.Fatalf("error %q does not wrap the API error", err)
	}
}
