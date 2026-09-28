// Kubernetes TokenReview bootstrap authentication (PKI-2b / Phase 7).
//
// In Kubernetes mode the agent has no pre-provisioned node cert; it presents
// its ServiceAccount projected token (bound audience = meridian-control).
// The control plane validates the token via the TokenReview API and derives
// the node identity from the token's bound node claim — breaking the
// bootstrap circularity described in docs/subsystems/04-spiffe.md.
package ca

import (
	"context"
	"fmt"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodeNameExtraKey is the UserInfo extra key carrying the node a bound
// ServiceAccount token was issued for (set by kube-apiserver for projected
// tokens with pod binding, K8s ≥ 1.30).
const NodeNameExtraKey = "authentication.kubernetes.io/node-name"

// serviceAccountUsernamePrefix is the username prefix of ServiceAccount
// principals ("system:serviceaccount:<namespace>:<name>").
const serviceAccountUsernamePrefix = "system:serviceaccount:"

// TokenReviewAuthenticator validates Kubernetes ServiceAccount tokens via
// the TokenReview API and maps them to a Meridian node ID.
type TokenReviewAuthenticator struct {
	kubeClient kubernetes.Interface
}

// NewTokenReviewAuthenticator returns an authenticator backed by kubeClient.
func NewTokenReviewAuthenticator(kubeClient kubernetes.Interface) *TokenReviewAuthenticator {
	return &TokenReviewAuthenticator{kubeClient: kubeClient}
}

// ValidateToken submits token to the TokenReview API scoped to audience and
// returns the node ID the token is bound to. Every rejection path fails
// closed with an error; there is no anonymous or partial success.
func (t *TokenReviewAuthenticator) ValidateToken(ctx context.Context, token, audience string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("tokenreview: empty token")
	}
	if audience == "" {
		return "", fmt.Errorf("tokenreview: empty audience")
	}

	review := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{audience},
		},
	}
	result, err := t.kubeClient.AuthenticationV1().TokenReviews().
		Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("tokenreview: API call: %w", err)
	}

	status := result.Status
	if status.Error != "" {
		return "", fmt.Errorf("tokenreview: apiserver rejected token: %s", status.Error)
	}
	if !status.Authenticated {
		return "", fmt.Errorf("tokenreview: token not authenticated")
	}
	// The apiserver echoes the intersection of requested and token audiences;
	// require our audience explicitly (an empty intersection means the token
	// was minted for someone else).
	if !containsString(status.Audiences, audience) {
		return "", fmt.Errorf("tokenreview: token audiences %v do not include %q",
			status.Audiences, audience)
	}
	if !strings.HasPrefix(status.User.Username, serviceAccountUsernamePrefix) {
		return "", fmt.Errorf("tokenreview: principal %q is not a serviceaccount",
			status.User.Username)
	}

	nodeID, err := nodeNameFromUserInfo(status.User)
	if err != nil {
		return "", err
	}
	return nodeID, nil
}

// nodeNameFromUserInfo extracts the bound node name claim. Tokens without a
// node binding are refused: falling back to the ServiceAccount name would
// give every agent replica the same node identity (fail closed instead).
func nodeNameFromUserInfo(user authnv1.UserInfo) (string, error) {
	values, ok := user.Extra[NodeNameExtraKey]
	if !ok || len(values) == 0 || values[0] == "" {
		return "", fmt.Errorf("tokenreview: token has no bound node name (%s claim); "+
			"use a projected token with pod binding", NodeNameExtraKey)
	}
	return values[0], nil
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
