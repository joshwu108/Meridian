// Package rest exposes the control plane's administrative REST surface (CP-1,
// MER-53): policy and service (identity) definitions in, status out.
//
// The surface fails closed: malformed or invalid request bodies are rejected
// with a 4xx and a structured error envelope, never partially applied. Service
// IDs are allocated server-side by the identity registry (CC-3) — clients must
// not supply them. The server depends only on the control.Store and
// identity.Registry interfaces, so the same handlers run against any backend.
package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/joshuawu/meridian/internal/control"
	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/pkg/wire"
)

// Server wires the control-plane Store and identity Registry to HTTP handlers.
type Server struct {
	store    control.Store
	registry *identity.Registry
	mux      *http.ServeMux
}

// NewServer constructs a Server backed by the given store and registry and
// registers its routes. Both dependencies are required.
func NewServer(store control.Store, registry *identity.Registry) *Server {
	s := &Server{store: store, registry: registry, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the http.Handler serving the control-plane REST API.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP lets Server satisfy http.Handler directly.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	s.mux.HandleFunc("POST /policies", s.handleCreatePolicy)
	s.mux.HandleFunc("GET /policies", s.handleListPolicies)
	s.mux.HandleFunc("POST /services", s.handleCreateService)
	s.mux.HandleFunc("GET /services", s.handleListServices)
	s.mux.HandleFunc("GET /status", s.handleStatus)
}

// envelope is the consistent response shape: exactly one of Data or Error is set.
type envelope struct {
	Data  any       `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

// apiError is the structured error returned on every 4xx/5xx response.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// serviceRequest is the POST /services body. ID is intentionally absent: the
// control plane is the sole identity allocator (CC-3).
type serviceRequest struct {
	Name      string `json:"name"`
	SpiffeID  string `json:"spiffeId"`
	Namespace string `json:"namespace"`
	PodIPv4   string `json:"podIpv4"`
}

func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request) {
	var req serviceRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_service", "name is required")
		return
	}
	if req.SpiffeID == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_service", "spiffeId is required")
		return
	}

	id, err := s.registry.Allocate(req.Name)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "allocation_failed", err.Error())
		return
	}

	svc := wire.Identity{
		ID:        id,
		Name:      req.Name,
		SpiffeID:  req.SpiffeID,
		Namespace: req.Namespace,
		PodIPv4:   req.PodIPv4,
	}
	if err := s.store.PutIdentity(r.Context(), svc); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope{Data: svc})
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	identities, err := s.store.ListIdentities(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{Data: identities})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var rule wire.PolicyRule
	if err := decodeStrict(r, &rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if err := validatePolicyRule(rule); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_policy", err.Error())
		return
	}
	if err := s.store.PutPolicy(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, envelope{Data: rule})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{Data: policies})
}

// statusBody is the GET /status payload.
type statusBody struct {
	Status     string `json:"status"`
	Identities int    `json:"identities"`
	Policies   int    `json:"policies"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	identities, err := s.store.ListIdentities(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	policies, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope{Data: statusBody{
		Status:     "ok",
		Identities: len(identities),
		Policies:   len(policies),
	}})
}

// validatePolicyRule enforces the minimal CP-1 fail-closed invariants on an
// inbound compiled rule. Full compiler-grade validation lives in package
// control; this guards the REST boundary against obviously-unsafe entries.
func validatePolicyRule(rule wire.PolicyRule) error {
	if rule.Key.SrcIdentity == wire.IdentityUnknown || rule.Key.DstIdentity == wire.IdentityUnknown {
		return fmt.Errorf("policy must not reference unknown identity (0)")
	}
	if rule.Key.DstPort == 0 {
		return fmt.Errorf("policy dstPort must be non-zero")
	}
	switch rule.Key.Direction {
	case wire.DirectionIngress, wire.DirectionEgress:
	default:
		return fmt.Errorf("unsupported direction: %d", rule.Key.Direction)
	}
	switch rule.Verdict.Action {
	case wire.PolicyActionAllow, wire.PolicyActionDeny, wire.PolicyActionRedirectProxy:
	default:
		return fmt.Errorf("unsupported action: %d", rule.Verdict.Action)
	}
	return nil
}

// decodeStrict decodes a single JSON object from the request body, rejecting
// unknown fields and trailing content so malformed bodies fail closed.
func decodeStrict(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing data after JSON object")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, envelope{Error: &apiError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, body envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
