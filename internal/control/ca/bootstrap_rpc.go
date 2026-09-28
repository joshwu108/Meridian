// Token-authenticated node bootstrap RPC (PKI-2b / Phase 7).
//
// BootstrapWithToken is the one control-plane endpoint reachable WITHOUT a
// client certificate: the caller authenticates with a Kubernetes SA token
// (validated via TokenReview) and presents a CSR for its node SPIFFE ID.
// The private key never crosses the wire. Follows the repo's no-protoc gRPC
// convention (ADR-0008 / CC-2): a hand-written grpc.ServiceDesc whose
// messages are versioned JSON inside wrapperspb.BytesValue.
package ca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// BootstrapServiceName is the gRPC service name.
	BootstrapServiceName = "meridian.ca.NodeBootstrap"
	// bootstrapMethodName is the single unary method.
	bootstrapMethodName = "BootstrapWithToken"
	// bootstrapWireVersion is the CC-2 JSON envelope version.
	bootstrapWireVersion = 1
	// bootstrapRPCTimeout bounds one bootstrap request server-side. This is
	// the only endpoint reachable without a client cert, so a slow apiserver
	// (TokenReview) must not pin goroutines indefinitely.
	bootstrapRPCTimeout = 15 * time.Second
)

// bootstrapFullMethod is the full gRPC method path.
const bootstrapFullMethod = "/" + BootstrapServiceName + "/" + bootstrapMethodName

// BootstrapTokenRequest is the wire request: SA token + node CSR.
type BootstrapTokenRequest struct {
	V      int    `json:"v"`
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
}

// NodeCert is the wire response: the signed node certificate chain.
type NodeCert struct {
	V            int       `json:"v"`
	NodeSpiffeID string    `json:"node_spiffe_id"`
	CertChainPEM string    `json:"cert_chain_pem"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenValidator authenticates a bootstrap token and returns the node ID it
// is bound to. TokenReviewAuthenticator is the production implementation.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token, audience string) (nodeID string, err error)
}

// BootstrapServer serves BootstrapWithToken.
type BootstrapServer struct {
	auth      *Authority
	validator TokenValidator
	audience  string
}

// NewBootstrapServer returns a server that validates tokens against
// validator (scoped to audience) and signs node CSRs with auth.
func NewBootstrapServer(auth *Authority, validator TokenValidator, audience string) *BootstrapServer {
	return &BootstrapServer{auth: auth, validator: validator, audience: audience}
}

// Register attaches the service to gs.
func (s *BootstrapServer) Register(gs *grpc.Server) {
	gs.RegisterService(&bootstrapServiceDesc, s)
}

// BootstrapWithToken validates the request token, checks that the CSR is for
// the token's own node, and returns the signed node cert chain. Every
// failure is a typed gRPC error; nothing is issued on partial validation.
func (s *BootstrapServer) BootstrapWithToken(ctx context.Context, req *BootstrapTokenRequest) (*NodeCert, error) {
	ctx, cancel := context.WithTimeout(ctx, bootstrapRPCTimeout)
	defer cancel()
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "bootstrap: empty token")
	}
	csr, err := parseCSRPEMBlock(req.CSRPEM)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bootstrap: %v", err)
	}

	nodeID, err := s.validator.ValidateToken(ctx, req.Token, s.audience)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "bootstrap: token rejected: %v", err)
	}

	// The token's node binding is the only accepted principal: a CSR naming
	// any other node SPIFFE ID fails SignNodeCert's SAN check (fail closed,
	// no cross-node issuance).
	nodeSpiffeID := NodeSPIFFEID(s.auth.TrustDomain(), nodeID)
	chain, err := s.auth.SignNodeCert(csr, nodeSpiffeID)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied,
			"bootstrap: sign node cert for %q: %v", nodeSpiffeID, err)
	}

	return &NodeCert{
		V:            bootstrapWireVersion,
		NodeSpiffeID: nodeSpiffeID,
		CertChainPEM: string(EncodeCertPEM(chain...)),
		ExpiresAt:    chain[0].NotAfter,
	}, nil
}

// BootstrapWithToken is the client side: it invokes the RPC over cc and
// decodes the response. csrPEM must contain one CERTIFICATE REQUEST block
// for the caller's own node SPIFFE ID (see GenerateNodeCSR).
func BootstrapWithToken(ctx context.Context, cc grpc.ClientConnInterface, token, csrPEM string) (*NodeCert, error) {
	in, err := encodeBootstrapJSON(&BootstrapTokenRequest{
		V:      bootstrapWireVersion,
		Token:  token,
		CSRPEM: csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap client: encode request: %w", err)
	}
	out := new(wrapperspb.BytesValue)
	if err := cc.Invoke(ctx, bootstrapFullMethod, in, out); err != nil {
		return nil, err
	}
	var resp NodeCert
	if err := json.Unmarshal(out.Value, &resp); err != nil {
		return nil, fmt.Errorf("bootstrap client: decode response: %w", err)
	}
	if resp.V != bootstrapWireVersion {
		return nil, fmt.Errorf("bootstrap client: unsupported response version %d", resp.V)
	}
	return &resp, nil
}

// EncodeCSRPEM encodes a certificate request as a PEM CERTIFICATE REQUEST
// block.
func EncodeCSRPEM(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})
}

// parseCSRPEMBlock decodes one CERTIFICATE REQUEST PEM block.
func parseCSRPEMBlock(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in csr_pem")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type %q, want CERTIFICATE REQUEST", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR DER: %w", err)
	}
	return csr, nil
}

// --- hand-written gRPC plumbing (no protoc, ADR-0008) ---

var bootstrapServiceDesc = grpc.ServiceDesc{
	ServiceName: BootstrapServiceName,
	HandlerType: (*bootstrapService)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: bootstrapMethodName,
		Handler:    bootstrapWithTokenHandler,
	}},
	Metadata: "internal/control/ca/bootstrap_rpc.go (CC-2 JSON in BytesValue)",
}

// bootstrapService pins the handler type for the ServiceDesc.
type bootstrapService interface {
	BootstrapWithToken(context.Context, *BootstrapTokenRequest) (*NodeCert, error)
}

func bootstrapWithTokenHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(wrapperspb.BytesValue)
	if err := dec(in); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return handleBootstrapRaw(ctx, srv.(bootstrapService), req.(*wrapperspb.BytesValue))
	}
	if interceptor == nil {
		return handler(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: bootstrapFullMethod}
	return interceptor(ctx, in, info, handler)
}

func handleBootstrapRaw(ctx context.Context, srv bootstrapService, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	var req BootstrapTokenRequest
	if err := json.Unmarshal(in.Value, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bootstrap: decode request: %v", err)
	}
	if req.V != bootstrapWireVersion {
		return nil, status.Errorf(codes.InvalidArgument,
			"bootstrap: unsupported request version %d", req.V)
	}
	resp, err := srv.BootstrapWithToken(ctx, &req)
	if err != nil {
		return nil, err
	}
	return encodeBootstrapJSON(resp)
}

func encodeBootstrapJSON(v any) (*wrapperspb.BytesValue, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal %T: %w", v, err)
	}
	return wrapperspb.Bytes(b), nil
}
