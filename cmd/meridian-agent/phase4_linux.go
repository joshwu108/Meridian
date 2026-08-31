//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net"

	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/agent/tproxy"
	"github.com/joshuawu/meridian/internal/agent/workloadapi"
	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/internal/proxy"
	"github.com/joshuawu/meridian/pkg/wire"
)

// phase4Options collects the Phase 4 flags.
type phase4Options struct {
	workloadAPISocket string
	proxyInPort       int
	proxyOutPort      int
	controlAddr       string
	bootstrapCert     string
	bootstrapKey      string
	standalone        bool // if true, run embedded CA + LocalSigner
}

// startPhase4 starts the Workload API socket, TPROXY rules, SVIDManager, and
// node proxy inbound/outbound handlers. It blocks until ctx is cancelled.
// Each component runs in its own goroutine; the first fatal error is logged.
//
// Standalone mode (--standalone):
//   - Generates an ephemeral in-process CA (dev/test).
//   - Uses LocalSigner backed by that CA for workload SVIDs.
//
// Remote mode (--control-addr):
//   - Loads the node bootstrap credential (--bootstrap-cert / --bootstrap-key).
//   - Uses RemoteSigner that posts CSRs to control-plane /svid/sign over mTLS.
func startPhase4(ctx context.Context, opts phase4Options) error {
	var (
		svidStore *svid.Store
		auth      *ca.Authority
		trustPool *x509.CertPool
	)

	svidStore = svid.NewStore()

	if opts.standalone {
		// Ephemeral CA for development.
		var err error
		auth, err = ca.NewTestAuthority("cluster.local")
		if err != nil {
			return fmt.Errorf("phase4: generate dev CA: %w", err)
		}
		trustPool = auth.TrustPool()

		// Issue an initial SVID for the node proxy identity.
		nodeSPIFFEID := ca.NodeSPIFFEID("cluster.local", "local-node")
		signer := svid.NewLocalSigner(auth)
		mgr := svid.NewManager(nodeSPIFFEID, signer, svidStore,
			svid.WithLogf(log.Printf))
		go func() {
			if err := mgr.Start(ctx); err != nil {
				log.Printf("phase4: svid manager: %v", err)
			}
		}()

	} else if opts.controlAddr != "" && opts.bootstrapCert != "" {
		// Load bootstrap credential and dial control plane.
		boot, err := ca.LoadBootstrapFiles(opts.bootstrapCert, opts.bootstrapKey)
		if err != nil {
			return fmt.Errorf("phase4: load bootstrap: %w", err)
		}
		tlsCert, err := boot.TLSCertificate()
		if err != nil {
			return fmt.Errorf("phase4: bootstrap tls cert: %w", err)
		}
		// Placeholder: trust pool from bootstrap cert chain for now.
		// In production, the trust bundle comes from FetchBundle RPC.
		trustPool = x509.NewCertPool()
		for _, c := range boot.Chain {
			trustPool.AddCert(c)
		}

		signer := svid.NewRemoteSigner(opts.controlAddr+"/svid/sign", tlsCert, trustPool)
		nodeSPIFFEID := boot.NodeSpiffeID
		mgr := svid.NewManager(nodeSPIFFEID, signer, svidStore,
			svid.WithLogf(log.Printf))
		go func() {
			if err := mgr.Start(ctx); err != nil {
				log.Printf("phase4: svid manager (remote): %v", err)
			}
		}()
	} else {
		log.Printf("phase4: neither --standalone nor --control-addr given; " +
			"proxy mTLS and SVID rotation disabled")
		return nil
	}

	// Workload API socket.
	if opts.workloadAPISocket != "" && auth != nil {
		wkldSrv := workloadapi.NewServer(opts.workloadAPISocket, svidStore, auth)
		go func() {
			if err := wkldSrv.Serve(ctx); err != nil {
				log.Printf("phase4: workload api: %v", err)
			}
		}()
		log.Printf("phase4: workload API socket: %s", opts.workloadAPISocket)
	}

	// TPROXY steering rules.
	tproxyInst := tproxy.NewInstaller()
	if err := tproxyInst.Install(ctx); err != nil {
		log.Printf("phase4: TPROXY install failed (proxy redirect disabled): %v", err)
	} else {
		log.Printf("phase4: TPROXY rules installed (mark=0x%x table=%d)",
			tproxy.TproxyMark, tproxy.TproxyTable)
		defer func() { _ = tproxyInst.Uninstall(context.Background()) }()
	}

	// CertSource for TLS configs.
	certSource := workloadapi.NewCertSource(svidStore)

	// Inbound mTLS handler (:proxy-inbound-port).
	if opts.proxyInPort > 0 {
		inAddr := fmt.Sprintf("0.0.0.0:%d", opts.proxyInPort)
		inLn, err := proxy.ListenTransparent(ctx, inAddr)
		if err != nil {
			return fmt.Errorf("phase4: inbound listen %s: %w", inAddr, err)
		}
		spiffeRes := proxy.NewMapSpiffeIDResolver()
		inHandler := proxy.NewInboundHandler(
			listenerAdapter(inLn),
			certSource,
			trustPool,
			proxy.NewTPROXYResolver(nil), // IdentityLookup wired in Phase 7
			&noopPolicySource{},
			proxy.WithInboundLogf(log.Printf),
			proxy.WithSpiffeIDResolver(spiffeRes),
		)
		go func() {
			if err := inHandler.Serve(ctx); err != nil {
				log.Printf("phase4: inbound handler: %v", err)
			}
		}()
		log.Printf("phase4: inbound mTLS listener: %s", inAddr)
	}

	// Outbound CONNECT handler (:proxy-outbound-port).
	if opts.proxyOutPort > 0 {
		outAddr := fmt.Sprintf("0.0.0.0:%d", opts.proxyOutPort)
		outLn, err := proxy.ListenTransparent(ctx, outAddr)
		if err != nil {
			return fmt.Errorf("phase4: outbound listen %s: %w", outAddr, err)
		}
		dialer := proxy.NewMTLSDialer(certSource, trustPool)
		cb := proxy.NewCircuitBreaker(5, 30e9) // 5 errors → open; 30s reset
		outHandler := proxy.NewOutboundHandler(
			listenerAdapter(outLn),
			proxy.NewTPROXYResolver(nil),
			dialer,
			proxy.WithOutboundLogf(log.Printf),
			proxy.WithCircuitBreaker(cb),
		)
		go func() {
			if err := outHandler.Serve(ctx); err != nil {
				log.Printf("phase4: outbound handler: %v", err)
			}
		}()
		log.Printf("phase4: outbound CONNECT listener: %s", outAddr)
	}

	return nil
}

// listenerAdapter wraps a net.Listener to satisfy proxy.Listener.
type listenerAdapter struct{ net.Listener }

// Ensure net.Listener already satisfies proxy.Listener (same method set).
var _ proxy.Listener = listenerAdapter{}

// noopPolicySource satisfies proxy.PolicySource with an empty snapshot.
type noopPolicySource struct{}

func (n *noopPolicySource) Current(_ context.Context) (wire.ProxyPolicySnapshot, error) {
	return wire.ProxyPolicySnapshot{}, nil
}
