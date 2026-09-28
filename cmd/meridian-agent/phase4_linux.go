//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/agent/tproxy"
	"github.com/joshuawu/meridian/internal/agent/workloadapi"
	"github.com/joshuawu/meridian/internal/agent/xds"
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
// node proxy inbound/outbound handlers. Each component runs in its own
// goroutine; the first fatal error is logged. It returns the SPIFFE ID
// resolver shared by the proxy handlers so the ADS post-apply hook can refresh
// it on every applied snapshot (nil when the proxy is disabled).
//
// Standalone mode (--standalone):
//   - Generates an ephemeral in-process CA (dev/test).
//   - Uses LocalSigner backed by that CA for workload SVIDs.
//
// Remote mode (--control-addr):
//   - Loads the node bootstrap credential (--bootstrap-cert / --bootstrap-key).
//   - Uses RemoteSigner that posts CSRs to control-plane /svid/sign over mTLS.
func startPhase4(ctx context.Context, opts phase4Options) (*proxy.MapSpiffeIDResolver, error) {
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
			return nil, fmt.Errorf("phase4: generate dev CA: %w", err)
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
			return nil, fmt.Errorf("phase4: load bootstrap: %w", err)
		}
		// Placeholder: trust pool from bootstrap cert chain for now.
		// In production, the trust bundle comes from FetchBundle RPC.
		trustPool = x509.NewCertPool()
		for _, c := range boot.Chain {
			trustPool.AddCert(c)
		}

		signer, err := newRemoteSigner(opts.controlAddr, opts.bootstrapCert, opts.bootstrapKey)
		if err != nil {
			return nil, fmt.Errorf("phase4: %w", err)
		}
		mgr := svid.NewManager(boot.NodeSpiffeID, signer, svidStore,
			svid.WithLogf(log.Printf))
		go func() {
			if err := mgr.Start(ctx); err != nil {
				log.Printf("phase4: svid manager (remote): %v", err)
			}
		}()
	} else {
		log.Printf("phase4: neither --standalone nor --control-addr given; " +
			"proxy mTLS and SVID rotation disabled")
		return nil, nil
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

	// SPIFFE ID resolver shared by both proxy handlers. Empty until the ADS
	// post-apply hook (main.go) feeds it the applied identity table.
	spiffeRes := proxy.NewMapSpiffeIDResolver()

	// Inbound mTLS handler (:proxy-inbound-port).
	if opts.proxyInPort > 0 {
		inAddr := fmt.Sprintf("0.0.0.0:%d", opts.proxyInPort)
		inLn, err := proxy.ListenTransparent(ctx, inAddr)
		if err != nil {
			return nil, fmt.Errorf("phase4: inbound listen %s: %w", inAddr, err)
		}
		inHandler := proxy.NewInboundHandler(
			listenerAdapter{inLn},
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
			return nil, fmt.Errorf("phase4: outbound listen %s: %w", outAddr, err)
		}
		dialer := proxy.NewMTLSDialer(certSource, trustPool)
		cb := proxy.NewCircuitBreaker(5, 30e9) // 5 errors → open; 30s reset
		outHandler := proxy.NewOutboundHandler(
			listenerAdapter{outLn},
			proxy.NewTPROXYResolver(nil),
			dialer,
			proxy.WithOutboundLogf(log.Printf),
			proxy.WithCircuitBreaker(cb),
			proxy.WithOutboundSpiffeIDLookup(spiffeRes),
		)
		go func() {
			if err := outHandler.Serve(ctx); err != nil {
				log.Printf("phase4: outbound handler: %v", err)
			}
		}()
		log.Printf("phase4: outbound CONNECT listener: %s", outAddr)
	}

	return spiffeRes, nil
}

// startADSClient dials the control plane's ADS gRPC endpoint and runs the
// agent's ADS client (A-3) until ctx is cancelled. When a SPIFFE ID resolver
// is present, a post-apply hook refreshes it from the applied identity table
// after every ACKed snapshot (Task: SpiffeIDResolver ↔ ADS apply loop seam).
func startADSClient(ctx context.Context, adsAddr string, writer datapath.Writer, spiffeRes *proxy.MapSpiffeIDResolver, p4 phase4Options) error {
	if writer == nil {
		return fmt.Errorf("ads client: no datapath writer available")
	}
	dialOpt, err := adsDialOption(p4.bootstrapCert, p4.bootstrapKey)
	if err != nil {
		return fmt.Errorf("ads client: %w", err)
	}
	conn, err := grpc.NewClient(adsAddr, dialOpt)
	if err != nil {
		return fmt.Errorf("ads client: dial %s: %w", adsAddr, err)
	}

	var opts []xds.Option
	var client *xds.Client
	if spiffeRes != nil {
		// The hook reloads the client's full applied identity set: the plan
		// only carries the delta, while the resolver swaps its whole table.
		opts = append(opts, xds.WithPostApply(newPostApply(func() []wire.Identity {
			_, identities := client.Applied()
			return identities
		}, spiffeRes)))
	}
	client = xds.NewClient(conn, writer, opts...)

	go func() {
		defer func() { _ = conn.Close() }()
		if err := client.Run(ctx); err != nil {
			log.Printf("ads client: %v", err)
		}
	}()
	log.Printf("ads client: streaming from %s", adsAddr)
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
