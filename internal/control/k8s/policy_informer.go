// MeridianPolicy informer (CP-5 / Phase 7): watches MeridianPolicy custom
// resources through the dynamic client (no code-gen) and mirrors them into
// the control-plane policy store as compiled wire.PolicyRule entries.
package k8s

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"github.com/joshuawu/meridian/pkg/wire"
)

// L4 protocol numbers used in compiled policy keys (IANA assigned).
const (
	ProtocolTCP uint8 = 6
	ProtocolUDP uint8 = 17
)

// policyResyncInterval matches the pod informer's resync period.
const policyResyncInterval = 30 * time.Second

// maxCompiledRulesPerPolicy bounds one policy's cartesian expansion
// (sources × destinations × ports × protocols): larger products are refused
// outright to protect the control plane and etcd from a single oversized
// object.
const maxCompiledRulesPerPolicy = 65536

// PolicyStore is the subset of control.Store the policy informer needs.
type PolicyStore interface {
	PutPolicy(context.Context, wire.PolicyRule) error
	DeletePolicy(context.Context, wire.PolicyRuleKey) error
}

// IdentityResolver maps the CRD's selector language onto numeric identity
// IDs. Implementations must fail closed: an unresolvable source or selector
// is an error, never an empty allow.
type IdentityResolver interface {
	// ResolveSelector returns the identity IDs of workloads matching sel.
	ResolveSelector(ctx context.Context, sel WorkloadSelector) ([]wire.IdentityID, error)
	// ResolveSpiffeID returns the identity ID registered for a SPIFFE ID.
	ResolveSpiffeID(ctx context.Context, spiffeID string) (wire.IdentityID, bool)
}

// StaticResolver is a map-backed IdentityResolver for tests and dev
// bootstrapping. Selector resolution matches on namespace only. The maps may
// be swapped under mu after construction.
type StaticResolver struct {
	mu          sync.RWMutex
	BySpiffeID  map[string]wire.IdentityID
	ByNamespace map[string][]wire.IdentityID
}

func (r *StaticResolver) ResolveSelector(_ context.Context, sel WorkloadSelector) ([]wire.IdentityID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids, ok := r.ByNamespace[sel.Namespace]
	if !ok || len(ids) == 0 {
		return nil, fmt.Errorf("no identities in namespace %q", sel.Namespace)
	}
	return append([]wire.IdentityID(nil), ids...), nil
}

func (r *StaticResolver) ResolveSpiffeID(_ context.Context, spiffeID string) (wire.IdentityID, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.BySpiffeID[spiffeID]
	return id, ok
}

// CompilePolicyRules expands one MeridianPolicy into compiled L4 rules:
// sources × destinations × ports × protocols, direction ingress (CRD
// policies protect the selected destination workloads). The spec is
// re-validated here so the informer never trusts objects that bypassed the
// admission webhook.
func CompilePolicyRules(ctx context.Context, pol MeridianPolicy, resolver IdentityResolver) ([]wire.PolicyRule, error) {
	if err := ValidatePolicySpec(pol.Spec); err != nil {
		return nil, fmt.Errorf("policy %s/%s: %w", pol.Namespace, pol.Name, err)
	}

	srcIDs := make([]wire.IdentityID, 0, len(pol.Spec.Sources))
	for _, src := range pol.Spec.Sources {
		id, ok := resolver.ResolveSpiffeID(ctx, src)
		if !ok {
			return nil, fmt.Errorf("policy %s/%s: source %q: no registered identity",
				pol.Namespace, pol.Name, src)
		}
		srcIDs = append(srcIDs, id)
	}
	dstIDs, err := resolver.ResolveSelector(ctx, pol.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("policy %s/%s: resolve selector: %w", pol.Namespace, pol.Name, err)
	}

	protocols, err := protocolNumbers(pol.Spec.Protocols)
	if err != nil {
		return nil, fmt.Errorf("policy %s/%s: %w", pol.Namespace, pol.Name, err)
	}
	verdict, err := verdictForAction(pol.Spec.Action)
	if err != nil {
		return nil, fmt.Errorf("policy %s/%s: %w", pol.Namespace, pol.Name, err)
	}

	product := len(srcIDs) * len(dstIDs) * len(pol.Spec.Ports) * len(protocols)
	if product > maxCompiledRulesPerPolicy {
		return nil, fmt.Errorf("policy %s/%s: expands to %d rules, max %d",
			pol.Namespace, pol.Name, product, maxCompiledRulesPerPolicy)
	}

	rules := make([]wire.PolicyRule, 0, product)
	for _, src := range srcIDs {
		for _, dst := range dstIDs {
			for _, port := range pol.Spec.Ports {
				for _, proto := range protocols {
					rules = append(rules, wire.PolicyRule{
						Key: wire.PolicyRuleKey{
							SrcIdentity: src,
							DstIdentity: dst,
							DstPort:     port,
							Protocol:    proto,
							Direction:   wire.DirectionIngress,
						},
						Verdict: verdict,
					})
				}
			}
		}
	}
	return rules, nil
}

func protocolNumbers(names []string) ([]uint8, error) {
	if len(names) == 0 {
		return []uint8{ProtocolTCP}, nil
	}
	out := make([]uint8, 0, len(names))
	for _, name := range names {
		switch name {
		case ProtocolNameTCP:
			out = append(out, ProtocolTCP)
		case ProtocolNameUDP:
			out = append(out, ProtocolUDP)
		default:
			return nil, fmt.Errorf("unknown protocol %q", name)
		}
	}
	return out, nil
}

func verdictForAction(action string) (wire.PolicyVerdict, error) {
	switch action {
	case PolicyActionNameAllow:
		return wire.PolicyVerdict{Action: wire.PolicyActionAllow}, nil
	case PolicyActionNameDeny:
		return wire.PolicyVerdict{Action: wire.PolicyActionDeny}, nil
	default:
		return wire.PolicyVerdict{}, fmt.Errorf("unknown action %q", action)
	}
}

// PolicyWatcher drives the MeridianPolicy informer loop and mirrors policy
// objects into the store. Invalid or unresolvable objects are logged and
// skipped (the store keeps its last good state — same fail-closed posture
// as the xDS NACK path).
type PolicyWatcher struct {
	client   dynamic.Interface
	store    PolicyStore
	resolver IdentityResolver
	logf     func(string, ...any)

	// applied tracks the rule keys actually written to the store per policy
	// object ("namespace/name"). Cleanup diffs against this record, never
	// against a recompile of the old spec: the resolver may have drifted
	// since the rules were applied, and recompiling would leak stale
	// (possibly ALLOW) rules — a fail-open bug.
	mu      sync.Mutex
	applied map[string][]wire.PolicyRuleKey
}

// NewPolicyWatcher returns a PolicyWatcher backed by client.
func NewPolicyWatcher(client dynamic.Interface, store PolicyStore, resolver IdentityResolver) *PolicyWatcher {
	return &PolicyWatcher{
		client:   client,
		store:    store,
		resolver: resolver,
		logf:     log.Printf,
		applied:  make(map[string][]wire.PolicyRuleKey),
	}
}

// Run starts the MeridianPolicy informer and blocks until ctx is cancelled.
func (w *PolicyWatcher) Run(ctx context.Context) error {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(w.client, policyResyncInterval)
	informer := factory.ForResource(PolicyGVR()).Informer()

	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.onUpsert(ctx, nil, obj) },
		UpdateFunc: func(oldObj, newObj any) { w.onUpsert(ctx, oldObj, newObj) },
		DeleteFunc: func(obj any) { w.onDelete(ctx, obj) },
	})
	if err != nil {
		return fmt.Errorf("policy informer: add event handler: %w", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return fmt.Errorf("policy informer: cache sync timed out")
	}
	w.logf("k8s watcher: meridianpolicy informer ready")

	<-ctx.Done()
	return nil
}

// onUpsert compiles the (new) object and puts its rules, then removes
// previously-applied keys the new revision no longer produces (diffed
// against the applied record, not a recompile of the old spec).
func (w *PolicyWatcher) onUpsert(ctx context.Context, _, newObj any) {
	pol, err := policyFromObject(newObj)
	if err != nil {
		w.logf("policy informer: %v", err)
		return
	}
	rules, err := CompilePolicyRules(ctx, pol, w.resolver)
	if err != nil {
		w.logf("policy informer: skip: %v", err)
		return
	}

	newKeys := make(map[wire.PolicyRuleKey]bool, len(rules))
	appliedKeys := make([]wire.PolicyRuleKey, 0, len(rules))
	for _, rule := range rules {
		newKeys[rule.Key] = true
		if err := w.store.PutPolicy(ctx, rule); err != nil {
			w.logf("policy informer: put %s/%s: %v", pol.Namespace, pol.Name, err)
			continue
		}
		appliedKeys = append(appliedKeys, rule.Key)
	}

	name := pol.Namespace + "/" + pol.Name
	for _, key := range w.swapApplied(name, appliedKeys) {
		if newKeys[key] {
			continue
		}
		if err := w.store.DeletePolicy(ctx, key); err != nil {
			w.logf("policy informer: delete stale %s: %v", name, err)
		}
	}
}

// onDelete removes every rule key recorded as applied for the object. When
// the watcher has no record (e.g. it restarted after the rules were
// applied), it falls back to recompiling the deleted spec — best effort,
// logged when even that fails.
func (w *PolicyWatcher) onDelete(ctx context.Context, obj any) {
	pol, err := policyFromObject(obj)
	if err != nil {
		w.logf("policy informer: delete: %v", err)
		return
	}
	name := pol.Namespace + "/" + pol.Name

	keys := w.swapApplied(name, nil)
	if keys == nil {
		rules, err := CompilePolicyRules(ctx, pol, w.resolver)
		if err != nil {
			w.logf("policy informer: delete %s: no applied record and recompile failed: %v",
				name, err)
			return
		}
		for _, rule := range rules {
			keys = append(keys, rule.Key)
		}
	}
	for _, key := range keys {
		if err := w.store.DeletePolicy(ctx, key); err != nil {
			w.logf("policy informer: delete rule %+v: %v", key, err)
		}
	}
}

// swapApplied records keys as the applied set for name (removing the record
// when keys is nil) and returns the previous set.
func (w *PolicyWatcher) swapApplied(name string, keys []wire.PolicyRuleKey) []wire.PolicyRuleKey {
	w.mu.Lock()
	defer w.mu.Unlock()
	prev := w.applied[name]
	if keys == nil {
		delete(w.applied, name)
	} else {
		w.applied[name] = keys
	}
	return prev
}

// policyFromObject converts an informer event payload into a MeridianPolicy.
// Delete events may deliver the object wrapped in DeletedFinalStateUnknown.
func policyFromObject(obj any) (MeridianPolicy, error) {
	if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tombstone.Obj
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return MeridianPolicy{}, fmt.Errorf("unexpected object type %T", obj)
	}
	var pol MeridianPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &pol); err != nil {
		return MeridianPolicy{}, fmt.Errorf("convert %s/%s: %w", u.GetNamespace(), u.GetName(), err)
	}
	return pol, nil
}
