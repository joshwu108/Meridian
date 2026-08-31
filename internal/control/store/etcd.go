// Package store provides the control-plane storage backends.
// This file implements the etcd backend (CP-5 / Phase 7).
//
// The etcd backend stores identities under /meridian/identities/<id> and
// policies under /meridian/policies/<key>. Watch events are coalesced into
// the StoreEvent channel (same semantics as the memory backend).
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"sync"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/joshuawu/meridian/internal/control"
	"github.com/joshuawu/meridian/pkg/wire"
)

const (
	identityPrefix = "/meridian/identities/"
	policyPrefix   = "/meridian/policies/"
)

// Etcd implements control.Store backed by etcd. All writes go to etcd;
// Watch delivers coalescing StoreEvents on any etcd change under the prefix.
type Etcd struct {
	client *clientv3.Client

	mu   sync.Mutex
	subs []chan control.StoreEvent
}

// NewEtcd constructs an Etcd store connected to endpoints.
// Callers should call Close on the returned store when done.
func NewEtcd(endpoints []string) (*Etcd, error) {
	cli, err := clientv3.New(clientv3.Config{Endpoints: endpoints})
	if err != nil {
		return nil, fmt.Errorf("etcd: connect to %v: %w", endpoints, err)
	}
	return &Etcd{client: cli}, nil
}

// Close releases the etcd client connection.
func (e *Etcd) Close() error { return e.client.Close() }

func (e *Etcd) PutIdentity(ctx context.Context, id wire.Identity) error {
	b, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("etcd: marshal identity: %w", err)
	}
	key := identityPrefix + strconv.FormatUint(uint64(id.ID), 10)
	if _, err := e.client.Put(ctx, key, string(b)); err != nil {
		return fmt.Errorf("etcd: put identity %d: %w", id.ID, err)
	}
	e.notify(control.StoreEvent{Kind: control.StoreEventIdentityChanged})
	return nil
}

func (e *Etcd) DeleteIdentity(ctx context.Context, id wire.IdentityID) error {
	key := identityPrefix + strconv.FormatUint(uint64(id), 10)
	if _, err := e.client.Delete(ctx, key); err != nil {
		return fmt.Errorf("etcd: delete identity %d: %w", id, err)
	}
	e.notify(control.StoreEvent{Kind: control.StoreEventIdentityChanged})
	return nil
}

func (e *Etcd) ListIdentities(ctx context.Context) ([]wire.Identity, error) {
	resp, err := e.client.Get(ctx, identityPrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd: list identities: %w", err)
	}
	out := make([]wire.Identity, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var id wire.Identity
		if err := json.Unmarshal(kv.Value, &id); err != nil {
			return nil, fmt.Errorf("etcd: unmarshal identity %q: %w", kv.Key, err)
		}
		out = append(out, id)
	}
	return out, nil
}

func (e *Etcd) PutPolicy(ctx context.Context, rule wire.PolicyRule) error {
	b, err := json.Marshal(rule)
	if err != nil {
		return fmt.Errorf("etcd: marshal policy: %w", err)
	}
	key := policyKey(rule.Key)
	if _, err := e.client.Put(ctx, key, string(b)); err != nil {
		return fmt.Errorf("etcd: put policy %s: %w", key, err)
	}
	e.notify(control.StoreEvent{Kind: control.StoreEventPolicyChanged})
	return nil
}

func (e *Etcd) DeletePolicy(ctx context.Context, key wire.PolicyRuleKey) error {
	k := policyKey(key)
	if _, err := e.client.Delete(ctx, k); err != nil {
		return fmt.Errorf("etcd: delete policy %s: %w", k, err)
	}
	e.notify(control.StoreEvent{Kind: control.StoreEventPolicyChanged})
	return nil
}

func (e *Etcd) ListPolicies(ctx context.Context) ([]wire.PolicyRule, error) {
	resp, err := e.client.Get(ctx, policyPrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd: list policies: %w", err)
	}
	out := make([]wire.PolicyRule, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var rule wire.PolicyRule
		if err := json.Unmarshal(kv.Value, &rule); err != nil {
			return nil, fmt.Errorf("etcd: unmarshal policy %q: %w", kv.Key, err)
		}
		out = append(out, rule)
	}
	return out, nil
}

// Watch subscribes to etcd changes under the Meridian prefix and delivers
// coalescing StoreEvents until ctx is cancelled. It uses etcd's native Watch
// RPC so no polling is needed.
func (e *Etcd) Watch(ctx context.Context) <-chan control.StoreEvent {
	ch := make(chan control.StoreEvent, 16)
	e.mu.Lock()
	e.subs = append(e.subs, ch)
	e.mu.Unlock()

	// Also subscribe to etcd Watch for real-time change delivery.
	go func() {
		watchCh := e.client.Watch(ctx, "/meridian/", clientv3.WithPrefix())
		for {
			select {
			case <-ctx.Done():
				close(ch)
				return
			case resp, ok := <-watchCh:
				if !ok {
					close(ch)
					return
				}
				if resp.Err() != nil {
					continue
				}
				for _, ev := range resp.Events {
					var kind control.StoreEventKind
					if path.Dir(string(ev.Kv.Key)) == path.Dir(identityPrefix+"x") {
						kind = control.StoreEventIdentityChanged
					} else {
						kind = control.StoreEventPolicyChanged
					}
					select {
					case ch <- control.StoreEvent{Kind: kind}:
					default:
					}
				}
			}
		}
	}()
	return ch
}

func (e *Etcd) notify(ev control.StoreEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ch := range e.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func policyKey(k wire.PolicyRuleKey) string {
	return fmt.Sprintf("%s%d_%d_%d_%d_%d",
		policyPrefix, k.SrcIdentity, k.DstIdentity, k.DstPort, k.Protocol, k.Direction)
}
