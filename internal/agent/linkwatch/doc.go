// Package linkwatch defines link event stream contracts.
package linkwatch

import "context"

// EventType classifies a link lifecycle transition.
type EventType uint8

const (
	EventAdded EventType = iota + 1
	EventRemoved
)

// Event describes one interface lifecycle change.
type Event struct {
	IfName string
	Type   EventType
}

// Watcher streams link events and supports full reconcile snapshots.
type Watcher interface {
	Reconcile(context.Context) ([]string, error)
	Events(context.Context) (<-chan Event, error)
}
