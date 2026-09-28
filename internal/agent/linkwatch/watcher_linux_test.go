//go:build linux

package linkwatch

import (
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestPrefixSelector(t *testing.T) {
	sel := PrefixSelector("mh-")
	if !sel("mh-abc") {
		t.Fatal("PrefixSelector should match mh-abc")
	}
	if sel("eth0") {
		t.Fatal("PrefixSelector should not match eth0")
	}
	if PrefixSelector("")("anything") {
		t.Fatal("empty prefix must match nothing (fail-closed)")
	}
}

// linkUpdate builds a synthetic RTNLGRP_LINK message for classify(); no socket
// or root is needed — only the in-memory netlink types.
func linkUpdate(msgType uint16, link netlink.Link) netlink.LinkUpdate {
	return netlink.LinkUpdate{
		Header: unix.NlMsghdr{Type: msgType},
		Link:   link,
	}
}

func veth(name string) *netlink.Veth {
	return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

func TestClassify(t *testing.T) {
	w := NewNetlinkWatcher(PrefixSelector("mh-"))

	tests := []struct {
		name   string
		update netlink.LinkUpdate
		wantEv Event
		wantOK bool
	}{
		{
			name:   "new veth matching prefix → EventAdded",
			update: linkUpdate(unix.RTM_NEWLINK, veth("mh-a")),
			wantEv: Event{IfName: "mh-a", Type: EventAdded},
			wantOK: true,
		},
		{
			name:   "del veth matching prefix → EventRemoved",
			update: linkUpdate(unix.RTM_DELLINK, veth("mh-a")),
			wantEv: Event{IfName: "mh-a", Type: EventRemoved},
			wantOK: true,
		},
		{
			name:   "del matching prefix without kind still removes (DELLINK may omit kind)",
			update: linkUpdate(unix.RTM_DELLINK, &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "mh-a"}}),
			wantEv: Event{IfName: "mh-a", Type: EventRemoved},
			wantOK: true,
		},
		{
			name:   "new non-matching name → ignored",
			update: linkUpdate(unix.RTM_NEWLINK, veth("eth0")),
			wantOK: false,
		},
		{
			name:   "new non-veth matching prefix → ignored (only veths attach)",
			update: linkUpdate(unix.RTM_NEWLINK, &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "mh-a"}}),
			wantOK: false,
		},
		{
			name:   "unrelated message type → ignored",
			update: linkUpdate(unix.RTM_NEWADDR, veth("mh-a")),
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := w.classify(tc.update)
			if ok != tc.wantOK {
				t.Fatalf("classify ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && ev != tc.wantEv {
				t.Fatalf("classify ev = %+v, want %+v", ev, tc.wantEv)
			}
		})
	}
}
