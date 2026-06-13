//go:build bpf

package bpftest

// tcSkBuff mirrors struct __sk_buff from vmlinux.h for prog_test_run context.
type tcSkBuff struct {
	Len            uint32
	PktType        uint32
	Mark           uint32
	QueueMapping   uint32
	Protocol       uint32
	VlanPresent    uint32
	VlanTci        uint32
	VlanProto      uint32
	Priority       uint32
	IngressIfindex uint32
	Ifindex        uint32
	TcIndex        uint32
	Cb             [5]uint32
	Hash           uint32
	TcClassid      uint32
	Data           uint32
	DataEnd        uint32
	NapiID         uint32
	Family         uint32
	RemoteIP4      uint32
	LocalIP4       uint32
	RemoteIP6      [4]uint32
	LocalIP6       [4]uint32
	RemotePort     uint32
	LocalPort      uint32
	DataMeta       uint32
	FlowKeys       uint64
	Tstamp         uint64
	WireLen        uint32
	GsoSegs        uint32
	Sk             uint64
	GsoSize        uint32
}
