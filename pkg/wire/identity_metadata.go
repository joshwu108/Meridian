package wire

// Identity describes a control-plane allocated identity and display metadata.
type Identity struct {
	ID        IdentityID
	PodIPv4   string
	SpiffeID  string
	Namespace string
	Name      string
}
