package wire

// Identity describes a control-plane allocated identity and display metadata.
type Identity struct {
	ID        IdentityID
	SpiffeID  string
	Namespace string
	Name      string
}
