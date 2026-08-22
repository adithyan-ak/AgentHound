package action

// Action identifies an internal scan capability. The values are registry and
// module metadata; they are not public CLI verbs.
type Action string

const (
	Scan        Action = "scan"
	Fingerprint Action = "fingerprint"
	Enumerate   Action = "enumerate"
	Collect     Action = "collect"
	Poison      Action = "poison"
)
