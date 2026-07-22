//go:build darwin

package identity

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func platformSignals() ([]rawSignal, []rawSignal) {
	var identity []rawSignal
	var stat unix.Statfs_t
	if err := unix.Statfs("/", &stat); err == nil {
		identity = append(identity, rawSignal{
			kind:  "os_instance",
			value: fmt.Sprintf("%08x%08x", uint32(stat.Fsid.Val[0]), uint32(stat.Fsid.Val[1])),
		})
	}
	if value, err := unix.Sysctl("kern.uuid"); err == nil && value != "" {
		identity = append(identity, rawSignal{kind: "platform", value: value})
	}
	identity = append(identity, rawSignal{kind: "principal", value: strconv.Itoa(os.Geteuid())})
	return identity, nil
}
