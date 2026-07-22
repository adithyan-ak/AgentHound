//go:build windows

package identity

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func platformSignals() ([]rawSignal, []rawSignal) {
	var identity []rawSignal
	if key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	); err == nil {
		if value, _, valueErr := key.GetStringValue("MachineGuid"); valueErr == nil && value != "" {
			identity = append(identity, rawSignal{kind: "os_instance", value: strings.ToLower(value)})
		}
		_ = key.Close()
	}
	if volume, err := windows.UTF16PtrFromString(`C:\`); err == nil {
		var serial uint32
		if err := windows.GetVolumeInformation(volume, nil, 0, &serial, nil, nil, nil, 0); err == nil {
			identity = append(identity, rawSignal{kind: "platform", value: fmt.Sprintf("%08x", serial)})
		}
	}
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err == nil {
		if user, userErr := token.GetTokenUser(); userErr == nil && user.User.Sid != nil {
			identity = append(identity, rawSignal{kind: "principal", value: user.User.Sid.String()})
		}
		_ = token.Close()
	}
	return identity, windowsNetworkProfiles()
}

func windowsNetworkProfiles() []rawSignal {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var signals []rawSignal
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		row := windows.MibIfRow2{InterfaceIndex: uint32(iface.Index)}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
			continue
		}
		if row.NetworkGuid == (windows.GUID{}) {
			continue
		}
		signals = append(signals, rawSignal{kind: "network_profile", value: row.NetworkGuid.String()})
	}
	return signals
}
