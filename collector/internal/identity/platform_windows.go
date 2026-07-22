//go:build windows

package identity

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func platformSignals() ([]rawSignal, []rawSignal, bool) {
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
	routes, routesComplete := windowsRouteSignals()
	return identity, append(windowsNetworkProfiles(), routes...), routesComplete
}

func windowsRouteSignals() ([]rawSignal, bool) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil || table == nil {
		return nil, false
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var signals []rawSignal
	complete := true
	for _, row := range table.Rows() {
		destination := windowsSockaddrIP(&row.DestinationPrefix.Prefix)
		if destination == nil {
			complete = false
			continue
		}
		bits := 128
		if destination.To4() != nil {
			bits = 32
		}
		if int(row.DestinationPrefix.PrefixLength) > bits {
			complete = false
			continue
		}
		gateway := windowsSockaddrIP(&row.NextHop)
		routeSignals, routeComplete := canonicalRouteSignals(
			destination,
			int(row.DestinationPrefix.PrefixLength),
			gateway,
			windowsRoutePathDiscriminator(row),
		)
		signals = append(signals, routeSignals...)
		complete = complete && routeComplete
	}
	return signals, complete
}

func windowsRoutePathDiscriminator(routeRow windows.MibIpForwardRow2) string {
	interfaceRow := windows.MibIfRow2{
		InterfaceLuid:  routeRow.InterfaceLuid,
		InterfaceIndex: routeRow.InterfaceIndex,
	}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &interfaceRow); err != nil {
		return ""
	}
	var parts []string
	if interfaceRow.InterfaceGuid != (windows.GUID{}) {
		parts = append(parts, "interface_guid="+strings.ToLower(interfaceRow.InterfaceGuid.String()))
	}
	if interfaceRow.NetworkGuid != (windows.GUID{}) {
		parts = append(parts, "network_guid="+strings.ToLower(interfaceRow.NetworkGuid.String()))
	}
	addressLength := int(interfaceRow.PhysicalAddressLength)
	if addressLength > len(interfaceRow.PermanentPhysicalAddress) {
		addressLength = len(interfaceRow.PermanentPhysicalAddress)
	}
	if address := stableLinkAddress(interfaceRow.PermanentPhysicalAddress[:addressLength]); address != "" {
		parts = append(parts, "link="+address)
	} else if address := stableLinkAddress(interfaceRow.PhysicalAddress[:addressLength]); address != "" {
		parts = append(parts, "link="+address)
	}
	return strings.Join(parts, "\x00")
}

func windowsSockaddrIP(address *windows.RawSockaddrInet) net.IP {
	if address == nil {
		return nil
	}
	switch address.Family {
	case windows.AF_INET:
		value := (*windows.RawSockaddrInet4)(unsafe.Pointer(address))
		return net.IPv4(value.Addr[0], value.Addr[1], value.Addr[2], value.Addr[3])
	case windows.AF_INET6:
		value := (*windows.RawSockaddrInet6)(unsafe.Pointer(address))
		return net.IP(value.Addr[:])
	default:
		return nil
	}
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
