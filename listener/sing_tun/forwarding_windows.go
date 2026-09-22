//go:build windows

package sing_tun

import (
	"errors"
	"net"
	"unsafe"

	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/windows"
)

// Windows keeps a per interface "forwarding" flag. Once it is enabled, the host
// behaves as a router on that interface: the packets the core dials out are fed
// back into our own TUN adapter, the loopback detector rejects them and every
// node dial fails with "dns resolve failed". A client machine never needs the
// flag, so disable it while TUN is up and put it back afterwards.
//
// Verified on Windows 11: with the flag enabled TUN mode is completely broken
// (no connectivity, thousands of "reject loopback connection"), with it
// disabled everything works on the very same build and configuration.

const scopeLevelCount = 16

type offloadRod uint8

// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipinterface_row
type mibIPInterfaceRow struct {
	Family                               uint16
	InterfaceLUID                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	RouterDiscoveryBehavior              uint32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMTUDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [scopeLevelCount]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NLMTU                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      offloadRod
	ReceiveOffload                       offloadRod
	DisableDefaultRoutes                 bool
}

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procConvertInterfaceIndexToLuid = modIphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procGetIpInterfaceEntry         = modIphlpapi.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry         = modIphlpapi.NewProc("SetIpInterfaceEntry")
)

func getInterfaceForwardingV4(ifIndex int) (bool, error) {
	var luid uint64
	r1, _, callErr := procConvertInterfaceIndexToLuid.Call(uintptr(ifIndex), uintptr(unsafe.Pointer(&luid)))
	if r1 != 0 {
		return false, callError("ConvertInterfaceIndexToLuid", callErr)
	}

	row := mibIPInterfaceRow{
		Family:         windows.AF_INET,
		InterfaceLUID:  luid,
		InterfaceIndex: uint32(ifIndex),
	}
	r1, _, callErr = procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r1 != 0 {
		return false, callError("GetIpInterfaceEntry", callErr)
	}
	return row.ForwardingEnabled, nil
}

func setInterfaceForwardingV4(ifIndex int, enabled bool) error {
	var luid uint64
	r1, _, callErr := procConvertInterfaceIndexToLuid.Call(uintptr(ifIndex), uintptr(unsafe.Pointer(&luid)))
	if r1 != 0 {
		return callError("ConvertInterfaceIndexToLuid", callErr)
	}

	row := mibIPInterfaceRow{
		Family:         windows.AF_INET,
		InterfaceLUID:  luid,
		InterfaceIndex: uint32(ifIndex),
	}
	// the caller must fetch the current entry first, SetIpInterfaceEntry
	// rejects a row that was not obtained from GetIpInterfaceEntry
	r1, _, callErr = procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r1 != 0 {
		return callError("GetIpInterfaceEntry", callErr)
	}

	row.ForwardingEnabled = enabled
	r1, _, callErr = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r1 != 0 {
		return callError("SetIpInterfaceEntry", callErr)
	}
	return nil
}

func callError(proc string, err error) error {
	if err == nil || errors.Is(err, windows.ERROR_SUCCESS) {
		return errors.New(proc + " failed")
	}
	return errors.New(proc + ": " + err.Error())
}

// fixEgressForwarding disables interface forwarding on every physical interface
// that is up, has an IPv4 address and has the flag enabled. It returns a
// function restoring the original values (called when TUN stops).
type forwardingRestoreEntry struct {
	index int
	name  string
}

func fixEgressForwarding() func() {
	interfaces, err := iface.Interfaces()
	if err != nil {
		log.Warnln("[TUN] unable to enumerate interfaces to check forwarding: %v", err)
		return func() {}
	}

	var restore []forwardingRestoreEntry
	for name, current := range interfaces {
		restore = append(restore, disableForwardingIfNeeded(name, current)...)
	}

	if len(restore) == 0 {
		return func() {}
	}

	return func() {
		for _, entry := range restore {
			if err := setInterfaceForwardingV4(entry.index, true); err != nil {
				log.Warnln("[TUN] failed to restore IPv4 forwarding on %s: %v", entry.name, err)
				continue
			}
			log.Infoln("[TUN] restored IPv4 forwarding on %s", entry.name)
		}
	}
}

func disableForwardingIfNeeded(name string, current *iface.Interface) []forwardingRestoreEntry {
	var result []forwardingRestoreEntry

	if current.Flags&net.FlagUp == 0 || current.Flags&net.FlagLoopback != 0 {
		return result
	}
	if iface.IsVirtualInterface(name) {
		return result
	}

	hasIPv4 := false
	for _, prefix := range current.Addresses {
		if prefix.Addr().Is4() && !prefix.Addr().IsLinkLocalUnicast() {
			hasIPv4 = true
			break
		}
	}
	if !hasIPv4 {
		return result
	}

	enabled, err := getInterfaceForwardingV4(current.Index)
	if err != nil {
		log.Debugln("[TUN] unable to read IPv4 forwarding of %s: %v", name, err)
		return result
	}
	if !enabled {
		return result
	}

	if err := setInterfaceForwardingV4(current.Index, false); err != nil {
		log.Warnln("[TUN] failed to disable IPv4 forwarding on %s: %v", name, err)
		return result
	}

	log.Warnln("[TUN] IPv4 forwarding was enabled on %s, disabled it for this TUN session "+
		"(an interface acting as router loops our own packets back into TUN and breaks all connections)", name)
	result = append(result, forwardingRestoreEntry{index: current.Index, name: name})
	return result
}
