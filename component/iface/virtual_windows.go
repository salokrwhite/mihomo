//go:build windows

package iface

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows interface types, see ipifcons.h
const (
	ifTypeEthernetCSMACD = 6
	ifTypeFastEther     = 62
	ifTypeIEEE80211     = 71
	ifTypeGigabitEther  = 117
)

// virtualInterfaceKeywords are matched against the adapter's friendly name and
// driver description. Virtual adapters (Wintun/TAP/VMware/Hyper-V/...) must not
// be used as the outbound interface of the TUN listener: packets sent to them
// can re-enter our own TUN, get rejected as loopback connections and break every
// node dial while TUN mode is enabled.
var virtualInterfaceKeywords = []string{
	"wintun",
	"wireguard",
	"tap-",
	"tap ",
	"tun",
	"tunnel",
	"vmware",
	"virtualbox",
	"vbox",
	"hyper-v",
	"vethernet",
	"loopback",
	"zerotier",
	"tailscale",
	"openvpn",
	"softether",
	"sing-box",
	"singbox",
	"mihomo",
	"clash",
	"v2ray",
	"vgate",
}

type windowsAdapter struct {
	friendlyName string
	description  string
	ifType       uint32
	physicalLen  uint32
	mtu          uint32
	operStatus   uint32
	linkSpeed    uint64
}

var (
	windowsAdaptersMu     sync.Mutex
	windowsAdaptersCache  []windowsAdapter
	windowsAdaptersExpire time.Time
)

// IsVirtualInterface reports whether the named interface is backed by a virtual
// adapter instead of physical hardware. Unknown interfaces are reported as
// non-virtual so that callers keep their previous behaviour.
func IsVirtualInterface(name string) bool {
	adapters := windowsAdapters()
	if len(adapters) == 0 {
		return false
	}

	lowerName := strings.ToLower(name)
	for _, adapter := range adapters {
		if strings.ToLower(adapter.friendlyName) != lowerName {
			continue
		}
		return adapter.isVirtual()
	}
	return false
}

func (a windowsAdapter) isVirtual() bool {
	lowerFriendlyName := strings.ToLower(a.friendlyName)
	lowerDescription := strings.ToLower(a.description)
	for _, keyword := range virtualInterfaceKeywords {
		if strings.Contains(lowerFriendlyName, keyword) || strings.Contains(lowerDescription, keyword) {
			return true
		}
	}

	// A physical adapter always exposes an unicast MAC address.
	if a.physicalLen == 0 {
		return true
	}

	switch a.ifType {
	case ifTypeEthernetCSMACD, ifTypeFastEther, ifTypeIEEE80211, ifTypeGigabitEther:
		// Wintun based adapters report an Ethernet media type, so double check
		// the MTU: they default to 65535 while real media stays at 9000 or below.
		return a.mtu == 0 || a.mtu > 9000
	default:
		// IF_TYPE_TUNNEL(131), IF_TYPE_PPP(23), IF_TYPE_SOFTWARE_LOOPBACK(24),
		// IF_TYPE_PROP_VIRTUAL(53) and friends are all unusable as egress.
		return true
	}
}

func windowsAdapters() []windowsAdapter {
	windowsAdaptersMu.Lock()
	defer windowsAdaptersMu.Unlock()

	if time.Now().Before(windowsAdaptersExpire) {
		return windowsAdaptersCache
	}

	windowsAdaptersCache = fetchWindowsAdapters()
	windowsAdaptersExpire = time.Now().Add(20 * time.Second)
	return windowsAdaptersCache
}

func fetchWindowsAdapters() []windowsAdapter {
	const (
		flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	)

	var size uint32 = 16 * 1024
	buffer := make([]byte, size)
	for attempt := 0; attempt < 4; attempt++ {
		addresses := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, addresses, &size)
		if err == nil {
			return collectWindowsAdapters(addresses)
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil
		}
		buffer = make([]byte, size)
	}

	return nil
}

func collectWindowsAdapters(addresses *windows.IpAdapterAddresses) []windowsAdapter {
	adapters := make([]windowsAdapter, 0, 8)
	for current := addresses; current != nil; current = current.Next {
		adapters = append(adapters, windowsAdapter{
			friendlyName: windows.UTF16PtrToString(current.FriendlyName),
			description:  windows.UTF16PtrToString(current.Description),
			ifType:       current.IfType,
			physicalLen:  current.PhysicalAddressLength,
			mtu:          current.Mtu,
			operStatus:   current.OperStatus,
			linkSpeed:    current.TransmitLinkSpeed,
		})
	}
	return adapters
}
