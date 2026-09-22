//go:build !windows

package iface

// IsVirtualInterface reports whether the named interface is backed by a virtual
// adapter. Only Windows has the problem this check works around, other
// platforms report every interface as non-virtual.
func IsVirtualInterface(name string) bool {
	return false
}
