//go:build !windows

package sing_tun

// fixEgressForwarding is a no-op outside Windows, the interface forwarding
// setting this works around is Windows specific.
func fixEgressForwarding() func() {
	return func() {}
}
