//go:build (linux || darwin) && !ts_omit_ssh

package derpcat

import (
	"net"
)

func (b *locoBackend) ShouldRunSSH() bool { return false }

func (s *Server) HandleTailscaleSSHConn(c net.Conn) {
	// SSH support requires fork-specific tailssh.NewDERPCatServer
	// which is not yet available in upstream tailscale.com.
	c.Close()
}
