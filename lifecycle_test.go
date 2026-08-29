// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcat

import (
	"context"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"
)

func TestServerCloseClosesActiveConnections(t *testing.T) {
	t.Parallel()

	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	clientKey := key.NewNode()
	accepted := make(chan net.Conn, 1)
	handlerDone := make(chan struct{})
	s := &Server{
		Logf:           mkLogger(t, "server"),
		Region:         reg,
		AllowedClients: []key.NodePublic{clientKey.Public()},
		ServedTCPPorts: []filter.PortRange{{First: 80, Last: 80}},
		OnTCP: func(port uint16) func(net.Conn) {
			if port != 80 {
				return nil
			}
			return func(conn net.Conn) {
				accepted <- conn
				defer close(handlerDone)
				var buf [1]byte
				_, _ = conn.Read(buf[:])
			}
		},
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	c := &Client{Server: s.ConnBlob(), Key: clientKey, Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientConn, err := c.DialTCPPort(ctx, 80)
	if err != nil {
		t.Fatalf("DialTCPPort: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
		t.Cleanup(func() { serverConn.Close() })
	case <-ctx.Done():
		t.Fatalf("waiting for accepted connection: %v", ctx.Err())
	}

	if err := s.Close(); err != nil {
		t.Fatalf("server Close: %v", err)
	}

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server Close left an active netstack connection open")
	}
}
