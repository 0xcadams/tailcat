# Tailpipe

Tailpipe is like netcat, but over WireGuard. It creates point-to-point
encrypted tunnels between two machines using Tailscale's data plane
(WireGuard, magicsock, DERP relays) without requiring a Tailscale
account or any coordination server.

The `tailpipe` CLI (in `cmd/tailpipe`) is built on the **derpcat** Go
library (in the `derpcat` package). The module is named `derpcat` for
historical reasons (a nod to [netcat](https://en.wikipedia.org/wiki/Netcat)) while the user-facing command is
called Tailpipe.

One side runs `tailpipe` to start a server and gets back a short
connection token. The other side passes that token to `tailpipe` to
connect. All traffic between the two is encrypted end-to-end with
WireGuard. The initial connection bootstraps through Tailscale's DERP
relay network, and then magicsock performs NAT traversal to upgrade to
a direct peer-to-peer UDP connection when possible.

No accounts, no login, no configuration files, no `sudo`.

## Usage

Pipe stdin/stdout between two machines:

```sh
# Machine A (server): listen and print what the client sends
tailpipe

# Machine B (client): send "hello" to the server
echo hello | tailpipe <token>
```

Expose local ports through the tunnel:

```sh
# Serve specific ports (forwarded to localhost)
tailpipe --serve=8080,8443

# Serve all ports
tailpipe --serve=all

# Client connects to a port
curl --connect-to ::localhost:1234 http://server/ | tailpipe <token> 8080
```

Run an auth-free Tailscale SSH server (Linux/macOS):

```sh
# Server
tailpipe --serve=no-auth-ssh

# Client
tailpipe ssh <token>
tailpipe ssh <token> ls -la
```

Ping to test connectivity:

```sh
tailpipe ping <token>
```

Run a command through a SOCKS5 proxy routed over the tunnel:

```sh
tailpipe socks <token> curl http://server.tailpipe:8081/
```

Act as an exit node so the client can reach the server's network:

```sh
tailpipe --serve=exit-node
```

Generate and save a persistent key (so the token stays stable across restarts):

```sh
tailpipe genkey --region=nyc
# prints the token; key saved to ~/.config/tailpipe/keys/default.private.json

# later:
tailpipe --key=default --serve=8080
```

Tokens can also be published as DNS TXT records and looked up by name:

```sh
# If example.com has a TXT record "tailpipe=dc..."
tailpipe example.com 8080
```

## How it works

### Connection tokens

A Tailpipe server is identified by a **connection token** (called a
ConnBlob internally). It looks like `dcXYZ...` and is a `"dc"` prefix
followed by base64-encoded [CBOR](https://cbor.io/) containing:

- The server's WireGuard public key (Curve25519, 32 bytes)
- A DERP relay region identifier (a small integer referencing one of
  Tailscale's global relay servers), or an embedded DERP node list for
  custom relays

A typical token with just a region ID is around 50 bytes. With embedded
DERP node details it's longer but self-contained (the client doesn't
need to fetch the DERP map).

### Network stack

Tailpipe reuses Tailscale's production networking components but
without the control plane. Internally it constructs a **locoBackend**
("loco" for local control, or Spanish) that wires together:

- **WireGuard engine** (`wgengine`) -- a userspace WireGuard
  implementation for encrypting all tunnel traffic. No kernel TUN/TAP
  device, no root required.
- **magicsock** -- Tailscale's transport layer that multiplexes traffic
  over direct UDP and DERP relays. It handles STUN-based endpoint
  discovery and UDP hole-punching for NAT traversal.
- **Netstack** (gVisor) -- a userspace TCP/IP stack that terminates
  TCP connections inside the process. This is what lets Tailpipe
  accept inbound connections and dial outbound ones without any OS
  network configuration.
- **DERP relay** -- Tailscale's encrypted relay protocol, used as a
  rendezvous channel and as a fallback data path when direct
  connectivity isn't possible.

### Connection flow

1. **Server starts.** It generates (or loads) a WireGuard keypair,
   connects to a DERP relay, and prints its connection token to stderr.
   It then waits for clients.

2. **Client parses the token** to learn the server's public key and
   DERP region. It generates its own ephemeral keypair and connects to
   the same DERP relay.

3. **Discovery handshake.** The client sends a **MeowPing** message
   (a custom Tailscale disco message type) to the server through the
   DERP relay. This message carries the client's node public key. The
   server receives it, adds the client to its WireGuard peer list and
   network map, reconfigures the WireGuard engine, and replies with a
   **Meowed** acknowledgment.

4. **WireGuard tunnel.** With both sides configured as WireGuard
   peers, the standard WireGuard handshake proceeds (routed through
   DERP initially). Once complete, the tunnel is up and encrypted
   traffic can flow.

5. **NAT traversal.** In parallel, magicsock runs Tailscale's
   disco protocol to exchange endpoint information (public IP:port
   learned via STUN). Both sides attempt UDP hole-punching. If
   successful, traffic upgrades from the DERP relay to a direct
   peer-to-peer path. If hole-punching fails, DERP continues as a
   fallback -- the connection still works, just with higher latency.

6. **Data transfer.** The client dials a TCP port on the server
   through the tunnel. gVisor's TCP/IP stack on both sides handles
   connection setup. On the server, the incoming connection is
   dispatched to a handler based on the port: forwarding to localhost,
   piping to stdout, running an SSH session, etc.

### Addressing

Each peer derives a deterministic IPv6 address from its WireGuard
public key, within Tailscale's ULA range (`fd7a:115c:a1e0::/48`). The
remaining 80 bits come from the first 10 bytes of the raw public key.
IPv4 destinations (when acting as an exit node) are mapped through the
NAT64 prefix `64:ff9b::/96`.

### Key reuse trick

The server reuses its WireGuard node key as its disco key (by
interpreting the same 32 bytes as both key types). This means the
client can derive the server's disco public key directly from the
token without any extra round trips or key exchange.
