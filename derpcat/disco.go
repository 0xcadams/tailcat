package derpcat

import (
	"errors"

	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

var errShort = errors.New("short message")

const (
	TypeMeow   = disco.MessageType(0x0a)
	TypeMeowed = disco.MessageType(0x0b)
)

// MeowPing is a "meow" discovery message sent by a derpcat client to a
// derpcat server to announce itself. The server registers the client's
// node key and replies with a Meowed.
type MeowPing struct {
	TxID    [12]byte
	NodeKey key.NodePublic
}

func (m *MeowPing) AppendMarshal(b []byte) []byte {
	ret, d := appendMsgHeader(b, TypeMeow, 0, 12+key.NodePublicRawLen)
	copy(d, m.TxID[:])
	m.NodeKey.AppendTo(d[:12])
	return ret
}

func parseMeow(ver uint8, p []byte) (*MeowPing, error) {
	if len(p) < 12+key.NodePublicRawLen {
		return nil, errShort
	}
	m := new(MeowPing)
	copy(m.TxID[:], p)
	m.NodeKey = key.NodePublicFromRaw32(mem.B(p[12 : 12+key.NodePublicRawLen]))
	return m, nil
}

// Meowed is a response to a MeowPing, sent by a derpcat server to
// confirm the client was added to the server's peer map.
type Meowed struct{}

func (m *Meowed) AppendMarshal(b []byte) []byte {
	ret, _ := appendMsgHeader(b, TypeMeowed, 0, 0)
	return ret
}

// appendMsgHeader is a copy of disco.appendMsgHeader.
func appendMsgHeader(b []byte, t disco.MessageType, ver uint8, dataLen int) (all, data []byte) {
	all = append(b, make([]byte, dataLen+2)...)
	all[len(b)] = byte(t)
	all[len(b)+1] = ver
	data = all[len(b)+2:]
	return
}

func init() {
	disco.ParseHook = func(t disco.MessageType, ver uint8, p []byte) (disco.Message, error) {
		switch t {
		case TypeMeow:
			return parseMeow(ver, p)
		case TypeMeowed:
			return &Meowed{}, nil
		default:
			return nil, nil
		}
	}
}
