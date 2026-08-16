package route

import (
	"net"

	"github.com/metacubex/http"
)

// UpgradeWebSocket and WriteWebSocketText expose the handshake and framing this package already
// uses for /traffic, /memory, /logs and /connections, so a route registered from outside can
// speak the same protocol instead of carrying a second implementation.
//
// A second implementation was the alternative and it was worse in a specific way: bind/hako
// already vendors coder/websocket for the CLIENT side, and reaching for it on the server side
// would have produced an endpoint whose framing, close behaviour and header handling were
// nobody's job to keep matched with the four upstream streams next to it. One protocol, one
// place.
//
// These are thin wrappers rather than moved code so the upstream functions stay exactly where a
// merge expects to find them.
func UpgradeWebSocket(request *http.Request, writer http.ResponseWriter) (net.Conn, error) {
	conn, _, err := wsUpgrade(request, writer)
	return conn, err
}

// WriteWebSocketText sends one text frame.
func WriteWebSocketText(conn net.Conn, payload []byte) error {
	return wsWriteServerText(conn, payload)
}
