package tunnel

import (
	"log"
	"os"
)

// tracePacketFlow emits packet-address and routing diagnostics only when explicitly
// enabled. Keep it disabled in production unless troubleshooting a packet-flow issue.
func tracePacketFlow(format string, args ...any) {
	if os.Getenv("PQTUNNEL_TRACE_PACKET_FLOW") != "1" {
		return
	}
	log.Printf("packet-flow "+format, args...)
}
