package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SSE endpoints — Server-Sent Events at the URLs the bundled Vite SPA
// expects (/blocks, /transactions, /token-transfers, /internal-txs,
// /tokens, /gas-tracker, /stats, /validators).
//
// Why this exists (2026-05-21):
//
// The SPA opens EventSource against `${window.location.origin}/<channel>`
// expecting `text/event-stream`. The Go backend previously had no
// handler for those paths, so every request fell through to the SPA's
// own static fallback (`handleSPA` → index.html), returning
// `text/html`. Browser console then logged:
//
//     EventSource's response has a MIME type ("text/html") that is not
//     "text/event-stream". Aborting the connection.
//
// …for every channel, on every page load. PR #4 silenced the HEAD
// pre-flight (so the SPA cleanly disabled itself). This file goes the
// other direction: make the SSE endpoints REAL, so the SPA opens them,
// gets a proper `text/event-stream` reply, stays connected, and
// receives broadcasts.
//
// Wire shape:
//   - GET  /blocks                      → SSE for hub channel "blocks"
//   - GET  /transactions                → SSE for hub channel "transactions"
//   - GET  /token-transfers             → SSE for hub channel "token_transfers"
//   - GET  /internal-txs                → SSE for hub channel "internal_transactions"
//   - GET  /tokens, /gas-tracker, /validators → SSE that stays open with
//     keep-alive pings; no broadcasters yet (placeholder so the SPA
//     channel doesn't show as broken)
//   - GET  /stats                       → SSE that emits the hub.Stats()
//     map every 5s — cheap server-side state, useful liveness signal
//   - HEAD <any>                        → 200 + the same headers so the
//     SPA pre-flight (`fetch(url, {method: HEAD}).then(r => r.ok)`)
//     succeeds before opening EventSource.
//
// Each connected client gets its own bounded channel. Slow consumers
// drop messages rather than back-pressure the hub; the SPA refreshes
// stale state via REST on reconnect.

// sseClient is a single SSE subscriber. One per connected browser per
// channel (the SPA opens one EventSource per channel it wants to follow).
type sseClient struct {
	channel string        // hub event-type to receive ("blocks" / "transactions" / ...)
	chain   string        // optional chain filter; "" = unscoped
	events  chan []byte   // buffered outbound queue; full → drop
	done    chan struct{} // closed when the client disconnects
}

// sseRegistry holds the live SSE clients. Kept separate from the
// WebSocket client map so the existing readPump/writePump paths don't
// need to learn a new client shape.
type sseRegistry struct {
	mu      sync.RWMutex
	clients map[*sseClient]struct{}
}

func newSSERegistry() *sseRegistry {
	return &sseRegistry{clients: make(map[*sseClient]struct{})}
}

func (r *sseRegistry) attach(c *sseClient) {
	r.mu.Lock()
	r.clients[c] = struct{}{}
	r.mu.Unlock()
}

func (r *sseRegistry) detach(c *sseClient) {
	r.mu.Lock()
	delete(r.clients, c)
	r.mu.Unlock()
	close(c.done)
}

// fanout pushes a pre-encoded message body to every SSE client whose
// channel filter matches. Called from RealtimeHub.Broadcast.
//
// Match policy mirrors the WebSocket subs lookup:
//   - exact channel match (client.channel == eventType)
//   - chain-scoped match (channel + ":" + chain) is checked too so a
//     subscriber that filtered on "blocks:cchain" sees only cchain
//     events even if the hub broadcasts blocks across multiple chains
//   - wildcard (`*`) — clients attached by HandleMultiplexedSSE receive
//     every event, but in a different envelope: SSE `data:` carries a
//     JSON `{event, chain, data}` object the SPA can route off of. The
//     wildcard `body` is built here; per-channel clients keep using the
//     prebuilt per-channel framing from Broadcast for cheap reuse.
func (r *sseRegistry) fanout(eventType, chain string, body []byte, wildcardEnvelope []byte) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for c := range r.clients {
		var payload []byte
		switch {
		case c.channel == "*":
			payload = wildcardEnvelope
		case c.channel == eventType:
			payload = body
		default:
			continue
		}
		if c.chain != "" && c.chain != chain {
			continue
		}
		if payload == nil {
			continue
		}
		select {
		case c.events <- payload:
		default:
			// Slow consumer — drop this event rather than block.
		}
	}
}

// HandleSSE returns an http.HandlerFunc bound to a specific channel
// name. main.go mounts one per path.
func (h *RealtimeHub) HandleSSE(channel string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SSE response headers — set BEFORE the HEAD short-circuit so
		// the pre-flight sees them and the SPA's `u.ok` check passes
		// (200 + text/event-stream → open EventSource).
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// Tell nginx-style proxies not to buffer the stream; without
		// this the first event can sit in a buffer for ~5s, defeating
		// the whole point of SSE.
		w.Header().Set("X-Accel-Buffering", "no")

		// HEAD pre-flight from EventSource open. Standard HTTP requires
		// HEAD to return the same headers as GET would, with no body.
		// We've already set them above; just acknowledge and return.
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			// Should be impossible on Go's net/http; defensive.
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Subscribe to the registry. `chain` query param is optional;
		// blank = no chain filter, see fanout()'s match policy.
		client := &sseClient{
			channel: channel,
			chain:   strings.TrimSpace(r.URL.Query().Get("chain")),
			events:  make(chan []byte, 64),
			done:    make(chan struct{}),
		}
		h.sse.attach(client)
		defer h.sse.detach(client)

		// Initial "connected" frame so the SPA's onopen handler fires
		// with a recognizable payload (matches the WebSocket "connected"
		// shape).
		writeSSE(w, flusher, "connected", []byte(`{}`))

		// Keep-alive ticker. Comment lines (`: ping`) don't fire the
		// EventSource onmessage handler but keep the TCP/TLS connection
		// alive through middleboxes that idle-timeout at 30s.
		keepAlive := time.NewTicker(30 * time.Second)
		defer keepAlive.Stop()

		// /stats is a special case — server-side periodic poll of the
		// hub's connection-count snapshot. Useful liveness signal even
		// when no hub broadcasts have been wired up yet.
		var statsTicker *time.Ticker
		if channel == "stats" {
			statsTicker = time.NewTicker(5 * time.Second)
			defer statsTicker.Stop()
		}

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-client.done:
				return
			case <-keepAlive.C:
				if _, err := w.Write([]byte(": ping\n\n")); err != nil {
					return
				}
				flusher.Flush()
			case msg := <-client.events:
				// Broadcast messages are already JSON-encoded by the
				// hub; we just prefix with the SSE framing.
				if _, err := w.Write(msg); err != nil {
					return
				}
				flusher.Flush()
			default:
				if statsTicker != nil {
					select {
					case <-statsTicker.C:
						// Synthesize a stats event from the hub.
						stats := fmt.Sprintf(
							`{"connections":%d,"subscriptions":%d}`,
							len(h.clients), len(h.sse.clients),
						)
						writeSSE(w, flusher, "stats", []byte(stats))
						continue
					default:
					}
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
}

// writeSSE emits one SSE event frame:
//
//	event: <name>
//	data: <payload>
//	(blank line)
//
// Per the SSE spec a frame ends with `\n\n`. Browsers tolerate `\r\n`
// too but `\n` is the canonical form Go's net/http uses elsewhere.
func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload []byte) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
	flusher.Flush()
}

// HandleMultiplexedSSE returns an http.HandlerFunc that fans EVERY hub
// broadcast into a single SSE stream, wrapping each event in a JSON
// envelope `{"event":"<channel>","chain":"<slug>","data":<payload>}`.
//
// Wire shape the bundled SPA expects at `/v1/base/realtime` — it uses
// `onmessage` (not event-typed listeners) and routes incoming frames
// via a handler map keyed off `msg.event`:
//
//	client.es.onmessage = o => {
//	    const c = JSON.parse(o.data);
//	    const d = this.handlers.get(c.event);
//	    if (d) for (const m of d) m(c.data);
//	};
//
// So the SPA gets ONE EventSource and receives all event types over it,
// instead of opening N parallel streams. This is the canonical realtime
// channel — the per-channel /blocks /transactions /etc. endpoints stay
// for backward compatibility and external consumers, but the SPA uses
// only this one.
func (h *RealtimeHub) HandleMultiplexedSSE() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Subscribe to ALL channels by registering a wildcard client.
		// The empty `channel` means fanout() needs special handling — we
		// use a sentinel "*" so we don't accidentally collide with a real
		// channel called "" elsewhere.
		client := &sseClient{
			channel: "*",
			chain:   strings.TrimSpace(r.URL.Query().Get("chain")),
			events:  make(chan []byte, 128),
			done:    make(chan struct{}),
		}
		h.sse.attach(client)
		defer h.sse.detach(client)

		writeSSE(w, flusher, "CONNECT", []byte(`{}`))

		keepAlive := time.NewTicker(30 * time.Second)
		defer keepAlive.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case <-client.done:
				return
			case <-keepAlive.C:
				if _, err := w.Write([]byte(": ping\n\n")); err != nil {
					return
				}
				flusher.Flush()
			case msg := <-client.events:
				if _, err := w.Write(msg); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
