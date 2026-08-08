package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server-Sent Events. One endpoint, GET /v1/base/realtime, carrying every hub
// broadcast for one chain in one envelope:
//
//	event: CONNECT     (once, on open)
//	data: {}
//
//	data: {"event":"<channel>","chain":"<slug>","data":<payload>}
//
//	: ping             (keep-alive every 30s)
//
// The SPA opens exactly one EventSource and routes frames off the envelope's
// `event` field, so there is nothing to gain from a stream per channel — and
// the per-channel endpoints that used to live here were mounted at bare
// /blocks, /tokens, /stats, /validators, which are SPA page paths. A mux
// serving both cannot serve either.
//
// HEAD is answered too: the SPA pre-flights with
// `fetch(url, {method: HEAD}).then(r => r.ok)` and net/http's ServeMux would
// otherwise answer 405 on a GET-only route, which reads as a dead channel.
//
// Each connected client gets its own bounded queue. Slow consumers drop
// messages rather than back-pressure the hub; the SPA refreshes stale state
// via REST on reconnect.

// sseClient is a single SSE subscriber — one per connected browser.
type sseClient struct {
	chain  string        // the only chain this subscriber receives
	events chan []byte   // buffered outbound queue; full → drop
	done   chan struct{} // closed when the client disconnects
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

// fanout pushes one pre-encoded envelope to every SSE subscriber of `chain`.
// Called from RealtimeHub.Broadcast, which encodes the frame once.
func (r *sseRegistry) fanout(chain string, envelope []byte) {
	if envelope == nil {
		return
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for c := range r.clients {
		if c.chain != chain {
			continue
		}
		select {
		case c.events <- envelope:
		default:
			// Slow consumer — drop this event rather than block.
		}
	}
}

// streamChain is the chain an SSE subscriber receives: whatever `?chain=`
// asks for, else the chain the request host is served. Never empty, because
// an empty filter means "every chain the hub broadcasts" and no brand host
// wants another brand's blocks.
func streamChain(cfg Config, r *http.Request) string {
	if q := strings.TrimSpace(r.URL.Query().Get("chain")); q != "" {
		return q
	}
	return cfg.Serves(r.Host).Slug
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
// channel.
//
// The stream carries one chain: the one `cfg` says the request host is served,
// unless `?chain=` names another. One binary indexes five chains and broadcasts
// all of them onto this hub, so an unfiltered stream handed Hanzo's browser
// Lux and Zoo blocks, which the SPA appended to Hanzo's list — 63 rows for a
// 50-row page, 2 Lux on top and 8 Zoo at the bottom.
func (h *RealtimeHub) HandleMultiplexedSSE(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// HEAD pre-flight: keep the response brief — GCP HTTP/2 load
		// balancers (and Traefik in some configs) 502 when a HEAD
		// response carries `Connection: keep-alive` + a streaming
		// content-type, because they expect HEAD to be a closed-body
		// response, not an opened SSE stream. Return only Content-Type
		// + 200, no streaming-only headers.
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		client := &sseClient{
			chain:  streamChain(cfg, r),
			events: make(chan []byte, 128),
			done:   make(chan struct{}),
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
