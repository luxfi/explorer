// DAG WebSocket streaming for live DAG visualization
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DAGNode represents a node in the DAG visualization
type DAGNode struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"` // transaction, vertex, utxo, block
	Label     string                 `json:"label"`
	Timestamp string                 `json:"timestamp,omitempty"`
	Status    string                 `json:"status,omitempty"` // accepted, pending, rejected
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// DAGEdge represents an edge in the DAG visualization
type DAGEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type,omitempty"` // input, output, parent, reference
	Label  string `json:"label,omitempty"`
}

// DAGMessage is the message sent over WebSocket
type DAGMessage struct {
	Type      string      `json:"type"` // vertex_added, vertex_accepted, edge_added, initial_state, heartbeat
	Data      interface{} `json:"data"`
	Timestamp string      `json:"timestamp"`
}

// DAGSubscriber handles WebSocket connections for DAG streaming
type DAGSubscriber struct {
	clients   map[*websocket.Conn]bool
	broadcast chan DAGMessage
	register  chan *websocket.Conn
	unregister chan *websocket.Conn
	mu        sync.RWMutex
	upgrader  websocket.Upgrader
}

// NewDAGSubscriber creates a new DAG subscriber
func NewDAGSubscriber() *DAGSubscriber {
	return &DAGSubscriber{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan DAGMessage, 100),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}
}

// Run starts the subscriber goroutine
func (ds *DAGSubscriber) Run(ctx context.Context) {
	// Heartbeat ticker
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			// Close all client connections
			ds.mu.Lock()
			for client := range ds.clients {
				client.Close()
				delete(ds.clients, client)
			}
			ds.mu.Unlock()
			return

		case client := <-ds.register:
			ds.mu.Lock()
			ds.clients[client] = true
			log.Printf("[DAG WS] Client connected. Total clients: %d", len(ds.clients))
			ds.mu.Unlock()

		case client := <-ds.unregister:
			ds.mu.Lock()
			if _, ok := ds.clients[client]; ok {
				delete(ds.clients, client)
				client.Close()
				log.Printf("[DAG WS] Client disconnected. Total clients: %d", len(ds.clients))
			}
			ds.mu.Unlock()

		case message := <-ds.broadcast:
			ds.mu.RLock()
			for client := range ds.clients {
				err := client.WriteJSON(message)
				if err != nil {
					log.Printf("[DAG WS] Write error: %v", err)
					go func(c *websocket.Conn) {
						ds.unregister <- c
					}(client)
				}
			}
			ds.mu.RUnlock()

		case <-heartbeat.C:
			ds.broadcast <- DAGMessage{
				Type:      "heartbeat",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
		}
	}
}

// HandleWebSocket handles WebSocket connections
func (ds *DAGSubscriber) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ds.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[DAG WS] Upgrade error: %v", err)
		return
	}

	ds.register <- conn

	// Send initial state
	ds.sendInitialState(conn)

	// Read messages (to detect disconnection)
	go func() {
		defer func() {
			ds.unregister <- conn
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

// sendInitialState sends current DAG state to new client
func (ds *DAGSubscriber) sendInitialState(conn *websocket.Conn) {
	// Send a batch of recent nodes as initial state
	// In production, this would query the database
	initialState := DAGMessage{
		Type: "initial_state",
		Data: map[string]interface{}{
			"nodes": []DAGNode{},
			"edges": []DAGEdge{},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	conn.WriteJSON(initialState)
}

// BroadcastVertex broadcasts a new vertex to all clients
func (ds *DAGSubscriber) BroadcastVertex(node DAGNode) {
	ds.broadcast <- DAGMessage{
		Type: "vertex_added",
		Data: map[string]interface{}{
			"node": node,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// BroadcastAccepted broadcasts vertex acceptance
func (ds *DAGSubscriber) BroadcastAccepted(nodeID string) {
	ds.broadcast <- DAGMessage{
		Type: "vertex_accepted",
		Data: map[string]interface{}{
			"node": DAGNode{
				ID:     nodeID,
				Status: "accepted",
			},
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// BroadcastEdge broadcasts a new edge to all clients
func (ds *DAGSubscriber) BroadcastEdge(edge DAGEdge) {
	ds.broadcast <- DAGMessage{
		Type: "edge_added",
		Data: map[string]interface{}{
			"edge": edge,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// GetClientCount returns the number of connected clients
func (ds *DAGSubscriber) GetClientCount() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.clients)
}

// DAGPoller polls the chain for new vertices and broadcasts them
type DAGPoller struct {
	indexer    *Indexer
	subscriber *DAGSubscriber
	lastTxID   string
	mu         sync.Mutex
}

// NewDAGPoller creates a new DAG poller
func NewDAGPoller(idx *Indexer, sub *DAGSubscriber) *DAGPoller {
	return &DAGPoller{
		indexer:    idx,
		subscriber: sub,
	}
}

// Run starts polling for new DAG vertices
func (dp *DAGPoller) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Println("[DAG Poller] Starting DAG polling...")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if dp.subscriber.GetClientCount() == 0 {
				continue // No clients connected, skip polling
			}

			dp.pollNewVertices(ctx)
		}
	}
}

// pollNewVertices polls for new transactions/vertices
func (dp *DAGPoller) pollNewVertices(ctx context.Context) {
	// Query recent transactions from RPC
	result, err := dp.indexer.RPCCall("xvm.getRecentTxs", map[string]interface{}{
		"num": 10,
	})
	if err != nil {
		// Fall back to database query
		dp.pollFromDatabase(ctx)
		return
	}

	var response struct {
		TxIDs []string `json:"txIDs"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		log.Printf("[DAG Poller] Parse error: %v", err)
		return
	}

	dp.mu.Lock()
	lastID := dp.lastTxID
	dp.mu.Unlock()

	// Process new transactions
	for _, txID := range response.TxIDs {
		if txID == lastID {
			break
		}

		// Fetch transaction details
		txResult, err := dp.indexer.RPCCall("xvm.getTx", map[string]interface{}{
			"txID":     txID,
			"encoding": "json",
		})
		if err != nil {
			continue
		}

		var tx struct {
			Unsigned struct {
				TypeID uint32 `json:"typeID"`
				Inputs []struct {
					TxID        string `json:"txID"`
					OutputIndex int    `json:"outputIndex"`
				} `json:"inputs"`
				Outputs []struct {
					AssetID string `json:"assetID"`
					Amount  uint64 `json:"amount"`
				} `json:"outputs"`
			} `json:"unsignedTx"`
		}
		json.Unmarshal(txResult, &tx)

		// Create DAG node for transaction
		txType := getTypeNameFromID(tx.Unsigned.TypeID)
		node := DAGNode{
			ID:        txID,
			Type:      "transaction",
			Label:     truncateID(txID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Status:    "accepted",
			Metadata: map[string]interface{}{
				"txType":      txType,
				"inputCount":  len(tx.Unsigned.Inputs),
				"outputCount": len(tx.Unsigned.Outputs),
			},
		}
		dp.subscriber.BroadcastVertex(node)

		// Create edges for inputs (parent references)
		for _, input := range tx.Unsigned.Inputs {
			edge := DAGEdge{
				Source: input.TxID,
				Target: txID,
				Type:   "input",
			}
			dp.subscriber.BroadcastEdge(edge)
		}
	}

	// Update last seen ID
	if len(response.TxIDs) > 0 {
		dp.mu.Lock()
		dp.lastTxID = response.TxIDs[0]
		dp.mu.Unlock()
	}
}

// pollFromDatabase polls from local database when RPC is unavailable
func (dp *DAGPoller) pollFromDatabase(ctx context.Context) {
	rows, err := dp.indexer.db.QueryContext(ctx, `
		SELECT id, type, timestamp, inputs
		FROM xchain_transactions
		ORDER BY timestamp DESC
		LIMIT 10
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	dp.mu.Lock()
	lastID := dp.lastTxID
	dp.mu.Unlock()

	var newLastID string
	for rows.Next() {
		var txID, txType string
		var timestamp time.Time
		var inputs []byte

		rows.Scan(&txID, &txType, &timestamp, &inputs)

		if newLastID == "" {
			newLastID = txID
		}

		if txID == lastID {
			break
		}

		node := DAGNode{
			ID:        txID,
			Type:      "transaction",
			Label:     truncateID(txID),
			Timestamp: timestamp.UTC().Format(time.RFC3339),
			Status:    "accepted",
			Metadata: map[string]interface{}{
				"txType": txType,
			},
		}
		dp.subscriber.BroadcastVertex(node)
	}

	if newLastID != "" {
		dp.mu.Lock()
		dp.lastTxID = newLastID
		dp.mu.Unlock()
	}
}

func getTypeNameFromID(typeID uint32) string {
	switch typeID {
	case 0:
		return "BaseTx"
	case 1:
		return "CreateAssetTx"
	case 2:
		return "OperationTx"
	case 3:
		return "ImportTx"
	case 4:
		return "ExportTx"
	default:
		return "Unknown"
	}
}

func truncateID(id string) string {
	if len(id) > 12 {
		return id[:8] + "..." + id[len(id)-4:]
	}
	return id
}
