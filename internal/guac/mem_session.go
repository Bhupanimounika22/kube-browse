package guac

import (
	"net/http"
	"net/url"
	"sync"
)

// ActiveTunnelStore is an in-memory store of active Guacamole tunnels.
type ActiveTunnelStore struct {
	sync.RWMutex
	// activeTunnels maps ConnectionID to the active Tunnel.
	activeTunnels map[string]Tunnel
	// connectionParams stores connection parameters for each tunnel
	connectionParams map[string]url.Values
}

// NewActiveTunnelStore creates a new store for active tunnels.
func NewActiveTunnelStore() *ActiveTunnelStore {
	return &ActiveTunnelStore{
		activeTunnels:    make(map[string]Tunnel),
		connectionParams: make(map[string]url.Values),
	}
}

// Get returns a tunnel by its ConnectionID.
func (s *ActiveTunnelStore) Get(id string) (Tunnel, bool) {
	s.RLock()
	defer s.RUnlock()
	tunnel, found := s.activeTunnels[id]
	return tunnel, found
}

// Add inserts a new tunnel into the store.
// The 'req' argument is kept for compatibility with existing callback signatures if needed,
// but might not be used directly in this version.
func (s *ActiveTunnelStore) Add(id string, tunnel Tunnel, req *http.Request) {
	s.Lock()
	defer s.Unlock()
	s.activeTunnels[id] = tunnel
}

// Delete removes a tunnel by its ConnectionID.
// The 'req' and 'tunnel' arguments are kept for compatibility with existing callback signatures,
// primarily the 'tunnel' parameter in OnDisconnect.
func (s *ActiveTunnelStore) Delete(id string, req *http.Request, closedTunnel Tunnel) {
	s.Lock()
	defer s.Unlock()
	// We could optionally verify if closedTunnel matches s.activeTunnels[id] before deleting
	// For now, just delete by id.
	delete(s.activeTunnels, id)
	delete(s.connectionParams, id)
}

// GetAllIDs returns a slice of all active ConnectionIDs.
func (s *ActiveTunnelStore) GetAllIDs() []string {
	s.RLock()
	defer s.RUnlock()
	ids := make([]string, 0, len(s.activeTunnels))
	for id := range s.activeTunnels {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active tunnels.
func (s *ActiveTunnelStore) Count() int {
	s.RLock()
	defer s.RUnlock()
	return len(s.activeTunnels)
}

// StoreConnectionParams stores connection parameters for a tunnel
func (s *ActiveTunnelStore) StoreConnectionParams(id string, params url.Values) {
	s.Lock()
	defer s.Unlock()
	s.connectionParams[id] = params
}

// GetConnectionParams retrieves connection parameters for a tunnel
func (s *ActiveTunnelStore) GetConnectionParams(id string) (url.Values, bool) {
	s.RLock()
	defer s.RUnlock()
	params, found := s.connectionParams[id]
	return params, found
}
