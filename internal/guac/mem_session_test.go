package guac

import (
	"io"
	"testing"
)

// mockTunnel is a minimal implementation of the Tunnel interface for testing.
type mockTunnel struct {
	connID string
	uuid   string
}

func (m *mockTunnel) AcquireReader() InstructionReader { return nil }
func (m *mockTunnel) ReleaseReader()                   {}
func (m *mockTunnel) HasQueuedReaderThreads() bool     { return false }
func (m *mockTunnel) AcquireWriter() io.Writer         { return nil }
func (m *mockTunnel) ReleaseWriter()                   {}
func (m *mockTunnel) HasQueuedWriterThreads() bool     { return false }
func (m *mockTunnel) GetUUID() string                  { return m.uuid }
func (m *mockTunnel) ConnectionID() string             { return m.connID }
func (m *mockTunnel) Close() error                     { return nil }

func TestActiveTunnelStore(t *testing.T) {
	store := NewActiveTunnelStore()

	// Test Get on an empty store
	if _, found := store.Get("nonexistent"); found {
		t.Errorf("Expected to not find tunnel 'nonexistent', but it was found")
	}

	// Test Count on an empty store
	if count := store.Count(); count != 0 {
		t.Errorf("Expected count to be 0 on empty store, got %d", count)
	}

	// Test Add and Get
	mockTunnel1 := &mockTunnel{connID: "conn1", uuid: "uuid1"}
	store.Add("conn1", mockTunnel1, nil)

	retrievedTunnel, found := store.Get("conn1")
	if !found {
		t.Errorf("Expected to find tunnel 'conn1', but it was not found")
	}
	if retrievedTunnel != mockTunnel1 {
		t.Errorf("Retrieved tunnel does not match the added tunnel")
	}

	// Test Count after adding one tunnel
	if count := store.Count(); count != 1 {
		t.Errorf("Expected count to be 1 after adding a tunnel, got %d", count)
	}

	// Test GetAllIDs
	ids := store.GetAllIDs()
	if len(ids) != 1 || ids[0] != "conn1" {
		t.Errorf("GetAllIDs returned incorrect IDs: got %v, expected ['conn1']", ids)
	}

	// Test adding another tunnel
	mockTunnel2 := &mockTunnel{connID: "conn2", uuid: "uuid2"}
	store.Add("conn2", mockTunnel2, nil)

	if count := store.Count(); count != 2 {
		t.Errorf("Expected count to be 2 after adding a second tunnel, got %d", count)
	}

	// Test Delete
	store.Delete("conn1", nil, mockTunnel1) // The actual tunnel instance passed to Delete isn't used in current implementation

	if _, found := store.Get("conn1"); found {
		t.Errorf("Expected tunnel 'conn1' to be deleted, but it was found")
	}

	if count := store.Count(); count != 1 {
		t.Errorf("Expected count to be 1 after deleting a tunnel, got %d", count)
	}

	// Test Get for the remaining tunnel
	retrievedTunnel, found = store.Get("conn2")
	if !found {
		t.Errorf("Expected to find tunnel 'conn2', but it was not found")
	}
	if retrievedTunnel != mockTunnel2 {
		t.Errorf("Retrieved tunnel 'conn2' does not match the added tunnel")
	}

	// Test Delete the second tunnel
	store.Delete("conn2", nil, mockTunnel2)
	if _, found := store.Get("conn2"); found {
		t.Errorf("Expected tunnel 'conn2' to be deleted, but it was found")
	}
	if count := store.Count(); count != 0 {
		t.Errorf("Expected count to be 0 after deleting all tunnels, got %d", count)
	}
}
