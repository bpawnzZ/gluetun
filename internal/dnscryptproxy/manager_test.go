package dnscryptproxy

import (
	"context"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/log"
)

func TestDNSCryptProxyManager(t *testing.T) {
	// Create a logger for testing
	logger := log.New(log.SetLevel(log.LevelDebug))

	// Create a new manager
	manager := NewManager(logger)

	// Test with disabled DNSCrypt-Proxy
	disabled := false
	settings := settings.DNSCryptProxy{
		Enabled: &disabled,
	}

	err := manager.SetSettings(context.Background(), settings)
	if err != nil {
		t.Errorf("Failed to set settings: %v", err)
	}

	err = manager.Start(context.Background())
	if err != nil {
		t.Errorf("Failed to start disabled manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Manager should not be running when disabled")
	}

	err = manager.Stop()
	if err != nil {
		t.Errorf("Failed to stop disabled manager: %v", err)
	}

	// Test with enabled DNSCrypt-Proxy
	enabled := true
	settings.Enabled = &enabled

	err = manager.SetSettings(context.Background(), settings)
	if err != nil {
		t.Errorf("Failed to set enabled settings: %v", err)
	}

	err = manager.Start(context.Background())
	if err != nil {
		t.Errorf("Failed to start enabled manager: %v", err)
	}

	if !manager.IsRunning() {
		t.Error("Manager should be running when enabled")
	}

	// Test health check
	err = manager.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}

	// Test settings change
	settings.ListenAddress = "127.0.0.1:53"
	err = manager.SetSettings(context.Background(), settings)
	if err != nil {
		t.Errorf("Failed to update settings: %v", err)
	}

	// Wait for restart
	time.Sleep(2 * time.Second)

	if !manager.IsRunning() {
		t.Error("Manager should still be running after settings change")
	}

	// Test stop
	err = manager.Stop()
	if err != nil {
		t.Errorf("Failed to stop manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Manager should not be running after stop")
	}

	// Test health check on stopped manager
	err = manager.HealthCheck(context.Background())
	if err == nil {
		t.Error("Health check should fail on stopped manager")
	}
}
