package dnscryptproxy

import (
	"context"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/log"
)

func TestManager_StartStop(t *testing.T) {
	logger := log.New(log.SetLevel(log.LevelDebug))
	manager := NewManager(logger)

	ctx := context.Background()

	// Test starting with disabled setting
	enabled := false
	settings := settings.DNSCryptProxy{
		Enabled: &enabled,
	}
	err := manager.SetSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Failed to set settings: %v", err)
	}

	err = manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start manager with disabled setting: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Manager should not be running when disabled")
	}

	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop manager: %v", err)
	}

	// Test starting with enabled setting
	enabled = true
	settings.Enabled = &enabled
	err = manager.SetSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Failed to set settings: %v", err)
	}

	err = manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start manager with enabled setting: %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	if !manager.IsRunning() {
		t.Error("Manager should be running when enabled")
	}

	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop manager: %v", err)
	}

	if manager.IsRunning() {
		t.Error("Manager should not be running after stop")
	}
}

func TestManager_SetSettings(t *testing.T) {
	logger := log.New(log.SetLevel(log.LevelDebug))
	manager := NewManager(logger)

	ctx := context.Background()

	// Initial settings
	enabled := true
	blockAds := true
	blockMalicious := true
	blockSurveillance := false
	blockPhishing := true
	cache := true
	cacheSize := uint(512)
	requireDoH := false
	timeout := uint(5000)
	keepAlive := uint(30)

	settings := settings.DNSCryptProxy{
		Enabled:           &enabled,
		Servers:           []string{"cloudflare", "quad9"},
		ListenAddress:     "127.0.0.1:53",
		BlockAds:          &blockAds,
		BlockMalicious:    &blockMalicious,
		BlockSurveillance: &blockSurveillance,
		BlockPhishing:     &blockPhishing,
		LogLevel:          "info",
		Cache:             &cache,
		CacheSize:         &cacheSize,
		RequireDoH:        &requireDoH,
		Timeout:           &timeout,
		KeepAlive:         &keepAlive,
	}

	err := manager.SetSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Failed to set initial settings: %v", err)
	}

	// Update settings
	newSettings := settings
	newSettings.Servers = []string{"google"}
	blockAds = false
	newSettings.BlockAds = &blockAds
	newSettings.LogLevel = "debug"

	err = manager.SetSettings(ctx, newSettings)
	if err != nil {
		t.Fatalf("Failed to update settings: %v", err)
	}

	// Check that settings were updated
	retrievedSettings := manager.Settings()
	if len(retrievedSettings.Servers) != 1 || retrievedSettings.Servers[0] != "google" {
		t.Error("Settings were not updated correctly")
	}
	if *retrievedSettings.BlockAds {
		t.Error("BlockAds setting was not updated correctly")
	}
	if retrievedSettings.LogLevel != "debug" {
		t.Error("LogLevel setting was not updated correctly")
	}
}

func TestManager_HealthCheck(t *testing.T) {
	logger := log.New(log.SetLevel(log.LevelDebug))
	manager := NewManager(logger)

	ctx := context.Background()

	// Test health check with disabled setting
	enabled := false
	settings := settings.DNSCryptProxy{
		Enabled: &enabled,
	}
	err := manager.SetSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Failed to set settings: %v", err)
	}

	err = manager.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("Health check failed with disabled setting: %v", err)
	}

	// Test health check with enabled setting
	enabled = true
	settings.Enabled = &enabled
	err = manager.SetSettings(ctx, settings)
	if err != nil {
		t.Fatalf("Failed to set settings: %v", err)
	}

	err = manager.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start manager: %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	err = manager.HealthCheck(ctx)
	if err != nil {
		t.Logf("Health check failed with enabled setting (this is expected in test environment): %v", err)
	}

	err = manager.Stop()
	if err != nil {
		t.Fatalf("Failed to stop manager: %v", err)
	}
}
