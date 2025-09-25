package dnscryptproxy

import (
	"context"

	"github.com/qdm12/gluetun/internal/configuration/settings"
)

// Interface defines the interface for DNSCryptProxy operations
type Interface interface {
	Settings() settings.DNSCryptProxy
	SetSettings(ctx context.Context, settings settings.DNSCryptProxy) error
	Start(ctx context.Context) error
	Stop() error
	IsRunning() bool
	HealthCheck(ctx context.Context) error
}
