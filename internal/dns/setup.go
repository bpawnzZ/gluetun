package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/qdm12/dns/v2/pkg/check"
	"github.com/qdm12/dns/v2/pkg/nameserver"
	"github.com/qdm12/dns/v2/pkg/server"
)

var errUpdateBlockLists = errors.New("cannot update filter block lists")

func (l *Loop) setupServer(ctx context.Context) (runError <-chan error, err error) {
	err = l.updateFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUpdateBlockLists, err)
	}

	settings := l.GetSettings()

	dotSettings, err := buildDoTSettings(settings, l.filter, l.logger)
	if err != nil {
		return nil, fmt.Errorf("building DoT settings: %w", err)
	}

	server, err := server.New(dotSettings)
	if err != nil {
		return nil, fmt.Errorf("creating DoT server: %w", err)
	}

	runError, err = server.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting server: %w", err)
	}
	l.server = server

	// use internal DNS server
	nameserver.UseDNSInternally(nameserver.SettingsInternalDNS{
		IP: settings.ServerAddress,
	})

	// Check if DNSCrypt-Proxy is enabled and use it as the system DNS
	if *settings.DNSCryptProxy.Enabled {
		// For now, use 127.0.0.1 as DNSCrypt-Proxy listens on localhost
		err = nameserver.UseDNSSystemWide(nameserver.SettingsSystemDNS{
			IP:         netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			ResolvPath: l.resolvConf,
		})
		if err != nil {
			l.logger.Error(err.Error())
		}
		l.logger.Info("Using DNSCrypt-Proxy as system DNS server")
	} else {
		err = nameserver.UseDNSSystemWide(nameserver.SettingsSystemDNS{
			IP:         settings.ServerAddress,
			ResolvPath: l.resolvConf,
		})
		if err != nil {
			l.logger.Error(err.Error())
		}
	}

	err = check.WaitForDNS(ctx, check.Settings{})
	if err != nil {
		l.stopServer()
		return nil, err
	}

	return runError, nil
}
