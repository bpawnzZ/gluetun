package settings

import (
	"fmt"
	"net/netip"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// DNSCryptProxy contains settings to configure the dnscrypt-proxy service.
type DNSCryptProxy struct {
	// Enabled is true if the dnscrypt-proxy service should be running
	// and used. It defaults to false, and cannot be nil in the internal state.
	Enabled *bool
	// Servers is a list of DNSCrypt proxy server names to use.
	// It defaults to ['cloudflare', 'quad9', 'google'].
	Servers []string
	// ListenAddress is the address where dnscrypt-proxy will listen for DNS queries.
	// It defaults to '127.0.0.1:53'.
	ListenAddress string
	// BlockAds is true if ads should be blocked.
	// It defaults to true.
	BlockAds *bool
	// BlockMalicious is true if malicious domains should be blocked.
	// It defaults to true.
	BlockMalicious *bool
	// BlockSurveillance is true if surveillance domains should be blocked.
	// It defaults to false.
	BlockSurveillance *bool
	// BlockPhishing is true if phishing domains should be blocked.
	// It defaults to true.
	BlockPhishing *bool
	// LogLevel is the logging level for dnscrypt-proxy.
	// It defaults to 'info'.
	LogLevel string
	// Cache is true if DNS caching should be enabled.
	// It defaults to true.
	Cache *bool
	// CacheSize is the size of the DNS cache in entries.
	// It defaults to 512.
	CacheSize *uint
	// RequireDoH is true if only DoH servers should be used.
	// It defaults to false.
	RequireDoH *bool
	// Timeout is the query timeout in milliseconds.
	// It defaults to 5000.
	Timeout *uint
	// KeepAlive is the keep-alive duration in seconds.
	// It defaults to 30.
	KeepAlive *uint
}

func (d *DNSCryptProxy) validate() (err error) {
	// Validate listen address
	_, err = netip.ParseAddrPort(d.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[d.LogLevel] {
		return fmt.Errorf("invalid log level: %s", d.LogLevel)
	}

	// Validate timeout
	if *d.Timeout < 100 || *d.Timeout > 30000 {
		return fmt.Errorf("timeout must be between 100 and 30000 milliseconds")
	}

	// Validate keep alive
	if *d.KeepAlive < 1 || *d.KeepAlive > 300 {
		return fmt.Errorf("keep alive must be between 1 and 300 seconds")
	}

	// Validate cache size
	if *d.CacheSize < 0 || *d.CacheSize > 10000 {
		return fmt.Errorf("cache size must be between 0 and 10000")
	}

	return nil
}

func (d *DNSCryptProxy) copy() (copied DNSCryptProxy) {
	return DNSCryptProxy{
		Enabled:           gosettings.CopyPointer(d.Enabled),
		Servers:           gosettings.CopySlice(d.Servers),
		ListenAddress:     d.ListenAddress,
		BlockAds:          gosettings.CopyPointer(d.BlockAds),
		BlockMalicious:    gosettings.CopyPointer(d.BlockMalicious),
		BlockSurveillance: gosettings.CopyPointer(d.BlockSurveillance),
		BlockPhishing:     gosettings.CopyPointer(d.BlockPhishing),
		LogLevel:          d.LogLevel,
		Cache:             gosettings.CopyPointer(d.Cache),
		CacheSize:         gosettings.CopyPointer(d.CacheSize),
		RequireDoH:        gosettings.CopyPointer(d.RequireDoH),
		Timeout:           gosettings.CopyPointer(d.Timeout),
		KeepAlive:         gosettings.CopyPointer(d.KeepAlive),
	}
}

func (d *DNSCryptProxy) overrideWith(other DNSCryptProxy) {
	d.Enabled = gosettings.OverrideWithPointer(d.Enabled, other.Enabled)
	d.Servers = gosettings.OverrideWithSlice(d.Servers, other.Servers)
	d.ListenAddress = gosettings.OverrideWithComparable(d.ListenAddress, other.ListenAddress)
	d.BlockAds = gosettings.OverrideWithPointer(d.BlockAds, other.BlockAds)
	d.BlockMalicious = gosettings.OverrideWithPointer(d.BlockMalicious, other.BlockMalicious)
	d.BlockSurveillance = gosettings.OverrideWithPointer(d.BlockSurveillance, other.BlockSurveillance)
	d.BlockPhishing = gosettings.OverrideWithPointer(d.BlockPhishing, other.BlockPhishing)
	d.LogLevel = gosettings.OverrideWithComparable(d.LogLevel, other.LogLevel)
	d.Cache = gosettings.OverrideWithPointer(d.Cache, other.Cache)
	d.CacheSize = gosettings.OverrideWithPointer(d.CacheSize, other.CacheSize)
	d.RequireDoH = gosettings.OverrideWithPointer(d.RequireDoH, other.RequireDoH)
	d.Timeout = gosettings.OverrideWithPointer(d.Timeout, other.Timeout)
	d.KeepAlive = gosettings.OverrideWithPointer(d.KeepAlive, other.KeepAlive)
}

func (d *DNSCryptProxy) setDefaults() {
	d.Enabled = gosettings.DefaultPointer(d.Enabled, false)
	d.Servers = gosettings.DefaultSlice(d.Servers, []string{"cloudflare", "quad9", "google"})
	d.ListenAddress = gosettings.DefaultComparable(d.ListenAddress, "127.0.0.1:53")
	d.BlockAds = gosettings.DefaultPointer(d.BlockAds, true)
	d.BlockMalicious = gosettings.DefaultPointer(d.BlockMalicious, true)
	d.BlockSurveillance = gosettings.DefaultPointer(d.BlockSurveillance, false)
	d.BlockPhishing = gosettings.DefaultPointer(d.BlockPhishing, true)
	d.LogLevel = gosettings.DefaultComparable(d.LogLevel, "info")
	d.Cache = gosettings.DefaultPointer(d.Cache, true)
	d.CacheSize = gosettings.DefaultPointer(d.CacheSize, 512)
	d.RequireDoH = gosettings.DefaultPointer(d.RequireDoH, false)
	d.Timeout = gosettings.DefaultPointer(d.Timeout, 5000)
	d.KeepAlive = gosettings.DefaultPointer(d.KeepAlive, 30)
}

func (d DNSCryptProxy) String() string {
	return d.toLinesNode().String()
}

func (d DNSCryptProxy) toLinesNode() (node *gotree.Node) {
	node = gotree.New("DNSCrypt proxy settings:")

	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(d.Enabled))
	if !*d.Enabled {
		return node
	}

	node.Appendf("Listen address: %s", d.ListenAddress)

	serversNode := node.Append("Servers:")
	for _, server := range d.Servers {
		serversNode.Append(server)
	}

	node.Appendf("Block ads: %s", gosettings.BoolToYesNo(d.BlockAds))
	node.Appendf("Block malicious: %s", gosettings.BoolToYesNo(d.BlockMalicious))
	node.Appendf("Block surveillance: %s", gosettings.BoolToYesNo(d.BlockSurveillance))
	node.Appendf("Block phishing: %s", gosettings.BoolToYesNo(d.BlockPhishing))
	node.Appendf("Log level: %s", d.LogLevel)
	node.Appendf("Cache: %s", gosettings.BoolToYesNo(d.Cache))
	node.Appendf("Cache size: %d", *d.CacheSize)
	node.Appendf("Require DoH: %s", gosettings.BoolToYesNo(d.RequireDoH))
	node.Appendf("Timeout: %dms", *d.Timeout)
	node.Appendf("Keep alive: %ds", *d.KeepAlive)

	return node
}

func (d *DNSCryptProxy) read(r *reader.Reader) (err error) {
	d.Enabled, err = r.BoolPtr("DNSCRYPT_PROXY_ENABLED")
	if err != nil {
		return err
	}

	d.Servers = r.CSV("DNSCRYPT_PROXY_SERVERS")

	d.ListenAddress = r.String("DNSCRYPT_PROXY_LISTEN_ADDRESS")

	d.BlockAds, err = r.BoolPtr("DNSCRYPT_PROXY_BLOCK_ADS")
	if err != nil {
		return err
	}

	d.BlockMalicious, err = r.BoolPtr("DNSCRYPT_PROXY_BLOCK_MALICIOUS")
	if err != nil {
		return err
	}

	d.BlockSurveillance, err = r.BoolPtr("DNSCRYPT_PROXY_BLOCK_SURVEILLANCE")
	if err != nil {
		return err
	}

	d.BlockPhishing, err = r.BoolPtr("DNSCRYPT_PROXY_BLOCK_PHISHING")
	if err != nil {
		return err
	}

	d.LogLevel = r.String("DNSCRYPT_PROXY_LOG_LEVEL")

	d.Cache, err = r.BoolPtr("DNSCRYPT_PROXY_CACHE")
	if err != nil {
		return err
	}

	d.CacheSize, err = r.UintPtr("DNSCRYPT_PROXY_CACHE_SIZE")
	if err != nil {
		return err
	}

	d.RequireDoH, err = r.BoolPtr("DNSCRYPT_PROXY_REQUIRE_DOH")
	if err != nil {
		return err
	}

	d.Timeout, err = r.UintPtr("DNSCRYPT_PROXY_TIMEOUT")
	if err != nil {
		return err
	}

	d.KeepAlive, err = r.UintPtr("DNSCRYPT_PROXY_KEEP_ALIVE")
	if err != nil {
		return err
	}

	return nil
}
