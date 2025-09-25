package dnscryptproxy

import (
	"fmt"
	"strings"
	"text/template"

	"github.com/qdm12/gluetun/internal/configuration/settings"
)

const configTemplate = `# dnscrypt-proxy configuration

{{ if .Enabled }}
server_names = [{{ range $i, $server := .Servers }}{{ if $i }}, {{ end }}"{{ $server }}"{{ end }}]

listen_addresses = ['{{ .ListenAddress }}']

require_dnssec = true
require_nolog = true
require_nofilter = false

{{ if .BlockAds }}block_ads = true{{ else }}block_ads = false{{ end }}
{{ if .BlockMalicious }}block_malicious = true{{ else }}block_malicious = false{{ end }}
{{ if .BlockSurveillance }}block_surveillance = true{{ else }}block_surveillance = false{{ end }}
{{ if .BlockPhishing }}block_phishing = true{{ else }}block_phishing = false{{ end }}

{{ if .Cache }}cache = true{{ else }}cache = false{{ end }}
{{ if .Cache }}cache_size = {{ .CacheSize }}{{ end }}

log_level = '{{ .LogLevel }}'

[source]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', 'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/dnscrypt-resolvers.txt']
  cache_file = '/etc/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQBpg6G8M5aPqHWXwlaNJPd26EHyVpTnh9ZC0gg2d1aI9dNAiN/8sJ'

{{ if .RequireDoH }}require_doh = true{{ else }}require_doh = false{{ end }}

timeout = {{ .Timeout }} # in milliseconds
keepalive = {{ .KeepAlive }} # in seconds
{{ end }}
`

// ConfigData contains the data needed to generate the dnscrypt-proxy configuration
type ConfigData struct {
	Enabled           bool
	Servers           []string
	ListenAddress     string
	BlockAds          bool
	BlockMalicious    bool
	BlockSurveillance bool
	BlockPhishing     bool
	LogLevel          string
	Cache             bool
	CacheSize         uint
	RequireDoH        bool
	Timeout           uint
	KeepAlive         uint
}

// GenerateConfig generates the dnscrypt-proxy configuration from the given settings
func GenerateConfig(settings settings.DNSCryptProxy) (string, error) {
	data := ConfigData{
		Enabled:           *settings.Enabled,
		Servers:           settings.Servers,
		ListenAddress:     settings.ListenAddress,
		BlockAds:          *settings.BlockAds,
		BlockMalicious:    *settings.BlockMalicious,
		BlockSurveillance: *settings.BlockSurveillance,
		BlockPhishing:     *settings.BlockPhishing,
		LogLevel:          settings.LogLevel,
		Cache:             *settings.Cache,
		CacheSize:         *settings.CacheSize,
		RequireDoH:        *settings.RequireDoH,
		Timeout:           *settings.Timeout,
		KeepAlive:         *settings.KeepAlive,
	}

	tmpl, err := template.New("dnscrypt-proxy").Parse(configTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var builder strings.Builder
	err = tmpl.Execute(&builder, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return builder.String(), nil
}
