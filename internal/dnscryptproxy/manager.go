package dnscryptproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/log"
)

type Manager struct {
	settings         settings.DNSCryptProxy
	logger           log.LoggerInterface
	configPath       string
	pidPath          string
	cmd              *exec.Cmd
	cmdMutex         sync.Mutex
	running          bool
	runningMutex     sync.Mutex
	restartRequested bool
	restartMutex     sync.Mutex
}

func NewManager(logger log.LoggerInterface) *Manager {
	return &Manager{
		logger:     logger,
		configPath: "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
		pidPath:    "/var/run/dnscrypt-proxy.pid",
	}
}

func (m *Manager) Settings() settings.DNSCryptProxy {
	m.runningMutex.Lock()
	defer m.runningMutex.Unlock()
	return m.settings
}

func (m *Manager) SetSettings(ctx context.Context, settings settings.DNSCryptProxy) error {
	m.runningMutex.Lock()
	defer m.runningMutex.Unlock()

	settingsUnchanged := reflect.DeepEqual(m.settings, settings)
	if settingsUnchanged {
		return nil
	}

	m.settings = settings

	if m.running {
		m.restartMutex.Lock()
		m.restartRequested = true
		m.restartMutex.Unlock()
		m.logger.Info("dnscrypt-proxy settings changed, restart scheduled")
	}

	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	m.runningMutex.Lock()
	defer m.runningMutex.Unlock()

	if m.running {
		return nil
	}

	if !*m.settings.Enabled {
		m.logger.Info("dnscrypt-proxy is disabled, not starting")
		return nil
	}

	m.logger.Info("starting dnscrypt-proxy")

	// Generate configuration file
	configContent, err := GenerateConfig(m.settings)
	if err != nil {
		return fmt.Errorf("failed to generate dnscrypt-proxy configuration: %w", err)
	}

	err = os.WriteFile(m.configPath, []byte(configContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write dnscrypt-proxy configuration: %w", err)
	}

	// Start dnscrypt-proxy
	m.cmdMutex.Lock()
	m.cmd = exec.CommandContext(ctx, "dnscrypt-proxy", "-config", m.configPath, "-pidfile", m.pidPath)

	// Create a writer that logs each line
	stdoutWriter := &logWriter{
		logger: m.logger,
		prefix: "dnscrypt-proxy stdout: ",
	}
	stderrWriter := &logWriter{
		logger: m.logger,
		prefix: "dnscrypt-proxy stderr: ",
	}

	m.cmd.Stdout = stdoutWriter
	m.cmd.Stderr = stderrWriter
	m.cmdMutex.Unlock()

	err = m.cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start dnscrypt-proxy: %w", err)
	}

	m.running = true
	m.logger.Info("dnscrypt-proxy started successfully")

	// Start restart monitor
	go m.restartMonitor(ctx)

	return nil
}

func (m *Manager) Stop() error {
	m.runningMutex.Lock()
	defer m.runningMutex.Unlock()

	if !m.running {
		return nil
	}

	m.logger.Info("stopping dnscrypt-proxy")

	m.cmdMutex.Lock()
	if m.cmd != nil && m.cmd.Process != nil {
		err := m.cmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			m.logger.Warn("failed to send SIGTERM to dnscrypt-proxy: " + err.Error())
		}

		// Wait for graceful shutdown
		done := make(chan error, 1)
		go func() {
			done <- m.cmd.Wait()
		}()

		select {
		case err := <-done:
			if err != nil {
				m.logger.Warn("dnscrypt-proxy shutdown error: " + err.Error())
			}
		case <-time.After(10 * time.Second):
			m.logger.Warn("dnscrypt-proxy did not shut down gracefully, killing")
			_ = m.cmd.Process.Kill()
		}
	}
	m.cmd = nil
	m.cmdMutex.Unlock()

	m.running = false
	m.logger.Info("dnscrypt-proxy stopped")

	return nil
}

// logWriter is an io.Writer that logs each line with the given logger
type logWriter struct {
	logger log.LoggerInterface
	prefix string
	buffer strings.Builder
}

func (lw *logWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	if n == 0 {
		return 0, nil
	}

	lw.buffer.Write(p)

	// Process complete lines
	str := lw.buffer.String()
	lines := strings.Split(str, "\n")

	// Keep the last incomplete line in the buffer
	if len(lines) > 0 {
		lw.buffer.Reset()
		if lines[len(lines)-1] != "" {
			lw.buffer.WriteString(lines[len(lines)-1])
		}

		// Log all complete lines
		for i := 0; i < len(lines)-1; i++ {
			line := strings.TrimSpace(lines[i])
			if line != "" {
				lw.logger.Info(line)
			}
		}
	}

	return n, nil
}

func (m *Manager) IsRunning() bool {
	m.runningMutex.Lock()
	defer m.runningMutex.Unlock()
	return m.running
}

func (m *Manager) restartMonitor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			m.restartMutex.Lock()
			restart := m.restartRequested
			m.restartRequested = false
			m.restartMutex.Unlock()

			if restart {
				m.logger.Info("restarting dnscrypt-proxy due to settings change")
				err := m.Stop()
				if err != nil {
					m.logger.Error("failed to stop dnscrypt-proxy for restart: " + err.Error())
					continue
				}

				err = m.Start(ctx)
				if err != nil {
					m.logger.Error("failed to restart dnscrypt-proxy: " + err.Error())
				}
			}
		}
	}
}

func (m *Manager) HealthCheck(ctx context.Context) error {
	m.runningMutex.Lock()
	running := m.running
	settings := m.settings
	m.runningMutex.Unlock()

	if !*settings.Enabled {
		return nil
	}

	if !running {
		return fmt.Errorf("dnscrypt-proxy is not running")
	}

	// Check if dnscrypt-proxy is responding to DNS queries
	// This is a simple check - in a real implementation, you might want to
	// perform an actual DNS query
	m.cmdMutex.Lock()
	if m.cmd == nil || m.cmd.Process == nil {
		m.cmdMutex.Unlock()
		return fmt.Errorf("dnscrypt-proxy process is not running")
	}

	// Check if process is still alive
	err := m.cmd.Process.Signal(syscall.Signal(0))
	m.cmdMutex.Unlock()

	if err != nil {
		return fmt.Errorf("dnscrypt-proxy process is not alive: %w", err)
	}

	return nil
}
