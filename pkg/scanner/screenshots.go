package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/H3llKa1ser/recon-storm/pkg/config"
	"github.com/H3llKa1ser/recon-storm/pkg/logger"
	"github.com/H3llKa1ser/recon-storm/pkg/state"
)

type ScreenshotsModule struct {
	cfg   *config.Config
	state *state.Manager
	log   *logger.Logger
}

func NewScreenshotsModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *ScreenshotsModule {
	return &ScreenshotsModule{cfg: cfg, state: sm, log: log}
}

func (m *ScreenshotsModule) Name() string { return "screenshots" }

func (m *ScreenshotsModule) Run(ctx context.Context, domain string) error {
	outDir := filepath.Join(m.cfg.OutputDir, domain, "screenshots")
	os.MkdirAll(outDir, 0755)

	liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
	if _, err := os.Stat(liveURLsFile); os.IsNotExist(err) {
		return fmt.Errorf("no live URLs found — run web module first")
	}

	// Empty-input guard
	if _, ok := readLinesOrWarn(liveURLsFile, m.log, "screenshots"); !ok {
		return nil
	}

	// ── gowitness ──
	if _, err := exec.LookPath("gowitness"); err == nil {
		m.log.Info("  Running gowitness screenshots...")

		cmd := exec.CommandContext(ctx, "gowitness",
			"file",
			"-f", liveURLsFile,
			"-P", outDir,
			"--threads", fmt.Sprintf("%d", m.cfg.Threads),
			"--timeout", "15",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			m.log.Warn("  gowitness error: %v — %s", err, string(output))
		}

		entries, _ := os.ReadDir(outDir)
		count := 0
		for _, e := range entries {
			if !e.IsDir() {
				count++
			}
		}

		m.state.UpdateStats(func(s *state.ScanStats) {
			s.TotalScreenshots += count
		})

		m.log.Success("  Captured %d screenshots", count)
	} else {
		m.log.Warn("  gowitness not found — install: go install github.com/sensepost/gowitness@latest")
	}

	return nil
}
