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
    if !fileExists(liveURLsFile) {
        m.log.Warn("  No live URLs — skipping screenshots")
        return nil
    }

    urlCount := countFileLines(liveURLsFile)
    if urlCount == 0 {
        m.log.Warn("  Live URLs file is empty — skipping screenshots")
        return nil
    }

    if !toolExists("gowitness") {
        m.log.Warn("  gowitness not found — skipping screenshots")
        return nil
    }

    m.log.Info("  Running gowitness on %d URLs...", urlCount)

    cmd := exec.CommandContext(ctx, "gowitness",
        "file",
        "-f", liveURLsFile,
        "-P", outDir,
        "--threads", fmt.Sprintf("%d", m.cfg.Threads),
        "--timeout", "15",
    )

    out, err := cmd.CombinedOutput()
    if err != nil {
        m.log.Warn("  gowitness error: %v — %s", err, string(out))
    }

    // Count screenshots
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
    return nil
}
