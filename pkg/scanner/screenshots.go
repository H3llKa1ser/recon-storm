package scanner

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"

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

    // gowitness v3 rewrote the CLI: the old `gowitness file -f … -P …` became
    // `gowitness scan file -f … --screenshot-path …`. Detect the major version
    // so a v3 install (what `go install …@latest` now pulls) doesn't silently
    // capture nothing.
    major := gowitnessMajor(ctx)
    m.log.Info("  Running gowitness (detected v%d) on %d URLs...", major, urlCount)

    var cmd *exec.Cmd
    if major >= 3 {
        cmd = exec.CommandContext(ctx, "gowitness",
            "scan", "file",
            "-f", liveURLsFile,
            "--screenshot-path", outDir,
            "--threads", fmt.Sprintf("%d", m.cfg.Threads),
            "--timeout", "15",
            "--write-db=false",
        )
    } else {
        cmd = exec.CommandContext(ctx, "gowitness",
            "file",
            "-f", liveURLsFile,
            "-P", outDir,
            "--threads", fmt.Sprintf("%d", m.cfg.Threads),
            "--timeout", "15",
        )
    }

    out, err := cmd.CombinedOutput()
    if err != nil {
        m.log.Warn("  gowitness error: %v — %s", err, string(out))
        // If v3 rejected our flags (or vice-versa), retry with the other form
        // before giving up, so a wrong version guess still produces output.
        if alt := m.altCommand(ctx, major, liveURLsFile, outDir); alt != nil {
            m.log.Info("  Retrying with alternate gowitness CLI form...")
            if out2, err2 := alt.CombinedOutput(); err2 != nil {
                m.log.Warn("  gowitness retry error: %v — %s", err2, string(out2))
            }
        }
    }

    count := countImages(outDir)
    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalScreenshots += count
    })

    m.log.Success("  Captured %d screenshots", count)
    return nil
}

// altCommand returns the opposite-version invocation for a best-effort retry.
func (m *ScreenshotsModule) altCommand(ctx context.Context, triedMajor int, list, outDir string) *exec.Cmd {
    if triedMajor >= 3 {
        return exec.CommandContext(ctx, "gowitness",
            "file", "-f", list, "-P", outDir,
            "--threads", fmt.Sprintf("%d", m.cfg.Threads), "--timeout", "15")
    }
    return exec.CommandContext(ctx, "gowitness",
        "scan", "file", "-f", list, "--screenshot-path", outDir,
        "--threads", fmt.Sprintf("%d", m.cfg.Threads), "--timeout", "15", "--write-db=false")
}

var gowitnessVerRe = regexp.MustCompile(`v?(\d+)\.\d+`)

// gowitnessMajor best-effort parses the installed gowitness major version.
// Defaults to 3 (current latest) when detection fails.
func gowitnessMajor(ctx context.Context) int {
    out, err := exec.CommandContext(ctx, "gowitness", "version").CombinedOutput()
    if err != nil {
        if out2, err2 := exec.CommandContext(ctx, "gowitness", "--version").CombinedOutput(); err2 == nil {
            out = out2
        }
    }
    if mm := gowitnessVerRe.FindStringSubmatch(string(out)); len(mm) == 2 {
        switch mm[1] {
        case "1":
            return 1
        case "2":
            return 2
        case "3":
            return 3
        case "4":
            return 4
        }
    }
    return 3 // assume modern CLI
}

func countImages(dir string) int {
    count := 0
    filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
        if err != nil || info == nil || info.IsDir() {
            return nil
        }
        switch filepath.Ext(info.Name()) {
        case ".png", ".jpg", ".jpeg":
            count++
        }
        return nil
    })
    return count
}
