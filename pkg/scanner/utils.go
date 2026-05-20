package scanner

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "github.com/H3llKa1ser/recon-storm/pkg/logger"
)

// readLines reads a file and returns non-empty trimmed lines
func readLines(path string) []string {
    f, err := os.Open(path)
    if err != nil {
        return nil
    }
    defer f.Close()
    var lines []string
    sc := bufio.NewScanner(f)
    sc.Buffer(make([]byte, 1024*1024), 1024*1024)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line != "" {
            lines = append(lines, line)
        }
    }
    return lines
}

// writeLines writes lines to a file
func writeLines(path string, lines []string) error {
    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()
    for _, l := range lines {
        fmt.Fprintln(f, l)
    }
    return nil
}

// fileExists checks if a file exists and is not empty
func fileExists(path string) bool {
    info, err := os.Stat(path)
    return err == nil && info.Size() > 0
}

// fileExistsAny returns true if file exists (even empty)
func fileExistsAny(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}

// toolExists checks if a tool binary is in PATH
func toolExists(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

// findHttpx locates the ProjectDiscovery httpx binary, resolving Python conflicts
func findHttpx(log *logger.Logger) (string, bool) {
    // Check common locations in priority order
    candidates := []string{}

    // Go bin paths
    home, _ := os.UserHomeDir()
    candidates = append(candidates,
        filepath.Join(home, "go", "bin", "httpx"),
        "/usr/local/bin/httpx",
    )

    // Then check PATH
    if path, err := exec.LookPath("httpx"); err == nil {
        candidates = append(candidates, path)
    }

    for _, path := range candidates {
        if _, err := os.Stat(path); err != nil {
            continue
        }
        // Verify it's the PD version
        cmd := exec.Command(path, "-version")
        out, err := cmd.CombinedOutput()
        if err == nil {
            lower := strings.ToLower(string(out))
            if strings.Contains(lower, "projectdiscovery") || strings.Contains(lower, "current version") {
                log.Debug("  Using httpx at: %s", path)
                return path, true
            }
        }
    }

    log.Warn("  ProjectDiscovery httpx not found")
    return "", false
}

// resolveInputFile finds the best available input file from a priority list
func resolveInputFile(paths ...string) string {
    for _, p := range paths {
        if fileExists(p) {
            return p
        }
    }
    return ""
}

// countFileLines counts lines in a file
func countFileLines(path string) int {
    return len(readLines(path))
}
