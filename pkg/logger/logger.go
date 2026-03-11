package logger

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "sync"
    "time"
)

type Logger struct {
    mu      sync.Mutex
    verbose bool
    logFile *os.File
    stdLog  *log.Logger
    fileLog *log.Logger
}

func New(outputDir string, verbose bool) *Logger {
    logDir := filepath.Join(outputDir, "logs")
    os.MkdirAll(logDir, 0755)

    logPath := filepath.Join(logDir, fmt.Sprintf("reconstorm-%s.log", time.Now().Format("20060102-150405")))
    logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        fmt.Printf("[!] Warning: cannot create log file: %v\n", err)
        logFile = nil
    }

    l := &Logger{
        verbose: verbose,
    }

    l.stdLog = log.New(os.Stdout, "", 0)
    if logFile != nil {
        l.logFile = logFile
        l.fileLog = log.New(logFile, "", log.Ldate|log.Ltime)
    }

    return l
}

func (l *Logger) Close() {
    if l.logFile != nil {
        l.logFile.Close()
    }
}

func (l *Logger) write(level, color, format string, args ...interface{}) {
    l.mu.Lock()
    defer l.mu.Unlock()

    msg := fmt.Sprintf(format, args...)
    timestamp := time.Now().Format("15:04:05")

    // Console output (colored)
    l.stdLog.Printf("%s[%s][%s]\033[0m %s", color, timestamp, level, msg)

    // File output (plain)
    if l.fileLog != nil {
        l.fileLog.Printf("[%s] %s", level, msg)
    }
}

func (l *Logger) Info(format string, args ...interface{}) {
    l.write("INF", "\033[34m", format, args...)
}

func (l *Logger) Success(format string, args ...interface{}) {
    l.write("OK ", "\033[32m", format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
    l.write("WRN", "\033[33m", format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
    l.write("ERR", "\033[31m", format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
    if l.verbose {
        l.write("DBG", "\033[90m", format, args...)
    }
}

func (l *Logger) Section(title string) {
    l.mu.Lock()
    defer l.mu.Unlock()

    border := "════════════════════════════════════════════════════════"
    l.stdLog.Printf("\n\033[36m%s\n  %s\n%s\033[0m\n", border, title, border)

    if l.fileLog != nil {
        l.fileLog.Printf("=== %s ===", title)
    }
}

func (l *Logger) Progress(module string, current, total int) {
    l.mu.Lock()
    defer l.mu.Unlock()

    pct := float64(current) / float64(total) * 100
    bar := ""
    filled := int(pct / 5)
    for i := 0; i < 20; i++ {
        if i < filled {
            bar += "█"
        } else {
            bar += "░"
        }
    }
    fmt.Printf("\r\033[35m[%s]\033[0m %s %3.0f%% (%d/%d)", module, bar, pct, current, total)
    if current == total {
        fmt.Println()
    }
}
