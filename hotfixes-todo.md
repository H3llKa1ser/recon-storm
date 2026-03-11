| #  | Suggestion                                                                                                         | Priority       |
|----|--------------------------------------------------------------------------------------------------------------------|----------------|
| 1  | Add `findHttpx()` binary resolver to distinguish Python vs Go httpx                                               | Critical       |
| 2  | Installer should log failure reasons at `Warn` level, not just `Debug`                                            | High           |
| 3  | Port module: if Naabu missing, run `nmap` with top-1000 on subdomains directly                                     | High           |
| 4  | DNS module: log when dnsx is skipped, don't silently skip                                                          | High           |
| 5  | Zone transfer: validate AXFR response actually contains records beyond SOA                                        | Medium         |
| 6  | Gate zone transfers behind `!cfg.PassiveOnly` check                                                                | Medium         |
| 7  | Installer: prepend `sudo` for apt commands, add `apt-get update` first                                             | Medium         |
| 8  | crt.sh: use `encoding/json` proper parsing instead of string splitting                                             | Medium         |
| 9  | All modules: log "skipped — tool not found" instead of silent no-op                                                | Medium         |
| 10 | Add input validation: if a module's input file is empty (0 lines), log and skip                                    | Low            |
| 11 | ffuf: log how many target URLs it's fuzzing and results per target                                                 | Low            |
| 12 | Add a `--dry-run` flag that shows what would run without executing                                                 | Nice-to-have   |
| 13 | Add Shodan/Censys/VirusTotal passive subdomain sources using the API key flags                                     | Nice-to-have   |
| 14 | Add a CORS misconfiguration check module                                                                           | Nice-to-have   |
| 15 | Add header security analysis (missing HSTS, CSP, X-Frame-Options, etc.)                                            | Nice-to-have   |
