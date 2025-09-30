# NameAlive - Network Host Discovery Tool

[![Go Reference](https://pkg.go.dev/badge/github.com/dmikushin/namealive.svg)](https://pkg.go.dev/github.com/dmikushin/namealive)
[![Go Report Card](https://goreportcard.com/badge/github.com/dmikushin/namealive)](https://goreportcard.com/report/github.com/dmikushin/namealive)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

High-performance network host discovery and identification tool using mDNS, NetBIOS, and SSH.

## ✨ Features

- 🚀 **Fast discovery** via mDNS (Linux/Mac) and NetBIOS (Windows)
- 🔍 **Smart fallback** to SSH when needed
- 🔑 **Flexible authentication** - SSH keys and passwords
- 📊 **Multiple output formats** - table, JSON, CSV
- 🎯 **Parallel scanning** with configurable concurrency
- 📝 **Extended information** - OS, uptime, MAC address
- 🔧 **Zero dependencies** - single binary

## 📦 Installation

### Via go install (recommended)

```bash
go install github.com/dmikushin/namealive@latest
```

The binary will be installed to `$GOPATH/bin/namealive` or `~/go/bin/namealive`.

### From source

```bash
git clone https://github.com/dmikushin/namealive.git
cd namealive
make build
sudo make install  # Installs to /usr/local/bin
```

### Download pre-built binary

Download the latest release from [Releases](https://github.com/dmikushin/namealive/releases).

```bash
# Linux amd64
wget https://github.com/dmikushin/namealive/releases/latest/download/namealive_linux_amd64.tar.gz
tar xzf namealive_linux_amd64.tar.gz
sudo mv namealive /usr/local/bin/

# macOS
wget https://github.com/dmikushin/namealive/releases/latest/download/namealive_darwin_amd64.tar.gz
tar xzf namealive_darwin_amd64.tar.gz
sudo mv namealive /usr/local/bin/
```

## 📋 Requirements

- Go 1.21+ (for building from source)
- Root privileges or CAP_NET_RAW for ICMP ping
- Linux, macOS, or Windows

## 🚀 Quick Start

```bash
# Scan default range (192.168.1.1-192.168.1.250)
sudo namealive

# Scan specific range
sudo namealive -r 10.0.0.1-10.0.0.100

# CIDR notation
sudo namealive -r 192.168.0.0/24

# Without password prompt (SSH keys only)
namealive --no-password

# Export to JSON
namealive --format json -o network.json
```

## 🎯 How It Works

NameAlive uses a multi-protocol approach for maximum speed and compatibility:

1. **ICMP Ping** - Checks if host is alive
2. **mDNS Query** - Fast hostname resolution for Linux/macOS (Avahi/Bonjour)
3. **NetBIOS Query** - Windows hostname resolution
4. **SSH Fallback** - When fast methods fail

```
┌─────────┐     ┌──────┐     ┌─────────┐     ┌─────────┐     ┌─────┐
│ IP Scan │────▶│ Ping │────▶│  mDNS   │────▶│ NetBIOS │────▶│ SSH │
└─────────┘     └──────┘     │ (2 sec) │     │ (2 sec) │     │(opt)│
                   │         └─────────┘     └─────────┘     └─────┘
                   ▼
                [Skip if not alive]
```

## 📊 Command Line Options

```
Flags:
  -r, --range string       IP range to scan (default "192.168.1.1-192.168.1.250")
  -u, --user string        SSH username (default: current user)
      --port int           SSH port (default 22)
  -p, --parallel int       Number of parallel connections (default 20)
      --timeout duration   Connection timeout (default 20s)
      --format string      Output format: table|json|csv (default "table")
  -o, --output string      Output file
  -v, --verbose            Verbose mode
      --extended           Show extended information
      --exclude strings    Exclude IP ranges
      --include-offline    Include offline hosts
      --no-password        Skip password prompt (SSH keys only)
  -h, --help              Display help
```

## 📖 Examples

### Extended scan with all protocols

```bash
sudo namealive --extended --verbose
```

### Large network scan with high parallelism

```bash
sudo namealive -r 10.0.0.0/16 -p 50 --timeout 5s
```

### Export results to CSV

```bash
namealive --format csv -o hosts.csv --extended
```

### Exclude specific ranges

```bash
namealive -r 192.168.1.0/24 --exclude 192.168.1.1 --exclude 192.168.1.254
```

## 📤 Output Formats

### Table (default)

```
+--------------+----------+--------+--------+
|     IP       | HOSTNAME | STATUS | METHOD |
+--------------+----------+--------+--------+
| 192.168.1.5  | server01 | online | mDNS   |
| 192.168.1.10 | desktop  | online | NetBIOS|
| 192.168.1.15 | laptop   | online | SSH    |
+--------------+----------+--------+--------+
```

### JSON

```json
[
  {
    "ip": "192.168.1.5",
    "hostname": "server01",
    "status": "online",
    "method": "mDNS",
    "response_time": "2.1ms",
    "timestamp": "2024-01-20T10:30:00Z"
  }
]
```

## 🔧 Performance Tuning

- **Parallel connections**: Increase `-p` flag (default: 20, max recommended: 100)
- **Timeout**: Reduce `--timeout` for faster scans of responsive networks
- **Exclude ranges**: Use `--exclude` to skip known empty ranges

## 🛡️ Security

- Passwords are never stored or logged
- SSH connections use standard Go crypto/ssh library
- Host key verification disabled by default (for automation)
- Supports standard SSH key locations

## 📝 Building from Source

```bash
# Clone repository
git clone https://github.com/dmikushin/namealive.git
cd namealive

# Build
make build

# Run tests
make test

# Install system-wide
sudo make install

# Cross-compile for different platforms
make build-all
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

