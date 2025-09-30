# NameAlive - Network Host Discovery Tool

A utility for discovering active hosts in the network and retrieving their hostnames.

## Features

- 🔍 Fast IP range scanning
- 🚀 Parallel host connections for improved performance
- 🔑 SSH key and password authentication support
- 📊 Multiple output formats (table, JSON, CSV)
- 📝 Extended host information (OS, uptime, MAC address)
- ⚙️ Flexible CLI configuration

## Installation

### From Source

```bash
git clone https://github.com/yourusername/namealive.git
cd namealive
go mod download
go build -o namealive
sudo cp namealive /usr/local/bin/  # Optional for global installation
```

### Requirements

- Go 1.21 or higher
- Root privileges or CAP_NET_RAW capability for ICMP ping

## Usage

### Basic Usage

```bash
# Scan default range (192.168.1.1-192.168.1.250)
sudo namealive

# With specific user
sudo namealive -u admin

# Custom range
sudo namealive -r 10.0.0.1-10.0.0.100

# CIDR notation
sudo namealive -r 192.168.0.0/24
```

### Command Line Options

```
Flags:
  -r, --range string       IP range to scan (default "192.168.1.1-192.168.1.250")
  -u, --user string        SSH username (default: current user)
      --port int           SSH port (default 22)
  -p, --parallel int       Number of parallel connections (default 20)
      --timeout duration   Connection timeout (default 20s)
      --format string      Output format: table|json|csv (default "table")
  -o, --output string      Output file
  -v, --verbose            Verbose mode with detailed logging
      --extended           Show extended host information
      --exclude strings    Exclude IP ranges (can specify multiple)
      --include-offline    Include offline hosts
      --no-password        Skip password prompt (use SSH keys only)
  -h, --help              Display help
```

### Examples

#### Extended Information in JSON Format

```bash
sudo namealive --extended --format json -o network_scan.json
```

#### Scanning Large Networks with Increased Parallelism

```bash
sudo namealive -r 10.0.0.0/16 -p 50 --verbose
```

#### Excluding Specific Addresses

```bash
sudo namealive -r 192.168.1.0/24 --exclude 192.168.1.1 --exclude 192.168.1.254
```

#### CSV Output to File

```bash
sudo namealive --format csv -o hosts.csv --extended
```

## Output Formats

### Table (default)

```
+---------------+-------------+--------+
|      IP       |  HOSTNAME   | STATUS |
+---------------+-------------+--------+
| 192.168.1.1   | router      | online |
| 192.168.1.10  | workstation | online |
| 192.168.1.20  | nas-server  | online |
+---------------+-------------+--------+
```

### JSON

```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router",
    "status": "online",
    "response_time": "15ms",
    "timestamp": "2024-01-20T10:30:00Z"
  }
]
```

### CSV

```csv
IP,Hostname,Status,Response Time
192.168.1.1,router,online,15ms
192.168.1.10,workstation,online,23ms
```

## Extended Mode (--extended)

When using the `--extended` flag, the utility collects additional information:

- **OS**: Operating system information (uname -a)
- **Uptime**: System uptime
- **Domain**: Domain name (if configured)
- **MAC Address**: Network interface MAC address (from local ARP cache)

## Authentication

The utility supports multiple authentication methods in the following priority:

1. **SSH Keys**: Automatically checks standard paths:
   - `~/.ssh/id_rsa`
   - `~/.ssh/id_ed25519`
   - `~/.ssh/id_ecdsa`

2. **Password**: Prompted once at startup and used for all hosts

3. **Keyboard Interactive**: Support for systems with additional authentication

## Performance

- Default: 20 parallel connections
- Can be increased to 50-100 for large networks using the `-p` flag
- Each connection has a 20-second timeout (configurable via `--timeout`)

## Troubleshooting

### Permission Denied for ICMP Ping

The utility requires permissions to send ICMP packets. Solutions:

1. Run with sudo:
   ```bash
   sudo namealive
   ```

2. Add CAP_NET_RAW capability:
   ```bash
   sudo setcap cap_net_raw+ep ./namealive
   ```

### SSH Connection Issues

- Ensure SSH service is running on target hosts
- Verify username is correct
- Check that keys or password are valid
- Use a different port via `--port` if needed

### Slow Scanning

- Increase parallel connections: `-p 50`
- Reduce timeout for unreachable hosts: `--timeout 5s`
- Use a narrower IP range

## Security

- Passwords are entered in hidden mode and not stored
- SSH connections use standard security mechanisms
- SSH keys are recommended over passwords
- Host key verification is disabled for first connections (InsecureIgnoreHostKey)

## License

MIT
