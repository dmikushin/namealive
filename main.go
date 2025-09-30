package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/hashicorp/mdns"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/term"
)

type Config struct {
	IPRange       string
	User          string
	Password      string
	Port          int
	Parallel      int
	Timeout       time.Duration
	Format        string
	OutputFile    string
	Verbose       bool
	Extended      bool
	ExcludeRanges []string
	IncludeOffline bool
	NoPassword    bool
}

type Host struct {
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Status       string    `json:"status"`
	Method       string    `json:"method,omitempty"`
	Error        string    `json:"error,omitempty"`
	OS           string    `json:"os,omitempty"`
	Uptime       string    `json:"uptime,omitempty"`
	Domain       string    `json:"domain,omitempty"`
	MACAddress   string    `json:"mac_address,omitempty"`
	ResponseTime string    `json:"response_time,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

var (
	config Config
	rootCmd = &cobra.Command{
		Use:   "namealive",
		Short: "Network host discovery and identification tool",
		Long:  `Namealive discovers active hosts in the network and retrieves their hostnames`,
		RunE:  run,
	}
)

func init() {
	currentUser, err := user.Current()
	username := "root"
	if err == nil {
		username = currentUser.Username
	}

	rootCmd.Flags().StringVarP(&config.IPRange, "range", "r", "192.168.1.1-192.168.1.250", "IP range to scan")
	rootCmd.Flags().StringVarP(&config.User, "user", "u", username, "SSH username")
	rootCmd.Flags().IntVarP(&config.Port, "port", "", 22, "SSH port")
	rootCmd.Flags().IntVarP(&config.Parallel, "parallel", "p", 20, "Number of parallel connections")
	rootCmd.Flags().DurationVar(&config.Timeout, "timeout", 20*time.Second, "Connection timeout")
	rootCmd.Flags().StringVar(&config.Format, "format", "table", "Output format (table|json|csv)")
	rootCmd.Flags().StringVarP(&config.OutputFile, "output", "o", "", "Output file")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose mode")
	rootCmd.Flags().BoolVar(&config.Extended, "extended", false, "Show extended information")
	rootCmd.Flags().StringSliceVar(&config.ExcludeRanges, "exclude", []string{}, "Exclude IP ranges")
	rootCmd.Flags().BoolVar(&config.IncludeOffline, "include-offline", false, "Include offline hosts")
	rootCmd.Flags().BoolVar(&config.NoPassword, "no-password", false, "Skip password prompt (use SSH keys only)")
}

func main() {
	// Suppress mdns library logs
	log.SetOutput(ioutil.Discard)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if config.Verbose {
		fmt.Printf("Starting scan of range: %s\n", config.IPRange)
	}

	ips, err := parseIPRange(config.IPRange)
	if err != nil {
		return fmt.Errorf("failed to parse IP range: %w", err)
	}

	ips = excludeIPs(ips, config.ExcludeRanges)

	fmt.Printf("🔍 Scanning %d IP addresses...\n", len(ips))

	if !config.NoPassword {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Print("Enter SSH password (will be hidden): ")
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			fmt.Println()
			config.Password = string(password)
		} else {
			if config.Verbose {
				fmt.Println("No terminal available, skipping password prompt")
			}
			config.NoPassword = true
		}
	}

	// Single-phase scan: discover and connect immediately
	fmt.Println("\n🚀 Starting network scan...")
	results := scanNetwork(ips)
	fmt.Printf("\n✅ Scan complete: %d hosts processed\n\n", len(results))

	if config.IncludeOffline {
		for _, ip := range ips {
			found := false
			for _, h := range results {
				if h.IP == ip {
					found = true
					break
				}
			}
			if !found {
				results = append(results, Host{
					IP:        ip,
					Status:    "offline",
					Timestamp: time.Now(),
				})
			}
		}
	}

	return outputResults(results)
}

func parseIPRange(ipRange string) ([]string, error) {
	var ips []string

	if strings.Contains(ipRange, "/") {
		_, ipnet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, err
		}
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			ips = append(ips, ip.String())
		}
	} else if strings.Contains(ipRange, "-") {
		parts := strings.Split(ipRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range format")
		}

		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))

		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP addresses in range")
		}

		for ip := startIP; !ip.Equal(endIP); incrementIP(ip) {
			ips = append(ips, ip.String())
		}
		ips = append(ips, endIP.String())
	} else {
		ip := net.ParseIP(ipRange)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address")
		}
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func excludeIPs(ips []string, excludeRanges []string) []string {
	if len(excludeRanges) == 0 {
		return ips
	}

	excluded := make(map[string]bool)
	for _, excludeRange := range excludeRanges {
		excludedIPs, err := parseIPRange(excludeRange)
		if err == nil {
			for _, ip := range excludedIPs {
				excluded[ip] = true
			}
		}
	}

	var result []string
	for _, ip := range ips {
		if !excluded[ip] {
			result = append(result, ip)
		}
	}
	return result
}

func scanNetwork(ips []string) []Host {
	var results []Host
	var mu sync.Mutex
	var wg sync.WaitGroup
	var alive int32
	var connected int32

	// Create progress bar
	bar := pb.StartNew(len(ips))
	bar.SetWriter(os.Stderr)
	bar.SetTemplateString(`{{string . "prefix"}} {{counters . }} {{bar . }} {{percent . }} {{etime . }} | {{string . "status"}}`)
	bar.Set("prefix", "Progress: ")
	bar.Set("status", "Starting...")

	sem := make(chan struct{}, config.Parallel)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}

		go func(ip string) {
			defer wg.Done()
			defer func() {
				<-sem
				bar.Increment()
			}()

			host := Host{
				IP:        ip,
				Timestamp: time.Now(),
			}

			// First check if host is alive
			if !isAlive(ip) {
				if config.IncludeOffline {
					host.Status = "offline"
					mu.Lock()
					results = append(results, host)
					mu.Unlock()
				}
				bar.Set("status", fmt.Sprintf("Alive: %d | Connected: %d | Scanning: %s",
					atomic.LoadInt32(&alive), atomic.LoadInt32(&connected), ip))
				return
			}

			atomic.AddInt32(&alive, 1)
			bar.Set("status", fmt.Sprintf("Alive: %d | Connected: %d | Found: %s",
				atomic.LoadInt32(&alive), atomic.LoadInt32(&connected), ip))

			// Try fast methods first (mDNS, NetBIOS), then fallback to SSH
			startTime := time.Now()

			// First try mDNS (fastest for Linux/Mac)
			hostname, method := getHostnameByMDNS(ip)

			// If mDNS fails, try NetBIOS (for Windows)
			if hostname == "" {
				hostname, method = getHostnameByNetBIOS(ip)
			}

			// If both fail, fallback to SSH
			var osInfo, uptime, domain string
			var err error
			if hostname == "" {
				hostname, osInfo, uptime, domain, err = getSSHInfo(ip)
				if err == nil {
					method = "SSH"
				}
			} else {
				// Got hostname via mDNS/NetBIOS, optionally get extended info via SSH
				if config.Extended && config.Password != "" {
					_, osInfo, uptime, domain, _ = getSSHInfo(ip)
				}
			}

			responseTime := time.Since(startTime)

			if hostname == "" && err != nil {
				host.Status = "error"
				host.Error = err.Error()
				bar.Set("status", fmt.Sprintf("Alive: %d | Connected: %d | Failed: %s",
					atomic.LoadInt32(&alive), atomic.LoadInt32(&connected), ip))
			} else if hostname != "" {
				host.Status = "online"
				host.Hostname = hostname
				host.Method = method
				host.ResponseTime = responseTime.String()
				atomic.AddInt32(&connected, 1)

				if config.Extended {
					host.OS = osInfo
					host.Uptime = uptime
					host.Domain = domain
					host.MACAddress = getMACAddress(ip)
				}

				bar.Set("status", fmt.Sprintf("Alive: %d | Connected: %d | ✓ %s: %s (%s)",
					atomic.LoadInt32(&alive), atomic.LoadInt32(&connected), ip, hostname, method))
			}

			mu.Lock()
			results = append(results, host)
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	bar.Finish()

	// Final statistics
	fmt.Printf("📊 Statistics: %d alive, %d connected\n",
		atomic.LoadInt32(&alive), atomic.LoadInt32(&connected))

	return results
}

func isAlive(ip string) bool {
	host, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return pingFallback(ip)
	}
	defer c.Close()

	wm := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("namealive"),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return false
	}

	if _, err := c.WriteTo(wb, host); err != nil {
		return false
	}

	rb := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return false
	}

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		return false
	}

	if rm.Type == ipv4.ICMPTypeEchoReply {
		return true
	}

	return false
}

func pingFallback(ip string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:22", ip), 2*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), 2*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", ip), 2*time.Second)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}


// getHostnameByMDNS tries to resolve hostname using mDNS (Avahi/Bonjour)
func getHostnameByMDNS(ip string) (string, string) {
	// Create mDNS query
	entriesCh := make(chan *mdns.ServiceEntry, 10)

	// Start mDNS query in background
	go func() {
		params := &mdns.QueryParam{
			Service: "_workstation._tcp",
			Domain:  "local",
			Timeout: 2 * time.Second,
			Entries: entriesCh,
			DisableIPv6: true,
		}
		mdns.Query(params)
		close(entriesCh)
	}()

	// Check results for matching IP
	for entry := range entriesCh {
		if entry.AddrV4 != nil && entry.AddrV4.String() == ip {
			// Remove .local suffix if present
			hostname := strings.TrimSuffix(entry.Host, ".local.")
			if hostname == "" {
				hostname = entry.Name
			}
			return hostname, "mDNS"
		}
		// Also check IPv6
		if entry.AddrV6 != nil && entry.AddrV6.String() == ip {
			hostname := strings.TrimSuffix(entry.Host, ".local.")
			if hostname == "" {
				hostname = entry.Name
			}
			return hostname, "mDNS"
		}
	}

	// Alternative: try reverse mDNS lookup
	// Convert IP to hostname.local format
	ipAddr := net.ParseIP(ip)
	if ipAddr != nil {
		// Try direct resolution
		resolver := &net.Resolver{}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		names, _ := resolver.LookupAddr(ctx, ip)
		for _, name := range names {
			if strings.HasSuffix(name, ".local.") {
				hostname := strings.TrimSuffix(name, ".local.")
				hostname = strings.TrimSuffix(hostname, ".")
				if hostname != "" {
					return hostname, "mDNS"
				}
			}
		}
	}

	return "", ""
}

// getHostnameByNetBIOS tries to resolve hostname using NetBIOS Name Service
func getHostnameByNetBIOS(ip string) (string, string) {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:137", ip), 2*time.Second)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// Create NetBIOS Name Service query packet
	// Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) + Answer RRs (2 bytes) +
	// Authority RRs (2 bytes) + Additional RRs (2 bytes) + Query
	var query bytes.Buffer

	// Transaction ID
	binary.Write(&query, binary.BigEndian, uint16(0x1234))
	// Flags: Standard query
	binary.Write(&query, binary.BigEndian, uint16(0x0010))
	// Questions: 1
	binary.Write(&query, binary.BigEndian, uint16(0x0001))
	// Answer RRs: 0
	binary.Write(&query, binary.BigEndian, uint16(0x0000))
	// Authority RRs: 0
	binary.Write(&query, binary.BigEndian, uint16(0x0000))
	// Additional RRs: 0
	binary.Write(&query, binary.BigEndian, uint16(0x0000))

	// Query: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (encoded "*")
	// This queries for all names
	query.WriteString(" CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	// Null terminator
	query.WriteByte(0x00)
	// Type: NBSTAT
	binary.Write(&query, binary.BigEndian, uint16(0x0021))
	// Class: IN
	binary.Write(&query, binary.BigEndian, uint16(0x0001))

	// Send query
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query.Bytes()); err != nil {
		return "", ""
	}

	// Read response
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil || n < 62 {
		return "", ""
	}

	// Parse NetBIOS names from response
	// Skip header (first 56 bytes) and get to the name list
	if n > 56 {
		nameCount := int(buffer[56])
		offset := 57

		for i := 0; i < nameCount && offset+18 <= n; i++ {
			// Each name entry is 18 bytes: 15 bytes name + 1 byte type + 2 bytes flags
			nameBytes := buffer[offset : offset+15]
			nameType := buffer[offset+15]

			// Look for unique workstation name (type 0x00 with unique flag)
			// or computer name (type 0x20)
			if nameType == 0x00 || nameType == 0x20 {
				// Decode NetBIOS name
				name := strings.TrimSpace(string(nameBytes))
				// Remove padding and non-printable characters
				name = strings.TrimRight(name, " \x00")
				if name != "" && !strings.Contains(name, "\x00") {
					return name, "NetBIOS"
				}
			}
			offset += 18
		}
	}

	return "", ""
}

func getSSHInfo(ip string) (hostname, osInfo, uptime, domain string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	sshConfig := &ssh.ClientConfig{
		User: config.User,
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: config.Timeout,  // Use full timeout for SSH connection
	}

	homeDir, _ := os.UserHomeDir()
	keyPaths := []string{
		fmt.Sprintf("%s/.ssh/id_rsa", homeDir),
		fmt.Sprintf("%s/.ssh/id_ed25519", homeDir),
		fmt.Sprintf("%s/.ssh/id_ecdsa", homeDir),
	}

	for _, keyPath := range keyPaths {
		if key, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(key); err == nil {
				sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
			}
		}
	}

	if config.Password != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(config.Password))
	}

	sshConfig.Auth = append(sshConfig.Auth, ssh.KeyboardInteractive(
		func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = config.Password
			}
			return answers, nil
		},
	))

	address := fmt.Sprintf("%s:%d", ip, config.Port)

	done := make(chan struct{})
	var client *ssh.Client
	var connErr error

	go func() {
		client, connErr = ssh.Dial("tcp", address, sshConfig)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return "", "", "", "", fmt.Errorf("connection timeout")
	case <-done:
		if connErr != nil {
			return "", "", "", "", connErr
		}
	}

	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", "", "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput("hostname")
	if err != nil {
		return "", "", "", "", err
	}
	hostname = strings.TrimSpace(string(output))

	if config.Extended {
		session2, _ := client.NewSession()
		if output, err := session2.CombinedOutput("uname -a"); err == nil {
			osInfo = strings.TrimSpace(string(output))
		}
		session2.Close()

		session3, _ := client.NewSession()
		if output, err := session3.CombinedOutput("uptime -p 2>/dev/null || uptime"); err == nil {
			uptime = strings.TrimSpace(string(output))
		}
		session3.Close()

		session4, _ := client.NewSession()
		if output, err := session4.CombinedOutput("hostname -d 2>/dev/null || dnsdomainname 2>/dev/null"); err == nil {
			domain = strings.TrimSpace(string(output))
		}
		session4.Close()
	}

	return hostname, osInfo, uptime, domain, nil
}

func getMACAddress(ip string) string {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ip {
			return fields[3]
		}
	}
	return ""
}

func outputResults(results []Host) error {
	var output string

	switch config.Format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		output = string(data)

	case "csv":
		var buf strings.Builder
		writer := csv.NewWriter(&buf)

		headers := []string{"IP", "Hostname", "Status", "Method", "Response Time"}
		if config.Extended {
			headers = append(headers, "OS", "Uptime", "Domain", "MAC Address")
		}
		headers = append(headers, "Error")
		writer.Write(headers)

		for _, host := range results {
			row := []string{host.IP, host.Hostname, host.Status, host.Method, host.ResponseTime}
			if config.Extended {
				row = append(row, host.OS, host.Uptime, host.Domain, host.MACAddress)
			}
			row = append(row, host.Error)
			writer.Write(row)
		}
		writer.Flush()
		output = buf.String()

	default: // table
		var buf strings.Builder
		var writer io.Writer = &buf
		if config.OutputFile == "" {
			writer = os.Stdout
		}

		table := tablewriter.NewWriter(writer)
		headers := []string{"IP", "Hostname", "Status", "Method"}
		if config.Extended {
			headers = append(headers, "OS", "Uptime", "MAC")
		}
		table.SetHeader(headers)
		table.SetBorder(true)
		table.SetRowLine(false)
		table.SetAutoWrapText(false)

		for _, host := range results {
			statusColor := ""
			switch host.Status {
			case "online":
				statusColor = fmt.Sprintf("\033[32m%s\033[0m", host.Status)
			case "error":
				statusColor = fmt.Sprintf("\033[33m%s\033[0m", host.Status)
			case "offline":
				statusColor = fmt.Sprintf("\033[31m%s\033[0m", host.Status)
			default:
				statusColor = host.Status
			}

			row := []string{host.IP, host.Hostname, statusColor, host.Method}
			if config.Extended {
				osShort := host.OS
				if len(osShort) > 30 {
					osShort = osShort[:30] + "..."
				}
				row = append(row, osShort, host.Uptime, host.MACAddress)
			}
			table.Append(row)
		}

		table.Render()

		if config.OutputFile == "" {
			return nil
		}
		output = buf.String()
	}

	if config.OutputFile != "" {
		return os.WriteFile(config.OutputFile, []byte(output), 0644)
	}

	if config.Format != "table" {
		fmt.Print(output)
	}

	return nil
}