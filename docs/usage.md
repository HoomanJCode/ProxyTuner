# Usage Guide

## Installation

```bash
# From PyPI
pip install proxy-tuner

# From source
git clone https://github.com/youruser/proxy-tuner.git
cd proxy-tuner
pip install -e .
```

## Privileges

ProxyTuner requires elevated privileges to intercept network traffic:

```bash
# Linux
sudo proxy-tuner start

# Windows (Run as Administrator)
proxy-tuner start
```

---

## Managing Outbounds

### Add a SOCKS5 Proxy

```bash
proxy-tuner outbound add my-vpn \
    --type socks5 \
    --host 127.0.0.1 \
    --port 1080
```

With authentication:
```bash
proxy-tuner outbound add my-vpn \
    --type socks5 \
    --host 127.0.0.1 \
    --port 1080 \
    --username myuser \
    --password mypass
```

### Add an HTTP Proxy

```bash
proxy-tuner outbound add my-http \
    --type http \
    --host 192.168.1.1 \
    --port 8080
```

### List Outbounds

```bash
proxy-tuner outbound list
```

Output:
```
Name          Type    Host             Port
my-vpn        socks5  127.0.0.1        1080
my-http       http    192.168.1.1      8080
```

### Remove an Outbound

```bash
proxy-tuner outbound remove my-vpn
```

### Test an Outbound

```bash
proxy-tuner outbound test my-vpn
```

Output:
```
Testing my-vpn (socks5://127.0.0.1:1080)...
  Connection: OK
  DNS resolve: OK (45ms)
  TCP connect: OK (120ms)
  Overall: PASS
```

---

## Managing Rules

### Add Rules

**Route a process through a proxy**:
```bash
proxy-tuner rule add firefox-vpn \
    --process firefox \
    --outbound my-vpn
```

**Route multiple processes**:
```bash
proxy-tuner rule add browsers-vpn \
    --process firefox,chrome,chromium \
    --outbound my-vpn
```

**Route by domain (wildcard)**:
```bash
proxy-tuner rule add china-domains \
    --domain "*.cn,*.com.cn" \
    --outbound my-http
```

**Route by domain (regex)**:
```bash
proxy-tuner rule add cdn-traffic \
    --domain-regex ".*\.cdn\..*" \
    --outbound fast-relay
```

**Route by IP range**:
```bash
proxy-tuner rule add private-ips \
    --ip-cidr "192.168.0.0/16,10.0.0.0/8" \
    --outbound direct
```

**Route by port**:
```bash
proxy-tuner rule add https-only \
    --port 443 \
    --outbound my-vpn
```

**Route by process path**:
```bash
proxy-tuner rule add custom-binary \
    --process-path "/opt/myapp/bin/*" \
    --outbound my-vpn
```

**Route by URL pattern**:
```bash
proxy-tuner rule add specific-sites \
    --url-regex "https?://.*\.example\.com/.*" \
    --outbound my-http
```

**Combined match (AND logic)**:
```bash
proxy-tuner rule add firefox-china \
    --process firefox \
    --domain "*.cn" \
    --outbound my-http
```

**Set priority** (lower = higher priority):
```bash
proxy-tuner rule add high-priority-rule \
    --process curl \
    --outbound my-vpn \
    --priority 5
```

### List Rules

```bash
proxy-tuner rule list
```

Output:
```
Priority  Name              Enabled  Outbound     Match
5         private-ips       yes      direct       ip_cidr: 192.168.0.0/16, 10.0.0.0/8
10        firefox-vpn       yes      my-vpn       process: firefox
20        china-domains     yes      my-http      domain: *.cn, *.com.cn
100       default           yes      my-http      (all traffic)
```

### Test a Rule

Check if a specific target matches a rule:
```bash
proxy-tuner rule test firefox-vpn --process firefox
# → MATCH: firefox-vpn → my-vpn

proxy-tuner rule test firefox-vpn --domain google.com
# → NO MATCH

proxy-tuner rule test china-domains --domain example.cn
# → MATCH: china-domains → my-http
```

### Move Rule Priority

```bash
proxy-tuner rule move firefox-vpn --priority 3
```

### Disable a Rule

```bash
proxy-tuner rule disable firefox-vpn
```

### Re-enable a Rule

```bash
proxy-tuner rule enable firefox-vpn
```

### Remove a Rule

```bash
proxy-tuner rule remove firefox-vpn
```

---

## Starting and Stopping

### Start Tuning

```bash
# Start as daemon (background)
sudo proxy-tuner start

# Start in foreground (logs to stdout)
sudo proxy-tuner start --foreground
```

### Stop Tuning

```bash
proxy-tuner stop
```

### Check Status

```bash
proxy-tuner status
```

Output:
```
Status:     running
PID:        12345
Uptime:     2h 15m
Listening:  127.0.0.1:10808
TUN:        proxytun0 (10.0.0.1/24)

Outbounds:
  my-vpn (socks5):   connected, 1.2 GB transferred
  my-http (http):    connected, 340 MB transferred

Rules (4 active):
  1. private-ips     → direct       (12,340 hits)
  2. firefox-vpn     → my-vpn       (45,123 hits)
  3. china-domains   → my-http      (8,901 hits)
  4. default         → my-http      (23,456 hits)
```

---

## Configuration Commands

### Show Current Config

```bash
proxy-tuner config show
```

### Show Config Path

```bash
proxy-tuner config path
# → /home/user/.config/proxy-tuner/config.json
```

### Edit Config in Default Editor

```bash
proxy-tuner config edit
```

### Validate Config

```bash
proxy-tuner config validate
```

---

## Common Workflows

### Workflow 1: Browser VPN

Route all browser traffic through a SOCKS5 VPN:

```bash
# 1. Add the proxy
proxy-tuner outbound add vpn --type socks5 --host 127.0.0.1 --port 1080

# 2. Add rule for browsers
proxy-tuner rule add browsers --process "firefox,chrome,chromium,brave" --outbound vpn

# 3. Start
sudo proxy-tuner start
```

### Workflow 2: Split Tunneling

Route specific apps through proxy, everything else direct:

```bash
# Add proxy
proxy-tuner outbound add remote --type socks5 --host 10.0.0.1 --port 1080

# Proxy specific apps
proxy-tuner rule add proxy-apps --process "firefox,telegram" --outbound remote --priority 10

# Local IPs always direct
proxy-tuner rule add local --ip-cidr "192.168.0.0/16,10.0.0.0/8,127.0.0.0/8" --outbound direct --priority 5

# Everything else direct
proxy-tuner rule add default --outbound direct --priority 100

sudo proxy-tuner start
```

### Workflow 3: Per-Region Routing

Route traffic by destination region:

```bash
# Add proxies for different regions
proxy-tuner outbound add us-proxy --type socks5 --host 1.2.3.4 --port 1080
proxy-tuner outbound add eu-proxy --type http --host 5.6.7.8 --port 3128

# Route by domain/IP
proxy-tuner rule add us-sites --domain "*.us.example.com" --outbound us-proxy --priority 10
proxy-tuner rule add eu-sites --domain "*.eu.example.com" --outbound eu-proxy --priority 10

# Default goes direct
proxy-tuner rule add default --outbound direct --priority 100

sudo proxy-tuner start
```

### Workflow 4: Development vs Browsing

Different routing for dev tools vs browsers:

```bash
proxy-tuner outbound add corp-vpn --type socks5 --host 10.0.0.1 --port 1080

# Dev tools direct (faster for package managers)
proxy-tuner rule add dev-tools --process "git,cargo,npm,yarn,pip,go" --outbound direct --priority 10

# Browsers through VPN
proxy-tuner rule add browsers --process "firefox,chrome" --outbound corp-vpn --priority 20

# Default direct
proxy-tuner rule add default --outbound direct --priority 100

sudo proxy-tuner start
```

---

## Logging

### View Logs

```bash
# If running as daemon, logs go to configured log file or stdout
proxy-tuner status  # shows log file path

# Or specify log file in config
proxy-tuner config show
```

### Set Log Level

Edit config or use:
```bash
proxy-tuner config set log_level debug
```

---

## Troubleshooting

### Permission Denied

```bash
# Make sure to run with sudo/root
sudo proxy-tuner start
```

### TUN Interface Already Exists

```bash
# Clean up manually
sudo ip tuntap del proxytun0 mode tun
# Then restart
sudo proxy-tuner start
```

### Proxy Connection Failed

```bash
# Test the outbound
proxy-tuner outbound test my-vpn

# Check with verbose logging
proxy-tuner start --foreground --log-level debug
```

### Rules Not Matching

```bash
# Test the specific rule
proxy-tuner rule test my-rule --process firefox --domain example.com

# List all rules to check order
proxy-tuner rule list
```

### Reset Everything

```bash
proxy-tuner stop
rm ~/.config/proxy-tuner/config.json
proxy-tuner config init  # creates fresh config
```
