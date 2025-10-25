# Network Connection Monitor

A Python tool for real-time network connection monitoring with timeline visualization. Monitor all connections on your system and see their activity over time in an easy-to-read console display.

## Features

- **Real-time monitoring**: Track all network connections as they happen
- **Visual timeline**: Each connection displayed as a timeline with symbols showing state changes
- **Two display modes**:
  - **Refresh mode** (default): Live dashboard with full overview
  - **Scroll mode**: Event log that never clears - perfect for copying IPs
- **DNS resolution**: Show hostnames instead of IP addresses
- **GeoIP lookups**: Display country codes and ASN information for each IP
- **Flexible filtering**:
  - Filter local/private addresses
  - Filter IPs from custom blocklist files
  - Combine multiple filters
- **Smart tracking**: Automatically save frequently connected IPs
- **Export capabilities**: Save complete timelines with detailed statistics
- **IPv4 and IPv6 support**: Works with both address families

## Requirements

- Python 3.6 or higher
- Administrator/root privileges (required to monitor network connections)
- Dependencies: `pip install -r requirements.txt`

## Installation

1. Clone or download this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

**Windows** (run PowerShell or Command Prompt as Administrator):
```bash
python connection_monitor.py
```

**Linux/Mac**:
```bash
sudo python3 connection_monitor.py
```

Press `Ctrl+C` to stop monitoring and save results.

## Display Modes

### Refresh Mode (Default)
Screen updates in place, showing a live dashboard of all connections:
```
Network Connection Monitor
Time: 45s | Interval: 1.0s | IPs: 3

▲ New   ■ Active   ○ Listen   × Closed   · Empty

192.168.1.100   ·····▲■■■■×···· [ACTIVE | Port:443]
8.8.8.8         ··▲■■■■■■■■■■■ [ACTIVE | Port:80,443]
```

### Scroll Mode (`--scroll`)
Events log to screen without clearing, making it easy to copy IPs and review history:
```
[14:30:16] NEW → 192.168.1.100  ESTABLISHED:443
[14:30:18] NEW → 8.8.8.8        ESTABLISHED:80,443
[14:30:25] Status: 3 active IPs | Runtime: 10s
```

## Command-Line Options

```bash
Display Options:
  -t, --time-unit SECONDS   Time per timeline character (default: 1.0)
  -w, --width CHARS         Timeline width (default: 80)
  --scroll                  Use scroll mode instead of refresh
  --no-color                Disable colored output
  -o, --output FILE         Auto-save timeline to file on exit

Information Display:
  --resolve-names           Show DNS hostnames for IPs
  --lookup-country          Show country codes (requires DB-IP CSV)
  --lookup-asn              Show ASN information (requires DB-IP CSV)
  --geo-path PATH           Custom path to GeoIP CSV files

Filtering Options:
  --filter-local            Hide local/private IP addresses
  --filter-file FILE        Hide IPs from file (one per line)
  --save-threshold PCT      Auto-save IPs connected ≥PCT% of time
```

## Examples

**Basic monitoring:**
```bash
# Default mode (refresh display)
python connection_monitor.py

# Scroll mode (easier to copy IPs)
python connection_monitor.py --scroll
```

**With DNS resolution:**
```bash
# Show hostnames instead of IPs
python connection_monitor.py --resolve-names
```

**With GeoIP information:**
```bash
# Show country codes only
python connection_monitor.py --lookup-country

# Show ASN information only
python connection_monitor.py --lookup-asn

# Show both country and ASN
python connection_monitor.py --lookup-country --lookup-asn

# Full details: hostnames, country, and ASN
python connection_monitor.py --resolve-names --lookup-country --lookup-asn
```

**Filtering:**
```bash
# Hide local/private IPs (192.168.x.x, 10.x.x.x, etc.)
python connection_monitor.py --filter-local

# Hide IPs from a blocklist file
python connection_monitor.py --filter-file blocked_ips.txt

# Combine filters
python connection_monitor.py --filter-local --filter-file blocked_ips.txt
```

**Tracking frequent connections:**
```bash
# Auto-save IPs connected ≥50% of the time
python connection_monitor.py --save-threshold 50

# Use the saved list as a filter in your next session
python connection_monitor.py --filter-file frequent_ips_50pct_20251025_143022.txt
```

**Advanced usage:**
```bash
# Fast updates with wide display
python connection_monitor.py -t 0.5 -w 120

# Complete monitoring session with all features
python connection_monitor.py --scroll --resolve-names --lookup-country --lookup-asn --filter-local --save-threshold 60
```

## GeoIP Lookups

The tool can display country codes and ASN (Autonomous System Number) information for each IP address using DB-IP databases.

### Setup

1. Download the free DB-IP Lite databases from [db-ip.com](https://db-ip.com/db/download/ip-to-country-lite) (free registration required)
2. Download both files:
   - `dbip-country-lite.csv` - IP to country mapping
   - `dbip-asn-lite.csv` - IP to ASN mapping
3. Place them in the same directory as `connection_monitor.py`
4. Run with `--lookup-country` and/or `--lookup-asn`

### Example Output

Without GeoIP:
```
1.1.1.1    ▲■■■■■ [ACTIVE | Port:443]
```

With GeoIP:
```
1.1.1.1    ▲■■■■■ [US | AS13335 Cloudflare, Inc. | ACTIVE | Port:443]
```

### Features
- Fast binary search lookups (pre-loaded data)
- Both IPv4 and IPv6 support
- Results are cached for performance
- No external API calls - everything runs locally
- Load only what you need: use `--lookup-country` alone for faster startup

### Custom Database Location
```bash
python connection_monitor.py --lookup-country --lookup-asn --geo-path /path/to/csvfiles
```

*IP Geolocation by [DB-IP](https://db-ip.com)*

## Filtering

### Filter Local Addresses
Use `--filter-local` to hide all local/private IPs:
- Private networks: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
- Loopback: 127.x.x.x
- Link-local: 169.254.x.x, fe80::
- Reserved addresses

### Filter from File
Create a text file with one IP per line:
```
# blocked_ips.txt
8.8.8.8
1.1.1.1
142.250.185.46
```

Then use: `--filter-file blocked_ips.txt`

Lines starting with `#` are treated as comments.

### Combine Filters
Filters work together:
```bash
python connection_monitor.py --filter-local --filter-file blocked_ips.txt
```

## Tracking Frequent IPs

Track which IPs maintain long-running connections:

```bash
# Automatically save IPs connected ≥50% of the time
python connection_monitor.py --save-threshold 50
```

When monitoring stops, a file is created with qualifying IPs:
```
frequent_ips_50pct_20251025_143022.txt
```

Use this file to filter out persistent connections in future sessions:
```bash
python connection_monitor.py --filter-file frequent_ips_50pct_20251025_143022.txt
```

This helps focus on sporadic or unexpected connections.

## Timeline Symbols

- `▲` New connection (Green)
- `■` Active connection (Blue)
- `○` Listening state (Yellow)
- `×` Connection closed (Red)
- `·` No activity (Gray)

Each character in the timeline represents one time unit (default: 1 second).

## Saving Results

When you stop monitoring with `Ctrl+C`, you can save the complete timeline to a file. The saved file includes:
- Full timeline for all IPs (not truncated like the display)
- Statistics for each IP (first seen, activity time, ports used)
- Top 10 most active connections
- GeoIP information (if enabled)
- Runtime summary

Use `-o filename.txt` to auto-save without prompting.

## Tips

- Use `--scroll` mode when you need to copy IPs while monitoring
- Use `--filter-local` to focus on external connections only
- Enable `--resolve-names` to see readable hostnames like "google.com"
- Use `--save-threshold 80` to build a baseline of normal connections
- Adjust `-t 0.5` for faster updates or `-t 2` for slower
- Increase `-w 120` to see more timeline history
- Combine features: `--resolve-names --lookup-country --lookup-asn --scroll`

## Troubleshooting

**"Access Denied" or permission errors:**
- Windows: Run Command Prompt or PowerShell as Administrator
- Linux/Mac: Use `sudo` before the command

**No connections showing:**
- Ensure you have active network connections (open a browser)
- The tool only shows remote connections (not localhost-only)

**Screen flashing or hard to read:**
- Use `--scroll` mode to disable screen clearing

**Colors not working on Windows:**
- Requires Windows 10+ with modern terminal
- Use `--no-color` to disable colors if needed

## Acknowledgments

This tool uses the following data sources and libraries:

- **[psutil](https://github.com/giampaolo/psutil)** - Cross-platform library for system and process monitoring
- **[DB-IP](https://db-ip.com)** - Free IP geolocation databases (country and ASN data)
  - Licensed under Creative Commons Attribution 4.0 International License
  - Databases must be downloaded separately and are not included with this software

## License

MIT License - see [LICENSE](LICENSE) file for details.

Note: GeoIP databases from DB-IP are licensed separately under CC BY 4.0.
