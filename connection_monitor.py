#!/usr/bin/env python3
"""
Network Connection Monitor with Timeline Visualization
Monitors network connections and displays them as a timeline in the console.
"""

import psutil
import time
import os
import sys
import ipaddress
import socket
import csv
import bisect
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Thread, Lock


class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright foreground colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    @staticmethod
    def disable():
        """Disable all colors (for file export)."""
        Colors.RESET = ''
        Colors.BOLD = ''
        Colors.DIM = ''
        Colors.BLACK = Colors.RED = Colors.GREEN = Colors.YELLOW = ''
        Colors.BLUE = Colors.MAGENTA = Colors.CYAN = Colors.WHITE = ''
        Colors.BRIGHT_BLACK = Colors.BRIGHT_RED = Colors.BRIGHT_GREEN = ''
        Colors.BRIGHT_YELLOW = Colors.BRIGHT_BLUE = Colors.BRIGHT_MAGENTA = ''
        Colors.BRIGHT_CYAN = Colors.BRIGHT_WHITE = ''
        Colors.BG_BLACK = Colors.BG_RED = Colors.BG_GREEN = Colors.BG_YELLOW = ''
        Colors.BG_BLUE = Colors.BG_MAGENTA = Colors.BG_CYAN = Colors.BG_WHITE = ''


class GeoIPLookup:
    """Handles GeoIP lookups using DB-IP CSV files."""

    def __init__(self, geo_path=None, enable_country=True, enable_asn=True):
        """
        Initialize GeoIP lookup.

        Args:
            geo_path: Directory containing CSV files (default: script directory)
            enable_country: Enable country lookups (default: True)
            enable_asn: Enable ASN lookups (default: True)
        """
        self.geo_path = geo_path or os.path.dirname(os.path.abspath(__file__))
        self.enable_country = enable_country
        self.enable_asn = enable_asn
        self.country_ranges_v4 = []  # List of (start_int, end_int, country)
        self.country_ranges_v6 = []  # List of (start_int, end_int, country)
        self.asn_ranges_v4 = []  # List of (start_int, end_int, asn_num, asn_name)
        self.asn_ranges_v6 = []  # List of (start_int, end_int, asn_num, asn_name)
        self.lookup_cache = {}  # IP -> (country, asn_num, asn_name)
        self.enabled = False

    def _ip_to_int(self, ip_str):
        """Convert IP address string to integer."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return int(ip)
        except (ValueError, AttributeError, TypeError):
            return None

    def load_databases(self):
        """Load GeoIP databases from CSV files."""
        country_file = os.path.join(self.geo_path, 'dbip-country-lite.csv')
        asn_file = os.path.join(self.geo_path, 'dbip-asn-lite.csv')

        loaded_country = False
        loaded_asn = False

        # Load country database (only if enabled)
        if self.enable_country and os.path.exists(country_file):
            print(f"{Colors.CYAN}Loading country database...{Colors.RESET}", end='', flush=True)
            try:
                with open(country_file, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 3:
                            start_ip, end_ip, country = row[0], row[1], row[2]
                            start_int = self._ip_to_int(start_ip)
                            end_int = self._ip_to_int(end_ip)

                            if start_int is not None and end_int is not None:
                                # Determine if IPv4 or IPv6
                                if ':' in start_ip:
                                    self.country_ranges_v6.append((start_int, end_int, country))
                                else:
                                    self.country_ranges_v4.append((start_int, end_int, country))

                # Sort for binary search
                self.country_ranges_v4.sort(key=lambda x: x[0])
                self.country_ranges_v6.sort(key=lambda x: x[0])
                loaded_country = True
                print(f" {Colors.GREEN}✓{Colors.RESET} Loaded {len(self.country_ranges_v4)} IPv4 + {len(self.country_ranges_v6)} IPv6 ranges")
            except Exception as e:
                print(f" {Colors.RED}✗{Colors.RESET} Error: {e}")

        # Load ASN database (only if enabled)
        if self.enable_asn and os.path.exists(asn_file):
            print(f"{Colors.CYAN}Loading ASN database...{Colors.RESET}", end='', flush=True)
            try:
                with open(asn_file, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 4:
                            start_ip, end_ip, asn_num, asn_name = row[0], row[1], row[2], row[3]
                            start_int = self._ip_to_int(start_ip)
                            end_int = self._ip_to_int(end_ip)

                            if start_int is not None and end_int is not None:
                                # Determine if IPv4 or IPv6
                                if ':' in start_ip:
                                    self.asn_ranges_v6.append((start_int, end_int, asn_num, asn_name))
                                else:
                                    self.asn_ranges_v4.append((start_int, end_int, asn_num, asn_name))

                # Sort for binary search
                self.asn_ranges_v4.sort(key=lambda x: x[0])
                self.asn_ranges_v6.sort(key=lambda x: x[0])
                loaded_asn = True
                print(f" {Colors.GREEN}✓{Colors.RESET} Loaded {len(self.asn_ranges_v4)} IPv4 + {len(self.asn_ranges_v6)} IPv6 ranges")
            except Exception as e:
                print(f" {Colors.RED}✗{Colors.RESET} Error: {e}")

        if loaded_country or loaded_asn:
            self.enabled = True
            print(f"{Colors.DIM}IP Geolocation by DB-IP (https://db-ip.com) - CC BY 4.0{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}Warning: No GeoIP databases found in {self.geo_path}{Colors.RESET}")
            return False

    def _binary_search_range(self, ranges, ip_int):
        """Binary search to find IP in sorted ranges."""
        # Find the rightmost range where start <= ip_int
        idx = bisect.bisect_right(ranges, (ip_int, float('inf'))) - 1

        if idx >= 0 and idx < len(ranges):
            start, end = ranges[idx][0], ranges[idx][1]
            if start <= ip_int <= end:
                return ranges[idx]
        return None

    def lookup(self, ip_str):
        """
        Look up country and ASN for an IP address.

        Returns:
            tuple: (country_code, asn_number, asn_name) or (None, None, None)
        """
        if not self.enabled:
            return None, None, None

        # Check cache first
        if ip_str in self.lookup_cache:
            return self.lookup_cache[ip_str]

        ip_int = self._ip_to_int(ip_str)
        if ip_int is None:
            return None, None, None

        # Determine IPv4 or IPv6
        is_v6 = ':' in ip_str
        country_ranges = self.country_ranges_v6 if is_v6 else self.country_ranges_v4
        asn_ranges = self.asn_ranges_v6 if is_v6 else self.asn_ranges_v4

        # Lookup country
        country = None
        country_result = self._binary_search_range(country_ranges, ip_int)
        if country_result:
            country = country_result[2]

        # Lookup ASN
        asn_num = None
        asn_name = None
        asn_result = self._binary_search_range(asn_ranges, ip_int)
        if asn_result:
            asn_num = asn_result[2]
            asn_name = asn_result[3]

        # Cache result
        result = (country, asn_num, asn_name)
        self.lookup_cache[ip_str] = result
        return result


class ConnectionMonitor:
    """Monitors network connections and displays them as a timeline."""

    # ASCII symbols for different connection states (simplified)
    SYMBOLS = {
        'new': '▲',        # New connection established
        'active': '■',     # Connection is active/maintained
        'listen': '○',     # Listening state
        'closed': '×',     # Connection closed
        'empty': '·',      # No activity in this time unit
    }

    # Color mapping for symbols (simplified palette)
    SYMBOL_COLORS = {
        'new': Colors.GREEN,
        'active': Colors.BLUE,
        'listen': Colors.YELLOW,
        'closed': Colors.RED,
        'empty': Colors.BRIGHT_BLACK,
    }

    def __init__(self, time_unit=1.0, max_width=80, no_color=False, output_file=None, scroll_mode=False,
                 filter_local=False, filter_file=None, save_threshold=None, resolve_names=False, geoip_lookup=None):
        """
        Initialize the connection monitor.

        Args:
            time_unit: Time in seconds for each character column (default: 1.0)
            max_width: Maximum width of timeline in characters (default: 80)
            no_color: Disable colored output (default: False)
            output_file: File path to save timeline on exit (default: None)
            scroll_mode: Use scrolling mode instead of clearing screen (default: False)
            filter_local: Filter out local/private IP addresses (default: False)
            filter_file: Path to file containing IPs to filter out (default: None)
            save_threshold: Save IPs connected more than X% of time (default: None)
            resolve_names: Enable DNS name resolution for IPs (default: False)
            geoip_lookup: GeoIPLookup instance for country/ASN lookups (default: None)
        """
        self.time_unit = time_unit
        self.max_width = max_width
        self.no_color = no_color
        self.output_file = output_file
        self.scroll_mode = scroll_mode
        self.filter_local = filter_local
        self.filter_file = filter_file
        self.save_threshold = save_threshold
        self.resolve_names = resolve_names
        self.geoip = geoip_lookup
        self.connections = defaultdict(list)  # IP -> list of states over time
        self.known_ips = {}  # IP -> {last_state, last_seen_time}
        self.ip_metadata = {}  # IP -> {first_seen, total_activity, ports}
        self.start_time = time.time()
        self.current_column = 0
        self.last_ip_count = 0  # Track changes in scroll mode
        self.filtered_ips = set()  # IPs to filter out
        self.dns_cache = {}  # IP -> resolved hostname
        self.dns_lock = Lock()  # Thread-safe access to DNS cache
        self.resolving_ips = set()  # IPs currently being resolved

        if self.no_color:
            Colors.disable()

        # Load filter list if provided
        self._load_filter_list()

    def _resolve_hostname(self, ip):
        """Resolve IP to hostname in background thread."""
        try:
            socket.setdefaulttimeout(2.0)  # 2 second timeout
            hostname, _, _ = socket.gethostbyaddr(ip)
            with self.dns_lock:
                self.dns_cache[ip] = hostname
                self.resolving_ips.discard(ip)
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            with self.dns_lock:
                self.dns_cache[ip] = None  # Mark as unresolvable
                self.resolving_ips.discard(ip)
        except Exception:
            # Catch any other unexpected errors
            with self.dns_lock:
                self.dns_cache[ip] = None
                self.resolving_ips.discard(ip)

    def _get_display_name(self, ip):
        """Get display name for IP (hostname if resolved, otherwise IP)."""
        if not self.resolve_names:
            return ip

        with self.dns_lock:
            if ip in self.dns_cache:
                hostname = self.dns_cache[ip]
                return hostname if hostname else ip
            elif ip not in self.resolving_ips:
                # Start resolution in background
                self.resolving_ips.add(ip)
                thread = Thread(target=self._resolve_hostname, args=(ip,), daemon=True)
                thread.start()
                return f"{ip} (resolving...)"
            else:
                return f"{ip} (resolving...)"

    def _load_filter_list(self):
        """Load IP addresses from filter file."""
        if self.filter_file and os.path.exists(self.filter_file):
            try:
                with open(self.filter_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.filtered_ips.add(line)
                print(f"{Colors.GREEN}✓{Colors.RESET} Loaded {len(self.filtered_ips)} IPs from filter file")
            except Exception as e:
                print(f"{Colors.RED}✗{Colors.RESET} Error loading filter file: {e}")

    def _is_local_ip(self, ip_str):
        """Check if an IP address is local/private."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except (ValueError, AttributeError, TypeError):
            return False

    def _should_filter_ip(self, ip):
        """Check if an IP should be filtered out."""
        # Filter local addresses if enabled
        if self.filter_local and self._is_local_ip(ip):
            return True

        # Filter IPs from filter list
        if ip in self.filtered_ips:
            return True

        return False

    def get_connections(self):
        """Get current network connections."""
        connections = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.raddr:  # Only remote connections
                        ip = conn.raddr.ip
                        port = conn.raddr.port
                        status = conn.status

                        # Apply filters
                        if self._should_filter_ip(ip):
                            continue

                        # Track metadata
                        if ip not in self.ip_metadata:
                            self.ip_metadata[ip] = {
                                'first_seen': self.current_column,
                                'total_activity': 0,
                                'ports': set()
                            }
                        self.ip_metadata[ip]['ports'].add(port)

                        if ip not in connections:
                            connections[ip] = status
                        # Prioritize certain states
                        elif status == 'ESTABLISHED':
                            connections[ip] = status
                except (AttributeError, TypeError):
                    # Handle malformed connection objects
                    continue

        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
        except Exception:
            # Catch any other unexpected errors during connection enumeration
            pass

        return connections

    def update_timeline(self):
        """Update the timeline with current connection states."""
        current_connections = self.get_connections()

        # Process each known IP
        all_ips = set(self.known_ips.keys()) | set(current_connections.keys())

        for ip in all_ips:
            current_state = current_connections.get(ip)
            last_info = self.known_ips.get(ip, {})
            last_state = last_info.get('state')

            # Determine the symbol to use
            if current_state:
                if last_state is None:
                    # New connection
                    symbol = self.SYMBOLS['new']
                elif current_state == 'LISTEN':
                    symbol = self.SYMBOLS['listen']
                elif current_state == 'ESTABLISHED':
                    symbol = self.SYMBOLS['active']
                else:
                    symbol = self.SYMBOLS['active']

                # Update known IPs
                self.known_ips[ip] = {
                    'state': current_state,
                    'last_seen': self.current_column
                }
            else:
                # Connection no longer present
                if last_state is not None:
                    symbol = self.SYMBOLS['closed']
                    # Remove from known IPs after showing closed state
                    if ip in self.known_ips:
                        del self.known_ips[ip]
                else:
                    symbol = self.SYMBOLS['empty']

            # Add symbol to this IP's timeline
            self.connections[ip].append(symbol)

            # Track activity
            if symbol != self.SYMBOLS['empty']:
                self.ip_metadata.setdefault(ip, {
                    'first_seen': self.current_column,
                    'total_activity': 0,
                    'ports': set()
                })
                self.ip_metadata[ip]['total_activity'] += 1

    def colorize_symbol(self, symbol):
        """Apply color to a symbol."""
        if self.no_color:
            return symbol

        for key, sym in self.SYMBOLS.items():
            if symbol == sym:
                color = self.SYMBOL_COLORS.get(key, '')
                return f"{color}{symbol}{Colors.RESET}"
        return symbol

    def render_timeline(self):
        """Render the timeline to console."""
        # Get all IPs sorted by activity
        active_ips = sorted(
            [ip for ip in self.connections.keys()
             if any(s != self.SYMBOLS['empty'] for s in self.connections[ip])],
            key=lambda x: self.ip_metadata.get(x, {}).get('total_activity', 0),
            reverse=True
        )

        if self.scroll_mode:
            self._render_scroll_mode(active_ips)
        else:
            self._render_refresh_mode(active_ips)

    def _render_refresh_mode(self, active_ips):
        """Render in refresh mode (clears screen each time)."""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')

        elapsed = time.time() - self.start_time

        # Simple, clean header
        print(f"\n{Colors.BOLD}Network Connection Monitor{Colors.RESET}")
        print(f"Time: {elapsed:.0f}s | Interval: {self.time_unit}s | IPs: {len(active_ips)}")
        print()

        # Legend - simple and clear
        print(f"{Colors.GREEN}▲{Colors.RESET} New   "
              f"{Colors.BLUE}■{Colors.RESET} Active   "
              f"{Colors.YELLOW}○{Colors.RESET} Listen   "
              f"{Colors.RED}×{Colors.RESET} Closed   "
              f"{Colors.BRIGHT_BLACK}·{Colors.RESET} Empty")
        print()

        if not active_ips:
            print(f"{Colors.DIM}Waiting for connections...{Colors.RESET}")
            return

        # Print each IP's timeline with clear formatting
        for ip in active_ips:
            timeline = self.connections[ip]

            # Pad timeline to current column if needed
            while len(timeline) < self.current_column + 1:
                timeline.append(self.SYMBOLS['empty'])

            # Truncate to max width
            visible_timeline = timeline[-self.max_width:]

            # Colorize timeline
            colored_timeline = ''.join([self.colorize_symbol(s) for s in visible_timeline])

            # Get display name (hostname or IP)
            if self.resolve_names:
                display_name = self._get_display_name(ip)
                if display_name != ip and '(resolving...)' not in display_name:
                    # Successfully resolved hostname
                    if len(display_name) > 35:
                        display_name = display_name[:32] + "..."
                    ip_label = f"{display_name:<40}"
                else:
                    # Could not resolve or still resolving - show IP
                    ip_label = f"{ip:<40}"
            else:
                ip_label = f"{ip:<40}"

            # Current state and ports (clean and simple)
            info_parts = []

            # Always show IP first if name resolution is enabled (whether successful or not)
            if self.resolve_names:
                info_parts.append(f"{Colors.DIM}{ip}{Colors.RESET}")

            # Add GeoIP info if available
            if self.geoip and self.geoip.enabled:
                country, asn_num, asn_name = self.geoip.lookup(ip)
                if country and self.geoip.enable_country:
                    info_parts.append(f"{Colors.BRIGHT_YELLOW}{country}{Colors.RESET}")
                if asn_num and asn_name and self.geoip.enable_asn:
                    # Truncate ASN name if too long
                    asn_display = asn_name if len(asn_name) <= 20 else asn_name[:17] + "..."
                    info_parts.append(f"{Colors.BRIGHT_BLUE}AS{asn_num} {asn_display}{Colors.RESET}")

            if ip in self.known_ips:
                state = self.known_ips[ip]['state']
                if state == 'ESTABLISHED':
                    info_parts.append(f"{Colors.GREEN}ACTIVE{Colors.RESET}")
                elif state == 'LISTEN':
                    info_parts.append(f"{Colors.YELLOW}LISTEN{Colors.RESET}")
                else:
                    info_parts.append(f"{Colors.DIM}{state}{Colors.RESET}")

            if ip in self.ip_metadata and self.ip_metadata[ip]['ports']:
                ports = sorted(self.ip_metadata[ip]['ports'])
                if len(ports) <= 3:
                    port_str = ','.join(map(str, ports))
                else:
                    port_str = f"{','.join(map(str, ports[:2]))}+{len(ports)-2}"
                info_parts.append(f"Port:{port_str}")

            info_str = f" [{' | '.join(info_parts)}]" if info_parts else ""

            print(f"{ip_label} {colored_timeline}{info_str}")

        print(f"\n{Colors.DIM}Press Ctrl+C to stop{Colors.RESET}")

    def _render_scroll_mode(self, active_ips):
        """Render in scroll mode (doesn't clear screen, easier to copy text)."""
        # Only print updates when something changes
        current_ip_count = len(active_ips)

        if self.current_column == 0:
            # Initial header
            print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
            print(f"{Colors.BOLD}Network Connection Monitor - Scroll Mode{Colors.RESET}")
            print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
            print(f"Interval: {self.time_unit}s per symbol")
            print(f"{Colors.BOLD}{'='*80}{Colors.RESET}\n")

            print(f"{Colors.GREEN}▲{Colors.RESET}=New  "
                  f"{Colors.BLUE}■{Colors.RESET}=Active  "
                  f"{Colors.YELLOW}○{Colors.RESET}=Listen  "
                  f"{Colors.RED}×{Colors.RESET}=Closed  "
                  f"{Colors.BRIGHT_BLACK}·{Colors.RESET}=Empty\n")
            self.last_ip_count = current_ip_count
            return

        # Print updates only for new IPs or state changes
        for ip in active_ips:
            if ip not in self.ip_metadata or self.ip_metadata[ip].get('first_seen', 0) == self.current_column:
                # New IP detected
                ports = sorted(self.ip_metadata.get(ip, {}).get('ports', set()))
                port_str = f":{','.join(map(str, ports[:3]))}" if ports else ""

                state = self.known_ips.get(ip, {}).get('state', 'UNKNOWN')
                if state == 'ESTABLISHED':
                    state_color = Colors.GREEN
                elif state == 'LISTEN':
                    state_color = Colors.YELLOW
                else:
                    state_color = Colors.WHITE

                timestamp = datetime.now().strftime('%H:%M:%S')

                # Build geo info string
                geo_str = ""
                if self.geoip and self.geoip.enabled:
                    country, asn_num, asn_name = self.geoip.lookup(ip)
                    geo_parts = []
                    if country and self.geoip.enable_country:
                        geo_parts.append(f"{Colors.BRIGHT_YELLOW}{country}{Colors.RESET}")
                    if asn_num and asn_name and self.geoip.enable_asn:
                        asn_display = asn_name if len(asn_name) <= 15 else asn_name[:12] + "..."
                        geo_parts.append(f"{Colors.BRIGHT_BLUE}AS{asn_num} {asn_display}{Colors.RESET}")
                    if geo_parts:
                        geo_str = f" [{' | '.join(geo_parts)}]"

                # Get display name if resolution enabled
                if self.resolve_names:
                    display_name = self._get_display_name(ip)
                    if display_name != ip and '(resolving...)' not in display_name:
                        # Show hostname with IP in brackets
                        if len(display_name) > 35:
                            display_name = display_name[:32] + "..."
                        print(f"[{timestamp}] {Colors.GREEN}NEW{Colors.RESET} → {Colors.BOLD}{display_name:<40}{Colors.RESET} "
                              f"({Colors.DIM}{ip}{Colors.RESET}){geo_str} {state_color}{state}{Colors.RESET}{port_str}")
                    else:
                        print(f"[{timestamp}] {Colors.GREEN}NEW{Colors.RESET} → {Colors.BOLD}{ip:<40}{Colors.RESET}{geo_str} "
                              f"{state_color}{state}{Colors.RESET}{port_str}")
                else:
                    print(f"[{timestamp}] {Colors.GREEN}NEW{Colors.RESET} → {Colors.BOLD}{ip:<40}{Colors.RESET}{geo_str} "
                          f"{state_color}{state}{Colors.RESET}{port_str}")

        # Print periodic status update every 10 intervals
        if self.current_column % 10 == 0 and self.current_column > 0:
            elapsed = time.time() - self.start_time
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"\n{Colors.DIM}[{timestamp}] Status: {len(active_ips)} active IPs | "
                  f"Runtime: {elapsed:.0f}s | Column: {self.current_column}{Colors.RESET}\n")

    def save_to_file(self, filename=None):
        """Save the timeline to a text file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_timeline_{timestamp}.txt"

        try:
            # Temporarily disable colors for file output
            colors_enabled = not self.no_color
            if colors_enabled:
                Colors.disable()

            with open(filename, 'w', encoding='utf-8') as f:
                # Write header
                elapsed = time.time() - self.start_time
                f.write("=" * 100 + "\n")
                f.write(f"Network Connection Monitor Timeline\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Runtime: {elapsed:.1f}s\n")
                f.write(f"Time unit: {self.time_unit}s per character\n")
                f.write(f"Total Columns: {self.current_column}\n")
                if self.geoip and self.geoip.enabled:
                    f.write(f"\nIP Geolocation by DB-IP (https://db-ip.com)\n")
                    f.write(f"Licensed under Creative Commons Attribution 4.0 International License\n")
                f.write("=" * 100 + "\n\n")

                # Write legend
                f.write(f"Legend: {self.SYMBOLS['new']}=New  {self.SYMBOLS['active']}=Active  "
                        f"{self.SYMBOLS['listen']}=Listen  {self.SYMBOLS['closed']}=Closed  "
                        f"{self.SYMBOLS['empty']}=Empty\n")
                f.write("-" * 100 + "\n\n")

                # Get all IPs with activity, sorted by total activity
                active_ips = sorted(
                    [ip for ip in self.connections.keys()
                     if any(s != self.SYMBOLS['empty'] for s in self.connections[ip])],
                    key=lambda x: self.ip_metadata.get(x, {}).get('total_activity', 0),
                    reverse=True
                )

                # Write timeline for each IP
                for ip in active_ips:
                    timeline = self.connections[ip]

                    # Pad timeline if needed
                    while len(timeline) < self.current_column + 1:
                        timeline.append(self.SYMBOLS['empty'])

                    timeline_str = ''.join(timeline)

                    # IP label (left-aligned for consistency with display, handles IPv6)
                    ip_label = f"{ip:<40}"

                    # Metadata
                    metadata = self.ip_metadata.get(ip, {})
                    first_seen = metadata.get('first_seen', 0)
                    total_activity = metadata.get('total_activity', 0)
                    ports = sorted(metadata.get('ports', set()))
                    port_str = ','.join(map(str, ports[:5]))
                    if len(ports) > 5:
                        port_str += f"+{len(ports)-5}"

                    # GeoIP info
                    geo_info = ""
                    if self.geoip and self.geoip.enabled:
                        country, asn_num, asn_name = self.geoip.lookup(ip)
                        geo_parts = []
                        if country:
                            geo_parts.append(f"Country: {country}")
                        if asn_num and asn_name:
                            geo_parts.append(f"ASN: AS{asn_num} {asn_name}")
                        if geo_parts:
                            geo_info = " | " + " | ".join(geo_parts)

                    f.write(f"{ip_label} │ {timeline_str}\n")
                    f.write(f"{'':40}   First seen: col {first_seen} | "
                            f"Activity: {total_activity} | Ports: {port_str}{geo_info}\n\n")

                # Write statistics
                f.write("-" * 100 + "\n")
                f.write(f"\nStatistics:\n")
                f.write(f"  Total unique IPs: {len(active_ips)}\n")
                f.write(f"  Total timeline columns: {self.current_column}\n")
                f.write(f"  Monitoring duration: {elapsed:.1f}s\n")
                f.write(f"  Time per column: {self.time_unit}s\n")

                # Top 10 most active IPs
                f.write(f"\nTop 10 Most Active IPs:\n")
                for idx, ip in enumerate(active_ips[:10], 1):
                    activity = self.ip_metadata[ip]['total_activity']
                    geo_suffix = ""
                    if self.geoip and self.geoip.enabled:
                        country, asn_num, asn_name = self.geoip.lookup(ip)
                        if country or asn_num:
                            geo_parts = []
                            if country:
                                geo_parts.append(country)
                            if asn_num:
                                geo_parts.append(f"AS{asn_num}")
                            geo_suffix = f" [{', '.join(geo_parts)}]"
                    f.write(f"  {idx:2d}. {ip:<40} - {activity} time units active{geo_suffix}\n")

            # Re-enable colors if they were enabled
            if colors_enabled:
                self.no_color = False

            return filename

        except Exception as e:
            print(f"{Colors.BRIGHT_RED}Error saving file: {e}{Colors.RESET}")
            return None

    def save_frequent_ips(self, threshold_percent):
        """Save IPs that were connected more than threshold% of the time."""
        if self.current_column == 0:
            print(f"{Colors.RED}✗{Colors.RESET} No data collected yet")
            return None

        # Calculate which IPs meet the threshold
        frequent_ips = []
        for ip, timeline in self.connections.items():
            if not timeline:
                continue

            # Calculate connection percentage
            active_time = sum(1 for s in timeline if s != self.SYMBOLS['empty'])
            connection_percent = (active_time / len(timeline)) * 100

            if connection_percent >= threshold_percent:
                frequent_ips.append((ip, connection_percent, active_time))

        if not frequent_ips:
            print(f"{Colors.YELLOW}No IPs found with ≥{threshold_percent}% connection time{Colors.RESET}")
            return None

        # Sort by connection percentage
        frequent_ips.sort(key=lambda x: x[1], reverse=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"frequent_ips_{threshold_percent}pct_{timestamp}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"# Frequent IP Addresses\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Threshold: {threshold_percent}% connection time\n")
                f.write(f"# Total monitoring time: {self.current_column} columns ({self.current_column * self.time_unit:.1f}s)\n")
                f.write(f"# Found {len(frequent_ips)} IPs meeting criteria\n")
                f.write(f"#\n")
                f.write(f"# Format: IP_ADDRESS (connection_percentage%, active_time_units)\n")
                f.write(f"#\n\n")

                for ip, percent, active_time in frequent_ips:
                    f.write(f"{ip}\n")
                    f.write(f"# {percent:.1f}% connected ({active_time}/{self.current_column} time units)\n")

            return filename, len(frequent_ips)

        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error saving frequent IPs: {e}")
            return None

    def run(self):
        """Run the monitoring loop."""
        if not self.scroll_mode:
            print(f"\n{Colors.BOLD}Starting Network Connection Monitor{Colors.RESET}")
            print(f"Mode: Refresh | Interval: {self.time_unit}s | Width: {self.max_width}")
            if self.output_file:
                print(f"Auto-save to: {self.output_file}")
            print(f"{Colors.DIM}Press Ctrl+C to stop{Colors.RESET}")
            time.sleep(2)

        try:
            while True:
                self.update_timeline()
                self.render_timeline()
                self.current_column += 1
                time.sleep(self.time_unit)

        except KeyboardInterrupt:
            print(f"\n\n{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"{Colors.BOLD}Monitoring Stopped{Colors.RESET}")
            print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

            elapsed = time.time() - self.start_time
            print(f"Runtime: {elapsed:.1f}s")
            print(f"Unique IPs: {len(self.connections)}")
            print(f"Total columns: {self.current_column}")

            # Save timeline to file
            save_it = False
            if self.output_file:
                save_it = True
            else:
                response = input(f"\nSave timeline to file? (y/n): ").lower()
                save_it = response.startswith('y')

            if save_it:
                filename = self.save_to_file(self.output_file)
                if filename:
                    print(f"{Colors.GREEN}✓{Colors.RESET} Saved to: {filename}")
                else:
                    print(f"{Colors.RED}✗{Colors.RESET} Save failed")

            # Save frequent IPs if threshold was set or user wants to
            if self.save_threshold is not None:
                result = self.save_frequent_ips(self.save_threshold)
                if result:
                    filename, count = result
                    print(f"{Colors.GREEN}✓{Colors.RESET} Saved {count} frequent IPs (≥{self.save_threshold}%) to: {filename}")
            else:
                response = input(f"\nSave frequently connected IPs to filter list? (y/n): ").lower()
                if response.startswith('y'):
                    try:
                        threshold = float(input(f"Enter connection threshold percentage (e.g., 50): "))
                        result = self.save_frequent_ips(threshold)
                        if result:
                            filename, count = result
                            print(f"{Colors.GREEN}✓{Colors.RESET} Saved {count} frequent IPs (≥{threshold}%) to: {filename}")
                            print(f"{Colors.DIM}Use --filter-file {filename} to filter these IPs next time{Colors.RESET}")
                    except ValueError:
                        print(f"{Colors.RED}✗{Colors.RESET} Invalid threshold value")

            sys.exit(0)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Monitor network connections with timeline visualization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Default: show all IPs
  %(prog)s --scroll                           # Scroll mode (easier to copy)
  %(prog)s --resolve-names                    # Show hostnames instead of IPs
  %(prog)s --lookup-country                   # Show country codes only
  %(prog)s --lookup-asn                       # Show ASN info only
  %(prog)s --lookup-country --lookup-asn      # Show both country and ASN
  %(prog)s --filter-local                     # Hide local/private IPs
  %(prog)s --filter-file blocked.txt          # Hide IPs from file
  %(prog)s --save-threshold 50                # Auto-save IPs connected ≥50%% of time
  %(prog)s --resolve-names --lookup-country --lookup-asn  # Full info
  %(prog)s -t 0.5 -w 120                      # Fast updates, wide display
        '''
    )
    parser.add_argument(
        '-t', '--time-unit',
        type=float,
        default=1.0,
        help='Time in seconds per character column (default: 1.0)'
    )
    parser.add_argument(
        '-w', '--width',
        type=int,
        default=80,
        help='Maximum timeline width in characters (default: 80)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output file to save timeline on exit'
    )
    parser.add_argument(
        '--scroll',
        action='store_true',
        help='Use scroll mode instead of refresh (easier to copy text)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--filter-local',
        action='store_true',
        help='Filter out local/private IP addresses'
    )
    parser.add_argument(
        '--filter-file',
        type=str,
        default=None,
        help='Path to file containing IPs to filter out (one per line)'
    )
    parser.add_argument(
        '--save-threshold',
        type=float,
        default=None,
        help='Auto-save IPs connected more than X%% of time (e.g., 50)'
    )
    parser.add_argument(
        '--resolve-names',
        action='store_true',
        help='Enable DNS name resolution for IP addresses'
    )
    parser.add_argument(
        '--lookup-country',
        action='store_true',
        help='Enable country lookups (requires DB-IP database - https://db-ip.com)'
    )
    parser.add_argument(
        '--lookup-asn',
        action='store_true',
        help='Enable ASN lookups (requires DB-IP database - https://db-ip.com)'
    )
    parser.add_argument(
        '--geo-path',
        type=str,
        default=None,
        help='Path to directory containing DB-IP CSV files (default: script directory)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.time_unit <= 0:
        print(f"{Colors.RED}ERROR: Time unit must be positive{Colors.RESET}")
        sys.exit(1)

    if args.width < 20 or args.width > 500:
        print(f"{Colors.RED}ERROR: Width must be between 20 and 500{Colors.RESET}")
        sys.exit(1)

    if args.save_threshold is not None and (args.save_threshold < 0 or args.save_threshold > 100):
        print(f"{Colors.RED}ERROR: Threshold must be between 0 and 100{Colors.RESET}")
        sys.exit(1)

    # Check if running with sufficient permissions
    try:
        psutil.net_connections()
    except psutil.AccessDenied:
        print(f"\n{Colors.RED}ERROR: Insufficient permissions{Colors.RESET}")
        print("Please run with administrator/root privileges:")
        if os.name == 'nt':
            print("  → Run as Administrator (Windows)")
        else:
            print("  → Use 'sudo' (Linux/Mac)")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}ERROR: Failed to access network connections: {e}{Colors.RESET}")
        sys.exit(1)

    # Enable ANSI colors on Windows
    if os.name == 'nt' and not args.no_color:
        os.system('')

    # Initialize GeoIP lookup if requested
    geoip = None
    if args.lookup_country or args.lookup_asn:
        geoip = GeoIPLookup(
            geo_path=args.geo_path,
            enable_country=args.lookup_country,
            enable_asn=args.lookup_asn
        )
        geoip.load_databases()

    # Show active filters
    filters_active = []
    if args.filter_local:
        filters_active.append("local IPs")
    if args.filter_file:
        filters_active.append(f"IPs from {args.filter_file}")

    if filters_active:
        print(f"{Colors.YELLOW}Active filters:{Colors.RESET} {', '.join(filters_active)}")

    if args.resolve_names:
        print(f"{Colors.CYAN}DNS resolution:{Colors.RESET} enabled (may be slower)")

    monitor = ConnectionMonitor(
        time_unit=args.time_unit,
        max_width=args.width,
        no_color=args.no_color,
        output_file=args.output,
        scroll_mode=args.scroll,
        filter_local=args.filter_local,
        filter_file=args.filter_file,
        save_threshold=args.save_threshold,
        resolve_names=args.resolve_names,
        geoip_lookup=geoip
    )
    monitor.run()


if __name__ == '__main__':
    main()
