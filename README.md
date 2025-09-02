# Network-Scanner-Port-Discovery-Tool
#!/usr/bin/env python3
"""
Advanced Network Scanner & Port Discovery Tool
A comprehensive network reconnaissance tool with host discovery, port scanning,
service detection, OS fingerprinting, and report generation.
"""

import socket
import threading
import subprocess
import argparse
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
import ipaddress
import sys
import time
import random
import struct
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

class NetworkScanner:
    def __init__(self, threads=100, timeout=3):
        self.threads = threads
        self.timeout = timeout
        self.scan_results = {}
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        self.service_banners = {}
        
        # Common service signatures
        self.service_signatures = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP-Proxy"
        }

    def ping_sweep(self, network):
        """Perform ping sweep to discover active hosts"""
        print(f"[*] Starting ping sweep on {network}")
        active_hosts = []
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError:
            print(f"[!] Invalid network format: {network}")
            return active_hosts

        def ping_host(ip):
            try:
                # Use system ping command
                if sys.platform.startswith('win'):
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                          capture_output=True, text=True)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                          capture_output=True, text=True)
                
                if result.returncode == 0:
                    return str(ip)
            except Exception:
                pass
            return None

        # Use ThreadPoolExecutor for concurrent pings
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in network_obj.hosts()}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    print(f"[+] Host {result} is alive")

        print(f"[*] Found {len(active_hosts)} active hosts")
        return active_hosts

    def scan_port(self, host, port):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Try to grab banner
                banner = self.grab_banner(sock, port)
                sock.close()
                return port, banner
            else:
                sock.close()
                return None
        except Exception:
            return None

    def grab_banner(self, sock, port):
        """Attempt to grab service banner"""
        try:
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            else:
                sock.send(b"\r\n")
            
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]  # Limit banner length
        except Exception:
            return ""

    def port_scan(self, host, ports=None):
        """Scan ports on a specific host"""
        if ports is None:
            ports = self.common_ports
            
        print(f"[*] Scanning {host} for open ports...")
        open_ports = []
        
        def scan_single_port(port):
            result = self.scan_port(host, port)
            if result:
                return result
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_single_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, banner = result
                    service = self.identify_service(port, banner)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner
                    })
                    print(f"[+] {host}:{port} ({service}) - {banner[:50]}")

        return sorted(open_ports, key=lambda x: x['port'])

    def identify_service(self, port, banner):
        """Identify service based on port and banner"""
        # Check predefined service signatures first
        service = self.service_signatures.get(port, f"Unknown ({port})")
        
        # Enhance identification based on banner
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = f"SSH - {banner.split()[0]}"
            elif 'ftp' in banner_lower:
                service = f"FTP - {banner.split()[0]}"
            elif 'http' in banner_lower or 'server:' in banner_lower:
                service = "HTTP"
                if 'nginx' in banner_lower:
                    service = "HTTP (nginx)"
                elif 'apache' in banner_lower:
                    service = "HTTP (Apache)"
            elif 'smtp' in banner_lower:
                service = "SMTP"
            elif 'mysql' in banner_lower:
                service = "MySQL"
        
        return service

    def os_fingerprint(self, host):
        """Basic OS fingerprinting using TTL and TCP window size"""
        print(f"[*] Attempting OS fingerprinting for {host}")
        
        try:
            # Try to get TTL value from ping
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', '1', host], 
                                      capture_output=True, text=True)
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:
                result = subprocess.run(['ping', '-c', '1', host], 
                                      capture_output=True, text=True)
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # Common TTL values for OS identification
                if ttl <= 64:
                    if ttl > 32:
                        return "Linux/Unix (TTL: {})".format(ttl)
                    else:
                        return "Network device (TTL: {})".format(ttl)
                elif ttl <= 128:
                    return "Windows (TTL: {})".format(ttl)
                elif ttl <= 255:
                    return "Cisco/Network device (TTL: {})".format(ttl)
            
            return "Unknown OS"
            
        except Exception as e:
            return f"OS detection failed: {str(e)}"

    def generate_port_range(self, port_range):
        """Generate list of ports from range string"""
        ports = []
        
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
            
        return ports

    def scan_network(self, network, port_range=None, ping_sweep_enabled=True):
        """Main scanning function"""
        print(f"\n{'='*60}")
        print(f"NETWORK SCANNER STARTED: {datetime.now()}")
        print(f"Target: {network}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Determine hosts to scan
        if ping_sweep_enabled:
            hosts = self.ping_sweep(network)
        else:
            try:
                network_obj = ipaddress.ip_network(network, strict=False)
                hosts = [str(ip) for ip in network_obj.hosts()]
            except ValueError:
                hosts = [network]  # Single host
        
        if not hosts:
            print("[!] No active hosts found")
            return {}
        
        # Determine ports to scan
        if port_range:
            ports = self.generate_port_range(port_range)
        else:
            ports = self.common_ports
        
        print(f"[*] Scanning {len(ports)} ports on {len(hosts)} hosts")
        
        # Scan each host
        for host in hosts:
            self.scan_results[host] = {
                'host': host,
                'os_guess': self.os_fingerprint(host),
                'scan_time': datetime.now().isoformat(),
                'open_ports': self.port_scan(host, ports)
            }
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        print(f"\n[*] Scan completed in {scan_duration:.2f} seconds")
        return self.scan_results

    def generate_report(self, output_format='txt', filename=None):
        """Generate scan report in various formats"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}"
        
        if output_format.lower() == 'json':
            self._generate_json_report(f"{filename}.json")
        elif output_format.lower() == 'csv':
            self._generate_csv_report(f"{filename}.csv")
        elif output_format.lower() == 'xml':
            self._generate_xml_report(f"{filename}.xml")
        else:
            self._generate_text_report(f"{filename}.txt")

    def _generate_text_report(self, filename):
        """Generate text report"""
        with open(filename, 'w') as f:
            f.write(f"NETWORK SCAN REPORT\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"{'='*60}\n\n")
            
            total_hosts = len(self.scan_results)
            total_open_ports = sum(len(host_data['open_ports']) for host_data in self.scan_results.values())
            
            f.write(f"SUMMARY:\n")
            f.write(f"Hosts scanned: {total_hosts}\n")
            f.write(f"Total open ports found: {total_open_ports}\n\n")
            
            for host, data in self.scan_results.items():
                f.write(f"HOST: {host}\n")
                f.write(f"OS Guess: {data['os_guess']}\n")
                f.write(f"Scan Time: {data['scan_time']}\n")
                f.write(f"Open Ports: {len(data['open_ports'])}\n")
                f.write("-" * 40 + "\n")
                
                for port_info in data['open_ports']:
                    f.write(f"  Port {port_info['port']}: {port_info['service']}\n")
                    if port_info['banner']:
                        f.write(f"    Banner: {port_info['banner']}\n")
                f.write("\n")
        
        print(f"[+] Text report saved to: {filename}")

    def _generate_json_report(self, filename):
        """Generate JSON report"""
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_hosts': len(self.scan_results),
                'total_open_ports': sum(len(host_data['open_ports']) for host_data in self.scan_results.values())
            },
            'results': self.scan_results
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"[+] JSON report saved to: {filename}")

    def _generate_csv_report(self, filename):
        """Generate CSV report"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Host', 'OS_Guess', 'Port', 'Service', 'Banner', 'Scan_Time'])
            
            for host, data in self.scan_results.items():
                if not data['open_ports']:
                    writer.writerow([host, data['os_guess'], 'None', 'None', 'None', data['scan_time']])
                else:
                    for port_info in data['open_ports']:
                        writer.writerow([
                            host,
                            data['os_guess'],
                            port_info['port'],
                            port_info['service'],
                            port_info['banner'],
                            data['scan_time']
                        ])
        
        print(f"[+] CSV report saved to: {filename}")

    def _generate_xml_report(self, filename):
        """Generate XML report"""
        root = ET.Element("NetworkScanReport")
        
        # Add scan info
        scan_info = ET.SubElement(root, "ScanInfo")
        ET.SubElement(scan_info, "Timestamp").text = datetime.now().isoformat()
        ET.SubElement(scan_info, "TotalHosts").text = str(len(self.scan_results))
        ET.SubElement(scan_info, "TotalOpenPorts").text = str(sum(len(host_data['open_ports']) for host_data in self.scan_results.values()))
        
        # Add results
        results = ET.SubElement(root, "Results")
        for host, data in self.scan_results.items():
            host_elem = ET.SubElement(results, "Host", ip=host)
            ET.SubElement(host_elem, "OSGuess").text = data['os_guess']
            ET.SubElement(host_elem, "ScanTime").text = data['scan_time']
            
            ports_elem = ET.SubElement(host_elem, "OpenPorts")
            for port_info in data['open_ports']:
                port_elem = ET.SubElement(ports_elem, "Port", number=str(port_info['port']))
                ET.SubElement(port_elem, "Service").text = port_info['service']
                ET.SubElement(port_elem, "Banner").text = port_info['banner']
        
        # Write to file
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        
        print(f"[+] XML report saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Network Scanner & Port Discovery Tool",
        epilog="Examples:\n"
               "  python scanner.py -t 192.168.1.0/24\n"
               "  python scanner.py -t 192.168.1.1 -p 1-1000\n"
               "  python scanner.py -t 10.0.0.0/16 -p 22,80,443 --no-ping\n"
               "  python scanner.py -t scanme.nmap.org -p 1-65535 -f json",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target network (CIDR) or single host')
    parser.add_argument('-p', '--ports',
                       help='Port range (e.g., 1-1000, 80,443,8080) or single port')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Socket timeout in seconds (default: 3)')
    parser.add_argument('--no-ping', action='store_true',
                       help='Skip ping sweep (scan all hosts in range)')
    parser.add_argument('-f', '--format', choices=['txt', 'json', 'csv', 'xml'],
                       default='txt', help='Output format (default: txt)')
    parser.add_argument('-o', '--output',
                       help='Output filename (without extension)')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = NetworkScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        # Perform scan
        results = scanner.scan_network(
            args.target,
            args.ports,
            ping_sweep_enabled=not args.no_ping
        )
        
        if results:
            # Generate report
            scanner.generate_report(args.format, args.output)
            
            # Print summary
            print(f"\n{'='*60}")
            print("SCAN SUMMARY")
            print(f"{'='*60}")
            print(f"Hosts scanned: {len(results)}")
            total_ports = sum(len(host_data['open_ports']) for host_data in results.values())
            print(f"Total open ports: {total_ports}")
            print(f"Report format: {args.format.upper()}")
        else:
            print("[!] No results to report")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
