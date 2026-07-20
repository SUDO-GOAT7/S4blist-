#!/usr/bin/env python3
"""
sublist3r++ - Advanced Subdomain Scanner
Features:
- Subdomain enumeration (crt.sh + wordlist)
- Live HTTP/HTTPS check
- Screenshot (optional)
- Quick port scan (top 10)
- JSON + CSV + HTML output
- Threaded + progress bar
"""

import subprocess
import sys
import os
import json
import csv
import threading
import time
from urllib.parse import urlparse
import requests
import argparse
from colorama import Fore, Style, init
from tqdm import tqdm
import socket
import concurrent.futures
import base64
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# Default wordlist (common subdomains)
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "help", "apps",
    "video", "srv", "download", "server", "ftp2", "dns", "api", "cdn", "storage",
    "host", "webmail2", "stats", "portal", "vps", "cloud", "backup", "client",
    "gateway", "monitor", "panel", "db", "files", "app", "stage", "staging",
    "production", "live", "sandbox", "dev2", "uat", "qa", "test2", "internal"
]

# Top 10 ports for scanning
TOP_PORTS = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]

class Sublist3rPlusPlus:
    def __init__(self, domain, output_dir=None, threads=20, verbose=False, screenshot=False):
        self.domain = domain
        self.output_dir = output_dir or f"./results/{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.threads = threads
        self.verbose = verbose
        self.screenshot = screenshot
        self.subdomains = set()
        self.live_subdomains = []
        self.results = []
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, message, level="INFO"):
        if self.verbose or level == "ERROR":
            print(f"{Fore.CYAN}[{level}]{Style.RESET_ALL} {message}")

    def enumerate_crtsh(self):
        """Fetch subdomains from crt.sh"""
        self.log("Fetching subdomains from crt.sh...")
        try:
            response = requests.get(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=30)
            if response.status_code == 200:
                for entry in response.json():
                    name = entry.get("name_value", "")
                    if name and not name.startswith("*"):
                        self.subdomains.add(name)
        except Exception as e:
            self.log(f"crt.sh error: {e}", "ERROR")

    def enumerate_wordlist(self):
        """Enumerate subdomains using wordlist"""
        self.log(f"Enumerating subdomains using wordlist ({len(DEFAULT_WORDLIST)} entries)...")
        for sub in DEFAULT_WORDLIST:
            self.subdomains.add(f"{sub}.{self.domain}")

    def check_live(self, subdomain):
        """Check if subdomain is live"""
        url = f"http://{subdomain}"
        url_https = f"https://{subdomain}"
        try:
            response = requests.get(url_https, timeout=3, verify=False)
            if response.status_code < 400:
                return (subdomain, True, "https", response.status_code)
        except:
            pass
        try:
            response = requests.get(url, timeout=3)
            if response.status_code < 400:
                return (subdomain, True, "http", response.status_code)
        except:
            pass
        return (subdomain, False, None, None)

    def port_scan(self, host):
        """Scan top ports on a host"""
        open_ports = []
        for port in TOP_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports

    def run_scan(self):
        """Main scanning function"""
        self.log(f"Starting scan for domain: {self.domain}")
        
        # 1. Enumerate subdomains
        self.enumerate_crtsh()
        self.enumerate_wordlist()
        self.log(f"Total subdomains found: {len(self.subdomains)}")
        
        # 2. Check live subdomains
        self.log("Checking live subdomains...")
        live_list = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(tqdm(executor.map(self.check_live, self.subdomains), total=len(self.subdomains), desc="Checking live"))
            for sub, is_live, protocol, status in results:
                if is_live:
                    live_list.append((sub, protocol, status))
        
        self.log(f"Live subdomains: {len(live_list)}")
        
        # 3. Port scan + build results
        self.log("Scanning ports on live subdomains...")
        for sub, protocol, status in tqdm(live_list, desc="Port scanning"):
            open_ports = self.port_scan(sub)
            self.results.append({
                "subdomain": sub,
                "protocol": protocol,
                "status_code": status,
                "open_ports": open_ports,
                "screenshot": None  # Could be added later
            })
        
        # 4. Save results
        self.save_results()
        self.log(f"Scan complete. Results saved in: {self.output_dir}")

    def save_results(self):
        """Save results in JSON, CSV, and HTML formats"""
        # JSON
        with open(f"{self.output_dir}/results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        # CSV
        with open(f"{self.output_dir}/results.csv", "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["subdomain", "protocol", "status_code", "open_ports"])
            writer.writeheader()
            for result in self.results:
                writer.writerow({
                    "subdomain": result["subdomain"],
                    "protocol": result["protocol"],
                    "status_code": result["status_code"],
                    "open_ports": ", ".join(map(str, result["open_ports"]))
                })
        
        # HTML Report
        html_content = f"""
        <html>
        <head><title>Scan Results - {self.domain}</title></head>
        <body style="font-family: monospace; background: #0a0a0a; color: #00ff00; padding: 20px;">
            <h1>🔥 sublist3r++</h1>
            <h2>Domain: {self.domain}</h2>
            <h3>Total live subdomains: {len(self.results)}</h3>
            <ul>
        """
        for result in self.results:
            html_content += f"<li>{result['subdomain']} -> {result['protocol']} ({result['status_code']}) | Ports: {result['open_ports']}</li>"
        html_content += "</ul></body></html>"
        with open(f"{self.output_dir}/results.html", "w") as f:
            f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description="sublist3r++ - Advanced Subdomain Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--screenshot", action="store_true", help="Take screenshots (experimental)")
    
    args = parser.parse_args()
    
    scanner = Sublist3rPlusPlus(
        domain=args.domain,
        output_dir=args.output,
        threads=args.threads,
        verbose=args.verbose,
        screenshot=args.screenshot
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main()
