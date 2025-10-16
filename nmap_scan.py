#!/usr/bin/env python3
"""
nmap_scan.py — small wrapper around python-nmap

USAGE WARNING:
  Only scan hosts you OWN or have EXPLICIT written permission to test.
  Misuse can be illegal or get you blocked by ISPs. See Nmap legal guide:
  https://nmap.org/book/legal-issues.html
"""

import sys
import nmap
from nmap import PortScanner, PortScannerError

def scan_target(target="127.0.0.1", output_file="scan_results.txt"):
    nm = PortScanner()


    args = f"-sV -sC -oN {output_file}"

    try:
        print(f"[+] Scanning {target} with arguments: {args}")
        nm.scan(hosts=target, arguments=args)
    except PortScannerError as e:
        print("[ERROR] nmap failed:", e, file=sys.stderr)
        return None
    except Exception as e:
        print("[ERROR] Unexpected error:", e, file=sys.stderr)
        return None

    return nm

def print_results(nm):
    if nm is None:
        print("[!] No results to show.")
        return

    hosts = nm.all_hosts()
    if not hosts:
        print("[!] nmap returned no hosts.")
        return

    for host in hosts:
        hostname = nm[host].hostname() or "(no hostname)"
        state = nm[host].state()
        print("\n" + "-"*60)
        print(f"Host: {host} ({hostname})  State: {state}")

        protocols = nm[host].all_protocols()
        if not protocols:
            print("  (no protocols found)")
            continue

        for proto in protocols:
            print(f"\n  Protocol: {proto}")
            ports = sorted(nm[host][proto].keys())
            if not ports:
                print("    (no ports found)")
                continue

            for port in ports:
                pdata = nm[host][proto][port]
                port_state = pdata.get("state", "unknown")
                service = pdata.get("name", "") or pdata.get("product", "") or "unknown"
                version = pdata.get("version", "")
                extra = pdata.get("extrainfo", "")
                svc = " ".join(filter(None, (service, version, extra))).strip()
                print(f"    port {port:<5}  state: {port_state:<6}  service: {svc}")

if __name__ == "__main__":

    target = "45.33.32.156"          # change only if you have permission
    nm = scan_target(target=target, output_file="scan_results.txt")
    print_results(nm)
    if nm:
        print("\n[+] Normal-format output saved to: scan_results.txt")
