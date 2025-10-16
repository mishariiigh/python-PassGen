"""
python_whois.py
Author: Mishari Ghanem
Date: 2025-10-16
Purpose: Lightweight WHOIS lookup tool for educational and authorized network research.
Notes: Part of Mishari’s Python_PassGen toolkit.
"""

import socket
from datetime import datetime

def whois_lookup(domain: str, log_file="mishari_whois_log.txt"):
    """
    Perform a WHOIS lookup on a domain by querying IANA then the authoritative server.
    Results are logged to a file for reference.
    """
    # Step 1: Query IANA for the TLD authoritative server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.iana.org", 43))
    s.send(f"{domain}\r\n".encode())
    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data
    s.close()

    response_text = response.decode(errors="ignore")
    whois_server = None
    for line in response_text.splitlines():
        if line.lower().startswith("whois:"):
            whois_server = line.split(":")[1].strip()
            break

    # Step 2: Query the authoritative server if found
    if whois_server:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((whois_server, 43))
        s.send(f"{domain}\r\n".encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        final_result = response.decode(errors="ignore")
    else:
        final_result = response_text

    # Step 3: Log the result with timestamp and initials
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"\n--- {timestamp} [MG] ---\nDomain: {domain}\n{final_result}\n")
    return final_result

if __name__ == "__main__":
    domain = input("Mishari’s WHOIS Tool > Enter domain (e.g., google.com): ")
    result = whois_lookup(domain)
    print(result)
    print(f"[+] Lookup completed and logged to mishari_whois_log.txt")
