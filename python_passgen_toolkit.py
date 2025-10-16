"""
Python-PassGen Toolkit
Author: Mishari Ghanem
Date: 2025-10-16
Purpose: Combined CLI toolkit for educational security tools
Notes: Includes password generator, manager, Caesar cipher, WHOIS lookup, and Nmap scan.
"""

import random
import string
import hashlib
import getpass
import socket
from datetime import datetime
import nmap

# -------------------------
# Password Generator
# -------------------------
def generate_password(length: int = 10):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(alphabet) for _ in range(length))
    return password

# -------------------------
# Password Manager
# -------------------------
password_manager = {}

def create_account():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    password_manager[username] = hashed_password
    print("Account created successfully!")

def login():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if username in password_manager and password_manager[username] == hashed_password:
        print("User logged in successfully!")
    else:
        print("Failed to log in!")

# -------------------------
# Caesar Cipher
# -------------------------
def caesar_encrypt(message: str, key: int) -> str:
    shift = key % 26
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    cipher_lower = str.maketrans(lower, lower[shift:] + lower[:shift])
    cipher_upper = str.maketrans(upper, upper[shift:] + upper[:shift])
    return message.translate(cipher_lower).translate(cipher_upper)

def caesar_decrypt(message: str, key: int) -> str:
    shift = 26 - (key % 26)
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    cipher_lower = str.maketrans(lower, lower[shift:] + lower[:shift])
    cipher_upper = str.maketrans(upper, upper[shift:] + upper[:shift])
    return message.translate(cipher_lower).translate(cipher_upper)

# -------------------------
# WHOIS Lookup
# -------------------------
def whois_lookup(domain: str, log_file="mishari_whois_log.txt"):
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

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"\n--- {timestamp} [MG] ---\nDomain: {domain}\n{final_result}\n")
    return final_result

# -------------------------
# Nmap Scanner
# -------------------------
def nmap_scan(target, output_file="scan_results.txt"):
    nm = nmap.PortScanner()
    options = "-sV -sC -oN " + output_file
    print(f"[+] Scanning {target} with arguments: {options}")
    nm.scan(target, arguments="-sV -sC")
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})  State: {nm[host].state()}")
        for protocol in nm[host].all_protocols():
            print(f"  Protocol: {protocol}")
            for port, info in nm[host][protocol].items():
                print(f"    Port: {port}  State: {info['state']}")
    print(f"[+] Scan results saved to {output_file}")

# -------------------------
# Main CLI
# -------------------------
def main():
    while True:
        print("\n=== Python-PassGen Toolkit ===")
        print("1 - Generate Password")
        print("2 - Password Manager (create/login)")
        print("3 - Caesar Cipher (encrypt/decrypt)")
        print("4 - WHOIS Lookup")
        print("5 - Nmap Scan")
        print("0 - Exit")
        choice = input("Select an option: ")

        if choice == "1":
            length_input = input("Enter password length: ")
            if length_input.isdigit():
                length = int(length_input)
                print("Generated password:", generate_password(length))
            else:
                print("Invalid input! Please enter a number.")
        elif choice == "2":
            while True:
                pm_choice = input("Enter 1 to create account, 2 to login, 0 to go back: ")
                if pm_choice == "1":
                    create_account()
                elif pm_choice == "2":
                    login()
                elif pm_choice == "0":
                    break
                else:
                    print("Invalid choice, please enter 1, 2, or 0.")
        elif choice == "3":
            msg = input("Enter message: ")
            while True:
                key_input = input("Enter shift key (integer): ")
                if key_input.isdigit():
                    key = int(key_input)
                    break
                else:
                    print("Invalid input! Please enter a numeric key.")
            action = input("Enter 'e' to encrypt or 'd' to decrypt: ").lower()
            if action == "e":
                print("Encrypted:", caesar_encrypt(msg, key))
            elif action == "d":
                print("Decrypted:", caesar_decrypt(msg, key))
            else:
                print("Invalid choice! Enter 'e' or 'd'.")
        elif choice == "4":
            domain = input("Mishari’s WHOIS Tool > Enter domain (e.g., google.com): ")
            print(whois_lookup(domain))
            print("[+] Lookup completed and logged.")
        elif choice == "5":
            target = input("Enter target IP or hostname: ")
            nmap_scan(target)
        elif choice == "0":
            print("Exiting Python-PassGen Toolkit.")
            break
        else:
            print("Invalid choice! Please select a valid option.")

if __name__ == "__main__":
    main()
