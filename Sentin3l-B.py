import requests
import socket
import threading
import time
import pyfiglet
import random
import re
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

# Display Banner
print("\033[92m" + pyfiglet.figlet_format("SENTIN3L-B") + "\033[0m")

# Function to check if the input is an IP or domain
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip)

# Take input for target URL or IP
target = input("\nEnter a URL or IP address: ").strip()

# Display a warning message for additional port scanning
print("\033[91m[!!] Warning: Scanning additional ports may increase detection risk.\033[0m")
additional_ports = input("Do you want to scan additional ports? [Y/N]: ").strip().lower()

# Default essential ports
essential_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306]
if additional_ports == 'y':
    custom_ports = input("Enter additional ports (comma-separated, e.g., 221, 222, 223): ")
    try:
        extra_ports = [int(port.strip()) for port in custom_ports.split(",") if port.strip().isdigit()]
        scan_ports = essential_ports + extra_ports
    except ValueError:
        print("\033[91m[!] Invalid port input. Scanning only essential ports.\033[0m")
        scan_ports = essential_ports
else:
    scan_ports = essential_ports

# Port Scanning with Multithreading
print(f"\n[*] Scanning ports for {target}...\n")

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target.replace("http://", "").replace("https://", ""), port))
    s.close()
    return port if result == 0 else None

with ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(scan_port, scan_ports))

open_ports = [port for port in results if port]

# Display open ports
if open_ports:
    print("\033[92m[+] Open Ports Found:\033[0m")
    for port in open_ports:
        print(f"    🔓 Port {port} - Open")
else:
    print("\033[91m[!] No open ports detected.\033[0m")

# Detect CMS
print("\n[*] Detecting CMS...")
cms_detected = "Unknown"

try:
    response = requests.get(target, timeout=5)
    if "wp-content" in response.text:
        cms_detected = "WordPress"
    elif "Joomla" in response.text:
        cms_detected = "Joomla"
    elif "Drupal" in response.text:
        cms_detected = "Drupal"
except requests.exceptions.RequestException:
    print("\033[91m[!] Could not fetch website content.\033[0m")

print(f"🔍 Detected CMS: {cms_detected}")

# SQL Injection Testing
print("\n[*] Testing for SQL Injection...\n")
sql_payloads = ["'", "\"", "OR 1=1 --", "admin' --", "admin\" --"]

vulnerable = False
for payload in sql_payloads:
    test_url = f"{target}/?id={payload}"
    try:
        response = requests.get(test_url, timeout=5)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            vulnerable = True
            print(f"\033[91m[!] Possible SQL Injection Found! \033[0m")
            print(f"    💥 Payload Used: {payload}")
            break
    except requests.exceptions.RequestException:
        continue

if not vulnerable:
    print("\033[92m[+] No SQL Injection vulnerability detected.\033[0m")

# Directory Enumeration
print("\n[*] Enumerating directories...\n")
directories = ["admin", "login", "dashboard", "wp-admin", "config"]

found_dirs = []
for dir in directories:
    test_url = f"{target}/{dir}"
    try:
        response = requests.get(test_url, timeout=5)
        if response.status_code == 200:
            found_dirs.append(test_url)
            print(f"📂 Found: {test_url}")
    except requests.exceptions.RequestException:
        continue

if not found_dirs:
    print("\033[91m[!] No directories found.\033[0m")

# Web Application Firewall (WAF) Detection
print("\n[*] Checking for WAF presence...\n")
waf_detected = False
waf_headers = ["X-Sucuri-ID", "X-Firewall", "X-Mod-Security"]

try:
    response = requests.get(target, timeout=5)
    for header in waf_headers:
        if header in response.headers:
            waf_detected = True
            print(f"🚧 WAF Detected: {header}")
except requests.exceptions.RequestException:
    print("\033[91m[!] Could not perform WAF detection.\033[0m")

if not waf_detected:
    print("\033[92m[+] No WAF Detected.\033[0m")

# Security Headers Analysis
print("\n[*] Analyzing security headers...\n")
security_headers = {
    "X-Frame-Options": "Protection against clickjacking",
    "Content-Security-Policy": "Mitigates XSS & injection attacks",
    "Strict-Transport-Security": "Forces HTTPS for security",
    "X-Content-Type-Options": "Prevents MIME type confusion",
}

missing_headers = []
try:
    response = requests.get(target, timeout=5)
    for header, description in security_headers.items():
        if header not in response.headers:
            missing_headers.append(f"{header} - {description}")

    if missing_headers:
        print("\033[91m[!] Missing Security Headers:\033[0m")
        for header in missing_headers:
            print(f"    ❌ {header}")
    else:
        print("\033[92m[+] All security headers are present.\033[0m")
except requests.exceptions.RequestException:
    print("\033[91m[!] Could not analyze security headers.\033[0m")

# Web Server Fingerprinting
print("\n[*] Detecting web server fingerprint...\n")
server_info = "Unknown"  # Set default value for server_info
try:
    server_info = response.headers.get("Server", "Unknown")
    print(f"🖥️ Web Server: {server_info}")
except:
    print("\033[91m[!] Could not retrieve server information.\033[0m")

# Save results to file
timestamp = time.strftime("%Y%m%d-%H%M%S")
report_file = f"scan_results_{timestamp}.txt"

with open(report_file, "w") as file:
    file.write(f"Sentin3l-B V2 Scan Report - {target}\n")
    file.write("="*50 + "\n")
    file.write(f"Open Ports: {open_ports}\n")
    file.write(f"Detected CMS: {cms_detected}\n")
    file.write(f"SQL Injection: {'Detected' if vulnerable else 'Not Detected'}\n")
    file.write(f"Discovered Directories: {found_dirs}\n")
    file.write(f"WAF Presence: {'Yes' if waf_detected else 'No'}\n")
    file.write(f"Missing Security Headers: {missing_headers}\n")
    file.write(f"Web Server: {server_info}\n")

print(f"\n📁 Results saved to {report_file}")

# Final Prompt
while True:
    action = input("\nPress B to run a new scan or X to exit: ").strip().lower()
    if action == "b":
        exec(open(__file__).read())  # Restart the script
    elif action == "x":
        print("Exiting Sentin3l-B. Goodbye!")
        break

