import re
from collections import defaultdict, Counter
import os
import sys

log_file = "Task4/network_logs.txt"

if not os.path.exists(log_file):
    print("Log file not found")
    sys.exit(1)

# Data Structures
attack_types = defaultdict(int)
failed_users = Counter()
source_ips = Counter()
ssh_failures = defaultdict(int)
ports_scanned = defaultdict(set)
protocol_count = Counter()
scan_types = defaultdict(lambda: defaultdict(int))
icmp_sweep = Counter()
udp_scan_detected = Counter()
web_404_hits = Counter()
errors = 0


# Regex patterns
ssh_fail = re.compile(r"Failed password .* user (\w+) from (\d+\.\d+\.\d+\.\d+)")
web_probe = re.compile(r'GET|POST .* 401')
web_404 = re.compile(r"(GET|POST).* 404")
port_scan = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)")
unauth = re.compile(r"NOT in sudoers|DENIED", re.IGNORECASE)
protocol_pattern = re.compile(r"PROTO=(TCP|UDP|ICMP)")
flags_pattern = re.compile(r"FLAGS=([A-Z]+)")
icmp_pattern = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+).*PROTO=ICMP.*TYPE=8")

#Classify scan type
def classify_scan(flags):
    if flags == "S": return "SYN Scan"
    if flags == "F": return "FIN Scan"
    if flags == "": return "NULL Scan"
    if set(flags) == {"F", "P", "U"}: return "XMAS Scan"
    return "Unknown Scan"

# Parse log file
with open(log_file) as file:
    for line in file:
        try:
            # Protocol detection
            proto = protocol_pattern.search(line)
            if proto:
                protocol_count[proto.group(1)] += 1

            # ICMP sweep detection
            icmp = icmp_pattern.search(line)
            if icmp:
                ip = icmp.group(1)
                icmp_sweep[ip] += 1
                source_ips[ip] += 1

            # SSH failures
            ssh = ssh_fail.search(line)
            if ssh:
                user, ip = ssh.groups()
                ssh_failures[ip] += 1
                failed_users[user] += 1
                source_ips[ip] += 1

            # Web probing
            if web_probe.search(line):
                attack_types["Web Probe"] += 1
                ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line).group()
                source_ips[ip] += 1

            # Web directory brute-force (404)
            if web_404.search(line):
                ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line).group()
                web_404_hits[ip] += 1
                source_ips[ip] += 1

            # Port scan detection
            ps = port_scan.search(line)
            if ps:
                ip, port = ps.groups()
                ports_scanned[ip].add(port)
                source_ips[ip] += 1

                # Flag-based scan detection
                flags = flags_pattern.search(line)
                if flags:
                    scan_type = classify_scan(flags.group(1))
                    scan_types[ip][scan_type] += 1

            # Unauthorized access
            if unauth.search(line):
                attack_types["Unauthorized Access"] += 1

        except Exception:
            errors += 1
            continue

#Post-Processing (Attack Logic)

# SSH brute force detection
for ip, count in ssh_failures.items():
    if count >= 5:
        attack_types["SSH Brute Force"] += 1

# Distributed brute force (many IPs failing same user)
if len(ssh_failures) >= 3:
    attack_types["Distributed SSH Attack"] += 1

# Credential stuffing detection (many users from same IP)
for ip in ssh_failures:
    if len(failed_users) >= 3:
        attack_types["Credential Stuffing"] += 1

# Port scan detection threshold
for ip, ports in ports_scanned.items():
    if len(ports) >= 4:
        attack_types["Port Scan"] += 1


# ICMP sweep detection
for ip, count in icmp_sweep.items():
    if count >= 3:
        attack_types["ICMP Sweep"] += 1

# Web directory brute-force
for ip, count in web_404_hits.items():
    if count >= 10:
        attack_types["Web Directory Brute Force"] += 1

# Output

print("\n---- Network Attack Report ----")
print("\nMost Active Source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"{ip}: {count} events")
    
print("\nDetected Attacks:")
for attack, count in attack_types.items():
    print(f"{attack}: {count}")

print("\nSSH Failed Login Users:")
for user, count in failed_users.items():
    print(f"  {user}: {count}")

print("\nProtocol Usage:")
for proto, count in protocol_count.items():
    print(f"  {proto}: {count} packets")

print("\nScan Types Detected:")
for ip, scans in scan_types.items():
    print(f"  {ip}: {dict(scans)}")

print("\nICMP Sweep Attempts:")
for ip, count in icmp_sweep.items():
    print(f"  {ip}: {count} ICMP echo requests")

print("\nWeb Directory Brute Force:")
for ip, count in web_404_hits.items():
    print(f"  {ip}: {count} missing pages (404)")


print(f"\nParsing Errors: {errors}")


