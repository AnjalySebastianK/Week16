import re
from collections import defaultdict, Counter
import os

log_file = "Task4/network_logs.txt"

if not os.path.exists(log_file):
    print("Log file not found")
    exit()

# Counters
attack_types = defaultdict(int)
failed_users = Counter()
source_ips = Counter()
ssh_failures = defaultdict(int)
ports_scanned = defaultdict(set)

# Regex patterns
ssh_fail = re.compile(r"Failed password .* user (\w+) from (\d+\.\d+\.\d+\.\d+)")
web_probe = re.compile(r'GET|POST .* 401')
port_scan = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)")
unauth = re.compile(r"NOT in sudoers|DENIED", re.IGNORECASE)

with open(log_file) as file:
    for line in file:
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

        # Port scan detection
        ps = port_scan.search(line)
        if ps:
            ip, port = ps.groups()
            ports_scanned[ip].add(port)
            source_ips[ip] += 1

        # Unauthorized access
        if unauth.search(line):
            attack_types["Unauthorized Access"] += 1

# SSH brute force detection
for ip, count in ssh_failures.items():
    if count >= 5:
        attack_types["SSH Brute Force"] += 1

# Credential stuffing detection (many users from same IP)
if any(len(set(failed_users)) >= 3 for _ in ssh_failures):
    attack_types["Credential Stuffing"] += 1

# Port scan detection threshold
for ip, ports in ports_scanned.items():
    if len(ports) >= 4:
        attack_types["Port Scan"] += 1

# Output
print("\nMost Active Source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"{ip}: {count} events")
    
print("\nDetected Attacks:")
for attack, count in attack_types.items():
    print(f"{attack}: {count}")

print("\nUsernames with Failed Logins:")
for user, count in failed_users.items():
    print(f"{user}: {count}")


