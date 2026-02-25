from scapy.all import IP, ICMP,TCP,UDP, sr1
import time

# IP range to scan
network_prefix = "10.0.0."
start_ip = 160
end_ip = 170

# Common TCP ports
tcp_ports = [
    21, 22, 23, 25, 53, 80, 443, 445]
# Common UDP ports
udp_ports = [53, 67, 69, 1900, 4500]           

timeout = 1

print("Starting network scan...\n")

active_hosts = []
host_details = {}

# ICMP Ping
def icmp_ping(ip):
    try:
        packet = IP(dst=ip) / ICMP()
        start = time.time()
        reply = sr1(packet, timeout=timeout, verbose=0)
        end = time.time()

        if reply:
            rtt = round((end - start) * 1000, 2)
            ttl = reply.ttl
            return True, rtt, ttl
        return False, None, None
    except Exception as e:
        return False, None, None

# TCP SYN Scan (Nmap-style)
def tcp_syn_scan(ip, port):
    try:
        syn = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(syn, timeout=timeout, verbose=0)

        if resp is None:
            return "Filtered"

        if resp.haslayer(TCP):
            flags = resp[TCP].flags

            if flags == "SA":
                return "Open"
            elif flags == "RA":
                return "Closed"

        return "Unknown"
    except Exception:
        return "Error"

# UDP Scan
def udp_scan(ip, port):
    try:
        pkt = IP(dst=ip) / UDP(dport=port)
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return "Open|Filtered"

        if resp.haslayer(ICMP):
            if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                return "Closed"

        return "Unknown"
    except Exception:
        return "Error"

# MAIN SCAN LOOP
for i in range(start_ip, end_ip + 1):
    ip = network_prefix + str(i)
    print(f"\nScanning {ip}...")

    reachable, rtt, ttl = icmp_ping(ip)

    if reachable:
        print(f"[+] Host {ip} is reachable | RTT = {rtt} ms | TTL = {ttl}")
        active_hosts.append(ip)
        host_details[ip] = {"rtt": rtt, "ttl": ttl, "tcp": {}, "udp": {}}

        # TCP SYN Scan
        for port in tcp_ports:
            state = tcp_syn_scan(ip, port)
            host_details[ip]["tcp"][port] = state
            print(f"   TCP {port}: {state}")

        # UDP Scan
        for port in udp_ports:
            state = udp_scan(ip, port)
            host_details[ip]["udp"][port] = state
            print(f"   UDP {port}: {state}")

    else:
        print(f"[-] Host {ip} is unreachable")

# SUMMARY REPORT

print("\nSummary of active hosts:")

if active_hosts:
    for ip in active_hosts:
        print(f"Host: {ip}")
        print(f"  RTT: {host_details[ip]['rtt']} ms")
        print(f"  TTL: {host_details[ip]['ttl']} (OS fingerprint hint)")

        print("  TCP Ports:")
        for port, state in host_details[ip]["tcp"].items():
            print(f"    {port}: {state}")

        print("  UDP Ports:")
        for port, state in host_details[ip]["udp"].items():
            print(f"    {port}: {state}")

        print()

else:
    print("No active hosts found in the given range.")

print("\nScan completed.\n")
