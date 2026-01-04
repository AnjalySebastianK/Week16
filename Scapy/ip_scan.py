from scapy.all import IP, ICMP, sr1
import time

# IP range to scan
network_prefix = "10.0.0."
start_ip = 160
end_ip = 170

print("Starting network scan...\n")

active_hosts = []

for i in range(start_ip, end_ip + 1):
    target_ip = network_prefix + str(i)
    
    packet = IP(dst=target_ip) / ICMP()
    
    start_time = time.time()
    reply = sr1(packet, timeout=1, verbose=0)
    end_time = time.time()
    
    if reply:
        rtt = round((end_time - start_time) * 1000, 2)  # ms
        active_hosts.append((target_ip, rtt))
        print(f"[+] Host {target_ip} is reachable | RTT = {rtt} ms")
    else:
        print(f"[-] Host {target_ip} is unreachable")

print("\nScan completed.")
