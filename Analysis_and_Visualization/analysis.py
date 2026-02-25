import pandas as pd
import matplotlib.pyplot as plt

try:
    df = pd.read_csv("Task5/security_logs.csv")
except FileNotFoundError:
    print("ERROR: security_logs.csv not found in Task5/")
    raise SystemExit
except pd.errors.EmptyDataError:
    print("ERROR: File is empty")
    raise SystemExit
except Exception as e:
    print(f"Unexpected error while loading file: {e}")
    raise SystemExit

required_cols = [
    "timestamp", "source_ip", "destination_ip",
    "protocol", "status", "action", "username"
]

missing = [c for c in required_cols if c not in df.columns]
if missing:
    print(f"ERROR: Missing required columns: {missing}")
    raise SystemExit

df.drop_duplicates(inplace=True)

df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
# If timestamp conversion fails → drop those rows
df = df[df['timestamp'].notna()]

df['source_ip'] = df['source_ip'].fillna("Unknown")
df['destination_ip'] = df['destination_ip'].fillna("Unknown")
df['username'] = df['username'].fillna("Unknown")
df['protocol'] = df['protocol'].fillna("Unknown")
df['status'] = df['status'].fillna("Unknown")
df['action'] = df['action'].fillna("None")

df.reset_index(drop=True, inplace=True)

print("Data loaded and cleaned successfully")

# ATTACK DETECTION

df['attack_type'] = "Normal Traffic"

# SSH Brute Force Detection (ANY destination IP)

ssh_fail = df[(df['protocol'] == 'TCP') & (df['status'] == 'failed')]
ssh_counts = ssh_fail.groupby(['source_ip', 'destination_ip']).size().reset_index(name='fail_count')

ssh_bruteforce = ssh_counts[ssh_counts['fail_count'] >= 5]

df = df.merge(
    ssh_bruteforce[['source_ip', 'destination_ip']],
    on=['source_ip', 'destination_ip'],
    how='left',
    indicator=True
)

df.loc[df['_merge'] == 'both', 'attack_type'] = 'SSH Brute Force'
df.drop(columns=['_merge'], inplace=True)

# RDP Brute Force (behavior-based)
rdp_fail = df[(df['protocol'] == 'TCP') & (df['status'] == 'failed')]
rdp_counts = rdp_fail.groupby(['source_ip', 'destination_ip']).size().reset_index(name='fail_count')

rdp_bruteforce = rdp_counts[rdp_counts['fail_count'] >= 8]

df = df.merge(
    rdp_bruteforce[['source_ip', 'destination_ip']],
    on=['source_ip', 'destination_ip'],
    how='left',
    indicator=True
)

df.loc[df['_merge'] == 'both', 'attack_type'] = 'RDP Brute Force'
df.drop(columns=['_merge'], inplace=True)

# Port Scan
df.loc[df['protocol'] == 'ICMP', 'attack_type'] = 'Port Scan'

# UDP Flood
udp_mask = (df['protocol'] == 'UDP') & (df['status'] == 'failed')
df.loc[udp_mask, 'attack_type'] = 'UDP Flood'

#Credential Stuffing
user_attempts = df.groupby('source_ip')['username'].nunique()
suspect_ips = user_attempts[user_attempts >= 5].index

df.loc[df['source_ip'].isin(suspect_ips), 'attack_type'] = 'Credential Stuffing'

# Privilaged Escalation Attempts
if "action" in df.columns:
    df.loc[df['action'].str.contains("sudo", na=False), 'attack_type'] = "Privilege Escalation Attempt"

# Suspicious night activity
df['hour'] = df['timestamp'].dt.hour
df.loc[(df['hour'] >= 1) & (df['hour'] <= 4), 'attack_type'] = "Suspicious Night Activity"


# VISUALIZATIONS

def safe_plot(title, plot_func):
    try:
        plt.figure(figsize=(9,5))
        plot_func()
        plt.title(title)
        plt.tight_layout()
        plt.show()
    except Exception as e:
        print(f"⚠ Plotting error in '{title}': {e}")

safe_plot("Top Source IPs", lambda: df['source_ip'].value_counts().head(10).plot(kind='bar'))
safe_plot("Login Attempt Status", lambda: df['status'].value_counts().plot(kind='bar'))
safe_plot("Attack Type Frequency", lambda: df['attack_type'].value_counts().plot(kind='bar'))
safe_plot("Attack Activity by Hour", lambda: df[df['attack_type'] != "Normal Traffic"].groupby('hour').size().plot())

#Save cleaned file

try:
    df.to_csv("Task5/cleaned_security_logs.csv", index=False)
    print("Cleaned data saved successfully")
except Exception as e:
    print(f"ERROR saving cleaned CSV: {e}")

print("Final record count:", len(df))
