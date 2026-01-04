import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("Task5/security_logs.csv")
df['timestamp'] = pd.to_datetime(df['timestamp'])

print("Data loaded successfully")
print("Total records (raw):", len(df))


# Remove duplicate rows
df.drop_duplicates(inplace=True)

# Fill missing values (do NOT drop real logs)
df['username'] = df['username'].fillna("Unknown")
df['destination_ip'] = df['destination_ip'].fillna("Unknown")

# Reset index for clean display
df.reset_index(drop=True, inplace=True)

print("Records after cleaning:", len(df))
print("Data cleaned successfully\n")
print(df.head(15))


df['attack_type'] = "Normal Traffic"

# SSH Brute Force
ssh_mask = (
    (df['protocol'] == 'TCP') &
    (df['status'] == 'failed') &
    (df['destination_ip'] == '10.0.0.5')
)
df.loc[ssh_mask, 'attack_type'] = 'SSH Brute Force'

# RDP Brute Force
rdp_mask = (
    (df['protocol'] == 'TCP') &
    (df['status'] == 'failed') &
    (df['destination_ip'] == '10.0.0.20')
)
df.loc[rdp_mask, 'attack_type'] = 'RDP Brute Force'

# Port Scan
df.loc[df['protocol'] == 'ICMP', 'attack_type'] = 'Port Scan'

# UDP Flood
udp_mask = (df['protocol'] == 'UDP') & (df['status'] == 'failed')
df.loc[udp_mask, 'attack_type'] = 'UDP Flood'


# VISUALIZATIONS

# Top Source IPs

plt.figure(figsize=(9,5))
df['source_ip'].value_counts().head(10).plot(kind='bar')
plt.title("Top Source IPs by Activity")
plt.xlabel("Source IP")
plt.ylabel("Number of Events")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Login Attempt Status

plt.figure(figsize=(6,5))
df['status'].value_counts().plot(kind='bar')
plt.title("Login Attempt Status")
plt.xlabel("Status")
plt.ylabel("Count")
plt.tight_layout()
plt.show()


# Attack Type Frequency

plt.figure(figsize=(9,5))
df['attack_type'].value_counts().plot(kind='bar')
plt.title("Attack Type Frequency")
plt.xlabel("Attack Type")
plt.ylabel("Occurrences")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()


# Attack Activity by Hour

df['hour'] = df['timestamp'].dt.hour
hourly_attacks = df[df['attack_type'] != 'Normal Traffic'].groupby('hour').size()
plt.figure(figsize=(8,5))
plt.plot(hourly_attacks.index, hourly_attacks.values, marker='o')
plt.title("Attack Activity by Hour")
plt.xlabel("Hour of Day")
plt.ylabel("Number of Attacks")
plt.grid(True)
plt.tight_layout()
plt.show()



df.to_csv("Task5/cleaned_security_logs.csv", index=False)

print("Cleaned data saved successfully")
print("Final record count:", len(df))

