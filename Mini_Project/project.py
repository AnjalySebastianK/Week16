import pandas as pd
import matplotlib.pyplot as plt

print("Loading security logs...\n")

# Load dataset
df = pd.read_csv("Project/logs.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

print("Total records:", len(df))
print(df.head())

print("\nCleaning data...")

df.drop_duplicates(inplace=True)
df["username"] = df["username"].fillna("Unknown")

print("Records after cleaning:", len(df))


def detect_attack(row):
    if row["protocol"] == "SSH" and row["status"] == "failed":
        return "SSH Brute Force"
    elif row["action"] == "blocked":
        return "Port Scan / Reconnaissance"
    elif row["status"] == "failed":
        return "Unauthorized Access"
    else:
        return "Normal Activity"

df["attack_type"] = df.apply(detect_attack, axis=1)
df["hour"] = df["timestamp"].dt.hour


top_ips = df["source_ip"].value_counts().head(10)
failed_attempts = df[df["status"] == "failed"]
attack_types = df["attack_type"].value_counts()
hourly_attacks = df["hour"].value_counts().sort_index()


print("\nGenerating graphs...")

# Top Source IPs
top_ips.plot(kind="bar")
plt.title("Top Source IP Addresses")
plt.xlabel("Source IP")
plt.ylabel("Number of Requests")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Failed Login Attempts
failed_attempts["source_ip"].value_counts().head(10).plot(kind="bar")
plt.title("Failed Login Attempts by IP")
plt.xlabel("Source IP")
plt.ylabel("Failed Attempts")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Attack Types
attack_types.plot(kind="bar")
plt.title("Attack Type Distribution")
plt.xlabel("Attack Type")
plt.ylabel("Occurrences")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Hourly Activity
hourly_attacks.plot(kind="line", marker="o")
plt.title("Security Events by Hour")
plt.xlabel("Hour of Day")
plt.ylabel("Number of Events")
plt.grid(True)
plt.tight_layout()
plt.show()


print("\n========== SECURITY INSIGHTS ==========")
print("1. Repeated failed SSH attempts indicate brute-force attacks.")
print("2. Certain IPs generate high traffic and should be monitored.")
print("3. Attacks peak during specific hours.")
print("4. Firewall blocks prevent unauthorized access.")
