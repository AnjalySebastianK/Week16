import pandas as pd
import matplotlib.pyplot as plt

CSV_PATH = "Project/logs.csv"

def load_csv_logs(path):
    print("Loading security logs...\n")
    try:
        df = pd.read_csv(path)
        print(f"CSV loaded from {path}")
    except FileNotFoundError:
        print(f"ERROR: CSV file not found at {path}")
        raise SystemExit
    except Exception as e:
        print(f"ERROR reading CSV: {e}")
        raise SystemExit

    required_cols = [
        "timestamp", "source_ip", "destination_ip",
        "protocol", "action", "status", "username"
    ]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        print(f"ERROR: Missing required columns: {missing}")
        raise SystemExit

    return df


def clean_data(df):
    print("\nCleaning data...")

    df = df.drop_duplicates()

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    before = len(df)
    df = df[df["timestamp"].notna()]
    after = len(df)

    if before != after:
        print(f"ℹ Removed {before - after} rows with invalid timestamps")

    df["source_ip"] = df["source_ip"].fillna("Unknown")
    df["destination_ip"] = df["destination_ip"].fillna("Unknown")
    df["username"] = df["username"].fillna("Unknown")
    df["protocol"] = df["protocol"].fillna("Unknown").str.upper()
    df["status"] = df["status"].fillna("Unknown").str.lower()
    df["action"] = df["action"].fillna("Unknown").str.lower()

    df["hour"] = df["timestamp"].dt.hour

    df = df.sort_values("timestamp").reset_index(drop=True)

    print("Data cleaned successfully")
    print("Total records after cleaning:", len(df))
    print(df.head(5))
    return df

#Attack Detection

def detect_attacks(df):
    print("\nDetecting attacks...")

    df["attack_type"] = "Normal Activity"

    ssh_mask = df["protocol"] == "SSH"
    tcp_mask = df["protocol"] == "TCP"
    failed_mask = df["status"] == "failed"
    blocked_mask = df["action"] == "blocked"

    # 1) SSH brute force
    ssh_fail = df[ssh_mask & failed_mask]
    ssh_counts = ssh_fail.groupby(["source_ip", "destination_ip"]).size().reset_index(name="fail_count")
    ssh_bruteforce = ssh_counts[ssh_counts["fail_count"] >= 5]
    idx = df.set_index(["source_ip", "destination_ip"]).index.isin(
        ssh_bruteforce.set_index(["source_ip", "destination_ip"]).index
    )
    df.loc[idx & ssh_mask & failed_mask, "attack_type"] = "SSH Brute Force"

    # 2) RDP brute force (simulated)
    rdp_fail = df[tcp_mask & failed_mask & blocked_mask]
    rdp_counts = rdp_fail.groupby(["source_ip", "destination_ip"]).size().reset_index(name="fail_count")
    rdp_bruteforce = rdp_counts[rdp_counts["fail_count"] >= 8]
    idx_rdp = df.set_index(["source_ip", "destination_ip"]).index.isin(
        rdp_bruteforce.set_index(["source_ip", "destination_ip"]).index
    )
    df.loc[idx_rdp & tcp_mask & blocked_mask, "attack_type"] = "RDP Brute Force"

    # 3) Port scan / reconnaissance
    df.loc[blocked_mask & (df["attack_type"] == "Normal Activity"), "attack_type"] = "Port Scan / Reconnaissance"

    # 4) Credential stuffing
    user_attempts = df.groupby("source_ip")["username"].nunique()
    stuffing_ips = user_attempts[user_attempts >= 3].index
    df.loc[df["source_ip"].isin(stuffing_ips) & failed_mask, "attack_type"] = "Credential Stuffing"

    # 5) Horizontal brute force
    horiz_counts = df[failed_mask].groupby("source_ip")["destination_ip"].nunique()
    horiz_ips = horiz_counts[horiz_counts >= 3].index
    df.loc[df["source_ip"].isin(horiz_ips) & failed_mask, "attack_type"] = "Horizontal Brute Force"

    # 6) Vertical brute force
    vert_counts = df[failed_mask].groupby("username")["source_ip"].nunique()
    vert_users = vert_counts[vert_counts >= 3].index
    df.loc[df["username"].isin(vert_users) & failed_mask, "attack_type"] = "Vertical Brute Force"

    # 7) Suspicious night activity
    night_mask = (df["hour"] >= 1) & (df["hour"] <= 4)
    df.loc[night_mask & (df["attack_type"] == "Normal Activity"), "attack_type"] = "Suspicious Night Activity"

    # 8) Privilege escalation
    df.loc[df["action"].str.contains("sudo", case=False, na=False), "attack_type"] = "Privilege Escalation Attempt"

    print("Attack detection completed")
    return df

# Visualizations and Terminal Summeries

def safe_plot(title, plot_func, summary_func):
    try:
        plt.figure(figsize=(9, 5))
        plot_func()
        plt.title(title)
        plt.tight_layout()
        plt.show()

        summary = summary_func().reset_index()
        summary.columns = ["Category", "Count"]

        print("\nSUMMARY:", title)
        print(summary)
        print("-" * 60)

    except Exception as e:
        print(f"Plotting error in '{title}': {e}")


def generate_visualizations(df):
    print("\nGenerating graphs...")

    safe_plot(
        "Top Source IP Addresses",
        lambda: df["source_ip"].value_counts().head(10).plot(kind="bar"),
        lambda: df["source_ip"].value_counts().head(10)
    )

    failed = df[df["status"] == "failed"]
    safe_plot(
        "Failed Login Attempts by IP",
        lambda: failed["source_ip"].value_counts().head(10).plot(kind="bar"),
        lambda: failed["source_ip"].value_counts().head(10)
    )

    safe_plot(
        "Attack Type Distribution",
        lambda: df["attack_type"].value_counts().plot(kind="bar"),
        lambda: df["attack_type"].value_counts()
    )

    safe_plot(
        "Security Events by Hour",
        lambda: df.groupby("hour").size().plot(kind="line", marker="o"),
        lambda: df.groupby("hour").size()
    )

# Insights

def print_insights(df):
    print("\n---- SECURITY INSIGHTS ----")

    top_attacker = df["source_ip"].value_counts().idxmax()
    print(f"- Most active source IP: {top_attacker}")

    top_target = df["destination_ip"].value_counts().idxmax()
    print(f"- Most targeted destination IP: {top_target}")

    top_attack = df["attack_type"].value_counts().idxmax()
    print(f"- Most frequent attack type: {top_attack}")

    peak_hour = df.groupby("hour").size().idxmax()
    print(f"- Peak activity hour: {peak_hour}:00")

    print("\nKey observations:")
    print("1. Repeated failed attempts and blocked traffic indicate active probing and brute-force behaviour.")
    print("2. High-activity IPs should be monitored or blocked at the firewall.")
    print("3. Night-time activity may indicate automated bots.")
    print("4. Credential stuffing suggests weak or reused passwords.\n")



def main():
    df = load_csv_logs(CSV_PATH)
    df = clean_data(df)
    df = detect_attacks(df)
    generate_visualizations(df)
    print_insights(df)

    try:
        output_path = "Project/cleaned_logs.csv"
        df.to_csv(output_path, index=False)
        print(f"Cleaned and labeled data saved to {output_path}")
    except Exception as e:
        print(f"ERROR saving cleaned CSV: {e}")


if __name__ == "__main__":
    main()
