import pandas as pd
import random
from datetime import datetime, timedelta
from pathlib import Path

# Success Criteria: 10,000 benign records and 50 injected malicious records.
NUM_BENIGN = 10000
NUM_MALICIOUS = 50

def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def generate_timestamp():
    # Start time is now, going back in time
    start_time = datetime.now()
    return (start_time - timedelta(seconds=random.randint(0, 86400 * 7))).isoformat() + "Z"

def create_log_entry(is_malicious=False):
    timestamp = generate_timestamp()
    source_ip = generate_ip()
    dest_ip = "10.0.4.15"  # Simulated internal server

    if is_malicious:
        # Malicious patterns
        anomaly_type = random.choice(["brute_force", "exfiltration", "suspicious_ua"])

        if anomaly_type == "brute_force":
            dest_port = random.choice([22, 3389])
            protocol = "TCP"
            bytes_transferred = random.randint(1000, 5000)
            failed_login_attempts = random.randint(10, 500)
            user_agent = "Nmap Scripting Engine"
            geo_location = random.choice(["RU", "CN", "KP"])
        elif anomaly_type == "exfiltration":
            dest_port = 443
            protocol = "TCP"
            bytes_transferred = random.randint(10**8, 10**9) # 100MB to 1GB
            failed_login_attempts = random.randint(0, 2)
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            geo_location = random.choice(["US", "NG", "GB"])
        else: # suspicious_ua
            dest_port = 80
            protocol = "TCP"
            bytes_transferred = random.randint(500, 2000)
            failed_login_attempts = 0
            user_agent = "Cobalt Strike Beacon"
            geo_location = "DE"

        label = 1
    else:
        # Mix common traffic profiles instead of making benign records identical.
        profile = random.choices(
            ["web", "dns", "admin", "api", "backup"],
            weights=[55, 15, 8, 17, 5],
            k=1,
        )[0]
        if profile == "web":
            dest_port = random.choice([80, 443])
            protocol = "TCP"
            bytes_transferred = random.randint(500, 100000)
            user_agent = random.choice(
                [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15",
                ]
            )
        elif profile == "dns":
            dest_port = 53
            protocol = "UDP"
            bytes_transferred = random.randint(60, 4096)
            user_agent = "dns-resolver/1.0"
        elif profile == "admin":
            dest_port = random.choice([22, 3389])
            protocol = "TCP"
            bytes_transferred = random.randint(1000, 20000)
            user_agent = random.choice(["OpenSSH_9.6", "Windows Remote Desktop"])
        elif profile == "api":
            dest_port = random.choice([443, 8080])
            protocol = "TCP"
            bytes_transferred = random.randint(1000, 250000)
            user_agent = random.choice(["Aegis-Service/2.1", "python-httpx/0.27"])
        else:
            dest_port = 443
            protocol = "TCP"
            bytes_transferred = random.randint(100000, 8_000_000)
            user_agent = "backup-agent/3.4"
        failed_login_attempts = random.choices([0, 1, 2], weights=[90, 9, 1], k=1)[0]
        geo_location = random.choice(["NG", "US", "GB", "ZA", "GH", "KE", "DE"])
        label = 0

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "failed_login_attempts": failed_login_attempts,
        "user_agent": user_agent,
        "geo_location": geo_location,
        "label": label
    }

def main():
    random.seed(42)
    print(f"Generating {NUM_BENIGN} benign and {NUM_MALICIOUS} malicious logs...")

    logs = []
    for _ in range(NUM_BENIGN):
        logs.append(create_log_entry(is_malicious=False))

    for _ in range(NUM_MALICIOUS):
        logs.append(create_log_entry(is_malicious=True))

    # Shuffle logs
    random.shuffle(logs)

    df = pd.DataFrame(logs)

    # Save to CSV
    output_path = Path(__file__).resolve().parent / "network_logs.csv"
    df.to_csv(output_path, index=False)
    print(f"Successfully generated logs at {output_path}")

if __name__ == "__main__":
    main()
