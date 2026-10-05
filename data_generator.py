import csv
import random
import os

THREAT_TYPES = ["Botnet", "Ransomware C2", "Phishing Host", "Port Scanner", "Malware Dropper", "DDoS Node", "Brute Force Attacker"]
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
SOURCES = ["AbuseIPDB", "AlienVault OTX", "Internal Honeypot", "CISA Alert Feed", "CrowdStrike Feed", "Darkweb Crawler"]

def generate_ip():
    """Generates a random valid IPv4 address."""
    # Avoid private or loopback ranges for realism in threat feeds, but keep standard octets
    first = random.choice([x for x in range(1, 223) if x not in [10, 127, 172, 192]])
    second = random.randint(0, 255)
    third = random.randint(0, 255)
    fourth = random.randint(1, 254)
    return f"{first}.{second}.{third}.{fourth}"

def generate_dataset(file_path="data/malicious_ips.csv", num_records=10000, seed=42):
    """Generates synthetic dataset of malicious IP addresses."""
    random.seed(seed)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    unique_ips = set()
    rows = []
    
    # Pre-add some fixed known demo IPs for easy testing during CIA3 presentation
    demo_ips = [
        ("185.220.101.25", "Tor Exit Node / Botnet", "Critical", "AlienVault OTX", "2026-09-15 14:22:00"),
        ("45.33.32.156", "Port Scanner", "High", "Internal Honeypot", "2026-09-20 09:10:15"),
        ("103.21.244.0", "Phishing Host", "Medium", "AbuseIPDB", "2026-09-28 18:45:30"),
        ("192.168.1.10", "Internal Suspicious Activity", "Low", "Internal SOC", "2026-10-01 11:05:00"),
        ("91.240.118.170", "Ransomware C2", "Critical", "CISA Alert Feed", "2026-10-04 22:30:12")
    ]
    
    for ip, threat, sev, src, dt in demo_ips:
        unique_ips.add(ip)
        rows.append({
            "ip": ip,
            "threat_type": threat,
            "severity": sev,
            "source": src,
            "date_added": dt
        })

    while len(unique_ips) < num_records:
        ip = generate_ip()
        if ip not in unique_ips:
            unique_ips.add(ip)
            threat = random.choice(THREAT_TYPES)
            sev = random.choice(SEVERITY_LEVELS)
            src = random.choice(SOURCES)
            day = random.randint(1, 30)
            month = random.randint(8, 10)
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            dt = f"2026-0{month}-{day:02d} {hour:02d}:{minute:02d}:00"
            rows.append({
                "ip": ip,
                "threat_type": threat,
                "severity": sev,
                "source": src,
                "date_added": dt
            })
            
    with open(file_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "threat_type", "severity", "source", "date_added"])
        writer.writeheader()
        writer.writerows(rows)
        
    print(f"Successfully generated {len(rows)} records in {file_path}")
    return file_path

if __name__ == "__main__":
    generate_dataset()
