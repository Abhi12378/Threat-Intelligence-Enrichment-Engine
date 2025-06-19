import json
import csv
import logging
import re
from datetime import datetime, timedelta, UTC
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
    HAS_ZONEINFO = True
except ImportError:
    HAS_ZONEINFO = False

# Setup logging
logger = logging.getLogger("ioc_enrichment")
logger.setLevel(logging.DEBUG)

base_dir = Path(__file__).resolve().parent.parent
logs_dir = base_dir / "logs"
logs_dir.mkdir(exist_ok=True)
log_file = logs_dir / "app.log"

fh = logging.FileHandler(log_file)
fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(fh)

# === Loaders ===
def load_internal_feed(path):
    with open(path) as f:
        return set(line.strip() for line in f if line.strip())

def load_misp_feed(path):
    with open(path) as f:
        return set(json.load(f))

def load_osint_feed(path):
    with open(path) as f:
        reader = csv.DictReader(f)
        return set(row["ioc"].strip() for row in reader if row["ioc"].strip())

def load_threat_rules(path):
    with open(path) as f:
        return json.load(f)["patterns"]

# === Helper Enrichment Functions ===
def determine_ioc_type(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ipv4-addr"
    elif re.match(r"^[a-fA-F0-9]{8,}$", ioc):
        return "file-hash"
    elif re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", ioc):
        return "email-addr"
    elif re.match(r"^(?!\d{1,3}(\.\d{1,3}){3}$)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
        return "domain-name"
    else:
        return "file-hash"

def determine_threat_type(ioc, rules):
    for rule in rules:
        if "ip_range" in rule and ioc.startswith(rule["ip_range"]):
            return rule["threat_type"]
        elif "keyword" in rule:
            if rule["keyword"] and rule["keyword"] in ioc:
                return rule["threat_type"]
    return "unknown"

def calculate_confidence(sources, threat_type):
    base = 0
    lower_sources = [s.lower() for s in sources]

    if "internal" in lower_sources:
        base += 50
    if "misp" in lower_sources:
        base += 30
    if "public" in lower_sources or "osint" in lower_sources:
        base += 10

    bonuses = {
        "ransomware": 10,
        "infostealer": 5,
        "botnet": 5,
        "phishing": 5,
        "malware": 5,
        "trojan": 5,
        "command-and-control": 5,
        "malicious-domain": 5
    }
    base += bonuses.get(threat_type.lower(), 0)

    return min(max(base, 10), 100)

def get_ist_time(utc_now):
    try:
        if HAS_ZONEINFO:
            return utc_now.astimezone(ZoneInfo("Asia/Kolkata"))
    except Exception as e:
        logger.warning(f"ZoneInfo not available, using timedelta fallback: {e}")
    return utc_now + timedelta(hours=5, minutes=30)

# === Core Enrichment Logic ===
def enrich_iocs(input_path, output_path, feeds, rules):
    with open(input_path) as f:
        raw_iocs = json.load(f)

    enriched = []
    for i, entry in enumerate(raw_iocs, 1):
        ioc = entry.get("ioc")
        if not ioc:
            continue

        sources = [src for src, items in feeds.items() if ioc in items]
        threat_type = determine_threat_type(ioc, rules)
        ioc_type = determine_ioc_type(ioc)
        confidence = calculate_confidence(sources, threat_type)

        utc_now = datetime.now(UTC)
        ist_now = get_ist_time(utc_now)

        enriched.append({
            "id": f"ioc-{1000 + i}",
            "value": ioc,
            "type": ioc_type,
            "source": ", ".join(sources) if sources else "unknown",
            "threat_type": threat_type,
            "confidence": confidence,
            "timestamp_utc": utc_now.isoformat().replace("+00:00", "Z"),
            "timestamp_ist": ist_now.isoformat()
        })

        logger.info(f"Processed IOC: {ioc} | Type: {ioc_type} | Threat: {threat_type} | Confidence: {confidence}")

    with open(output_path, "w") as f:
        json.dump(enriched, f, indent=2)

    logger.info(f"Enriched IOCs written to {output_path}")

# === Main Function ===
def main():
    feeds_dir = base_dir / "feeds"
    inputs_dir = base_dir / "inputs"
    outputs_dir = base_dir / "outputs"
    rules_file = base_dir / "rules" / "threat_rules.json"

    outputs_dir.mkdir(exist_ok=True)

    internal_feed = feeds_dir / "internal.txt"
    misp_feed = feeds_dir / "misp_feed.json"
    osint_feed = feeds_dir / "osint.csv"
    ioc_input_file = inputs_dir / "iocs.json"
    output_file = outputs_dir / "enriched_iocs.json"

    internal = load_internal_feed(internal_feed)
    misp = load_misp_feed(misp_feed)
    osint = load_osint_feed(osint_feed)
    rules = load_threat_rules(rules_file)

    feeds = {
        "internal": internal,
        "MISP": misp,
        "public": osint
    }

    enrich_iocs(ioc_input_file, output_file, feeds, rules)
    logger.info("IOC enrichment complete.")

# Entry Point
if __name__ == "__main__":
    main()
