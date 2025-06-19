import re
from datetime import datetime, timezone

def determine_ioc_type(ioc):
    """Classify the type of IOC."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):  # IPv4
        return "ipv4-addr"
    elif re.match(r"^[a-fA-F0-9]{8,}$", ioc):  # Hexadecimal hash
        return "file-hash"
    elif re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):  # Email
        return "email-addr"
    elif re.match(r"^(?!\d{1,3}(\.\d{1,3}){3}$)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):  # Domain
        return "domain-name"
    else:
        return "file-hash"  # Fallback

def determine_threat_type(ioc, rules):
    ioc_lower = ioc.lower()
    for rule in rules:
        # Handle IP-based matching
        if "ip_range" in rule and ioc.startswith(rule["ip_range"]):
            return rule["threat_type"]
        # Handle keyword-based matching
        elif "keyword" in rule and rule["keyword"]:
            keyword = rule["keyword"].lower().strip()
            if keyword in ioc_lower:
                return rule["threat_type"]
    return "unknown"



def calculate_confidence(sources, threat_type):
    """Assign confidence score based on sources and threat type."""
    base = 0
    lower_sources = [s.lower() for s in sources]

    if "internal" in lower_sources:
        base += 50
    if "misp" in lower_sources:
        base += 30
    if "public" in lower_sources or "osint" in lower_sources:
        base += 10

    # Threat-type boost
    boost_map = {
        "ransomware": 10,
        "infostealer": 5,
        "malware": 5,
        "trojan": 5,
        "botnet": 5,
        "command-and-control": 5,
        "phishing": 5,
        "malicious-domain": 5
    }
    base += boost_map.get(threat_type.lower(), 0)

    return min(max(base, 10), 100)

def enrich_ioc(ioc, rules, feeds, id_counter):
    """Enrich a single IOC with metadata."""
    if not ioc:
        return {
            "id": f"ioc-{id_counter}",
            "value": "",
            "type": "file-hash",
            "threat_type": "unknown",
            "confidence": 10,
            "source": "unknown",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    ioc_type = determine_ioc_type(ioc)
    threat_type = determine_threat_type(ioc, rules)

    source_list = []
    for src, items in feeds.items():
        if ioc in items:
            source_list.append(src)

    confidence = calculate_confidence(source_list, threat_type)

    # Choose canonical source
    source = (
        "internal" if "internal" in source_list
        else "MISP" if "misp" in [s.lower() for s in source_list]
        else "public" if any(s.lower() in ["osint", "public"] for s in source_list)
        else "unknown"
    )

    enriched = {
        "id": f"ioc-{id_counter}",
        "value": ioc,
        "type": ioc_type,
        "threat_type": threat_type,
        "confidence": confidence,
        "source": source,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    return enriched
