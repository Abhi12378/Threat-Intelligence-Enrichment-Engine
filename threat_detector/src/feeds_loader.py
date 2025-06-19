import json
import csv

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

def load_all_feeds(internal_path, misp_path, osint_path):
    return {
        "internal": load_internal_feed(internal_path),
        "misp": load_misp_feed(misp_path),
        "osint": load_osint_feed(osint_path)
    }
