Threat Intelligence Enrichment Engine
===========================================

📌 Project Overview:
---------------------
This project is a Python-based Threat Intelligence IOC (Indicator of Compromise) Enrichment Engine. It automatically enriches raw IOCs (domains, IPs, file hashes) with relevant metadata like:

- Threat Type (based on keyword or IP range rules)

- IOC Type (domain, IP address, file hash, etc.)

- Source Feed (internal, MISP, OSINT)

- Internal: Your organization's own threat intel

- OSINT, or Open Source Intelligence, in cybersecurity refers to the practice of gathering and analyzing publicly available information to gain insights into potential threats and vulnerabilities

- MISP, which stands for Malware Information Sharing Platform and Threat Sharing, is an open-source threat intelligence platform used for collecting, storing, analyzing, and sharing cyber threat information

- Ransomware is a type of malicious software (malware) that restricts access to computer systems or files, often by encrypting them, and demands a ransom payment for their release.

- InfoStealer (short for Information Stealer) is a type of malware designed specifically to steal sensitive data from a victim's device without their knowledge. It is commonly used by cybercriminals to extract valuable personal, financial, or corporate information.

- Botnet (short for robot network) is a network of compromised computers or devices—often referred to as "bots" or "zombies"—that are infected with malware and remotely controlled by a cybercriminal known as a botmaster. These devices, which can include PCs, servers, IoT gadgets, and mobile phones, are unknowingly co-opted to perform coordinated malicious tasks without the owners' knowledge. Botnets are commonly used for large-scale cyberattacks such as Distributed Denial of Service (DDoS) attacks, 

- Confidence Score

- Timestamp (in UTC)

It also supports ingestion of threat feeds from JSON files and evaluates each IOC for enrichment.

🧠 Problem Statement:
----------------------
Given a collection of threat IOCs and a set of rules/feeds:
- Identify the type of each IOC (domain-name, ipv4-addr, file-hash)
- Map each IOC to a threat type using matching rules
- Identify the source (internal, misp, osint)
- Compute a confidence score based on source + threat type
- Generate a structured, enriched output with a timestamp

✅ Features:
------------
- Rule-based threat type classification
- IOC type determination via regex
- Confidence scoring using a heuristic model
- Feed loader for rules and threat intel sets
- Complete unit test coverage with `pytest` and `pytest-cov`

⚙️ How to Use:
--------------
1. Clone the project and navigate into the root directory.

2. Ensure Python 3.12+ is installed.

3. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate   # On Windows


Run Tests:
pytest threat_enricher/tests/ -v

Generate HTML Coverage Report:
pytest --cov=enrich --cov-report=html threat_enricher/tests/
pytest --cov=src tests/ --cov-report=html

🧪 Testing:

  1)  All core logic (enrich.py) is covered by unittest cases.

  2)  Includes positive and negative tests for:
        Threat type determination
        IOC type detection
        Confidence calculation
        Full enrichment of IOC with realistic inputs

  3)  Also includes tests for:
        Feed loading functions in feeds_loader.py
        JSON error handling
        File not found and value error edge cases

  4)  📊 Sample IOC Enrichment Output:

{
  "value": "stealer-domain.com",
  "type": "domain-name",
  "threat_type": "infostealer",
  "source": "public",
  "confidence": 60,
  "timestamp": "2025-06-17T08:00:00Z"
}

📝 Notes:

1) The engine defaults unknown values gracefully (e.g., empty input or unmatched rules).

2) Uses regex to determine IOC type.

3) If no known sources are found, confidence score defaults to a minimal value (e.g., 10).

4) Uses datetime in UTC format for reporting.

📦 Requirements (requirements.txt):
    pip install pytest
    pip install pytest-cov
    pip install tzdata
    
