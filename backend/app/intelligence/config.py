# Intelligence configuration defaults
import os
from pathlib import Path

# Ingestion settings
INGESTION_BATCH_SIZE = int(os.getenv("INGESTION_BATCH_SIZE", "100"))  # small batch for low RAM
INGESTION_TIMEOUT_SECONDS = float(os.getenv("INGESTION_TIMEOUT_SECONDS", "30"))

# Collection names (can be overridden via env if needed)
INTEL_THREAT_RECORDS = os.getenv("INTEL_THREAT_RECORDS", "threat_records")
INTEL_ATTACK_TECHNIQUES = os.getenv("INTEL_ATTACK_TECHNIQUES", "attack_techniques")
INTEL_ATTACK_PATTERNS = os.getenv("INTEL_ATTACK_PATTERNS", "attack_patterns")
INTEL_VULNERABILITIES = os.getenv("INTEL_VULNERABILITIES", "vulnerabilities")
INTEL_DETECTION_RULES = os.getenv("INTEL_DETECTION_RULES", "detection_rules")
INTEL_THREAT_RELATIONS = os.getenv("INTEL_THREAT_RELATIONS", "threat_relationships")
INTEL_KNOWLEDGE_CHUNKS = os.getenv("INTEL_KNOWLEDGE_CHUNKS", "knowledge_chunks")
INTEL_DATASET_SOURCES = os.getenv("INTEL_DATASET_SOURCES", "dataset_sources")
INTEL_INGESTION_JOBS = os.getenv("INTEL_INGESTION_JOBS", "ingestion_jobs")

# URLs for external data sources – can be overridden via env
MITRE_ATTACK_URL = os.getenv("MITRE_ATTACK_URL", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
CAPEC_URL = os.getenv("CAPEC_URL", "https://capec.mitre.org/data/json/attack-patterns.json")
NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_PAGE_SIZE = int(os.getenv("NVD_PAGE_SIZE", "200"))
NVD_REQUEST_DELAY = float(os.getenv("NVD_REQUEST_DELAY", "0.6"))
CISA_KEV_URL = os.getenv("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
SIGMA_REPOSITORY = os.getenv("SIGMA_REPOSITORY", "SigmaHQ/sigma")
SIGMA_BRANCH = os.getenv("SIGMA_BRANCH", "master")
SIGMA_MAX_RULES = int(os.getenv("SIGMA_MAX_RULES", "200"))
