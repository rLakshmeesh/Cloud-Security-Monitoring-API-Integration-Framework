# ☁️ Cloud Security Monitoring & API Integration Framework

> A Python-based security automation pipeline that interconnects AWS security services (CloudTrail, GuardDuty, IAM) with Wazuh SIEM — aggregating, enriching, and correlating cloud threat signals into a unified detection feed.

---

## 📌 Overview

Modern cloud environments generate security events across multiple isolated consoles. This project builds an **API-driven security pipeline** that pulls signals from AWS, enriches them with external threat intelligence, detects IAM misconfigurations, and pushes structured alerts into a SIEM — reducing analyst context-switching and improving time-to-detect (MTTD).

**Mapped to:** MITRE ATT&CK | CIS AWS Benchmarks | OWASP API Security

---

## 🏗️ Architecture

```
AWS Account
├── CloudTrail     →  S3 bucket (API audit logs)
├── GuardDuty      →  Threat findings via API
└── IAM            →  Roles / Users via API
          ↓
   Python Pipeline (boto3)
   ├── Module 1 — GuardDuty Findings Collector
   ├── Module 2 — CloudTrail Suspicious Event Detector
   ├── Module 3 — IAM Misconfiguration Checker
   ├── Module 4 — IP Enrichment (AbuseIPDB)
   └── Module 5 — Main Aggregator & Alert Writer
          ↓
   Wazuh SIEM
   └── Custom decoder + rules → Dashboard alerts
```

---

## 🎯 Key Features

- **GuardDuty Integration** — Pulls medium/high severity findings via boto3 API
- **CloudTrail Monitoring** — Detects suspicious events (DeleteTrail, CreateUser, AttachUserPolicy, StopLogging, ConsoleLogin)
- **IAM Misconfiguration Detection** — Flags users with no MFA, AdministratorAccess, or access keys older than 90 days; mapped to CIS AWS Benchmarks
- **Threat Intel Enrichment** — Queries AbuseIPDB to append abuse confidence score, country, and malicious flag to IP-based findings
- **SIEM Pipeline Output** — Writes structured JSON alerts consumed by Wazuh custom decoder
- **Automated Scheduling** — Cron-based hourly execution

---

## 🛠️ Tech Stack

| Layer | Tool |
|---|---|
| Cloud Provider | AWS (Free Tier) |
| AWS Services | CloudTrail, GuardDuty, IAM, S3 |
| Language | Python 3.x |
| AWS SDK | boto3 |
| Threat Intel | AbuseIPDB API (free tier) |
| SIEM | Wazuh (self-hosted) |
| Scheduling | Linux cron |

---

## 📁 Project Structure

```
cloud-security-pipeline/
│
├── modules/
│   ├── guardduty_collector.py      # GuardDuty findings via API
│   ├── cloudtrail_monitor.py       # CloudTrail suspicious event detection
│   ├── iam_checker.py              # IAM misconfiguration scanner
│   └── ip_enrichment.py           # AbuseIPDB threat intel enrichment
│
├── pipeline.py                     # Main aggregator — runs all modules
├── config.py                       # AWS region, API keys, thresholds
├── wazuh/
│   ├── decoder_aws_pipeline.xml    # Custom Wazuh decoder
│   └── rules_aws_pipeline.xml      # Custom Wazuh detection rules
│
├── sample_output/
│   └── sample_alerts.json          # Example pipeline output
│
├── requirements.txt
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites

- AWS account (free tier)
- Python 3.8+
- Wazuh manager (self-hosted)
- AbuseIPDB free API key → [Register here](https://www.abuseipdb.com/register)

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/rLakshmeesh/cloud-security-pipeline.git
cd cloud-security-pipeline
```

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```
boto3
requests
```

### Step 3 — AWS Setup

**Enable CloudTrail:**
```
AWS Console → CloudTrail → Create Trail
  Trail name     : security-monitoring-trail
  S3 bucket      : Create new (auto-named)
  Log validation : Enabled
```

**Enable GuardDuty:**
```
AWS Console → GuardDuty → Get Started → Enable GuardDuty
(30-day free trial — disable after project to avoid charges)

To generate test findings:
  GuardDuty → Settings → Generate sample findings
```

**Create IAM Bot User (least privilege):**
```
IAM → Users → Create User → "security-monitor-bot"

Attach policies:
  - AmazonGuardDutyReadOnlyAccess
  - AWSCloudTrailReadOnlyAccess
  - IAMReadOnlyAccess
  - AmazonS3ReadOnlyAccess

→ Security credentials → Create access key → Download CSV
```

### Step 4 — Configure AWS Credentials

```bash
aws configure
# AWS Access Key ID     : <from CSV>
# AWS Secret Access Key : <from CSV>
# Default region        : ap-south-1
# Default output format : json
```

### Step 5 — Add API Keys to config.py

```python
# config.py

AWS_REGION = "ap-south-1"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"
SEVERITY_THRESHOLD = 4          # GuardDuty: 4=Medium, 7=High
CLOUDTRAIL_LOOKBACK_HOURS = 24
IAM_KEY_AGE_THRESHOLD_DAYS = 90
ALERT_OUTPUT_PATH = "/var/ossec/logs/"
```

---

## 🐍 Source Code

### Module 1 — GuardDuty Findings Collector

```python
# modules/guardduty_collector.py

import boto3
from config import AWS_REGION, SEVERITY_THRESHOLD

def get_guardduty_findings():
    client = boto3.client('guardduty', region_name=AWS_REGION)

    detectors = client.list_detectors()
    detector_id = detectors['DetectorIds'][0]

    finding_ids = client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            'Criterion': {
                'severity': {'Gte': SEVERITY_THRESHOLD}
            }
        }
    )['FindingIds']

    if not finding_ids:
        print("[*] GuardDuty: No findings above threshold.")
        return []

    findings = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )['Findings']

    for f in findings:
        print(f"[!] GuardDuty Finding: {f['Type']} | Severity: {f['Severity']} | Region: {f['Region']}")

    return findings
```

---

### Module 2 — CloudTrail Suspicious Event Detector

```python
# modules/cloudtrail_monitor.py

import boto3
from datetime import datetime, timedelta
from config import AWS_REGION, CLOUDTRAIL_LOOKBACK_HOURS

SUSPICIOUS_EVENTS = [
    'DeleteTrail',
    'StopLogging',
    'DeleteBucket',
    'CreateUser',
    'AttachUserPolicy',
    'ConsoleLogin',
    'PutBucketPolicy',
    'DeleteAccessKey'
]

def get_cloudtrail_events():
    client = boto3.client('cloudtrail', region_name=AWS_REGION)

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=CLOUDTRAIL_LOOKBACK_HOURS)

    events = []
    for event_name in SUSPICIOUS_EVENTS:
        response = client.lookup_events(
            LookupAttributes=[{
                'AttributeKey': 'EventName',
                'AttributeValue': event_name
            }],
            StartTime=start_time,
            EndTime=end_time
        )
        for e in response['Events']:
            print(f"[*] CloudTrail Event: {e['EventName']} by {e.get('Username', 'unknown')} at {e['EventTime']}")
            events.append(e)

    return events
```

---

### Module 3 — IAM Misconfiguration Checker

```python
# modules/iam_checker.py

import boto3
from datetime import datetime
from config import IAM_KEY_AGE_THRESHOLD_DAYS

def check_iam_misconfigs():
    iam = boto3.client('iam')
    issues = []

    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']

        # Check 1: No MFA enabled
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        if not mfa_devices:
            issue = {"type": "NO_MFA", "user": username, "severity": "HIGH"}
            print(f"[!] IAM: User '{username}' has no MFA — CIS AWS 1.10")
            issues.append(issue)

        # Check 2: AdministratorAccess attached directly
        attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for policy in attached:
            if policy['PolicyName'] == 'AdministratorAccess':
                issue = {"type": "OVER_PERMISSIONED", "user": username, "policy": "AdministratorAccess", "severity": "CRITICAL"}
                print(f"[!] IAM: User '{username}' has AdministratorAccess — over-permissioned")
                issues.append(issue)

        # Check 3: Access keys older than threshold
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            age_days = (datetime.utcnow().replace(tzinfo=key['CreateDate'].tzinfo) - key['CreateDate']).days
            if age_days > IAM_KEY_AGE_THRESHOLD_DAYS:
                issue = {"type": "OLD_ACCESS_KEY", "user": username, "key_id": key['AccessKeyId'], "age_days": age_days, "severity": "MEDIUM"}
                print(f"[!] IAM: Access key for '{username}' is {age_days} days old — rotate required")
                issues.append(issue)

    return issues
```

---

### Module 4 — IP Enrichment via AbuseIPDB

```python
# modules/ip_enrichment.py

import requests
from config import ABUSEIPDB_API_KEY

def enrich_ip(ip_address):
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        },
        params={
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }
    )

    if response.status_code != 200:
        return {"ip": ip_address, "error": "enrichment_failed"}

    data = response.json()['data']
    enrichment = {
        "ip": ip_address,
        "abuse_confidence_score": data['abuseConfidenceScore'],
        "country": data['countryCode'],
        "total_reports": data['totalReports'],
        "is_malicious": data['abuseConfidenceScore'] > 50,
        "isp": data.get('isp', 'unknown')
    }

    if enrichment['is_malicious']:
        print(f"[!] Malicious IP detected: {ip_address} | Score: {data['abuseConfidenceScore']} | Country: {data['countryCode']}")

    return enrichment
```

---

### Module 5 — Main Pipeline Aggregator

```python
# pipeline.py

import json
from datetime import datetime
from modules.guardduty_collector import get_guardduty_findings
from modules.cloudtrail_monitor import get_cloudtrail_events
from modules.iam_checker import check_iam_misconfigs
from modules.ip_enrichment import enrich_ip
from config import ALERT_OUTPUT_PATH

def run_pipeline():
    print("=" * 60)
    print(f"[+] Pipeline Start: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 60)

    all_alerts = []

    # --- GuardDuty ---
    print("\n[1/3] Collecting GuardDuty Findings...")
    findings = get_guardduty_findings()
    for f in findings:
        alert = {
            "source": "guardduty",
            "type": f['Type'],
            "severity": f['Severity'],
            "timestamp": str(f['CreatedAt']),
            "description": f['Description'],
            "region": f['Region']
        }
        # Enrich IP if network action present
        try:
            action = f['Service']['Action']
            if 'NetworkConnectionAction' in action:
                ip = action['NetworkConnectionAction']['RemoteIpDetails']['IpAddressV4']
                alert['ip_enrichment'] = enrich_ip(ip)
        except KeyError:
            pass
        all_alerts.append(alert)

    # --- CloudTrail ---
    print("\n[2/3] Scanning CloudTrail Events...")
    events = get_cloudtrail_events()
    for e in events:
        all_alerts.append({
            "source": "cloudtrail",
            "event_name": e['EventName'],
            "user": e.get('Username', 'unknown'),
            "timestamp": str(e['EventTime']),
            "source_ip": e.get('SourceIPAddress', 'unknown')
        })

    # --- IAM ---
    print("\n[3/3] Checking IAM Misconfigurations...")
    misconfigs = check_iam_misconfigs()
    for m in misconfigs:
        all_alerts.append({"source": "iam_checker", **m})

    # --- Write Output ---
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    output_file = f"{ALERT_OUTPUT_PATH}security_pipeline_{timestamp}.json"

    with open(output_file, 'w') as f:
        json.dump(all_alerts, f, indent=2, default=str)

    print(f"\n{'=' * 60}")
    print(f"[+] Pipeline Complete: {len(all_alerts)} alerts written to {output_file}")
    print(f"{'=' * 60}\n")

if __name__ == "__main__":
    run_pipeline()
```

---

## 🔌 Wazuh Integration

### 1. Add Custom Decoder

Place in `/var/ossec/etc/decoders/decoder_aws_pipeline.xml`:

```xml
<decoder name="aws-security-pipeline">
  <prematch>{"source":</prematch>
  <regex>"source": "(\w+)"</regex>
  <order>aws.source</order>
</decoder>
```

### 2. Add Custom Rules

Place in `/var/ossec/etc/rules/rules_aws_pipeline.xml`:

```xml
<group name="aws,cloud,security-pipeline">

  <rule id="100200" level="10">
    <decoded_as>aws-security-pipeline</decoded_as>
    <field name="aws.source">guardduty</field>
    <description>GuardDuty: Threat finding detected in AWS environment</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>

  <rule id="100201" level="8">
    <decoded_as>aws-security-pipeline</decoded_as>
    <field name="aws.source">cloudtrail</field>
    <description>CloudTrail: Suspicious API event detected</description>
  </rule>

  <rule id="100202" level="12">
    <decoded_as>aws-security-pipeline</decoded_as>
    <field name="aws.source">iam_checker</field>
    <description>IAM Misconfiguration: CIS AWS Benchmark violation detected</description>
    <mitre>
      <id>T1078.004</id>
    </mitre>
  </rule>

</group>
```

### 3. Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/ossec-logtest   # Validate decoder
```

---

## ⏰ Automate with Cron

Run the pipeline every hour automatically:

```bash
crontab -e
```

Add this line:

```bash
0 * * * * python3 /home/laksh/cloud-security-pipeline/pipeline.py >> /home/laksh/pipeline.log 2>&1
```

---

## 📊 Sample Output

```json
[
  {
    "source": "guardduty",
    "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    "severity": 7.5,
    "timestamp": "2025-06-15 09:42:11",
    "description": "API calls were made from a known malicious IP.",
    "region": "ap-south-1",
    "ip_enrichment": {
      "ip": "185.220.101.45",
      "abuse_confidence_score": 98,
      "country": "RO",
      "total_reports": 512,
      "is_malicious": true,
      "isp": "Frantech Solutions"
    }
  },
  {
    "source": "cloudtrail",
    "event_name": "DeleteTrail",
    "user": "dev-user-01",
    "timestamp": "2025-06-15 10:01:33",
    "source_ip": "103.x.x.x"
  },
  {
    "source": "iam_checker",
    "type": "NO_MFA",
    "user": "test-user",
    "severity": "HIGH"
  }
]
```

---

## 🔍 MITRE ATT&CK Coverage

| Technique | ID | Detection Source |
|---|---|---|
| Valid Accounts — Cloud Accounts | T1078.004 | GuardDuty + IAM Checker |
| Brute Force | T1110 | GuardDuty |
| Disable Cloud Logs | T1562.008 | CloudTrail (StopLogging, DeleteTrail) |
| Create Account | T1136 | CloudTrail (CreateUser) |
| Account Manipulation | T1098 | CloudTrail (AttachUserPolicy) |

---

## ⚠️ Cost & Free Tier Notice

This project is designed to run **entirely within AWS Free Tier**:

| Service | Free Tier Limit |
|---|---|
| CloudTrail | 1 trail + 90-day event history — Free |
| GuardDuty | 30-day free trial — **disable after use** |
| IAM | Always free |
| S3 | 5 GB storage free |
| AbuseIPDB | 1,000 checks/day free |

> ⚡ **Important:** Disable GuardDuty after completing the project if you don't plan to use it actively. It charges per GB of data analysed after the free trial ends.

---

## 🚀 Future Enhancements

- [ ] Add Slack / email alerting for critical findings
- [ ] Integrate AWS Security Hub as a unified findings aggregator
- [ ] Extend IAM checks to detect unused roles and S3 public bucket exposure
- [ ] Add Terraform scripts to provision the entire AWS setup as Infrastructure as Code
- [ ] Build a lightweight Flask dashboard to visualize pipeline output

---

## 👤 Author

**Lakshmeesh R**
Cybersecurity Analyst | Detection Engineering | Cloud Security

[![LinkedIn](https://img.shields.io/badge/LinkedIn-lakshmeesh-blue)](https://linkedin.com/in/lakshmeesh)
[![GitHub](https://img.shields.io/badge/GitHub-rLakshmeesh-black)](https://github.com/rLakshmeesh)

---

## 📄 License

This project is licensed under the MIT License — free to use, modify, and distribute.
