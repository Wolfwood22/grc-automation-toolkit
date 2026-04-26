## AWS Security Hub Compliance Extractor

Pulls active findings from AWS Security Hub, calculates compliance 
percentage by severity, and outputs a POA&M-ready CSV report.

### What It Does
- Connects to Security Hub via boto3 with least-privilege read-only credentials
- Filters to active, unresolved findings (NEW workflow status)
- Calculates compliance percentage and severity breakdown
- Outputs a CSV formatted for direct use in POA&M and audit packages
- Supports mock mode for testing without AWS access

### Compliance Relevance
- FedRAMP: ConMon evidence collection and POA&M population
- NIST 800-53: Supports CA-7 (Continuous Monitoring) and RA-5 (Vulnerability Monitoring)
- CMS ARS: Aligns with continuous monitoring requirements
- HITRUST: Supports Control Category 09 (Vulnerability Management)

### Requirements
Python 3.10+, boto3, a read-only IAM role with SecurityAudit policy

### Usage
```bash
# With real AWS credentials
python security_hub_report.py

# Mock mode (no AWS needed)
# Set client=None in get_findings() call
python security_hub_report.py
```

### Sample Output
See samples/security_hub_report_sample.csv
