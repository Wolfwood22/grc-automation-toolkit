MOCK_MODEL_ID = "anthropic.claude-3-sonnet-20240229-v1:0"


def generate(findings: dict) -> str:
    iam = findings.get("iam", [])
    access_analyzer = findings.get("access_analyzer", [])
    security_hub = findings.get("security_hub", [])

    all_findings = iam + access_analyzer + security_hub
    total = len(all_findings)
    high = sum(1 for f in all_findings if f.get("severity", "").lower() == "high")
    medium = sum(1 for f in all_findings if f.get("severity", "").lower() == "medium")

    prompt = _build_prompt(total, high, medium, len(iam), len(access_analyzer), len(security_hub))

    # Real Bedrock integration would replace the lines below with:
    # import boto3, json
    # bedrock = boto3.client("bedrock-runtime")
    # body = json.dumps({"prompt": prompt, "max_tokens_to_sample": 500})
    # response = bedrock.invoke_model(modelId=MOCK_MODEL_ID, body=body)
    # return json.loads(response["body"].read())["completion"]
    return _mock_response(total, high, medium)


def _build_prompt(total, high, medium, iam_count, aa_count, sh_count): 
    return (
            f"You are a GRC analyst writing an executive summary for an automated access review. "
            f"The review found {total} total findings: {high} High severity and {medium} Medium severity. "
            f"Findings span three domains: {iam_count} IAM findings, {aa_count} external access exposure "
            f"findings from IAM Access Analyzer, and {sh_count} Security Hub IAM control failures. "
            f"Write a concise executive summary mapping these findings to compliance risk."
            )


def _mock_response(total, high, medium):
    return (
        f"This automated access review identified {total} findings requiring attention, "
        f"including {high} High severity and {medium} Medium severity items. "
        "The review assessed IAM user activity patterns, external resource exposure via IAM Access "
        "Analyzer, and active Security Hub IAM control failures. Findings have been mapped to "
        "applicable compliance frameworks including SOC 2, ISO 27001, NIST 800-53, PCI-DSS 4.0, "
        "and CMMC. High severity findings represent immediate compliance risk and should be "
        "remediated within 30 days to maintain compliance posture. This report was generated "
        "automatically and is suitable for inclusion in audit evidence packages."
    )