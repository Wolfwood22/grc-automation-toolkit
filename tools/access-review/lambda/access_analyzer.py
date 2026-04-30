import boto3    


def collect(analyzer_client=None):
    if analyzer_client is None:
        analyzer_client = boto3.client("accessanalyzer")
    analyzers = analyzer_client.list_analyzers()["analyzers"]                                       
    if not analyzers:
        return []                                                                                   
                
    analyzer_arn = analyzers[0]["arn"]
    findings = []

    paginator = analyzer_client.get_paginator("list_findings")                                      
    for page in paginator.paginate(
        analyzerArn=analyzer_arn,                                                                   
        filter={"status": {"eq": ["ACTIVE"]}},
    ):
        for f in page["findings"]:
            findings.append({                                                                       
                "resource_type": f.get("resourceType", "Unknown"),
                "resource_arn": f.get("resource", "Unknown"),                                       
                "principal": str(f.get("principal", {})),
                "access_level": f.get("action", ["Unknown"])[0] if f.get("action") else "Unknown",  
                "severity": "High" if f.get("isPublic") else "Medium",
            })                                                                                      
    return findings 