"""Offline cloud configuration checks for sample JSON objects."""
def audit_resource(resource: dict) -> list[dict]:
    findings = []
    name = str(resource.get("name", "unnamed-resource"))
    def add(rule, severity, detail):
        findings.append({"resource": name, "rule": rule, "severity": severity, "detail": detail})
    if resource.get("type") == "storage":
        if resource.get("public_access") is True:
            add("CLOUD-STORAGE-001", "high", "Public access is enabled")
        if resource.get("encryption") is not True:
            add("CLOUD-STORAGE-002", "high", "Encryption at rest is not confirmed")
        if resource.get("logging") is not True:
            add("CLOUD-STORAGE-003", "medium", "Access logging is not confirmed")
    if resource.get("type") == "iam":
        if "*" in resource.get("actions", []):
            add("CLOUD-IAM-001", "high", "Wildcard actions may violate least privilege")
        if resource.get("mfa_required") is False:
            add("CLOUD-IAM-002", "high", "MFA is not required")
    return findings

if __name__ == "__main__":
    samples = [
        {"name":"demo-public-bucket", "type":"storage", "public_access":True, "encryption":False, "logging":False},
        {"name":"demo-admin-role", "type":"iam", "actions":["*"], "mfa_required":False}
    ]
    for sample in samples:
        for finding in audit_resource(sample): print(finding)