"""Offline cloud configuration auditor for sample JSON resources."""
from __future__ import annotations
import json
from pathlib import Path

def audit_resource(resource: dict) -> list[dict]:
    if not isinstance(resource, dict): raise ValueError("Each resource must be a JSON object")
    findings=[]; name=str(resource.get("name","unnamed"))
    def add(rule,severity,detail): findings.append({"resource":name,"rule":rule,"severity":severity,"detail":detail})
    if resource.get("type")=="storage":
        if resource.get("public_access") is True: add("CLOUD-STORAGE-001","high","Public access is enabled")
        if resource.get("encryption") is not True: add("CLOUD-STORAGE-002","high","Encryption at rest is not confirmed")
        if resource.get("logging") is not True: add("CLOUD-STORAGE-003","medium","Access logging is not confirmed")
    elif resource.get("type")=="iam":
        actions=resource.get("actions",[])
        if not isinstance(actions,list): raise ValueError("IAM actions must be a list")
        if "*" in actions: add("CLOUD-IAM-001","high","Wildcard actions may violate least privilege")
        if resource.get("mfa_required") is not True: add("CLOUD-IAM-002","high","MFA is not explicitly required")
    return findings

def audit_file(path: str) -> list[dict]:
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data,list): raise ValueError("Input JSON must be a list of resources")
    return [finding for resource in data for finding in audit_resource(resource)]

if __name__=="__main__":
    demo=[{"name":"demo-storage","type":"storage","public_access":True,"encryption":False,"logging":False},{"name":"demo-role","type":"iam","actions":["*"],"mfa_required":False}]
    print(json.dumps([f for r in demo for f in audit_resource(r)],indent=2))
