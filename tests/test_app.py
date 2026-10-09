import unittest
from app import audit_resource
class CloudAuditTests(unittest.TestCase):
 def test_public_storage_flagged(self):
  self.assertIn("CLOUD-STORAGE-001",[x["rule"] for x in audit_resource({"name":"x","type":"storage","public_access":True})])
 def test_encryption_missing_flagged(self):
  self.assertIn("CLOUD-STORAGE-002",[x["rule"] for x in audit_resource({"type":"storage"})])
 def test_wildcard_iam_flagged(self):
  self.assertIn("CLOUD-IAM-001",[x["rule"] for x in audit_resource({"type":"iam","actions":["*"],"mfa_required":True})])
 def test_bad_resource_rejected(self):
  with self.assertRaises(ValueError): audit_resource([])
 def test_no_findings_for_hardened_storage(self):
  self.assertEqual(audit_resource({"type":"storage","public_access":False,"encryption":True,"logging":True}),[])
if __name__=="__main__": unittest.main()
