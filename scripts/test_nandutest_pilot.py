import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+".py"))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

metrics=load("nandutest_metrics")
preflight=load("nandutest_model_preflight")

class PilotTests(unittest.TestCase):
    def test_no_reports_no_fake_precision(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=metrics.aggregate(Path(tmp))
            self.assertEqual(result["jobs_total"],0)
            self.assertIsNone(result["precision_reviewed_pct"])

    def test_p50_p95_and_human_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,complete,seconds in (("r1",True,10),("r2",True,30),("r3",False,900)):
                d=root/name
                d.mkdir()
                (d/"metrics.json").write_text(json.dumps({
                    "mode":"offline-source-only","fully_completed":complete,
                    "scan_total_seconds":seconds,"semgrep_findings":2,"trivy_findings":1}))
            review=root/"reviews.csv"
            with review.open("w",newline="") as f:
                w=csv.writer(f)
                w.writerow(["run_id","finding_id","verdict"])
                w.writerow(["r1","a","confirmed"])
                w.writerow(["r1","b","false_positive"])
            result=metrics.aggregate(root,review)
            self.assertEqual(result["jobs_total"],3)
            self.assertEqual(result["jobs_complete"],2)
            self.assertEqual(result["duration_p50_s"],10)
            self.assertEqual(result["duration_p95_s"],30)
            self.assertEqual(result["precision_reviewed_pct"],50)

    def test_ollama_endpoint_restricted(self):
        for url in ("https://ollama:11434/api/tags","http://evil.example/api/tags","http://127.0.0.1.evil.example/api/tags","file:///etc/passwd"):
            self.assertFalse(preflight.private_endpoint(url))
        self.assertTrue(preflight.private_endpoint("http://ollama:11434/api/tags"))

if __name__=="__main__":
    unittest.main()
