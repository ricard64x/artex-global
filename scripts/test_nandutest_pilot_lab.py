import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

here=Path(__file__).with_name("nandutest_pilot_lab.py")
spec=importlib.util.spec_from_file_location("nandutest_pilot_lab",here)
lab=importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

class ContinuousPilotLabTest(unittest.TestCase):
    def test_explicit_lab_authorization_required(self):
        result=lab.run_lab(False)
        self.assertFalse(result["completed"])
        self.assertEqual(result["phases"][0]["id"],"mandate")
        self.assertEqual(result["phases"][0]["state"],"blocked")
        self.assertFalse(result["real_target_tested"])

    def test_all_eight_isolated_phases_and_access_canary(self):
        result=lab.run_lab(True)
        self.assertTrue(result["completed"])
        self.assertEqual([p["id"] for p in result["phases"]],list(lab.PHASES))
        self.assertTrue(all(p["state"]=="passed" for p in result["phases"]))
        self.assertTrue(result["synthetic_access_verified"])
        self.assertEqual(len(result["canary_sha256"]),64)
        self.assertFalse(result["real_access_demonstrated"])
        self.assertFalse(result["continuous_pentest_verified"])
        self.assertFalse(result["real_target_tested"])
        self.assertNotIn("token",json.dumps(result))

    def test_runtime_entrypoint_matches_immutable_image_path(self):
        repo=Path(__file__).resolve().parents[1]
        handler=(repo/"server/nandutest_pilot_lab.go").read_text()
        docker=(repo/"Dockerfile.nandutest").read_text()
        path="/usr/local/lib/nandutest/pilot_lab.py"
        self.assertIn('const script = "'+path+'"',handler)
        self.assertIn(path,docker)
        self.assertIn("gosu artex python3",docker)

    def test_proof_is_unique_and_not_reused_as_credential(self):
        a,b=lab.run_lab(True),lab.run_lab(True)
        self.assertNotEqual(a["canary_sha256"],b["canary_sha256"])
        self.assertTrue(a["completed"] and b["completed"])

if __name__=="__main__":
    unittest.main()
