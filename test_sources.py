"""检查演练来源和本地回放端。"""
import json
import subprocess
import threading
import unittest
from urllib.request import urlopen

from replay import ROOT, ReplayHandler, ThreadingHTTPServer


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.data = {p.stem: json.loads(p.read_bytes()) for p in (ROOT / "data").glob("*.json")}

    def test_replay_source(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), ReplayHandler) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
            worker.start()
            try:
                prefix = "http://127.0.0.1:" + str(server.server_port)
                with urlopen(prefix + "/streams", timeout=5) as response:
                    self.assertEqual(set(json.load(response)), set(self.data))
                first = self.data["timeline"][0]
                with urlopen(prefix + "/timeline?through=" + str(first["at"]), timeout=5) as response:
                    events = json.load(response)
                self.assertIn(first, events)
                self.assertLess(len(events), len(self.data["timeline"]))
            finally:
                server.shutdown()
                worker.join()

    def test_source_relationships(self):
        d = self.data
        import hashlib
        packages = {r["id"]: (r, hashlib.sha256((ROOT / r["artifact"]).read_bytes()).hexdigest())
                    for r in d["packages"]}
        self.assertEqual(len({row["version"] for row, _ in packages.values()}), 1)
        self.assertEqual(len({digest for _, digest in packages.values()}), 2)
        for package, digest in packages.values():
            proof = json.loads((ROOT / "proofs" / (package["id"] + ".json")).read_bytes())
            self.assertEqual(proof["sha256"], digest)
        self.assertEqual(len({r["authority"] for r in d["identities"] if r["person"] == "P8"}), 2)
        self.check_signatures()


    def check_signatures(self):
        proofs = ROOT / "proofs"
        files = list(proofs.glob("*.sig"))
        self.assertTrue(files)
        for signature in files:
            payload = signature.with_suffix(".json")
            key = proofs / "public" / json.loads(payload.read_bytes())["public_key"]
            result = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                                     "-inkey", str(key), "-in", str(payload),
                                     "-sigfile", str(signature)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
