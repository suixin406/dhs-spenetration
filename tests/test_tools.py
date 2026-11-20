import base64
import hashlib
import hmac
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_tool(name):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ScopeGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("scope_guard")
        cls.config = json.loads((ROOT / "AUTHORIZED-TARGETS.template.json").read_text(encoding="utf-8"))

    def test_local_lab_allowed(self):
        result = self.tool.evaluate(self.config, "https://127.0.0.1:8443", "active")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["scopeId"], "local-lab")

    def test_wildcard_and_port(self):
        now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        result = self.tool.evaluate(self.config, "https://api.example.test:443", "active", now=now)
        self.assertTrue(result["allowed"])
        implicit = self.tool.evaluate(self.config, "https://api.example.test/path", "active", now=now)
        self.assertTrue(implicit["allowed"])
        denied = self.tool.evaluate(self.config, "https://api.example.test:444", "active", now=now)
        self.assertFalse(denied["allowed"])

    def test_out_of_scope_denied(self):
        result = self.tool.evaluate(self.config, "https://example.com", "active")
        self.assertFalse(result["allowed"])

    def test_raw_ipv6(self):
        result = self.tool.evaluate(self.config, "::1", "active")
        self.assertTrue(result["allowed"])

    def test_destructive_requires_per_invocation_confirmation(self):
        denied = self.tool.evaluate(self.config, "localhost", "destructive")
        allowed = self.tool.evaluate(self.config, "localhost", "destructive", confirm_destructive=True)
        self.assertFalse(denied["allowed"])
        self.assertTrue(allowed["allowed"])


class CryptoToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("crypto_tool")

    def test_auto_prefers_hex(self):
        self.assertEqual(self.tool.try_decode("deadbeef"), bytes.fromhex("deadbeef"))

    def test_strict_base64(self):
        self.assertEqual(self.tool.try_decode("aGVsbG8=", "base64"), b"hello")
        with self.assertRaises(ValueError):
            self.tool.try_decode("not base64!", "base64")


class JwtToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool("jwt_tool")

    def test_hs512_signing_uses_header_algorithm(self):
        token = self.tool.sign_hs({"alg": "HS512", "typ": "JWT"}, {"sub": "1"}, b"secret")
        header, payload, signature = token.split(".")
        expected = base64.urlsafe_b64encode(
            hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha512).digest()
        ).rstrip(b"=").decode()
        self.assertEqual(signature, expected)

    def test_non_hmac_algorithm_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.tool.sign_hs({"alg": "RS256"}, {"sub": "1"}, b"secret")


class ExtractorSmokeTests(unittest.TestCase):
    def test_cli_help(self):
        for name in (
            "apk_extract.py",
            "crypto_tool.py",
            "http_concurrent.py",
            "jsintel.py",
            "jwt_tool.py",
            "otp_brute.py",
            "scope_guard.py",
        ):
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "tools" / name), "--help"],
                    check=False,
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_apk_manifest_output(self):
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            apk = temp_path / "sample.apk"
            output = temp_path / "out"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"package.name\x00android.permission.INTERNET\x00")
                archive.writestr("classes.dex", b"https://api.example.test/v1/login\x00token\x00")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "apk_extract.py"), str(apk), "-o", str(output)],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            manifest = (output / "manifest.txt").read_text(encoding="utf-8")
            self.assertIn("android.permission.INTERNET", manifest)
            self.assertTrue((output / "endpoints.txt").is_file())

    def test_jsintel_local_file(self):
        tool = load_tool("jsintel")
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "app.js"
            source.write_text('const baseURL="https://api.example.test"; fetch("/api/login")', encoding="utf-8")
            text = tool.read_source(str(source), max_bytes=1024)
            self.assertIn("/api/login", text)


if __name__ == "__main__":
    unittest.main()
