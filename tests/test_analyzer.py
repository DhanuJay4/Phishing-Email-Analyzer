import unittest
from pathlib import Path
import sys

# Allow importing analyzer.py from the src folder
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analyzer import (
    extract_urls,
    analyze_url,
    get_severity,
)


class TestPhishingAnalyzer(unittest.TestCase):

    def test_url_extraction(self):
        body = "Please verify here: https://secure-login.example.com/verify"

        urls = extract_urls(body)

        self.assertEqual(len(urls), 1)
        self.assertEqual(
            urls[0],
            "https://secure-login.example.com/verify"
        )

    def test_ip_based_url(self):
        url = "http://192.0.2.10/verify"

        findings = analyze_url(url)

        self.assertTrue(
            any("IP address" in finding for finding in findings)
        )

    def test_risk_severity(self):
        self.assertEqual(get_severity(10), "LOW")
        self.assertEqual(get_severity(30), "MEDIUM")
        self.assertEqual(get_severity(50), "HIGH")
        self.assertEqual(get_severity(100), "CRITICAL")


if __name__ == "__main__":
    unittest.main()