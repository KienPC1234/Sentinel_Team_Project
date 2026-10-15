#!/usr/bin/env python3
"""
ShieldCall VN Backend API - Modern V1 Test Suite

This script tests active v1 API endpoints to ensure they are working correctly.
"""

import json
import urllib.request
import urllib.parse
import sys
import os

# Configuration
API_BASE_URL = os.getenv('API_BASE_URL', "http://localhost:8001/api/v1")
SCHEMA_URL = os.getenv('SCHEMA_URL', "http://localhost:8001/api/schema/")


class APITester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.test_results = []
    
    def log_test(self, name, status, details=""):
        """Log test result"""
        result = {
            "name": name,
            "status": status,
            "details": details
        }
        self.test_results.append(result)
        status_symbol = "✓" if status == "PASS" else "✗"
        print(f"{status_symbol} {name}: {status}")
        if details:
            print(f"  Details: {details}")

    def test_schema_endpoint(self):
        """Test 1: OpenAPI Schema Endpoint"""
        print("\n=== Test 1: OpenAPI Schema ===")
        try:
            req = urllib.request.Request(SCHEMA_URL, headers={'Accept': 'application/vnd.oai.openapi'})
            response = urllib.request.urlopen(req, timeout=10)
            content = response.read().decode('utf-8')
            if "openapi: 3.0" in content:
                self.log_test("OpenAPI 3.0 Schema Availability", "PASS", "Schema fetched and verified")
            else:
                self.log_test("OpenAPI 3.0 Schema Availability", "FAIL", "Invalid schema content")
        except Exception as e:
            self.log_test("OpenAPI 3.0 Schema Availability", "FAIL", str(e))

    def test_scan_phone(self):
        """Test 2: Phone Risk Scan (v1)"""
        print("\n=== Test 2: Phone Risk Scan ===")
        test_phones = ["0912345678", "0988888888"]
        for phone in test_phones:
            try:
                payload = {"phone": phone}
                req = urllib.request.Request(
                    f"{self.base_url}/scan/phone/",
                    data=json.dumps(payload).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                response = urllib.request.urlopen(req, timeout=15)
                data = json.loads(response.read())
                if "risk_level" in data and "risk_score" in data:
                    self.log_test(f"Scan Phone {phone}", "PASS", f"Risk: {data['risk_level']} (Score: {data['risk_score']})")
                else:
                    self.log_test(f"Scan Phone {phone}", "FAIL", str(data))
            except Exception as e:
                self.log_test(f"Scan Phone {phone}", "FAIL", str(e))

    def test_scan_domain(self):
        """Test 3: Domain Risk Scan (v1)"""
        print("\n=== Test 3: Domain Risk Scan ===")
        try:
            payload = {"domain": "google.com"}
            req = urllib.request.Request(
                f"{self.base_url}/scan/domain/",
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            response = urllib.request.urlopen(req, timeout=15)
            data = json.loads(response.read())
            if "risk_level" in data:
                self.log_test("Scan Domain google.com", "PASS", f"Risk: {data.get('risk_level')}")
            else:
                self.log_test("Scan Domain google.com", "FAIL", str(data))
        except Exception as e:
            self.log_test("Scan Domain google.com", "FAIL", str(e))

    def test_trends(self):
        """Test 4: Trends APIs (v1)"""
        print("\n=== Test 4: Trends APIs ===")
        try:
            req = urllib.request.Request(f"{self.base_url}/trends/daily/")
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read())
            self.log_test("Daily Trends Retrieval", "PASS", f"Received {len(data) if isinstance(data, list) else 'dict'} items")
        except Exception as e:
            self.log_test("Daily Trends Retrieval", "FAIL", str(e))

        try:
            req = urllib.request.Request(f"{self.base_url}/trends/hot/")
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read())
            self.log_test("Hot Trends Retrieval", "PASS", "Hot trends OK")
        except Exception as e:
            self.log_test("Hot Trends Retrieval", "FAIL", str(e))

    def print_summary(self):
        """Print test summary"""
        print("\n=== TEST SUMMARY ===")
        passed = sum(1 for t in self.test_results if t["status"] == "PASS")
        failed = sum(1 for t in self.test_results if t["status"] == "FAIL")
        total = len(self.test_results)
        
        print(f"Total: {total} | Passed: {passed} | Failed: {failed}")
        if failed == 0:
            print("\nAll tests passed successfully.")
            return 0
        else:
            print(f"\n{failed} test(s) failed.")
            return 1

    def run_all_tests(self):
        """Run all tests"""
        print("ShieldCall VN Backend API - Modern V1 Test Suite")
        print(f"Base URL: {self.base_url}")
        print("=" * 50)
        
        self.test_schema_endpoint()
        self.test_scan_phone()
        self.test_scan_domain()
        self.test_trends()
        
        return self.print_summary()


if __name__ == "__main__":
    tester = APITester(API_BASE_URL)
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)

