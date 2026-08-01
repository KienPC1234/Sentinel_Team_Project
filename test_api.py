#!/usr/bin/env python3
"""
ShieldCall VN Backend API - Test Suite

This script tests all API endpoints to ensure they are working correctly.
"""

import json
import urllib.request
import urllib.parse
import uuid
import sys
from pathlib import Path

# Configuration
API_BASE_URL = "http://localhost:8001"

class APITester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session_id = None
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
    
    def test_check_session(self):
        """Test 1: Check Session Management"""
        print("\n=== Test 1: Session Management ===")
        
        # Create new session with fresh UUID (non-existent in DB)
        print("\n1.1 Testing new session (non-existent UUID):")
        try:
            new_uuid = str(uuid.uuid4())
            url = f"{self.base_url}/check-session?session_id={new_uuid}"
            response = urllib.request.urlopen(url)
            data = json.loads(response.read())
            
            if data.get("is_valid") == False and data.get("new_session_id"):
                self.log_test("Create session with non-existent UUID", "PASS", 
                             f"Got new session: {data['new_session_id']}")
                self.session_id = data['new_session_id']
            else:
                self.log_test("Create session with non-existent UUID", "FAIL", str(data))
        except Exception as e:
            self.log_test("Create session with non-existent UUID", "FAIL", str(e))
        
        # Test with existing valid UUID 
        print("\n1.2 Testing existing valid session:")
        try:
            if self.session_id:
                url = f"{self.base_url}/check-session?session_id={self.session_id}"
                response = urllib.request.urlopen(url)
                data = json.loads(response.read())
                
                if data.get("is_valid") == True and data.get("new_session_id") is None:
                    self.log_test("Check existing valid session", "PASS")
                else:
                    self.log_test("Check existing valid session", "FAIL", str(data))
            else:
                self.log_test("Check existing valid session", "SKIP", "No session ID available")
        except Exception as e:
            self.log_test("Check existing valid session", "FAIL", str(e))
    
    def test_check_phone(self):
        """Test 2: Phone Security"""
        print("\n\n=== Test 2: Phone Security ===")
        
        test_phones = [
            "0912345678",
            "+84912345678",
            "0932123456"
        ]
        
        for phone in test_phones:
            try:
                url = f"{self.base_url}/check-phone?phone={urllib.parse.quote(phone)}"
                response = urllib.request.urlopen(url)
                data = json.loads(response.read())
                
                if "risk_level" in data and data["risk_level"] in ["SAFE", "GREEN", "YELLOW", "RED"]:
                    self.log_test(f"Check phone {phone}", "PASS", f"Risk: {data['risk_level']}")
                else:
                    self.log_test(f"Check phone {phone}", "FAIL", str(data))
            except Exception as e:
                self.log_test(f"Check phone {phone}", "FAIL", str(e))
    
    def test_chat_ai(self):
        """Test 3: AI Chat"""
        print("\n\n=== Test 3: AI Chat ===")
        
        if not self.session_id:
            print("Generating new session ID for chat test...")
            try:
                url = f"{self.base_url}/check-session?session_id={uuid.uuid4()}"
                response = urllib.request.urlopen(url)
                data = json.loads(response.read())
                self.session_id = data.get("new_session_id")
            except Exception as e:
                self.log_test("Chat AI", "FAIL", f"Could not get session: {e}")
                return
        
        test_messages = [
            {"message": "Tin nhắn này lừa đảo không?", "context": "general"},
            {"message": "Một ngân hàng yêu cầu tôi cung cấp thông tin tài khoản", "context": "scam"},
        ]
        
        for i, test in enumerate(test_messages):
            try:
                payload = {
                    "user_message": test["message"],
                    "session_id": self.session_id,
                    "context": test["context"]
                }
                
                req = urllib.request.Request(
                    f"{self.base_url}/chat-ai",
                    data=json.dumps(payload).encode('utf-8'),
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                
                response = urllib.request.urlopen(req)
                data = json.loads(response.read())
                
                if ("ai_response" in data):
                    self.log_test(f"Chat AI - Test {i+1}", "PASS", 
                                 f"Response length: {len(data['ai_response'])}")
                else:
                    self.log_test(f"Chat AI - Test {i+1}", "FAIL", str(data))
            except Exception as e:
                self.log_test(f"Chat AI - Test {i+1}", "FAIL", str(e))
    
    def test_report_crash(self):
        """Test 4: Crash Reporting"""
        print("\n\n=== Test 4: Crash Reporting ===")
        
        try:
            payload = {
                "device_info": "Samsung SM-G991B (SDK 34)",
                "stack_trace": "java.lang.NullPointerException...",
                "timestamp": 1706450000000,
                "version": "1.0.0",
                "severity": "ERROR"
            }
            
            req = urllib.request.Request(
                f"{self.base_url}/report-crash",
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            response = urllib.request.urlopen(req)
            data = json.loads(response.read())
            
            if data.get("status") == "success" and "report_id" in data:
                self.log_test("Report Crash", "PASS", f"Report ID: {data['report_id']}")
            else:
                self.log_test("Report Crash", "FAIL", str(data))
        except Exception as e:
            self.log_test("Report Crash", "FAIL", str(e))
    
    def print_summary(self):
        """Print test summary"""
        print("\n\n=== TEST SUMMARY ===")
        passed = sum(1 for t in self.test_results if t["status"] == "PASS")
        failed = sum(1 for t in self.test_results if t["status"] == "FAIL")
        skipped = sum(1 for t in self.test_results if t["status"] == "SKIP")
        total = len(self.test_results)
        
        print(f"Total: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Skipped: {skipped}")
        
        if failed == 0:
            print("\n✓ All tests passed!")
            return 0
        else:
            print(f"\n✗ {failed} test(s) failed")
            return 1
    
    def run_all_tests(self):
        """Run all tests"""
        print("ShieldCall VN Backend API - Test Suite")
        print(f"Base URL: {self.base_url}")
        print("=" * 50)
        
        self.test_check_session()
        self.test_check_phone()
        self.test_chat_ai()
        self.test_report_crash()
        
        return self.print_summary()


if __name__ == "__main__":
    tester = APITester(API_BASE_URL)
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)
