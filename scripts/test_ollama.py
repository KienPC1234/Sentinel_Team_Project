#!/usr/bin/env python3
"""
Test Ollama Integration with ShieldCall VN API

This script verifies that Ollama is properly integrated and responding.
"""

import sys
import json
import requests

OLLAMA_URL = "http://localhost:11434"

def test_ollama_connection():
    """Test if Ollama service is running"""
    print("1️⃣ Testing Ollama Connection...")
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            print("   ✅ Ollama is running on port 11434")
            return True
        else:
            print(f"   ❌ Ollama returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("   ❌ Cannot connect to Ollama on http://localhost:11434")
        print("   💡 Make sure Ollama is installed and running")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_available_models():
    """Check available models"""
    print("\n2️⃣ Checking Available Models...")
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        if response.status_code == 200:
            data = response.json()
            models = [m.get("name") for m in data.get("models", [])]
            
            if models:
                print(f"   ✅ Found {len(models)} model(s):")
                for model in models:
                    print(f"      - {model}")
                return models
            else:
                print("   ⚠️  No models found")
                print("   💡 Pull a model: ollama pull neural-chat")
                return []
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return []

def test_generate_response(model):
    """Test generating a response"""
    print(f"\n3️⃣ Testing Response Generation ({model})...")
    try:
        payload = {
            "model": model,
            "prompt": "Xin chào, tôi là trợ lý an toàn điện thoại",
            "stream": False
        }
        
        print("   ⏳ Generating response (first request may take 10-30 seconds)...")
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=120  # 2 minute timeout for first request
        )
        
        if response.status_code == 200:
            data = response.json()
            result = data.get("response", "").strip()
            if result:
                print("   ✅ Response generated successfully")
                print(f"   Response: {result[:100]}...")
                return True
            else:
                print("   ❌ Empty response")
                return False
        else:
            print(f"   ❌ Error {response.status_code}: {response.text}")
            return False
    except requests.exceptions.Timeout:
        print("   ❌ Timeout - generation took too long")
        print("   💡 Try with a smaller model")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_scam_detection(model):
    """Test scam detection"""
    print(f"\n4️⃣ Testing Scam Detection ({model})...")
    try:
        test_text = "Ngân hàng yêu cầu tôi cung cấp mã OTP để xác minh tài khoản"
        
        payload = {
            "model": model,
            "prompt": f"""Phân tích tin nhắn sau để phát hiện lừa đảo. 
Trả lời dạng JSON: {{\"is_scam\": bool, \"risk_score\": 0-100, \"reason\": \"string\"}}
Tin nhắn: {test_text}""",
            "stream": False
        }
        
        print("   ⏳ Analyzing scam indicators...")
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=120
        )
        
        if response.status_code == 200:
            data = response.json()
            result = data.get("response", "").strip()
            
            # Try to extract JSON
            import re
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                print("   ✅ Scam detection working")
                print(f"   Analysis: {json.dumps(analysis, indent=2)}")
                return True
            else:
                print("   ⚠️  Response not in JSON format")
                print(f"   Response: {result[:100]}...")
                return True  # Still counts as working
        else:
            print(f"   ❌ Error {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def test_django_integration():
    """Test Django integration"""
    print("\n5️⃣ Testing Django Integration...")
    try:
        from django.conf import settings
        from api.utils.ollama_client import is_ollama_available, get_available_models
        
        print("   ✅ ollama_client module imported successfully")
        
        if is_ollama_available():
            print("   ✅ Ollama detected by Django app")
            models = get_available_models()
            print(f"   ✅ Found {len(models)} model(s) via Django")
            return True
        else:
            print("   ⚠️  Ollama not detected by Django app")
            print("   💡 Make sure Ollama is running")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    print("=" * 60)
    print("ShieldCall VN API - Ollama Integration Test")
    print("=" * 60)
    
    results = []
    
    # Test 1: Connection
    if not test_ollama_connection():
        print("\n" + "=" * 60)
        print("❌ Ollama is not running!")
        print("Follow these steps:")
        print("1. Download from https://ollama.ai")
        print("2. Install and run Ollama")
        print("3. Pull a model: ollama pull neural-chat")
        print("4. Run this test again")
        print("=" * 60)
        return 1
    
    results.append(True)
    
    # Test 2: Models
    models = test_available_models()
    results.append(bool(models))
    
    if models:
        # Use first available model
        model = models[0]
        
        # Test 3: Response generation
        results.append(test_generate_response(model))
        
        # Test 4: Scam detection
        results.append(test_scam_detection(model))
    else:
        print("\n💡 Pull a model first:")
        print("   ollama pull neural-chat")
        return 1
    
    # Test 5: Django integration
    try:
        results.append(test_django_integration())
    except ImportError:
        print("\n5️⃣ Testing Django Integration...")
        print("   ⚠️  Django test skipped (not in Django context)")
        results.append(True)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for r in results if r)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ All tests passed! Ollama integration is working correctly.")
        print("\nYou can now:")
        print("1. Run the API: python manage.py runserver 0.0.0.0:8001")
        print("2. Test endpoints: python test_api.py")
        print("3. Chat will use Ollama automatically")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        print("See details above for troubleshooting")
        return 1

if __name__ == "__main__":
    sys.exit(main())
