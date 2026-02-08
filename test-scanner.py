#!/usr/bin/env python3
"""
FinGuard Comprehensive Test Suite
Tests all scanner configurations, file uploads, and security modes
"""

import requests
import base64
import json
import time
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple

# Configuration
BASE_URL = os.getenv('FINGUARD_URL', 'http://localhost:3000')
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'admin123')
USER_USER = os.getenv('USER_USER', 'user')
USER_PASS = os.getenv('USER_PASS', 'user123')

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.errors = []
    
    def pass_test(self, name: str):
        self.passed += 1
        print(f"{Colors.GREEN}✓{Colors.END} {name}")
    
    def fail_test(self, name: str, reason: str):
        self.failed += 1
        error_msg = f"{name}: {reason}"
        self.errors.append(error_msg)
        print(f"{Colors.RED}✗{Colors.END} {name}")
        print(f"  {Colors.RED}Reason: {reason}{Colors.END}")
    
    def skip_test(self, name: str, reason: str):
        self.skipped += 1
        print(f"{Colors.YELLOW}⊘{Colors.END} {name} (skipped: {reason})")
    
    def summary(self):
        total = self.passed + self.failed + self.skipped
        print(f"\n{Colors.BOLD}=== Test Summary ==={Colors.END}")
        print(f"Total Tests: {total}")
        print(f"{Colors.GREEN}Passed: {self.passed}{Colors.END}")
        print(f"{Colors.RED}Failed: {self.failed}{Colors.END}")
        print(f"{Colors.YELLOW}Skipped: {self.skipped}{Colors.END}")
        
        if self.errors:
            print(f"\n{Colors.RED}{Colors.BOLD}Failed Tests:{Colors.END}")
            for error in self.errors:
                print(f"  - {error}")
        
        return self.failed == 0

def create_eicar() -> bytes:
    """Create EICAR test file content"""
    return b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def create_basic_auth(username: str, password: str) -> str:
    """Create Basic Auth header"""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"

def test_health_check(results: TestResults):
    """Test health endpoint"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Health Check{Colors.END}")
    
    try:
        auth = create_basic_auth(ADMIN_USER, ADMIN_PASS)
        response = requests.get(
            f"{BASE_URL}/api/health",
            headers={"Authorization": auth},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'healthy':
                results.pass_test("Health check returns healthy status")
                print(f"  Scanner: {data.get('services', {}).get('scanner', {}).get('status', 'unknown')}")
                print(f"  Security Mode: {data.get('securityMode', 'unknown')}")
            else:
                results.fail_test("Health check", f"Status is {data.get('status')}")
        else:
            results.fail_test("Health check", f"HTTP {response.status_code}")
    except Exception as e:
        results.fail_test("Health check", str(e))

def test_authentication(results: TestResults):
    """Test authentication mechanisms"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Authentication{Colors.END}")
    
    # Test admin login
    try:
        auth = create_basic_auth(ADMIN_USER, ADMIN_PASS)
        response = requests.get(
            f"{BASE_URL}/api/health",
            headers={"Authorization": auth},
            timeout=10
        )
        if response.status_code == 200:
            results.pass_test("Admin authentication")
        else:
            results.fail_test("Admin authentication", f"HTTP {response.status_code}")
    except Exception as e:
        results.fail_test("Admin authentication", str(e))
    
    # Test user login
    try:
        auth = create_basic_auth(USER_USER, USER_PASS)
        response = requests.get(
            f"{BASE_URL}/api/health",
            headers={"Authorization": auth},
            timeout=10
        )
        if response.status_code == 200:
            results.pass_test("User authentication")
        else:
            results.fail_test("User authentication", f"HTTP {response.status_code}")
    except Exception as e:
        results.fail_test("User authentication", str(e))
    
    # Test invalid credentials
    try:
        auth = create_basic_auth("invalid", "invalid")
        response = requests.get(
            f"{BASE_URL}/api/health",
            headers={"Authorization": auth},
            timeout=10
        )
        if response.status_code == 401:
            results.pass_test("Invalid credentials rejected")
        else:
            results.fail_test("Invalid credentials", f"Expected 401, got {response.status_code}")
    except Exception as e:
        results.fail_test("Invalid credentials test", str(e))

def get_current_config(auth: str) -> Dict:
    """Get current system configuration"""
    try:
        response = requests.get(
            f"{BASE_URL}/api/config",
            headers={"Authorization": auth},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}

def update_config(auth: str, config: Dict) -> bool:
    """Update system configuration"""
    try:
        response = requests.post(
            f"{BASE_URL}/api/config",
            headers={
                "Authorization": auth,
                "Content-Type": "application/json"
            },
            json=config,
            timeout=10
        )
        return response.status_code == 200
    except:
        return False

def upload_file(auth: str, filename: str, content: bytes) -> Tuple[int, Dict]:
    """Upload a file for scanning"""
    try:
        files = {'file': (filename, content)}
        response = requests.post(
            f"{BASE_URL}/api/upload",
            headers={"Authorization": auth},
            files=files,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            # Handle both response formats: direct array or wrapped in results
            if isinstance(data, dict) and 'results' in data:
                return response.status_code, data['results']
            else:
                return response.status_code, data
        else:
            return response.status_code, {"error": response.text}
    except Exception as e:
        return 500, {"error": str(e)}

def test_eicar_detection(results: TestResults):
    """Test EICAR malware detection"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing EICAR Detection{Colors.END}")
    
    auth_admin = create_basic_auth(ADMIN_USER, ADMIN_PASS)
    auth_user = create_basic_auth(USER_USER, USER_PASS)
    
    # Ensure we're in logOnly mode for proper scanning
    current_config = get_current_config(auth_admin)
    if current_config.get('securityMode') != 'logOnly':
        update_config(auth_admin, {**current_config, 'securityMode': 'logOnly'})
        time.sleep(2)
    
    eicar_content = create_eicar()
    status, response = upload_file(auth_user, "eicar.txt", eicar_content)
    
    if status == 200:
        if isinstance(response, list) and len(response) > 0:
            result = response[0]
            scan_result = result.get('scanResult', {})
            is_safe = scan_result.get('isSafe', True)
            if not is_safe:
                results.pass_test("EICAR detected as malware")
                print(f"  Scan ID: {scan_result.get('scanId', 'N/A')}")
            else:
                results.fail_test("EICAR detection", "File marked as safe (should be malware)")
        else:
            results.fail_test("EICAR detection", "Invalid response format")
    else:
        results.fail_test("EICAR detection", f"HTTP {status}")

def test_safe_file(results: TestResults, filepath: Path):
    """Test scanning a safe file"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Safe File: {filepath.name}{Colors.END}")
    
    if not filepath.exists():
        results.skip_test(f"Safe file {filepath.name}", "File not found")
        return
    
    auth = create_basic_auth(USER_USER, USER_PASS)
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        
        status, response = upload_file(auth, filepath.name, content)
        
        if status == 200:
            if isinstance(response, list) and len(response) > 0:
                result = response[0]
                scan_result = result.get('scanResult', {})
                is_safe = scan_result.get('isSafe', False)
                if is_safe:
                    results.pass_test(f"Safe file {filepath.name} detected as clean")
                    print(f"  Scan ID: {scan_result.get('scanId', 'N/A')}")
                else:
                    results.fail_test(f"Safe file {filepath.name}", "File marked as malware (false positive)")
            else:
                results.fail_test(f"Safe file {filepath.name}", "Invalid response format")
        else:
            results.fail_test(f"Safe file {filepath.name}", f"HTTP {status}")
    except Exception as e:
        results.fail_test(f"Safe file {filepath.name}", str(e))

def test_active_content_file(results: TestResults, filepath: Path):
    """Test scanning a file with active content"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Active Content: {filepath.name}{Colors.END}")
    
    if not filepath.exists():
        results.skip_test(f"Active content {filepath.name}", "File not found")
        return
    
    auth = create_basic_auth(ADMIN_USER, ADMIN_PASS)
    
    # Enable active content detection
    config = get_current_config(auth)
    original_active_content = config.get('activeContentEnabled', False)
    
    config['activeContentEnabled'] = True
    if not update_config(auth, config):
        results.skip_test(f"Active content {filepath.name}", "Failed to enable active content detection")
        return
    
    time.sleep(2)  # Wait for config to apply
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        
        status, response = upload_file(auth, filepath.name, content)
        
        if status == 200:
            if isinstance(response, list) and len(response) > 0:
                result = response[0]
                scan_result = result.get('scanResult', {})
                results.pass_test(f"Active content file {filepath.name} scanned successfully")
                print(f"  Scan ID: {scan_result.get('scanId', 'N/A')}")
                print(f"  Safe: {scan_result.get('isSafe', 'unknown')}")
            else:
                results.fail_test(f"Active content {filepath.name}", "Invalid response format")
        else:
            results.fail_test(f"Active content {filepath.name}", f"HTTP {status}")
    except Exception as e:
        results.fail_test(f"Active content {filepath.name}", str(e))
    finally:
        # Restore original config
        config['activeContentEnabled'] = original_active_content
        update_config(auth, config)

def test_scanner_configurations(results: TestResults):
    """Test different scanner configurations"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Scanner Configurations{Colors.END}")
    
    auth = create_basic_auth(ADMIN_USER, ADMIN_PASS)
    original_config = get_current_config(auth)
    
    test_configs = [
        {
            "name": "PML Enabled",
            "config": {"pmlEnabled": True},
        },
        {
            "name": "Verbose Enabled",
            "config": {"verboseEnabled": True},
        },
        {
            "name": "Active Content Enabled",
            "config": {"activeContentEnabled": True},
        },
        {
            "name": "All Features Enabled",
            "config": {
                "pmlEnabled": True,
                "verboseEnabled": True,
                "activeContentEnabled": True,
                "spnFeedbackEnabled": True,
            },
        },
        {
            "name": "Buffer Scan Method",
            "config": {"scanMethod": "buffer"},
        },
        {
            "name": "File Scan Method",
            "config": {"scanMethod": "file"},
        },
    ]
    
    for test in test_configs:
        # Merge with original config
        config = {**original_config, **test["config"]}
        
        if update_config(auth, config):
            time.sleep(1)  # Wait for config to apply
            
            # Verify config was applied
            current = get_current_config(auth)
            success = all(
                current.get(key) == value 
                for key, value in test["config"].items()
            )
            
            if success:
                results.pass_test(f"Configuration: {test['name']}")
            else:
                results.fail_test(f"Configuration: {test['name']}", "Config not applied correctly")
        else:
            results.fail_test(f"Configuration: {test['name']}", "Failed to update config")
    
    # Restore original config
    update_config(auth, original_config)
    time.sleep(2)  # Wait for config to fully apply

def test_security_modes(results: TestResults):
    """Test different security modes with EICAR uploads"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Security Modes with EICAR{Colors.END}")
    
    auth = create_basic_auth(ADMIN_USER, ADMIN_PASS)
    original_config = get_current_config(auth)
    eicar_content = create_eicar()
    
    # Test 1: Prevent Mode - Should block malware upload
    print(f"\n  Testing {Colors.YELLOW}prevent{Colors.END} mode...")
    prevent_config = {**original_config, "securityMode": "prevent"}
    if update_config(auth, prevent_config):
        time.sleep(1)
        status, response = upload_file(auth, "eicar-prevent.txt", eicar_content)
        
        # In prevent mode, check response status field (server returns HTTP 200 with status='error')
        if status == 200:
            if isinstance(response, list) and len(response) > 0:
                result = response[0]
                result_status = result.get('status', '')
                
                if result_status == 'error':
                    # Prevented upload
                    results.pass_test("Security mode: prevent (blocked malware)")
                    print(f"    ✓ Malware detected and blocked")
                    print(f"    Error: {result.get('error', 'N/A')}")
                elif result_status == 'warning':
                    # Should not happen in prevent mode
                    results.fail_test("Security mode: prevent", "Malware allowed (should be blocked)")
                else:
                    # Check scanResult
                    scan_result = result.get('scanResult', {})
                    is_safe = scan_result.get('isSafe', True)
                    if not is_safe:
                        results.fail_test("Security mode: prevent", "Malware not blocked properly")
                    else:
                        results.fail_test("Security mode: prevent", "Malware marked as safe")
            else:
                results.fail_test("Security mode: prevent", "Invalid response format")
        else:
            results.fail_test("Security mode: prevent", f"Unexpected HTTP status: {status}")
    else:
        results.fail_test("Security mode: prevent", "Failed to update config")
    
    # Test 2: LogOnly Mode - Should allow upload but log detection
    print(f"\n  Testing {Colors.YELLOW}logOnly{Colors.END} mode...")
    logonly_config = {**original_config, "securityMode": "logOnly"}
    if update_config(auth, logonly_config):
        time.sleep(1)
        status, response = upload_file(auth, "eicar-logonly.txt", eicar_content)
        
        # In logOnly mode, upload should succeed but malware should be detected
        if status == 200:
            if isinstance(response, list) and len(response) > 0:
                scan_result = response[0].get('scanResult', {})
                is_safe = scan_result.get('isSafe', True)
                if not is_safe:
                    results.pass_test("Security mode: logOnly (detected & allowed)")
                    print(f"    ✓ Upload allowed, malware detected")
                    print(f"    Scan ID: {scan_result.get('scanId', 'N/A')}")
                else:
                    results.fail_test("Security mode: logOnly", "Malware not detected")
            else:
                results.fail_test("Security mode: logOnly", "Invalid response")
        else:
            results.fail_test("Security mode: logOnly", f"Upload failed with status: {status}")
    else:
        results.fail_test("Security mode: logOnly", "Failed to update config")
    
    # Test 3: Disabled Mode - Should allow upload without scanning
    print(f"\n  Testing {Colors.YELLOW}disabled{Colors.END} mode...")
    disabled_config = {**original_config, "securityMode": "disabled"}
    if update_config(auth, disabled_config):
        time.sleep(1)
        status, response = upload_file(auth, "eicar-disabled.txt", eicar_content)
        
        # In disabled mode, upload should succeed (scanning bypassed)
        if status == 200:
            results.pass_test("Security mode: disabled (scanning bypassed)")
            print(f"    ✓ Upload allowed, scanning disabled")
        else:
            results.fail_test("Security mode: disabled", f"Upload failed with status: {status}")
    else:
        results.fail_test("Security mode: disabled", "Failed to update config")
    
    # Restore original config
    update_config(auth, original_config)
    time.sleep(2)  # Wait for config to fully apply

def test_scan_results_api(results: TestResults):
    """Test scan results retrieval"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}Testing Scan Results API{Colors.END}")
    
    auth = create_basic_auth(USER_USER, USER_PASS)
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/scan-results",
            headers={"Authorization": auth},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                results.pass_test("Scan results API accessible")
                print(f"  Total scans in history: {len(data)}")
            else:
                results.fail_test("Scan results API", "Invalid response format")
        else:
            results.fail_test("Scan results API", f"HTTP {response.status_code}")
    except Exception as e:
        results.fail_test("Scan results API", str(e))

def main():
    """Run all tests"""
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}FinGuard Comprehensive Test Suite{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"Testing server: {BASE_URL}")
    print(f"Admin credentials: {ADMIN_USER}:{'*' * len(ADMIN_PASS)}")
    print(f"User credentials: {USER_USER}:{'*' * len(USER_PASS)}")
    
    results = TestResults()
    
    # Run tests
    test_health_check(results)
    test_authentication(results)
    test_scanner_configurations(results)
    test_security_modes(results)
    test_eicar_detection(results)
    
    # Test sample files
    samples_dir = Path(__file__).parent / "samples"
    if samples_dir.exists():
        safe_pdf = samples_dir / "safe-file.pdf"
        test_safe_file(results, safe_pdf)
        
        active_content_pdf = samples_dir / "file_active_content.pdf"
        test_active_content_file(results, active_content_pdf)
    else:
        results.skip_test("Sample files", "samples directory not found")
    
    test_scan_results_api(results)
    
    # Summary
    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    success = results.summary()
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
