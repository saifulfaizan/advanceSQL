#!/usr/bin/env python3
"""
Basic SQL Injection Scanner Usage Example
Demonstrates simple scanning of a single URL
"""

import sys
import os

# Add the parent directory to the path so we can import the scanner
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import SQLiScanner
from src.logger import setup_logger

def main():
    # Setup logging
    logger = setup_logger(verbose=True)
    
    # Target URL to scan - Replace with your target
    # Examples of real vulnerable applications for testing:
    # - DVWA: http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit
    # - bWAPP: http://localhost/bWAPP/sqli_1.php?title=1&action=search
    # - Mutillidae: http://localhost/mutillidae/index.php?page=user-info.php&username=admin&password=admin&user-info-php-submit-button=View+Account+Details
    
    target_url = input("Enter target URL to scan (or press Enter for demo): ").strip()
    if not target_url:
        target_url = "https://httpbin.org/get?id=1"  # Safe testing endpoint
        print(f"Using demo URL: {target_url}")
    
    print("🔍 Advanced SQL Injection Scanner - Basic Example")
    print("=" * 60)
    print(f"Target: {target_url}")
    print("=" * 60)
    
    # Initialize scanner with basic settings
    scanner = SQLiScanner(
        crawl_depth=2,
        threads=3,
        delay=1.0,
        timeout=10,
        output_format='json',
        verbose=True
    )
    
    try:
        # Perform the scan
        results = scanner.scan_url(
            url=target_url,
            include_forms=True
        )
        
        # Display results summary
        scanner.display_summary(results)
        
        # Export results
        json_report = scanner.export_results('json', 'basic_scan_results.json')
        html_report = scanner.export_results('html', 'basic_scan_results.html')
        
        print(f"\n📊 Reports generated:")
        print(f"  JSON: {json_report}")
        print(f"  HTML: {html_report}")
        
        # Show vulnerabilities found
        vulnerabilities = scanner.get_vulnerabilities()
        if vulnerabilities:
            print(f"\n🚨 Vulnerabilities Found ({len(vulnerabilities)}):")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"  {i}. {vuln['url']}")
                print(f"     Parameter: {vuln['parameter']}")
                print(f"     Type: {vuln['injection_type']}")
                print(f"     Severity: {vuln['severity']}")
                print(f"     DBMS: {vuln['dbms']}")
                print(f"     Payload: {vuln['payload'][:50]}...")
                print()
        else:
            print("\n✅ No SQL injection vulnerabilities found!")
    
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Scan failed: {str(e)}")

if __name__ == "__main__":
    main()
