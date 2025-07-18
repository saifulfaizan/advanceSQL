#!/usr/bin/env python3
"""
Advanced SQL Injection Scanner Usage Example
Demonstrates advanced features including authentication, proxy, and custom payloads
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
    
    print("🔍 Advanced SQL Injection Scanner - Advanced Example")
    print("=" * 60)
    
    # Initialize scanner with advanced settings
    scanner = SQLiScanner(
        crawl_depth=3,
        threads=5,
        delay=0.5,
        timeout=15,
        proxy=None,  # Set to "http://127.0.0.1:8080" for Burp Suite
        output_format='html',
        verbose=True
    )
    
    # Example 1: Scan with authentication
    print("\n📋 Example 1: Authenticated Scan")
    print("-" * 40)
    
    # Get authentication details from user
    target_url = input("Enter target URL for authenticated scan (or press Enter for demo): ").strip()
    if not target_url:
        target_url = "https://httpbin.org/basic-auth/user/pass"
        auth_url = target_url
        username = "user"
        password = "pass"
        print(f"Using demo authenticated endpoint: {target_url}")
    else:
        auth_url = input("Enter authentication URL: ").strip() or target_url
        username = input("Enter username: ").strip() or "admin"
        password = input("Enter password: ").strip() or "admin"
    
    try:
        results = scanner.scan_url(
            url=target_url,
            auth_url=auth_url,
            username="test",
            password="test",
            include_forms=True,
            custom_payloads="payloads/custom_payloads.txt"
        )
        
        print(f"✅ Authenticated scan completed")
        print(f"   Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        
    except Exception as e:
        print(f"❌ Authenticated scan failed: {str(e)}")
    
    # Example 2: Scan with Burp Suite integration
    print("\n📋 Example 2: Burp Suite Integration")
    print("-" * 40)
    
    # Setup Burp Suite integration (requires Burp running on localhost:8080)
    burp_configured = scanner.setup_burp_integration(
        burp_host='127.0.0.1',
        burp_port=8080
    )
    
    if burp_configured:
        print("✅ Burp Suite integration configured")
        
        try:
            target_url = "http://testphp.vulnweb.com/artists.php?artist=1"
            results = scanner.scan_url(
                url=target_url,
                include_forms=True
            )
            
            print(f"✅ Burp-proxied scan completed")
            print(f"   Check Burp Suite history for captured requests")
            
        except Exception as e:
            print(f"❌ Burp-proxied scan failed: {str(e)}")
    else:
        print("⚠️  Burp Suite not available, skipping integration example")
    
    # Example 3: Scan with OWASP ZAP integration
    print("\n📋 Example 3: OWASP ZAP Integration")
    print("-" * 40)
    
    # Setup ZAP integration (requires ZAP running with API enabled)
    zap_configured = scanner.setup_zap_integration(
        zap_host='127.0.0.1',
        zap_port=8080,
        api_key='your-zap-api-key'  # Replace with actual API key
    )
    
    if zap_configured:
        print("✅ OWASP ZAP integration configured")
        
        try:
            target_url = "http://testphp.vulnweb.com/"
            results = scanner.scan_url(
                url=target_url,
                include_forms=True
            )
            
            print(f"✅ ZAP-integrated scan completed")
            print(f"   Check ZAP for additional security findings")
            
        except Exception as e:
            print(f"❌ ZAP-integrated scan failed: {str(e)}")
    else:
        print("⚠️  OWASP ZAP not available, skipping integration example")
    
    # Example 4: Batch scan from file
    print("\n📋 Example 4: Batch Scan from File")
    print("-" * 40)
    
    # Create a sample URL list file
    url_list_file = "examples/target_urls.txt"
    sample_urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg",
    ]
    
    try:
        with open(url_list_file, 'w') as f:
            f.write("# Sample target URLs for batch scanning\n")
            for url in sample_urls:
                f.write(f"{url}\n")
        
        print(f"📝 Created sample URL list: {url_list_file}")
        
        # Perform batch scan
        batch_results = scanner.scan_from_file(
            file_path=url_list_file,
            include_forms=True,
            custom_payloads="payloads/custom_payloads.txt"
        )
        
        print(f"✅ Batch scan completed")
        print(f"   Total targets scanned: {batch_results.get('scan_statistics', {}).get('total_targets_tested', 0)}")
        print(f"   Total vulnerabilities: {batch_results.get('scan_statistics', {}).get('total_vulnerabilities_found', 0)}")
        
        # Display batch results summary
        scanner.display_summary(batch_results)
        
    except Exception as e:
        print(f"❌ Batch scan failed: {str(e)}")
    
    # Example 5: Custom payload testing
    print("\n📋 Example 5: Custom Payload Testing")
    print("-" * 40)
    
    try:
        target_url = "http://testphp.vulnweb.com/artists.php?artist=1"
        
        results = scanner.scan_url(
            url=target_url,
            custom_payloads="payloads/custom_payloads.txt",
            target_dbms="mysql",  # Target specific DBMS
            include_forms=True
        )
        
        print(f"✅ Custom payload scan completed")
        
        # Show database dumps if any
        database_dumps = scanner.get_database_dumps()
        if database_dumps:
            print(f"\n💾 Database Information Extracted:")
            for dump in database_dumps:
                print(f"   DBMS: {dump.get('dbms', 'Unknown')}")
                if dump.get('version'):
                    print(f"   Version: {dump['version']}")
                if dump.get('current_database'):
                    print(f"   Database: {dump['current_database']}")
                if dump.get('current_user'):
                    print(f"   User: {dump['current_user']}")
                if dump.get('tables'):
                    for db, tables in dump['tables'].items():
                        print(f"   Tables in {db}: {', '.join(tables[:5])}")
        
    except Exception as e:
        print(f"❌ Custom payload scan failed: {str(e)}")
    
    # Generate comprehensive reports
    print("\n📊 Generating Reports")
    print("-" * 40)
    
    try:
        # Generate reports in all formats
        json_report = scanner.export_results('json', 'advanced_scan_results.json')
        html_report = scanner.export_results('html', 'advanced_scan_results.html')
        txt_report = scanner.export_results('txt', 'advanced_scan_results.txt')
        
        print(f"✅ Reports generated:")
        print(f"   JSON: {json_report}")
        print(f"   HTML: {html_report}")
        print(f"   Text: {txt_report}")
        
        # Show scan statistics
        stats = scanner.get_scan_statistics()
        if stats:
            print(f"\n📈 Scan Statistics:")
            for key, value in stats.items():
                print(f"   {key.replace('_', ' ').title()}: {value}")
        
    except Exception as e:
        print(f"❌ Report generation failed: {str(e)}")
    
    print("\n" + "=" * 60)
    print("🎉 Advanced scanning examples completed!")
    print("Check the generated reports for detailed results.")
    print("=" * 60)

if __name__ == "__main__":
    main()
