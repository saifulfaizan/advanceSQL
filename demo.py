#!/usr/bin/env python3
"""
Advance SQL Injection Scanner - Demo Script
Demonstrates the scanner capabilities with a safe test environment
"""

import sys
import os
import time
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.scanner import SQLiScanner
from src.logger import setup_logger

def print_banner():
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                Advanced SQL Injection Scanner                ║
║                        DEMO SCRIPT                          ║
║                     Version 1.0                             ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def print_section(title):
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"🔍 {title}")
    print(f"{'='*60}{Style.RESET_ALL}")

def print_success(message):
    print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")

def print_info(message):
    print(f"{Fore.BLUE}ℹ️  {message}{Style.RESET_ALL}")

def print_warning(message):
    print(f"{Fore.YELLOW}⚠️  {message}{Style.RESET_ALL}")

def print_error(message):
    print(f"{Fore.RED}❌ {message}{Style.RESET_ALL}")

def demo_basic_features():
    """Demonstrate basic scanner features"""
    print_section("BASIC SCANNER FEATURES")
    
    # Initialize scanner
    scanner = SQLiScanner(
        crawl_depth=2,
        threads=3,
        delay=1.0,
        timeout=10,
        verbose=True
    )
    
    print_info("Scanner initialized with basic configuration")
    print_info("- Crawl depth: 2")
    print_info("- Threads: 3")
    print_info("- Delay: 1.0s")
    print_info("- Timeout: 10s")
    
    # Demonstrate payload generation
    print_info("\nGenerating SQL injection payloads...")
    payloads = scanner.payload_generator.get_payloads('error_based')
    print_success(f"Generated {len(payloads)} error-based payloads")
    
    # Show sample payloads
    print_info("Sample payloads:")
    for i, payload in enumerate(payloads[:5], 1):
        print(f"  {i}. {payload['payload']} ({payload['description']})")
    
    # Demonstrate DBMS-specific payloads
    mysql_payloads = scanner.payload_generator.get_targeted_payloads('mysql')
    print_success(f"Generated {len(mysql_payloads)} MySQL-specific payloads")
    
    return scanner

def demo_advanced_features(scanner):
    """Demonstrate advanced scanner features"""
    print_section("ADVANCED SCANNER FEATURES")
    
    # Demonstrate authentication handler
    print_info("Authentication capabilities:")
    auth_types = ['form', 'basic', 'digest', 'jwt', 'oauth']
    for auth_type in auth_types:
        print(f"  ✓ {auth_type.upper()} authentication")
    
    # Demonstrate proxy integration
    print_info("\nProxy integration capabilities:")
    print("  ✓ Burp Suite integration")
    print("  ✓ OWASP ZAP integration")
    print("  ✓ Custom proxy support")
    print("  ✓ Proxy chaining")
    
    # Demonstrate detection techniques
    print_info("\nDetection techniques:")
    techniques = [
        "Error-based injection",
        "Union-based injection", 
        "Boolean-based blind injection",
        "Time-based blind injection",
        "Second-order injection",
        "Header-based injection",
        "Cookie-based injection"
    ]
    
    for technique in techniques:
        print(f"  ✓ {technique}")
    
    # Demonstrate database support
    print_info("\nSupported databases:")
    databases = ['MySQL/MariaDB', 'Microsoft SQL Server', 'Oracle', 'PostgreSQL', 'SQLite']
    for db in databases:
        print(f"  ✓ {db}")

def demo_reporting_features(scanner):
    """Demonstrate reporting capabilities"""
    print_section("REPORTING CAPABILITIES")
    
    # Create sample results for demonstration
    sample_results = {
        'targets': [
            {'url': 'http://example.com/page.php?id=1', 'parameters': ['id'], 'method': 'GET'},
            {'url': 'http://example.com/search.php', 'parameters': ['query'], 'method': 'POST'}
        ],
        'vulnerabilities': [
            {
                'url': 'http://example.com/page.php?id=1',
                'parameter': 'id',
                'method': 'GET',
                'injection_type': 'error_based',
                'payload': "' OR '1'='1",
                'evidence': 'MySQL syntax error detected',
                'severity': 'high',
                'dbms': 'mysql',
                'confidence': 'high'
            }
        ],
        'scan_statistics': {
            'scan_duration': 45.2,
            'targets_tested': 2,
            'vulnerabilities_found': 1,
            'high_risk_vulns': 1,
            'medium_risk_vulns': 0,
            'low_risk_vulns': 0
        }
    }
    
    scanner.scan_results = sample_results
    
    print_info("Available report formats:")
    formats = ['JSON', 'HTML', 'TXT']
    for fmt in formats:
        print(f"  ✓ {fmt} format")
    
    print_info("\nReport contents:")
    contents = [
        "Executive summary",
        "Vulnerability details", 
        "Database dump results",
        "Scan statistics",
        "Remediation recommendations"
    ]
    for content in contents:
        print(f"  ✓ {content}")
    
    # Demonstrate summary display
    print_info("\nSample scan summary:")
    scanner.display_summary(sample_results)

def demo_configuration():
    """Demonstrate configuration options"""
    print_section("CONFIGURATION OPTIONS")
    
    print_info("Configuration files:")
    print("  ✓ config/scanner_config.json - Main configuration")
    print("  ✓ payloads/custom_payloads.txt - Custom payloads")
    
    print_info("\nConfigurable settings:")
    settings = [
        "Thread count and delays",
        "Detection thresholds",
        "Rate limiting options",
        "Output preferences",
        "Authentication settings",
        "Proxy configurations"
    ]
    
    for setting in settings:
        print(f"  ✓ {setting}")

def demo_usage_examples():
    """Show usage examples"""
    print_section("USAGE EXAMPLES")
    
    examples = [
        {
            'title': 'Basic URL scan',
            'command': 'python main.py -u "http://example.com/page.php?id=1"'
        },
        {
            'title': 'Authenticated scan',
            'command': 'python main.py -u "http://example.com/admin/" --auth-url "http://example.com/login.php" --username "admin" --password "password"'
        },
        {
            'title': 'Scan with custom payloads',
            'command': 'python main.py -u "http://example.com/page.php?id=1" --payloads payloads/custom_payloads.txt'
        },
        {
            'title': 'Multi-threaded scan with proxy',
            'command': 'python main.py -u "http://example.com/" --threads 10 --proxy "http://127.0.0.1:8080"'
        },
        {
            'title': 'Batch scan from file',
            'command': 'python main.py -l urls.txt --format html -o results/'
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['title']}:")
        print(f"   {Fore.GREEN}{example['command']}{Style.RESET_ALL}")

def main():
    """Main demo function"""
    print_banner()
    
    print_info("Welcome to the Advanced SQL Injection Scanner Demo!")
    print_info("This demonstration will showcase the scanner's capabilities.")
    
    try:
        # Demo basic features
        scanner = demo_basic_features()
        time.sleep(2)
        
        # Demo advanced features
        demo_advanced_features(scanner)
        time.sleep(2)
        
        # Demo reporting
        demo_reporting_features(scanner)
        time.sleep(2)
        
        # Demo configuration
        demo_configuration()
        time.sleep(2)
        
        # Demo usage examples
        demo_usage_examples()
        
        # Final message
        print_section("DEMO COMPLETE")
        print_success("Demo completed successfully!")
        print_info("\nTo get started:")
        print("  1. Run: python install.bat (Windows) or ./install.sh (Linux/Mac)")
        print("  2. Try: python examples/basic_scan.py")
        print("  3. Read: README.md for detailed documentation")
        
        print(f"\n{Fore.CYAN}Happy hunting! 🎯{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print_warning("\nDemo interrupted by user")
    except Exception as e:
        print_error(f"Demo failed: {str(e)}")

if __name__ == "__main__":
    main()
