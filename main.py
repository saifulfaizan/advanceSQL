#!/usr/bin/env python3
"""
Advanced SQL Injection Scanner
A comprehensive tool for automated SQL injection testing
"""

import argparse
import sys
import os
from colorama import init, Fore, Style
from src.scanner import SQLiScanner
from src.logger import setup_logger

# Initialize colorama for cross-platform colored output
init()

def print_banner():
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                Advanced SQL Injection Scanner                ║
║                     Version 1.0                             ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced SQL Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target options
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-l', '--list', help='File containing list of URLs')
    
    # Crawling options
    parser.add_argument('--crawl', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--forms', action='store_true', help='Include forms in scan')
    parser.add_argument('--cookies', help='Custom cookies (format: name=value;name2=value2)')
    
    # Authentication options
    parser.add_argument('--auth-url', help='Authentication URL for login')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--headers', help='Custom headers (format: Header:Value;Header2:Value2)')
    
    # Scanning options
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    
    # Payload options
    parser.add_argument('--payloads', help='Custom payload file')
    parser.add_argument('--dbms', choices=['mysql', 'mssql', 'oracle', 'postgresql', 'sqlite'], 
                       help='Target DBMS type')
    
    # Proxy options
    parser.add_argument('--proxy', help='Proxy URL (http://host:port)')
    parser.add_argument('--proxy-auth', help='Proxy authentication (username:password)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output directory for results')
    parser.add_argument('--format', choices=['json', 'html', 'txt'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.url and not args.list:
        print(f"{Fore.RED}[!] Error: Please specify a target URL (-u) or URL list (-l){Style.RESET_ALL}")
        parser.print_help()
        sys.exit(1)
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    
    # Initialize scanner
    scanner = SQLiScanner(
        crawl_depth=args.crawl,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        proxy_auth=args.proxy_auth,
        output_dir=args.output,
        output_format=args.format,
        verbose=args.verbose
    )
    
    try:
        if args.url:
            # Single URL scan
            logger.info(f"Starting scan for: {args.url}")
            results = scanner.scan_url(
                url=args.url,
                cookies=args.cookies,
                headers=args.headers,
                auth_url=args.auth_url,
                username=args.username,
                password=args.password,
                include_forms=args.forms,
                custom_payloads=args.payloads,
                target_dbms=args.dbms
            )
        else:
            # Multiple URLs scan
            logger.info(f"Starting batch scan from: {args.list}")
            results = scanner.scan_from_file(
                file_path=args.list,
                cookies=args.cookies,
                headers=args.headers,
                auth_url=args.auth_url,
                username=args.username,
                password=args.password,
                include_forms=args.forms,
                custom_payloads=args.payloads,
                target_dbms=args.dbms
            )
        
        # Display results summary
        scanner.display_summary(results)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
