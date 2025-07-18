"""
Main Scanner Module
Orchestrates all components for comprehensive SQL injection testing
"""

import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import json

from .crawler import WebCrawler, APIDiscovery, ParameterDiscovery
from .payloads import PayloadGenerator, CustomPayloadLoader
from .injector import InjectionEngine, AdvancedInjectionTester, BlindInjectionTester
from .analyzer import ResponseAnalyzer, PatternMatcher, AnomalyDetector, FingerprintAnalyzer
from .dumper import DatabaseDumper, BlindDataExtractor, DataFormatter
from .auth import AuthenticationHandler, CSRFBypass, SessionManager, TokenExtractor
from .proxy import ProxyManager, BurpSuiteIntegration, ZAPIntegration
from .logger import ReportGenerator, ScanLogger

logger = logging.getLogger('sqli_scanner')

class SQLiScanner:
    """Main SQL injection scanner orchestrating all components"""
    
    def __init__(self, crawl_depth=2, threads=5, delay=1.0, timeout=10, 
                 proxy=None, proxy_auth=None, output_dir=None, 
                 output_format='json', verbose=False):
        
        # Core configuration
        self.crawl_depth = crawl_depth
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.verbose = verbose
        
        # Initialize components
        self.proxy_manager = ProxyManager(proxy, proxy_auth) if proxy else None
        self.session = self.proxy_manager.create_session() if self.proxy_manager else None
        
        # Core components
        self.crawler = WebCrawler(
            max_depth=crawl_depth, 
            delay=delay, 
            timeout=timeout,
            proxy=proxy
        )
        
        self.payload_generator = PayloadGenerator()
        self.injection_engine = InjectionEngine(
            threads=threads,
            delay=delay,
            timeout=timeout,
            proxy=proxy,
            proxy_auth=proxy_auth
        )
        
        self.response_analyzer = ResponseAnalyzer()
        self.pattern_matcher = PatternMatcher()
        self.anomaly_detector = AnomalyDetector()
        self.fingerprint_analyzer = FingerprintAnalyzer()
        
        self.auth_handler = AuthenticationHandler(self.session, timeout)
        self.csrf_bypass = CSRFBypass(self.session) if self.session else None
        self.session_manager = SessionManager(self.session) if self.session else None
        self.token_extractor = TokenExtractor()
        
        # Advanced components
        self.advanced_tester = AdvancedInjectionTester(self.injection_engine)
        self.blind_tester = BlindInjectionTester(self.injection_engine)
        self.database_dumper = DatabaseDumper(self.session or self.injection_engine.session, delay, timeout)
        self.blind_extractor = BlindDataExtractor(self.session or self.injection_engine.session, delay, timeout)
        
        # Reporting
        self.report_generator = ReportGenerator(output_dir)
        self.scan_logger = ScanLogger(output_dir)
        self.output_format = output_format
        
        # Results storage
        self.scan_results = {
            'targets': [],
            'vulnerabilities': [],
            'crawled_urls': [],
            'parameters_found': {},
            'database_dumps': [],
            'scan_statistics': {}
        }
        
        # Integration components
        self.burp_integration = None
        self.zap_integration = None
        
    def scan_url(self, url, cookies=None, headers=None, auth_url=None, 
                 username=None, password=None, include_forms=True, 
                 custom_payloads=None, target_dbms=None):
        """Scan a single URL for SQL injection vulnerabilities"""
        
        logger.info(f"Starting comprehensive scan of: {url}")
        start_time = time.time()
        
        try:
            # Step 1: Authentication (if required)
            if auth_url and username and password:
                logger.info("Performing authentication")
                auth_success = self.auth_handler.authenticate(auth_url, username, password)
                if not auth_success:
                    logger.warning("Authentication failed, continuing without authentication")
            
            # Step 2: URL Parameter Discovery
            logger.info("Starting URL parameter discovery")
            crawl_results = self.crawler.crawl(url, cookies, headers)
            
            self.scan_results['crawled_urls'] = crawl_results['urls']
            self.scan_results['parameters_found'] = crawl_results['parameters']
            
            logger.info(f"Discovered {len(crawl_results['urls'])} URLs and {len(crawl_results['forms'])} forms")
            
            # Step 3: API Discovery
            api_discovery = APIDiscovery(timeout=self.timeout, proxy=self.proxy_manager.proxy_url if self.proxy_manager else None)
            api_endpoints = api_discovery.discover_api_endpoints(url)
            
            if api_endpoints:
                logger.info(f"Discovered {len(api_endpoints)} API endpoints")
                self.scan_results['crawled_urls'].extend([ep['url'] for ep in api_endpoints])
            
            # Step 4: Parameter Discovery
            param_discovery = ParameterDiscovery()
            
            # Step 5: Payload Generation
            if custom_payloads:
                custom_loader = CustomPayloadLoader(custom_payloads)
                payloads = custom_loader.get_payloads()
            else:
                payloads = self.payload_generator.get_payloads()
            
            if target_dbms:
                payloads = self.payload_generator.get_targeted_payloads(target_dbms)
            
            logger.info(f"Generated {len(payloads)} payloads for testing")
            
            # Step 6: Injection Testing
            all_targets = []
            
            # Add discovered URLs with parameters
            for test_url, params in crawl_results['parameters'].items():
                for method in ['GET', 'POST']:
                    if params.get(method):
                        all_targets.append({
                            'url': test_url,
                            'parameters': params[method],
                            'method': method,
                            'type': 'url_param'
                        })
            
            # Add forms
            if include_forms:
                for form in crawl_results['forms']:
                    if form['parameters']:
                        all_targets.append({
                            'url': form['action'],
                            'parameters': [p['name'] for p in form['parameters']],
                            'method': form['method'],
                            'type': 'form',
                            'form_data': form
                        })
            
            self.scan_results['targets'] = all_targets
            logger.info(f"Testing {len(all_targets)} targets")
            
            # Step 7: Multi-threaded injection testing
            vulnerabilities = self._perform_injection_testing(all_targets, payloads, cookies, headers)
            
            # Step 8: Advanced testing techniques
            logger.info("Performing advanced injection tests")
            
            # Second-order injection testing
            for target in all_targets[:5]:  # Limit to first 5 targets
                second_order_vulns = self.advanced_tester.test_second_order_injection(
                    target['url'], target['parameters'], payloads[:10]  # Use subset of payloads
                )
                vulnerabilities.extend(second_order_vulns)
            
            # Header-based injection testing
            header_vulns = self.advanced_tester.test_header_injection(url, payloads[:20])
            vulnerabilities.extend(header_vulns)
            
            # Cookie-based injection testing
            cookie_vulns = self.advanced_tester.test_cookie_injection(url, payloads[:20])
            vulnerabilities.extend(cookie_vulns)
            
            # Step 9: Database fingerprinting and dumping
            for vuln in vulnerabilities:
                if vuln['confidence'] == 'high':
                    logger.info(f"Attempting database dump for {vuln['url']}")
                    
                    # Fingerprint DBMS if not already identified
                    if vuln['dbms'] == 'unknown':
                        responses = [self.injection_engine.session.get(vuln['url'])]
                        vuln['dbms'] = self.fingerprint_analyzer.fingerprint_dbms(responses)
                    
                    # Attempt database dump
                    try:
                        dump_data = self.database_dumper.dump_database(
                            vuln['url'], 
                            vuln['parameter'], 
                            vuln['method'], 
                            vuln['dbms'], 
                            vuln['injection_type']
                        )
                        
                        if dump_data and any(dump_data.values()):
                            self.scan_results['database_dumps'].append(dump_data)
                            logger.info(f"Database dump successful for {vuln['url']}")
                    
                    except Exception as e:
                        logger.debug(f"Database dump failed: {str(e)}")
            
            # Step 10: Compile results
            self.scan_results['vulnerabilities'] = vulnerabilities
            
            # Calculate scan statistics
            end_time = time.time()
            self.scan_results['scan_statistics'] = {
                'scan_duration': end_time - start_time,
                'targets_tested': len(all_targets),
                'vulnerabilities_found': len(vulnerabilities),
                'high_risk_vulns': len([v for v in vulnerabilities if v['severity'] == 'high']),
                'medium_risk_vulns': len([v for v in vulnerabilities if v['severity'] == 'medium']),
                'low_risk_vulns': len([v for v in vulnerabilities if v['severity'] == 'low']),
                'urls_crawled': len(crawl_results['urls']),
                'forms_found': len(crawl_results['forms']),
                'parameters_found': sum(len(params.get('GET', [])) + len(params.get('POST', [])) 
                                     for params in crawl_results['parameters'].values())
            }
            
            logger.info(f"Scan completed in {end_time - start_time:.2f} seconds")
            logger.info(f"Found {len(vulnerabilities)} potential vulnerabilities")
            
            # Step 11: Generate reports
            self._generate_reports()
            
            return self.scan_results
        
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise
    
    def scan_from_file(self, file_path, **kwargs):
        """Scan multiple URLs from a file"""
        logger.info(f"Starting batch scan from file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            all_results = []
            
            for i, url in enumerate(urls, 1):
                logger.info(f"Scanning URL {i}/{len(urls)}: {url}")
                
                try:
                    result = self.scan_url(url, **kwargs)
                    all_results.append(result)
                    
                    # Brief pause between scans
                    time.sleep(self.delay)
                
                except Exception as e:
                    logger.error(f"Failed to scan {url}: {str(e)}")
                    continue
            
            # Combine results
            combined_results = self._combine_scan_results(all_results)
            
            return combined_results
        
        except Exception as e:
            logger.error(f"Batch scan failed: {str(e)}")
            raise
    
    def _perform_injection_testing(self, targets, payloads, cookies=None, headers=None):
        """Perform multi-threaded injection testing"""
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit injection tests
            future_to_target = {}
            
            for target in targets:
                future = executor.submit(
                    self._test_target_injection,
                    target, payloads, cookies, headers
                )
                future_to_target[future] = target
            
            # Collect results
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                
                try:
                    target_vulns = future.result()
                    vulnerabilities.extend(target_vulns)
                    
                    if target_vulns:
                        logger.info(f"Found {len(target_vulns)} vulnerabilities in {target['url']}")
                
                except Exception as e:
                    logger.error(f"Injection test failed for {target['url']}: {str(e)}")
        
        return vulnerabilities
    
    def _test_target_injection(self, target, payloads, cookies=None, headers=None):
        """Test a single target for SQL injection"""
        vulnerabilities = []
        
        try:
            # Basic injection testing
            basic_vulns = self.injection_engine.test_injection(
                target['url'],
                target['parameters'],
                payloads,
                target['method'],
                cookies,
                headers
            )
            vulnerabilities.extend(basic_vulns)
            
            # Boolean blind testing for parameters that didn't show obvious vulnerabilities
            if not basic_vulns:
                for param in target['parameters']:
                    blind_vuln = self.blind_tester.test_boolean_blind_advanced(
                        target['url'], param, target['method']
                    )
                    if blind_vuln:
                        vulnerabilities.append(blind_vuln)
            
            # Log all requests for this target
            for vuln in vulnerabilities:
                self.scan_logger.log_vulnerability(
                    vuln['url'],
                    vuln['parameter'],
                    vuln['method'],
                    vuln['injection_type'],
                    vuln['payload'],
                    vuln['evidence'],
                    vuln['severity'],
                    vuln.get('dbms')
                )
        
        except Exception as e:
            logger.debug(f"Target injection test error: {str(e)}")
        
        return vulnerabilities
    
    def _generate_reports(self):
        """Generate scan reports in various formats"""
        try:
            if self.output_format == 'json':
                report_file = self.report_generator.generate_json_report(self.scan_results)
                logger.info(f"JSON report generated: {report_file}")
            
            elif self.output_format == 'html':
                report_file = self.report_generator.generate_html_report(self.scan_results)
                logger.info(f"HTML report generated: {report_file}")
            
            elif self.output_format == 'txt':
                report_file = self.report_generator.generate_txt_report(self.scan_results)
                logger.info(f"Text report generated: {report_file}")
            
            # Always save detailed logs
            self.scan_logger.save_logs()
        
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
    
    def _combine_scan_results(self, results_list):
        """Combine multiple scan results"""
        combined = {
            'targets': [],
            'vulnerabilities': [],
            'crawled_urls': [],
            'parameters_found': {},
            'database_dumps': [],
            'scan_statistics': {}
        }
        
        total_duration = 0
        total_targets = 0
        total_vulns = 0
        
        for result in results_list:
            combined['targets'].extend(result.get('targets', []))
            combined['vulnerabilities'].extend(result.get('vulnerabilities', []))
            combined['crawled_urls'].extend(result.get('crawled_urls', []))
            combined['parameters_found'].update(result.get('parameters_found', {}))
            combined['database_dumps'].extend(result.get('database_dumps', []))
            
            stats = result.get('scan_statistics', {})
            total_duration += stats.get('scan_duration', 0)
            total_targets += stats.get('targets_tested', 0)
            total_vulns += stats.get('vulnerabilities_found', 0)
        
        # Combined statistics
        combined['scan_statistics'] = {
            'total_scan_duration': total_duration,
            'total_targets_tested': total_targets,
            'total_vulnerabilities_found': total_vulns,
            'high_risk_vulns': len([v for v in combined['vulnerabilities'] if v['severity'] == 'high']),
            'medium_risk_vulns': len([v for v in combined['vulnerabilities'] if v['severity'] == 'medium']),
            'low_risk_vulns': len([v for v in combined['vulnerabilities'] if v['severity'] == 'low']),
            'unique_urls_crawled': len(set(combined['crawled_urls'])),
            'scans_performed': len(results_list)
        }
        
        return combined
    
    def display_summary(self, results):
        """Display scan results summary"""
        stats = results.get('scan_statistics', {})
        vulns = results.get('vulnerabilities', [])
        
        print("\n" + "="*60)
        print("SQL INJECTION SCAN SUMMARY")
        print("="*60)
        
        print(f"Scan Duration: {stats.get('scan_duration', 0):.2f} seconds")
        print(f"Targets Tested: {stats.get('targets_tested', 0)}")
        print(f"URLs Crawled: {stats.get('urls_crawled', 0)}")
        print(f"Parameters Found: {stats.get('parameters_found', 0)}")
        print(f"Forms Found: {stats.get('forms_found', 0)}")
        
        print(f"\nVulnerabilities Found: {len(vulns)}")
        print(f"  High Risk: {stats.get('high_risk_vulns', 0)}")
        print(f"  Medium Risk: {stats.get('medium_risk_vulns', 0)}")
        print(f"  Low Risk: {stats.get('low_risk_vulns', 0)}")
        
        if vulns:
            print(f"\nTop Vulnerabilities:")
            for i, vuln in enumerate(vulns[:5], 1):
                print(f"  {i}. {vuln['url']} - {vuln['parameter']} ({vuln['severity']})")
        
        database_dumps = results.get('database_dumps', [])
        if database_dumps:
            print(f"\nDatabase Information Extracted:")
            for dump in database_dumps:
                print(f"  DBMS: {dump.get('dbms', 'Unknown')}")
                if dump.get('version'):
                    print(f"  Version: {dump['version']}")
                if dump.get('databases'):
                    print(f"  Databases: {len(dump['databases'])}")
        
        print("="*60)
    
    def setup_burp_integration(self, burp_host='127.0.0.1', burp_port=8080, api_key=None):
        """Setup Burp Suite integration"""
        self.burp_integration = BurpSuiteIntegration(burp_host, burp_port, api_key)
        
        if self.burp_integration.check_burp_connection():
            # Update proxy configuration
            burp_proxy = self.burp_integration.setup_burp_proxy()
            if not self.proxy_manager:
                self.proxy_manager = ProxyManager(f"http://{burp_host}:{burp_port}")
            logger.info("Burp Suite integration configured")
            return True
        else:
            logger.warning("Burp Suite integration failed - proxy not accessible")
            return False
    
    def setup_zap_integration(self, zap_host='127.0.0.1', zap_port=8080, api_key=None):
        """Setup OWASP ZAP integration"""
        self.zap_integration = ZAPIntegration(zap_host, zap_port, api_key)
        
        if self.zap_integration.check_zap_connection():
            # Update proxy configuration
            zap_proxy = self.zap_integration.setup_zap_proxy()
            if not self.proxy_manager:
                self.proxy_manager = ProxyManager(f"http://{zap_host}:{zap_port}")
            logger.info("OWASP ZAP integration configured")
            return True
        else:
            logger.warning("OWASP ZAP integration failed - proxy not accessible")
            return False
    
    def export_results(self, format_type='json', filename=None):
        """Export scan results in specified format"""
        try:
            if format_type == 'json':
                return self.report_generator.generate_json_report(self.scan_results, filename)
            elif format_type == 'html':
                return self.report_generator.generate_html_report(self.scan_results, filename)
            elif format_type == 'txt':
                return self.report_generator.generate_txt_report(self.scan_results, filename)
            else:
                logger.error(f"Unsupported export format: {format_type}")
                return None
        
        except Exception as e:
            logger.error(f"Export failed: {str(e)}")
            return None
    
    def get_scan_statistics(self):
        """Get detailed scan statistics"""
        return self.scan_results.get('scan_statistics', {})
    
    def get_vulnerabilities(self, severity=None):
        """Get vulnerabilities, optionally filtered by severity"""
        vulns = self.scan_results.get('vulnerabilities', [])
        
        if severity:
            return [v for v in vulns if v['severity'] == severity]
        
        return vulns
    
    def get_database_dumps(self):
        """Get all database dump results"""
        return self.scan_results.get('database_dumps', [])
