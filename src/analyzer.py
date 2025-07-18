"""
Response Analyzer Module
Advanced response analysis for detecting SQL injection vulnerabilities
"""

import re
import time
import hashlib
import logging
from difflib import SequenceMatcher
from urllib.parse import urlparse
import statistics

logger = logging.getLogger('sqli_scanner')

class ResponseAnalyzer:
    """Analyze HTTP responses for SQL injection indicators"""
    
    def __init__(self):
        self.error_signatures = self._load_error_signatures()
        self.dbms_signatures = self._load_dbms_signatures()
        self.baseline_responses = {}
        self.response_patterns = {}
    
    def analyze_response(self, url, parameter, payload_data, response, baseline_response=None, response_time=None):
        """Comprehensive response analysis for SQL injection detection"""
        analysis_result = {
            'vulnerable': False,
            'confidence': 'low',
            'injection_type': None,
            'dbms': 'unknown',
            'evidence': [],
            'severity': 'low'
        }
        
        # Error-based analysis
        error_analysis = self._analyze_errors(response.text, response.status_code)
        if error_analysis['detected']:
            analysis_result.update({
                'vulnerable': True,
                'confidence': 'high',
                'injection_type': 'error_based',
                'dbms': error_analysis['dbms'],
                'evidence': error_analysis['evidence'],
                'severity': 'high'
            })
            return analysis_result
        
        # Time-based analysis
        if payload_data.get('type') == 'time_based' and response_time:
            time_analysis = self._analyze_time_delay(response_time, payload_data.get('delay', 5))
            if time_analysis['detected']:
                analysis_result.update({
                    'vulnerable': True,
                    'confidence': 'high',
                    'injection_type': 'time_based',
                    'evidence': time_analysis['evidence'],
                    'severity': 'high'
                })
                return analysis_result
        
        # Boolean-based analysis (requires baseline)
        if baseline_response:
            boolean_analysis = self._analyze_boolean_differences(response, baseline_response)
            if boolean_analysis['detected']:
                analysis_result.update({
                    'vulnerable': True,
                    'confidence': 'medium',
                    'injection_type': 'boolean_blind',
                    'evidence': boolean_analysis['evidence'],
                    'severity': 'medium'
                })
                return analysis_result
        
        # UNION-based analysis
        if payload_data.get('type') == 'union_based':
            union_analysis = self._analyze_union_injection(response.text, baseline_response)
            if union_analysis['detected']:
                analysis_result.update({
                    'vulnerable': True,
                    'confidence': 'high',
                    'injection_type': 'union_based',
                    'dbms': union_analysis.get('dbms', 'unknown'),
                    'evidence': union_analysis['evidence'],
                    'severity': 'high'
                })
                return analysis_result
        
        # Content-based anomaly detection
        content_analysis = self._analyze_content_anomalies(response, baseline_response)
        if content_analysis['detected']:
            analysis_result.update({
                'vulnerable': True,
                'confidence': 'low',
                'injection_type': 'generic',
                'evidence': content_analysis['evidence'],
                'severity': 'low'
            })
        
        return analysis_result
    
    def _analyze_errors(self, response_text, status_code):
        """Analyze response for database error messages"""
        result = {'detected': False, 'dbms': 'unknown', 'evidence': []}
        
        # Check HTTP status codes that might indicate errors
        if status_code in [500, 400, 403]:
            result['evidence'].append(f"HTTP {status_code} error status")
        
        # Check for database error patterns
        for dbms, patterns in self.error_signatures.items():
            for pattern_data in patterns:
                pattern = pattern_data['pattern']
                matches = re.findall(pattern, response_text, re.IGNORECASE | re.MULTILINE)
                
                if matches:
                    result['detected'] = True
                    result['dbms'] = dbms
                    result['evidence'].append(f"{dbms.upper()} error: {pattern_data['description']}")
                    
                    # Extract specific error details if available
                    if matches[0]:
                        result['evidence'].append(f"Error detail: {matches[0][:200]}")
        
        return result
    
    def _analyze_time_delay(self, response_time, expected_delay):
        """Analyze response time for time-based injection"""
        result = {'detected': False, 'evidence': []}
        
        # Allow for some variance in timing (network delays, etc.)
        min_delay = expected_delay * 0.8
        max_delay = expected_delay * 1.5
        
        if min_delay <= response_time <= max_delay:
            result['detected'] = True
            result['evidence'].append(f"Time delay detected: {response_time:.2f}s (expected: {expected_delay}s)")
        elif response_time > max_delay:
            result['detected'] = True
            result['evidence'].append(f"Excessive delay detected: {response_time:.2f}s (expected: {expected_delay}s)")
        
        return result
    
    def _analyze_boolean_differences(self, response, baseline_response):
        """Analyze differences between current and baseline response"""
        result = {'detected': False, 'evidence': []}
        
        if not baseline_response:
            return result
        
        # Compare content lengths
        current_length = len(response.content)
        baseline_length = len(baseline_response.content)
        length_diff = abs(current_length - baseline_length)
        
        if length_diff > 100:  # Significant difference
            result['detected'] = True
            result['evidence'].append(f"Content length difference: {length_diff} bytes")
        
        # Compare status codes
        if response.status_code != baseline_response.status_code:
            result['detected'] = True
            result['evidence'].append(f"Status code change: {baseline_response.status_code} -> {response.status_code}")
        
        # Compare response times
        current_time = response.elapsed.total_seconds()
        baseline_time = baseline_response.elapsed.total_seconds()
        time_diff = abs(current_time - baseline_time)
        
        if time_diff > 2.0:  # Significant time difference
            result['detected'] = True
            result['evidence'].append(f"Response time difference: {time_diff:.2f}s")
        
        # Compare content similarity
        similarity = self._calculate_content_similarity(response.text, baseline_response.text)
        if similarity < 0.8:  # Less than 80% similar
            result['detected'] = True
            result['evidence'].append(f"Content similarity: {similarity:.2f}")
        
        return result
    
    def _analyze_union_injection(self, response_text, baseline_response):
        """Analyze response for UNION injection success indicators"""
        result = {'detected': False, 'evidence': [], 'dbms': 'unknown'}
        
        # Look for version strings and database information
        version_patterns = [
            (r'(\d+\.\d+\.\d+[-\w]*)', 'Version information'),
            (r'(MySQL|MariaDB|PostgreSQL|Oracle|Microsoft SQL Server)', 'DBMS identification'),
            (r'(information_schema|sys|dual|pg_catalog)', 'System schema access'),
            (r'(root@localhost|postgres|sa|system)', 'Database user information'),
        ]
        
        for pattern, description in version_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                result['detected'] = True
                result['evidence'].append(f"{description}: {matches[0]}")
                
                # Try to identify DBMS from the match
                match_lower = matches[0].lower()
                if 'mysql' in match_lower or 'mariadb' in match_lower:
                    result['dbms'] = 'mysql'
                elif 'postgresql' in match_lower or 'postgres' in match_lower:
                    result['dbms'] = 'postgresql'
                elif 'oracle' in match_lower:
                    result['dbms'] = 'oracle'
                elif 'microsoft' in match_lower or 'sql server' in match_lower:
                    result['dbms'] = 'mssql'
        
        # Check for additional columns in response
        if baseline_response:
            baseline_text = baseline_response.text
            
            # Look for repeated NULL values or additional data
            null_pattern = r'(null\s*,?\s*){3,}'
            if re.search(null_pattern, response_text, re.IGNORECASE):
                if not re.search(null_pattern, baseline_text, re.IGNORECASE):
                    result['detected'] = True
                    result['evidence'].append("Multiple NULL values detected (UNION injection)")
        
        return result
    
    def _analyze_content_anomalies(self, response, baseline_response):
        """Analyze content for general anomalies that might indicate injection"""
        result = {'detected': False, 'evidence': []}
        
        if not baseline_response:
            return result
        
        # Check for unusual content patterns
        unusual_patterns = [
            (r'<br\s*/?>.*<br\s*/?>', 'Multiple line breaks'),
            (r'(\w+\s*,\s*){5,}', 'Comma-separated values'),
            (r'(\|\s*\w+\s*){3,}', 'Pipe-separated values'),
            (r'(null\s*){3,}', 'Multiple null values'),
            (r'(\d+\s*){5,}', 'Multiple numeric values'),
        ]
        
        for pattern, description in unusual_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                if not re.search(pattern, baseline_response.text, re.IGNORECASE):
                    result['detected'] = True
                    result['evidence'].append(f"Unusual pattern: {description}")
        
        return result
    
    def _calculate_content_similarity(self, text1, text2):
        """Calculate similarity between two text contents"""
        return SequenceMatcher(None, text1, text2).ratio()
    
    def _load_error_signatures(self):
        """Load database error signatures for detection"""
        return {
            'mysql': [
                {'pattern': r"You have an error in your SQL syntax", 'description': 'MySQL syntax error'},
                {'pattern': r"mysql_fetch_array\(\)", 'description': 'MySQL fetch function error'},
                {'pattern': r"mysql_fetch_assoc\(\)", 'description': 'MySQL fetch assoc error'},
                {'pattern': r"mysql_fetch_row\(\)", 'description': 'MySQL fetch row error'},
                {'pattern': r"mysql_num_rows\(\)", 'description': 'MySQL num rows error'},
                {'pattern': r"Warning.*mysql_.*", 'description': 'MySQL warning'},
                {'pattern': r"MySQL server version for the right syntax", 'description': 'MySQL version syntax error'},
                {'pattern': r"supplied argument is not a valid MySQL", 'description': 'Invalid MySQL argument'},
                {'pattern': r"Column count doesn't match value count", 'description': 'MySQL column count mismatch'},
                {'pattern': r"Duplicate entry.*for key", 'description': 'MySQL duplicate key error'},
                {'pattern': r"Table.*doesn't exist", 'description': 'MySQL table not found'},
                {'pattern': r"Unknown column.*in.*list", 'description': 'MySQL unknown column'},
            ],
            'mssql': [
                {'pattern': r"Microsoft OLE DB Provider for ODBC Drivers", 'description': 'MSSQL ODBC error'},
                {'pattern': r"Microsoft OLE DB Provider for SQL Server", 'description': 'MSSQL OLE DB error'},
                {'pattern': r"Unclosed quotation mark after the character string", 'description': 'MSSQL unclosed quote'},
                {'pattern': r"Microsoft JET Database Engine", 'description': 'MS JET engine error'},
                {'pattern': r"ADODB\.Field error", 'description': 'ADODB field error'},
                {'pattern': r"BOF or EOF", 'description': 'MSSQL BOF/EOF error'},
                {'pattern': r"ADODB\.Command", 'description': 'ADODB command error'},
                {'pattern': r"JET Database", 'description': 'JET database error'},
                {'pattern': r"Access Database Engine", 'description': 'Access DB engine error'},
                {'pattern': r"Syntax error in string in query expression", 'description': 'MSSQL syntax error'},
                {'pattern': r"Conversion failed when converting", 'description': 'MSSQL conversion error'},
                {'pattern': r"Invalid column name", 'description': 'MSSQL invalid column'},
            ],
            'oracle': [
                {'pattern': r"ORA-\d{5}", 'description': 'Oracle error code'},
                {'pattern': r"Oracle error", 'description': 'Generic Oracle error'},
                {'pattern': r"Oracle driver", 'description': 'Oracle driver error'},
                {'pattern': r"Warning.*oci_.*", 'description': 'Oracle OCI warning'},
                {'pattern': r"Warning.*ora_.*", 'description': 'Oracle warning'},
                {'pattern': r"oracle\.jdbc\.driver", 'description': 'Oracle JDBC error'},
                {'pattern': r"ORA-00933: SQL command not properly ended", 'description': 'Oracle SQL command error'},
                {'pattern': r"ORA-00936: missing expression", 'description': 'Oracle missing expression'},
                {'pattern': r"ORA-00942: table or view does not exist", 'description': 'Oracle table not found'},
            ],
            'postgresql': [
                {'pattern': r"PostgreSQL query failed", 'description': 'PostgreSQL query failure'},
                {'pattern': r"supplied argument is not a valid PostgreSQL result", 'description': 'Invalid PostgreSQL result'},
                {'pattern': r"Warning.*pg_.*", 'description': 'PostgreSQL warning'},
                {'pattern': r"valid PostgreSQL result resource", 'description': 'PostgreSQL resource error'},
                {'pattern': r"Npgsql\.", 'description': 'Npgsql error'},
                {'pattern': r"PG::[a-zA-Z]*Error", 'description': 'PostgreSQL PG error'},
                {'pattern': r"ERROR:.*syntax error at or near", 'description': 'PostgreSQL syntax error'},
                {'pattern': r"ERROR:.*relation.*does not exist", 'description': 'PostgreSQL relation error'},
                {'pattern': r"ERROR:.*column.*does not exist", 'description': 'PostgreSQL column error'},
            ],
            'sqlite': [
                {'pattern': r"SQLite/JDBCDriver", 'description': 'SQLite JDBC error'},
                {'pattern': r"SQLite.Exception", 'description': 'SQLite exception'},
                {'pattern': r"System.Data.SQLite.SQLiteException", 'description': 'SQLite system exception'},
                {'pattern': r"Warning.*sqlite_.*", 'description': 'SQLite warning'},
                {'pattern': r"SQLITE_ERROR", 'description': 'SQLite error'},
                {'pattern': r"sqlite3.OperationalError", 'description': 'SQLite operational error'},
                {'pattern': r"no such table", 'description': 'SQLite table not found'},
                {'pattern': r"no such column", 'description': 'SQLite column not found'},
            ]
        }
    
    def _load_dbms_signatures(self):
        """Load DBMS identification signatures"""
        return {
            'mysql': [
                r'mysql.*version',
                r'mariadb',
                r'@@version',
                r'information_schema',
                r'mysql_.*\(',
            ],
            'mssql': [
                r'microsoft.*sql.*server',
                r'@@version',
                r'sysobjects',
                r'syscolumns',
                r'xp_cmdshell',
            ],
            'oracle': [
                r'oracle',
                r'ora-\d+',
                r'dual',
                r'v\$version',
                r'all_tables',
            ],
            'postgresql': [
                r'postgresql',
                r'postgres',
                r'pg_.*',
                r'information_schema',
                r'current_database',
            ],
            'sqlite': [
                r'sqlite',
                r'sqlite_version',
                r'sqlite_master',
            ]
        }

class PatternMatcher:
    """Advanced pattern matching for SQL injection detection"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def match_patterns(self, text, pattern_type='all'):
        """Match patterns in text"""
        matches = []
        
        patterns_to_check = self.patterns if pattern_type == 'all' else self.patterns.get(pattern_type, {})
        
        for category, pattern_list in patterns_to_check.items():
            for pattern_data in pattern_list:
                pattern = pattern_data['pattern']
                matches_found = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                
                if matches_found:
                    matches.append({
                        'category': category,
                        'description': pattern_data['description'],
                        'matches': matches_found,
                        'severity': pattern_data.get('severity', 'medium')
                    })
        
        return matches
    
    def _load_patterns(self):
        """Load detection patterns"""
        return {
            'error_indicators': [
                {'pattern': r'(syntax error|sql syntax|mysql_fetch|ora-\d+)', 'description': 'Database error', 'severity': 'high'},
                {'pattern': r'(warning.*mysql|warning.*pg_|warning.*oci)', 'description': 'Database warning', 'severity': 'medium'},
                {'pattern': r'(unclosed quotation|unexpected end of sql)', 'description': 'SQL syntax issue', 'severity': 'high'},
            ],
            'version_disclosure': [
                {'pattern': r'(\d+\.\d+\.\d+[-\w]*)', 'description': 'Version information', 'severity': 'medium'},
                {'pattern': r'(mysql|mariadb|postgresql|oracle|sql server)\s*[\d\.]+', 'description': 'DBMS version', 'severity': 'medium'},
            ],
            'information_disclosure': [
                {'pattern': r'(root@localhost|postgres|sa@|system)', 'description': 'Database user', 'severity': 'high'},
                {'pattern': r'(information_schema|sys|dual|pg_catalog)', 'description': 'System schema access', 'severity': 'high'},
                {'pattern': r'(database.*name|current.*database)', 'description': 'Database name disclosure', 'severity': 'medium'},
            ],
            'injection_artifacts': [
                {'pattern': r'(null\s*,\s*null\s*,\s*null)', 'description': 'UNION injection artifacts', 'severity': 'high'},
                {'pattern': r'(\|\s*\w+\s*\|\s*\w+\s*\|)', 'description': 'Pipe-separated data', 'severity': 'medium'},
                {'pattern': r'(,\s*\d+\s*,\s*\d+\s*,)', 'description': 'Comma-separated numeric data', 'severity': 'medium'},
            ]
        }

class AnomalyDetector:
    """Detect anomalies in HTTP responses that might indicate SQL injection"""
    
    def __init__(self):
        self.baseline_stats = {}
        self.response_history = []
    
    def add_baseline_response(self, url, response):
        """Add a baseline response for comparison"""
        key = self._get_url_key(url)
        
        stats = {
            'content_length': len(response.content),
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'header_count': len(response.headers),
            'content_hash': hashlib.md5(response.content).hexdigest(),
            'word_count': len(response.text.split()),
            'line_count': response.text.count('\n')
        }
        
        if key not in self.baseline_stats:
            self.baseline_stats[key] = []
        
        self.baseline_stats[key].append(stats)
    
    def detect_anomalies(self, url, response):
        """Detect anomalies in response compared to baseline"""
        key = self._get_url_key(url)
        
        if key not in self.baseline_stats or not self.baseline_stats[key]:
            return {'anomalies': [], 'score': 0}
        
        current_stats = {
            'content_length': len(response.content),
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'header_count': len(response.headers),
            'content_hash': hashlib.md5(response.content).hexdigest(),
            'word_count': len(response.text.split()),
            'line_count': response.text.count('\n')
        }
        
        baseline_stats = self.baseline_stats[key]
        anomalies = []
        anomaly_score = 0
        
        # Calculate baseline averages
        avg_stats = {}
        for stat_name in current_stats.keys():
            if stat_name != 'content_hash':
                values = [stats[stat_name] for stats in baseline_stats if stat_name in stats]
                if values:
                    avg_stats[stat_name] = statistics.mean(values)
                    avg_stats[f'{stat_name}_std'] = statistics.stdev(values) if len(values) > 1 else 0
        
        # Check for anomalies
        for stat_name, current_value in current_stats.items():
            if stat_name == 'content_hash':
                # Check if content hash is completely different
                baseline_hashes = [stats['content_hash'] for stats in baseline_stats]
                if current_value not in baseline_hashes:
                    anomalies.append({
                        'type': 'content_change',
                        'description': 'Content completely different from baseline',
                        'severity': 'high'
                    })
                    anomaly_score += 3
                continue
            
            if stat_name in avg_stats:
                avg_value = avg_stats[stat_name]
                std_value = avg_stats.get(f'{stat_name}_std', 0)
                
                # Calculate z-score
                if std_value > 0:
                    z_score = abs(current_value - avg_value) / std_value
                    
                    if z_score > 3:  # 3 standard deviations
                        anomalies.append({
                            'type': f'{stat_name}_anomaly',
                            'description': f'{stat_name} significantly different (z-score: {z_score:.2f})',
                            'severity': 'high' if z_score > 5 else 'medium',
                            'current_value': current_value,
                            'baseline_avg': avg_value
                        })
                        anomaly_score += 2 if z_score > 5 else 1
                
                # Check for specific thresholds
                if stat_name == 'content_length':
                    length_diff = abs(current_value - avg_value)
                    if length_diff > 1000:  # Significant length difference
                        anomalies.append({
                            'type': 'significant_length_change',
                            'description': f'Content length changed by {length_diff} bytes',
                            'severity': 'medium'
                        })
                        anomaly_score += 1
                
                elif stat_name == 'response_time':
                    if current_value > avg_value + 5:  # 5+ seconds longer
                        anomalies.append({
                            'type': 'response_delay',
                            'description': f'Response time increased by {current_value - avg_value:.2f}s',
                            'severity': 'high'
                        })
                        anomaly_score += 2
        
        return {
            'anomalies': anomalies,
            'score': anomaly_score,
            'baseline_count': len(baseline_stats)
        }
    
    def _get_url_key(self, url):
        """Get a normalized key for URL"""
        parsed = urlparse(url)
        return f"{parsed.netloc}{parsed.path}"

class FingerprintAnalyzer:
    """Analyze responses to fingerprint the backend database"""
    
    def __init__(self):
        self.fingerprints = self._load_fingerprints()
    
    def fingerprint_dbms(self, responses):
        """Fingerprint DBMS based on multiple responses"""
        scores = {dbms: 0 for dbms in self.fingerprints.keys()}
        
        for response in responses:
            response_text = response.text.lower()
            
            for dbms, indicators in self.fingerprints.items():
                for indicator in indicators:
                    if indicator['pattern'] in response_text:
                        scores[dbms] += indicator['weight']
        
        # Return the DBMS with highest score
        if max(scores.values()) > 0:
            return max(scores, key=scores.get)
        
        return 'unknown'
    
    def _load_fingerprints(self):
        """Load DBMS fingerprinting patterns"""
        return {
            'mysql': [
                {'pattern': 'mysql', 'weight': 3},
                {'pattern': 'mariadb', 'weight': 3},
                {'pattern': '@@version', 'weight': 2},
                {'pattern': 'information_schema', 'weight': 2},
                {'pattern': 'mysql_fetch', 'weight': 2},
                {'pattern': 'you have an error in your sql syntax', 'weight': 3},
            ],
            'mssql': [
                {'pattern': 'microsoft sql server', 'weight': 3},
                {'pattern': 'ole db provider', 'weight': 2},
                {'pattern': 'unclosed quotation mark', 'weight': 3},
                {'pattern': 'sysobjects', 'weight': 2},
                {'pattern': 'xp_cmdshell', 'weight': 2},
            ],
            'oracle': [
                {'pattern': 'oracle', 'weight': 3},
                {'pattern': 'ora-', 'weight': 3},
                {'pattern': 'dual', 'weight': 2},
                {'pattern': 'v$version', 'weight': 2},
                {'pattern': 'all_tables', 'weight': 2},
            ],
            'postgresql': [
                {'pattern': 'postgresql', 'weight': 3},
                {'pattern': 'postgres', 'weight': 3},
                {'pattern': 'pg_', 'weight': 2},
                {'pattern': 'current_database', 'weight': 2},
                {'pattern': 'syntax error at or near', 'weight': 3},
            ],
            'sqlite': [
                {'pattern': 'sqlite', 'weight': 3},
                {'pattern': 'sqlite_version', 'weight': 2},
                {'pattern': 'sqlite_master', 'weight': 2},
                {'pattern': 'no such table', 'weight': 2},
            ]
        }
