"""
URL Parameter Discovery Module
Auto crawl URLs, forms, APIs and detect GET & POST parameters
"""

import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time
import logging
from fake_useragent import UserAgent

logger = logging.getLogger('sqli_scanner')

class WebCrawler:
    """Web crawler for discovering URLs, forms, and parameters"""
    
    def __init__(self, max_depth=3, delay=1.0, timeout=10, proxy=None):
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        self.proxy = proxy
        self.session = requests.Session()
        self.ua = UserAgent()
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.parameters = {}
        
        # Setup session
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
    
    def crawl(self, start_url, cookies=None, headers=None):
        """Start crawling from the given URL"""
        logger.info(f"Starting crawl from: {start_url}")
        
        if cookies:
            self.session.cookies.update(self._parse_cookies(cookies))
        
        if headers:
            self.session.headers.update(self._parse_headers(headers))
        
        self._crawl_recursive(start_url, 0)
        
        return {
            'urls': list(self.discovered_urls),
            'forms': self.forms,
            'parameters': self.parameters
        }
    
    def _crawl_recursive(self, url, depth):
        """Recursively crawl URLs up to max_depth"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        logger.debug(f"Crawling: {url} (depth: {depth})")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Parse URL parameters
            self._extract_url_parameters(url)
            
            # Parse HTML content
            if 'text/html' in response.headers.get('content-type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                self._extract_forms(url, soup)
                
                # Extract links for further crawling
                if depth < self.max_depth:
                    links = self._extract_links(url, soup)
                    for link in links:
                        if link not in self.visited_urls:
                            time.sleep(self.delay)
                            self._crawl_recursive(link, depth + 1)
            
            self.discovered_urls.add(url)
            
        except Exception as e:
            logger.warning(f"Failed to crawl {url}: {str(e)}")
        
        time.sleep(self.delay)
    
    def _extract_url_parameters(self, url):
        """Extract GET parameters from URL"""
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            if base_url not in self.parameters:
                self.parameters[base_url] = {'GET': [], 'POST': []}
            
            for param_name in params.keys():
                if param_name not in self.parameters[base_url]['GET']:
                    self.parameters[base_url]['GET'].append(param_name)
                    logger.debug(f"Found GET parameter: {param_name} in {base_url}")
    
    def _extract_forms(self, url, soup):
        """Extract forms and their parameters"""
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'url': url,
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'parameters': [],
                'hidden_fields': {}
            }
            
            # Extract input fields
            inputs = form.find_all(['input', 'select', 'textarea'])
            for input_field in inputs:
                field_name = input_field.get('name')
                field_type = input_field.get('type', 'text')
                field_value = input_field.get('value', '')
                
                if field_name:
                    if field_type == 'hidden':
                        form_data['hidden_fields'][field_name] = field_value
                    else:
                        form_data['parameters'].append({
                            'name': field_name,
                            'type': field_type,
                            'value': field_value
                        })
            
            self.forms.append(form_data)
            
            # Add to parameters dictionary
            action_url = form_data['action']
            if action_url not in self.parameters:
                self.parameters[action_url] = {'GET': [], 'POST': []}
            
            method = form_data['method']
            for param in form_data['parameters']:
                param_name = param['name']
                if param_name not in self.parameters[action_url][method]:
                    self.parameters[action_url][method].append(param_name)
                    logger.debug(f"Found {method} parameter: {param_name} in {action_url}")
    
    def _extract_links(self, base_url, soup):
        """Extract links from HTML for further crawling"""
        links = set()
        
        # Extract from <a> tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            
            # Only crawl same domain
            if self._is_same_domain(base_url, full_url):
                links.add(full_url)
        
        # Extract from JavaScript (basic patterns)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                js_urls = self._extract_urls_from_js(script.string, base_url)
                links.update(js_urls)
        
        return links
    
    def _extract_urls_from_js(self, js_content, base_url):
        """Extract URLs from JavaScript content"""
        urls = set()
        
        # Common patterns for URLs in JavaScript
        patterns = [
            r'["\']([^"\']*\.php[^"\']*)["\']',
            r'["\']([^"\']*\.asp[^"\']*)["\']',
            r'["\']([^"\']*\.jsp[^"\']*)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'ajax\(["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self._is_same_domain(base_url, full_url):
                    urls.add(full_url)
        
        return urls
    
    def _is_same_domain(self, url1, url2):
        """Check if two URLs belong to the same domain"""
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
    
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

class APIDiscovery:
    """Discover API endpoints and parameters"""
    
    def __init__(self, timeout=10, proxy=None):
        self.timeout = timeout
        self.proxy = proxy
        self.session = requests.Session()
        self.ua = UserAgent()
        
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json'
        })
        
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
    
    def discover_api_endpoints(self, base_url):
        """Discover common API endpoints"""
        logger.info(f"Discovering API endpoints for: {base_url}")
        
        common_endpoints = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/api', '/rest/v1',
            '/graphql', '/graph',
            '/admin/api', '/admin',
            '/user', '/users', '/user/profile',
            '/login', '/auth', '/authenticate',
            '/search', '/query',
            '/data', '/info', '/status',
            '/config', '/settings'
        ]
        
        discovered_apis = []
        
        for endpoint in common_endpoints:
            test_url = base_url.rstrip('/') + endpoint
            
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                
                if response.status_code in [200, 201, 202, 400, 401, 403, 422]:
                    content_type = response.headers.get('content-type', '')
                    
                    if any(ct in content_type.lower() for ct in ['json', 'xml', 'api']):
                        discovered_apis.append({
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_type': content_type,
                            'response_size': len(response.content)
                        })
                        logger.debug(f"Found API endpoint: {test_url}")
                
            except Exception as e:
                logger.debug(f"Failed to test endpoint {test_url}: {str(e)}")
        
        return discovered_apis
    
    def analyze_api_parameters(self, api_url):
        """Analyze API endpoint for parameters"""
        logger.debug(f"Analyzing API parameters for: {api_url}")
        
        parameters = {'GET': [], 'POST': []}
        
        try:
            # Test GET request
            response = self.session.get(api_url, timeout=self.timeout)
            
            if response.status_code == 400:  # Bad Request might indicate missing parameters
                error_text = response.text.lower()
                
                # Look for parameter hints in error messages
                param_patterns = [
                    r'parameter ["\']([^"\']+)["\']',
                    r'field ["\']([^"\']+)["\']',
                    r'missing ["\']([^"\']+)["\']',
                    r'required ["\']([^"\']+)["\']'
                ]
                
                for pattern in param_patterns:
                    matches = re.findall(pattern, error_text)
                    parameters['GET'].extend(matches)
            
            # Test common parameter names
            common_params = [
                'id', 'user_id', 'username', 'email', 'token',
                'page', 'limit', 'offset', 'sort', 'order',
                'search', 'query', 'filter', 'category',
                'start', 'end', 'from', 'to', 'date'
            ]
            
            for param in common_params:
                test_url = f"{api_url}?{param}=test"
                try:
                    test_response = self.session.get(test_url, timeout=self.timeout)
                    if test_response.status_code != 404:
                        if param not in parameters['GET']:
                            parameters['GET'].append(param)
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Failed to analyze API parameters for {api_url}: {str(e)}")
        
        return parameters

class ParameterDiscovery:
    """Advanced parameter discovery techniques"""
    
    def __init__(self):
        self.common_parameters = [
            # Common web parameters
            'id', 'user_id', 'userid', 'uid', 'user',
            'username', 'email', 'login', 'account',
            'password', 'pass', 'pwd', 'token', 'auth',
            'session', 'sessid', 'sid', 'key', 'api_key',
            'page', 'p', 'pg', 'pagenum', 'offset', 'limit',
            'search', 'q', 'query', 'keyword', 'term',
            'category', 'cat', 'type', 'sort', 'order',
            'filter', 'status', 'state', 'action', 'cmd',
            'file', 'path', 'url', 'redirect', 'return',
            'callback', 'jsonp', 'format', 'output',
            'lang', 'language', 'locale', 'country',
            'date', 'time', 'start', 'end', 'from', 'to',
            'debug', 'test', 'dev', 'admin', 'mode'
        ]
    
    def discover_hidden_parameters(self, url, method='GET', session=None):
        """Discover hidden parameters using various techniques"""
        if not session:
            session = requests.Session()
        
        discovered_params = []
        
        # Test common parameter names
        for param in self.common_parameters:
            if method.upper() == 'GET':
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=test"
                try:
                    response = session.get(test_url, timeout=10)
                    baseline_response = session.get(url, timeout=10)
                    
                    # Check for differences in response
                    if (response.status_code != baseline_response.status_code or
                        len(response.content) != len(baseline_response.content)):
                        discovered_params.append(param)
                        logger.debug(f"Discovered hidden parameter: {param}")
                
                except Exception:
                    pass
            
            elif method.upper() == 'POST':
                try:
                    response = session.post(url, data={param: 'test'}, timeout=10)
                    baseline_response = session.post(url, data={}, timeout=10)
                    
                    if (response.status_code != baseline_response.status_code or
                        len(response.content) != len(baseline_response.content)):
                        discovered_params.append(param)
                        logger.debug(f"Discovered hidden POST parameter: {param}")
                
                except Exception:
                    pass
        
        return discovered_params
    
    def analyze_javascript_parameters(self, html_content, base_url):
        """Extract parameters from JavaScript code"""
        parameters = []
        
        # Extract JavaScript content
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = soup.find_all('script')
        
        for script in scripts:
            if script.string:
                js_content = script.string
                
                # Look for parameter patterns in JavaScript
                patterns = [
                    r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:\s*',  # Object properties
                    r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  # Property assignments
                    r'data\[["\']([^"\']+)["\']\]',  # Array access
                    r'params\[["\']([^"\']+)["\']\]',  # Parameter arrays
                    r'getParameter\(["\']([^"\']+)["\']\)',  # Parameter getters
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if match not in parameters and len(match) > 1:
                            parameters.append(match)
        
        return parameters
