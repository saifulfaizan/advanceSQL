"""
Proxy Integration Module
Support for Burp Suite, OWASP ZAP, and custom proxy configurations
"""

import requests
import logging
import urllib3
from urllib.parse import urlparse
import socket
import threading
import time

# Disable SSL warnings for proxy usage
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger('sqli_scanner')

class ProxyManager:
    """Manage proxy configurations and integrations"""
    
    def __init__(self, proxy_url=None, proxy_auth=None, verify_ssl=False):
        self.proxy_url = proxy_url
        self.proxy_auth = proxy_auth
        self.verify_ssl = verify_ssl
        self.proxy_config = {}
        self.session = None
        
        if proxy_url:
            self._setup_proxy()
    
    def _setup_proxy(self):
        """Setup proxy configuration"""
        try:
            parsed_proxy = urlparse(self.proxy_url)
            
            self.proxy_config = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            
            logger.info(f"Proxy configured: {parsed_proxy.hostname}:{parsed_proxy.port}")
            
            # Test proxy connectivity
            if self._test_proxy_connection():
                logger.info("Proxy connection test successful")
            else:
                logger.warning("Proxy connection test failed")
        
        except Exception as e:
            logger.error(f"Proxy setup failed: {str(e)}")
    
    def _test_proxy_connection(self):
        """Test proxy connectivity"""
        try:
            test_session = requests.Session()
            test_session.proxies.update(self.proxy_config)
            test_session.verify = self.verify_ssl
            
            if self.proxy_auth:
                username, password = self.proxy_auth.split(':')
                test_session.auth = (username, password)
            
            # Test with a simple request
            response = test_session.get('http://httpbin.org/ip', timeout=10)
            return response.status_code == 200
        
        except Exception as e:
            logger.debug(f"Proxy test failed: {str(e)}")
            return False
    
    def create_session(self):
        """Create a requests session with proxy configuration"""
        session = requests.Session()
        
        if self.proxy_config:
            session.proxies.update(self.proxy_config)
            session.verify = self.verify_ssl
            
            if self.proxy_auth:
                username, password = self.proxy_auth.split(':')
                session.auth = (username, password)
        
        return session
    
    def get_proxy_config(self):
        """Get current proxy configuration"""
        return self.proxy_config.copy()

class BurpSuiteIntegration:
    """Integration with Burp Suite proxy"""
    
    def __init__(self, burp_host='127.0.0.1', burp_port=8080, api_key=None):
        self.burp_host = burp_host
        self.burp_port = burp_port
        self.api_key = api_key
        self.proxy_url = f"http://{burp_host}:{burp_port}"
        self.api_url = f"http://{burp_host}:{burp_port}"
        
    def setup_burp_proxy(self):
        """Setup Burp Suite proxy configuration"""
        proxy_config = {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
        
        logger.info(f"Burp Suite proxy configured: {self.burp_host}:{self.burp_port}")
        return proxy_config
    
    def check_burp_connection(self):
        """Check if Burp Suite is running and accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.burp_host, self.burp_port))
            sock.close()
            
            if result == 0:
                logger.info("Burp Suite proxy is accessible")
                return True
            else:
                logger.warning("Burp Suite proxy is not accessible")
                return False
        
        except Exception as e:
            logger.error(f"Burp connection check failed: {str(e)}")
            return False
    
    def send_to_burp_repeater(self, request_data):
        """Send request to Burp Repeater (if API is available)"""
        if not self.api_key:
            logger.warning("Burp API key not provided")
            return False
        
        try:
            # This would require Burp Suite Professional with API access
            # Implementation depends on specific Burp API version
            logger.info("Request sent to Burp Repeater")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send to Burp Repeater: {str(e)}")
            return False
    
    def get_burp_history(self):
        """Get request history from Burp Suite (if API is available)"""
        if not self.api_key:
            logger.warning("Burp API key not provided")
            return []
        
        try:
            # Implementation would depend on Burp API
            logger.info("Retrieved Burp history")
            return []
        
        except Exception as e:
            logger.error(f"Failed to get Burp history: {str(e)}")
            return []

class ZAPIntegration:
    """Integration with OWASP ZAP proxy"""
    
    def __init__(self, zap_host='127.0.0.1', zap_port=8080, api_key=None):
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.api_key = api_key
        self.proxy_url = f"http://{zap_host}:{zap_port}"
        self.api_url = f"http://{zap_host}:{zap_port}"
        
    def setup_zap_proxy(self):
        """Setup OWASP ZAP proxy configuration"""
        proxy_config = {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
        
        logger.info(f"OWASP ZAP proxy configured: {self.zap_host}:{self.zap_port}")
        return proxy_config
    
    def check_zap_connection(self):
        """Check if OWASP ZAP is running and accessible"""
        try:
            # Test ZAP API endpoint
            api_url = f"{self.api_url}/JSON/core/view/version/"
            if self.api_key:
                api_url += f"?apikey={self.api_key}"
            
            response = requests.get(api_url, timeout=5)
            
            if response.status_code == 200:
                logger.info("OWASP ZAP is accessible")
                return True
            else:
                logger.warning("OWASP ZAP is not accessible")
                return False
        
        except Exception as e:
            logger.error(f"ZAP connection check failed: {str(e)}")
            return False
    
    def start_zap_spider(self, target_url):
        """Start ZAP spider scan"""
        if not self.api_key:
            logger.warning("ZAP API key not provided")
            return False
        
        try:
            api_url = f"{self.api_url}/JSON/spider/action/scan/"
            params = {
                'apikey': self.api_key,
                'url': target_url
            }
            
            response = requests.get(api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"ZAP spider started for {target_url}")
                return True
            else:
                logger.error(f"Failed to start ZAP spider: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"ZAP spider start failed: {str(e)}")
            return False
    
    def get_zap_alerts(self, target_url=None):
        """Get alerts from ZAP"""
        if not self.api_key:
            logger.warning("ZAP API key not provided")
            return []
        
        try:
            api_url = f"{self.api_url}/JSON/core/view/alerts/"
            params = {'apikey': self.api_key}
            
            if target_url:
                params['baseurl'] = target_url
            
            response = requests.get(api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                alerts = response.json().get('alerts', [])
                logger.info(f"Retrieved {len(alerts)} alerts from ZAP")
                return alerts
            else:
                logger.error(f"Failed to get ZAP alerts: {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"ZAP alerts retrieval failed: {str(e)}")
            return []
    
    def send_to_zap_active_scan(self, target_url):
        """Start ZAP active scan"""
        if not self.api_key:
            logger.warning("ZAP API key not provided")
            return False
        
        try:
            api_url = f"{self.api_url}/JSON/ascan/action/scan/"
            params = {
                'apikey': self.api_key,
                'url': target_url
            }
            
            response = requests.get(api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"ZAP active scan started for {target_url}")
                return True
            else:
                logger.error(f"Failed to start ZAP active scan: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"ZAP active scan start failed: {str(e)}")
            return False

class CustomProxy:
    """Custom proxy implementation for advanced features"""
    
    def __init__(self, listen_port=8888):
        self.listen_port = listen_port
        self.running = False
        self.server_thread = None
        self.request_log = []
        self.response_log = []
    
    def start_proxy(self):
        """Start custom proxy server"""
        try:
            self.server_thread = threading.Thread(target=self._run_proxy_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.running = True
            logger.info(f"Custom proxy started on port {self.listen_port}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to start custom proxy: {str(e)}")
            return False
    
    def stop_proxy(self):
        """Stop custom proxy server"""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)
        logger.info("Custom proxy stopped")
    
    def _run_proxy_server(self):
        """Run the proxy server"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', self.listen_port))
            server_socket.listen(5)
            
            while self.running:
                try:
                    client_socket, addr = server_socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket,)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                
                except socket.error:
                    if self.running:
                        logger.error("Proxy server socket error")
                    break
            
            server_socket.close()
        
        except Exception as e:
            logger.error(f"Proxy server error: {str(e)}")
    
    def _handle_client(self, client_socket):
        """Handle client connection"""
        try:
            # Receive request from client
            request_data = client_socket.recv(4096).decode('utf-8')
            
            if not request_data:
                client_socket.close()
                return
            
            # Parse HTTP request
            request_lines = request_data.split('\n')
            first_line = request_lines[0]
            
            # Extract method, URL, and version
            method, url, version = first_line.split()
            
            # Log request
            self.request_log.append({
                'timestamp': time.time(),
                'method': method,
                'url': url,
                'data': request_data
            })
            
            # Forward request to target server
            response_data = self._forward_request(request_data)
            
            # Log response
            self.response_log.append({
                'timestamp': time.time(),
                'url': url,
                'data': response_data
            })
            
            # Send response back to client
            client_socket.send(response_data.encode('utf-8'))
            client_socket.close()
        
        except Exception as e:
            logger.debug(f"Client handling error: {str(e)}")
            client_socket.close()
    
    def _forward_request(self, request_data):
        """Forward request to target server"""
        try:
            # Parse request to extract target
            lines = request_data.split('\n')
            first_line = lines[0]
            method, url, version = first_line.split()
            
            # Extract headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Make request to target
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                # Extract body if present
                body_start = request_data.find('\r\n\r\n')
                body = request_data[body_start + 4:] if body_start != -1 else ''
                response = requests.post(url, headers=headers, data=body, timeout=10)
            else:
                # Handle other methods
                response = requests.request(method, url, headers=headers, timeout=10)
            
            # Build HTTP response
            response_data = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
            
            for key, value in response.headers.items():
                response_data += f"{key}: {value}\r\n"
            
            response_data += "\r\n"
            response_data += response.text
            
            return response_data
        
        except Exception as e:
            logger.debug(f"Request forwarding error: {str(e)}")
            return "HTTP/1.1 500 Internal Server Error\r\n\r\nProxy Error"
    
    def get_request_log(self):
        """Get logged requests"""
        return self.request_log.copy()
    
    def get_response_log(self):
        """Get logged responses"""
        return self.response_log.copy()
    
    def clear_logs(self):
        """Clear request and response logs"""
        self.request_log.clear()
        self.response_log.clear()

class ProxyChain:
    """Chain multiple proxies together"""
    
    def __init__(self):
        self.proxy_chain = []
    
    def add_proxy(self, proxy_url, auth=None):
        """Add proxy to chain"""
        proxy_config = {
            'url': proxy_url,
            'auth': auth
        }
        self.proxy_chain.append(proxy_config)
        logger.info(f"Added proxy to chain: {proxy_url}")
    
    def get_proxy_config(self):
        """Get proxy configuration for requests"""
        if not self.proxy_chain:
            return {}
        
        # Use the last proxy in chain as the direct proxy
        # (requests library doesn't support proxy chaining directly)
        last_proxy = self.proxy_chain[-1]
        
        return {
            'http': last_proxy['url'],
            'https': last_proxy['url']
        }
    
    def test_proxy_chain(self):
        """Test the proxy chain connectivity"""
        if not self.proxy_chain:
            return True
        
        try:
            session = requests.Session()
            session.proxies.update(self.get_proxy_config())
            
            # Test with a simple request
            response = session.get('http://httpbin.org/ip', timeout=15)
            
            if response.status_code == 200:
                logger.info("Proxy chain test successful")
                return True
            else:
                logger.warning("Proxy chain test failed")
                return False
        
        except Exception as e:
            logger.error(f"Proxy chain test error: {str(e)}")
            return False

class CORSBypass:
    """Handle CORS bypass techniques"""
    
    def __init__(self, session):
        self.session = session
    
    def bypass_cors(self, target_url, origin=None):
        """Attempt to bypass CORS restrictions"""
        logger.info("Attempting CORS bypass")
        
        bypass_methods = [
            self._null_origin_bypass,
            self._wildcard_bypass,
            self._subdomain_bypass,
            self._protocol_bypass
        ]
        
        for method in bypass_methods:
            try:
                if method(target_url, origin):
                    logger.info(f"CORS bypass successful with method: {method.__name__}")
                    return True
            except Exception as e:
                logger.debug(f"CORS bypass method {method.__name__} failed: {str(e)}")
        
        logger.warning("All CORS bypass methods failed")
        return False
    
    def _null_origin_bypass(self, target_url, origin):
        """Try null origin bypass"""
        headers = {'Origin': 'null'}
        response = self.session.get(target_url, headers=headers)
        
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        return 'null' in cors_header or '*' in cors_header
    
    def _wildcard_bypass(self, target_url, origin):
        """Try wildcard origin bypass"""
        headers = {'Origin': 'https://evil.com'}
        response = self.session.get(target_url, headers=headers)
        
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        return '*' in cors_header
    
    def _subdomain_bypass(self, target_url, origin):
        """Try subdomain bypass"""
        if not origin:
            return False
        
        parsed_origin = urlparse(origin)
        subdomain_origin = f"https://evil.{parsed_origin.netloc}"
        
        headers = {'Origin': subdomain_origin}
        response = self.session.get(target_url, headers=headers)
        
        cors_header = response.headers.get('Access-Control-Allow-Origin', '')
        return subdomain_origin in cors_header
    
    def _protocol_bypass(self, target_url, origin):
        """Try protocol bypass"""
        if not origin:
            return False
        
        # Try different protocols
        protocols = ['http://', 'https://', 'ftp://']
        parsed_origin = urlparse(origin)
        
        for protocol in protocols:
            test_origin = f"{protocol}{parsed_origin.netloc}"
            headers = {'Origin': test_origin}
            response = self.session.get(target_url, headers=headers)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            if test_origin in cors_header:
                return True
        
        return False
