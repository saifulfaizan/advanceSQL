"""
Authentication Flow Module
Handle cookies, sessions, tokens, and authentication bypass
"""

import requests
import re
import time
import logging
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import base64
import json

logger = logging.getLogger('sqli_scanner')

class AuthenticationHandler:
    """Handle various authentication mechanisms"""
    
    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.auth_tokens = {}
        self.csrf_tokens = {}
        self.session_cookies = {}
    
    def authenticate(self, auth_url, username, password, auth_type='form'):
        """Authenticate using various methods"""
        logger.info(f"Attempting authentication at {auth_url}")
        
        auth_methods = {
            'form': self._form_authentication,
            'basic': self._basic_authentication,
            'digest': self._digest_authentication,
            'jwt': self._jwt_authentication,
            'oauth': self._oauth_authentication
        }
        
        auth_method = auth_methods.get(auth_type, self._form_authentication)
        return auth_method(auth_url, username, password)
    
    def _form_authentication(self, auth_url, username, password):
        """Handle form-based authentication"""
        try:
            # Get login page
            response = self.session.get(auth_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            login_form = self._find_login_form(soup)
            if not login_form:
                logger.error("No login form found")
                return False
            
            # Extract form details
            form_action = urljoin(auth_url, login_form.get('action', ''))
            form_method = login_form.get('method', 'POST').upper()
            
            # Build form data
            form_data = self._build_form_data(login_form, username, password)
            
            # Extract CSRF token if present
            csrf_token = self._extract_csrf_token(soup, login_form)
            if csrf_token:
                form_data.update(csrf_token)
                logger.debug("CSRF token extracted and added to form data")
            
            # Submit login form
            if form_method == 'POST':
                auth_response = self.session.post(form_action, data=form_data, timeout=self.timeout)
            else:
                auth_response = self.session.get(form_action, params=form_data, timeout=self.timeout)
            
            # Check if authentication was successful
            success = self._check_auth_success(auth_response)
            
            if success:
                logger.info("Form authentication successful")
                self._store_session_info(auth_response)
                return True
            else:
                logger.warning("Form authentication failed")
                return False
        
        except Exception as e:
            logger.error(f"Form authentication error: {str(e)}")
            return False
    
    def _basic_authentication(self, auth_url, username, password):
        """Handle HTTP Basic authentication"""
        try:
            self.session.auth = (username, password)
            response = self.session.get(auth_url, timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info("Basic authentication successful")
                return True
            else:
                logger.warning(f"Basic authentication failed: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Basic authentication error: {str(e)}")
            return False
    
    def _digest_authentication(self, auth_url, username, password):
        """Handle HTTP Digest authentication"""
        try:
            from requests.auth import HTTPDigestAuth
            self.session.auth = HTTPDigestAuth(username, password)
            response = self.session.get(auth_url, timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info("Digest authentication successful")
                return True
            else:
                logger.warning(f"Digest authentication failed: {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Digest authentication error: {str(e)}")
            return False
    
    def _jwt_authentication(self, auth_url, username, password):
        """Handle JWT token authentication"""
        try:
            # Attempt to get JWT token
            auth_data = {
                'username': username,
                'password': password
            }
            
            response = self.session.post(auth_url, json=auth_data, timeout=self.timeout)
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Look for JWT token in response
                token = None
                for key in ['token', 'access_token', 'jwt', 'authToken']:
                    if key in response_data:
                        token = response_data[key]
                        break
                
                if token:
                    # Add JWT token to session headers
                    self.session.headers['Authorization'] = f'Bearer {token}'
                    self.auth_tokens['jwt'] = token
                    logger.info("JWT authentication successful")
                    return True
            
            logger.warning("JWT authentication failed")
            return False
        
        except Exception as e:
            logger.error(f"JWT authentication error: {str(e)}")
            return False
    
    def _oauth_authentication(self, auth_url, username, password):
        """Handle OAuth authentication (simplified)"""
        try:
            # This is a simplified OAuth implementation
            # Real OAuth would require proper flow handling
            oauth_data = {
                'grant_type': 'password',
                'username': username,
                'password': password
            }
            
            response = self.session.post(auth_url, data=oauth_data, timeout=self.timeout)
            
            if response.status_code == 200:
                response_data = response.json()
                
                if 'access_token' in response_data:
                    token = response_data['access_token']
                    self.session.headers['Authorization'] = f'Bearer {token}'
                    self.auth_tokens['oauth'] = token
                    logger.info("OAuth authentication successful")
                    return True
            
            logger.warning("OAuth authentication failed")
            return False
        
        except Exception as e:
            logger.error(f"OAuth authentication error: {str(e)}")
            return False
    
    def _find_login_form(self, soup):
        """Find login form in HTML"""
        # Look for forms with login-related attributes
        login_indicators = [
            'login', 'signin', 'auth', 'logon', 'sign-in',
            'username', 'password', 'email'
        ]
        
        forms = soup.find_all('form')
        
        for form in forms:
            # Check form attributes
            form_attrs = ' '.join([
                form.get('id', ''),
                form.get('class', ''),
                form.get('name', ''),
                form.get('action', '')
            ]).lower()
            
            if any(indicator in form_attrs for indicator in login_indicators):
                return form
            
            # Check for username/password fields
            inputs = form.find_all('input')
            input_types = [inp.get('type', '').lower() for inp in inputs]
            input_names = [inp.get('name', '').lower() for inp in inputs]
            
            has_password = 'password' in input_types
            has_username = any(indicator in ' '.join(input_names) for indicator in ['user', 'email', 'login'])
            
            if has_password and has_username:
                return form
        
        # If no specific login form found, return the first form
        return forms[0] if forms else None
    
    def _build_form_data(self, form, username, password):
        """Build form data for authentication"""
        form_data = {}
        
        inputs = form.find_all(['input', 'select', 'textarea'])
        
        for input_field in inputs:
            field_name = input_field.get('name')
            field_type = input_field.get('type', 'text').lower()
            field_value = input_field.get('value', '')
            
            if not field_name:
                continue
            
            # Handle different field types
            if field_type == 'password':
                form_data[field_name] = password
            elif field_type in ['text', 'email'] or 'user' in field_name.lower() or 'email' in field_name.lower():
                form_data[field_name] = username
            elif field_type == 'hidden':
                form_data[field_name] = field_value
            elif field_type == 'submit':
                if field_value:
                    form_data[field_name] = field_value
            else:
                # For other types, use existing value or empty string
                form_data[field_name] = field_value
        
        return form_data
    
    def _extract_csrf_token(self, soup, form):
        """Extract CSRF token from form or page"""
        csrf_data = {}
        
        # Common CSRF token names
        csrf_names = [
            'csrf_token', 'csrftoken', '_token', 'authenticity_token',
            'csrf', '_csrf', 'csrfmiddlewaretoken', 'csrf_hash'
        ]
        
        # Look in form inputs
        inputs = form.find_all('input', {'type': 'hidden'})
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            if any(csrf_name in name for csrf_name in csrf_names):
                csrf_data[input_field.get('name')] = input_field.get('value', '')
                break
        
        # Look in meta tags
        if not csrf_data:
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                name = meta.get('name', '').lower()
                if any(csrf_name in name for csrf_name in csrf_names):
                    csrf_data[meta.get('name')] = meta.get('content', '')
                    break
        
        return csrf_data
    
    def _check_auth_success(self, response):
        """Check if authentication was successful"""
        # Check status code
        if response.status_code not in [200, 302, 301]:
            return False
        
        # Check for redirect to dashboard/home
        if response.status_code in [302, 301]:
            location = response.headers.get('Location', '').lower()
            success_indicators = ['dashboard', 'home', 'profile', 'admin', 'welcome']
            if any(indicator in location for indicator in success_indicators):
                return True
        
        # Check response content for success indicators
        content_lower = response.text.lower()
        
        # Failure indicators
        failure_indicators = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error',
            'login failed', 'authentication failed', 'access denied'
        ]
        
        if any(indicator in content_lower for indicator in failure_indicators):
            return False
        
        # Success indicators
        success_indicators = [
            'welcome', 'dashboard', 'logout', 'profile', 'settings',
            'successfully logged in', 'login successful'
        ]
        
        if any(indicator in content_lower for indicator in success_indicators):
            return True
        
        # Check for session cookies
        if response.cookies:
            return True
        
        # Default to success if no clear failure indicators
        return True
    
    def _store_session_info(self, response):
        """Store session information for later use"""
        # Store cookies
        for cookie in response.cookies:
            self.session_cookies[cookie.name] = cookie.value
        
        # Store any tokens found in response
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                data = response.json()
                for key in ['token', 'session_id', 'auth_token']:
                    if key in data:
                        self.auth_tokens[key] = data[key]
        except:
            pass

class CSRFBypass:
    """Handle CSRF token bypass techniques"""
    
    def __init__(self, session):
        self.session = session
    
    def bypass_csrf(self, url, form_data):
        """Attempt to bypass CSRF protection"""
        logger.info("Attempting CSRF bypass")
        
        bypass_methods = [
            self._remove_csrf_token,
            self._empty_csrf_token,
            self._wrong_csrf_token,
            self._csrf_header_bypass,
            self._referer_bypass
        ]
        
        for method in bypass_methods:
            try:
                if method(url, form_data.copy()):
                    logger.info(f"CSRF bypass successful with method: {method.__name__}")
                    return True
            except Exception as e:
                logger.debug(f"CSRF bypass method {method.__name__} failed: {str(e)}")
        
        logger.warning("All CSRF bypass methods failed")
        return False
    
    def _remove_csrf_token(self, url, form_data):
        """Try removing CSRF token entirely"""
        csrf_keys = [k for k in form_data.keys() if 'csrf' in k.lower() or 'token' in k.lower()]
        
        for key in csrf_keys:
            del form_data[key]
        
        response = self.session.post(url, data=form_data)
        return response.status_code == 200 and 'error' not in response.text.lower()
    
    def _empty_csrf_token(self, url, form_data):
        """Try empty CSRF token"""
        csrf_keys = [k for k in form_data.keys() if 'csrf' in k.lower() or 'token' in k.lower()]
        
        for key in csrf_keys:
            form_data[key] = ''
        
        response = self.session.post(url, data=form_data)
        return response.status_code == 200 and 'error' not in response.text.lower()
    
    def _wrong_csrf_token(self, url, form_data):
        """Try wrong CSRF token"""
        csrf_keys = [k for k in form_data.keys() if 'csrf' in k.lower() or 'token' in k.lower()]
        
        for key in csrf_keys:
            form_data[key] = 'wrong_token_value'
        
        response = self.session.post(url, data=form_data)
        return response.status_code == 200 and 'error' not in response.text.lower()
    
    def _csrf_header_bypass(self, url, form_data):
        """Try CSRF bypass using headers"""
        # Remove CSRF from form data and add to headers
        csrf_token = None
        csrf_keys = [k for k in form_data.keys() if 'csrf' in k.lower() or 'token' in k.lower()]
        
        for key in csrf_keys:
            csrf_token = form_data[key]
            del form_data[key]
            break
        
        if csrf_token:
            headers = {'X-CSRF-Token': csrf_token}
            response = self.session.post(url, data=form_data, headers=headers)
            return response.status_code == 200 and 'error' not in response.text.lower()
        
        return False
    
    def _referer_bypass(self, url, form_data):
        """Try CSRF bypass using referer header"""
        headers = {'Referer': url}
        response = self.session.post(url, data=form_data, headers=headers)
        return response.status_code == 200 and 'error' not in response.text.lower()

class SessionManager:
    """Manage session state and cookies"""
    
    def __init__(self, session):
        self.session = session
        self.session_data = {}
    
    def maintain_session(self, url):
        """Maintain session by periodically accessing the application"""
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                logger.debug("Session maintained successfully")
                return True
            else:
                logger.warning(f"Session maintenance failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Session maintenance error: {str(e)}")
            return False
    
    def extract_session_info(self, response):
        """Extract session information from response"""
        session_info = {}
        
        # Extract cookies
        for cookie in response.cookies:
            session_info[f'cookie_{cookie.name}'] = cookie.value
        
        # Extract session ID from URL
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        
        for param, value in query_params.items():
            if 'session' in param.lower() or 'sid' in param.lower():
                session_info[f'url_param_{param}'] = value[0] if value else ''
        
        # Extract session tokens from response body
        session_patterns = [
            r'session[_-]?id["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]+)',
            r'sessionToken["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]+)',
            r'PHPSESSID["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]+)',
            r'JSESSIONID["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]+)'
        ]
        
        for pattern in session_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            if matches:
                session_info['extracted_session'] = matches[0]
                break
        
        self.session_data.update(session_info)
        return session_info
    
    def clone_session(self):
        """Clone current session for parallel requests"""
        new_session = requests.Session()
        
        # Copy cookies
        new_session.cookies.update(self.session.cookies)
        
        # Copy headers
        new_session.headers.update(self.session.headers)
        
        # Copy auth
        if hasattr(self.session, 'auth') and self.session.auth:
            new_session.auth = self.session.auth
        
        return new_session

class TokenExtractor:
    """Extract and manage various types of authentication tokens"""
    
    def __init__(self):
        self.tokens = {}
    
    def extract_jwt_token(self, response_text):
        """Extract JWT token from response"""
        jwt_patterns = [
            r'["\']?(?:access_token|token|jwt)["\']?\s*[:=]\s*["\']?(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\']?',
            r'Bearer\s+(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
            r'Authorization:\s*Bearer\s+(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'
        ]
        
        for pattern in jwt_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                token = matches[0]
                self.tokens['jwt'] = token
                logger.info("JWT token extracted")
                return token
        
        return None
    
    def extract_api_key(self, response_text):
        """Extract API key from response"""
        api_patterns = [
            r'["\']?(?:api_key|apikey|key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            r'X-API-Key:\s*([a-zA-Z0-9_-]{20,})',
            r'API-Key:\s*([a-zA-Z0-9_-]{20,})'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                key = matches[0]
                self.tokens['api_key'] = key
                logger.info("API key extracted")
                return key
        
        return None
    
    def extract_bearer_token(self, response_text):
        """Extract Bearer token from response"""
        bearer_patterns = [
            r'["\']?(?:access_token|bearer_token|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            r'Bearer\s+([a-zA-Z0-9_-]{20,})',
            r'Authorization:\s*Bearer\s+([a-zA-Z0-9_-]{20,})'
        ]
        
        for pattern in bearer_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                token = matches[0]
                self.tokens['bearer'] = token
                logger.info("Bearer token extracted")
                return token
        
        return None
    
    def decode_jwt_payload(self, jwt_token):
        """Decode JWT payload (without verification)"""
        try:
            # JWT format: header.payload.signature
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode payload (second part)
            payload = parts[1]
            
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            decoded_bytes = base64.urlsafe_b64decode(payload)
            decoded_json = json.loads(decoded_bytes.decode('utf-8'))
            
            logger.info("JWT payload decoded successfully")
            return decoded_json
        
        except Exception as e:
            logger.debug(f"JWT decode error: {str(e)}")
            return None
    
    def get_all_tokens(self):
        """Get all extracted tokens"""
        return self.tokens.copy()
