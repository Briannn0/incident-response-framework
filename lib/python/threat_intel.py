#!/usr/bin/env python3
"""
Threat Intelligence Integration for the Incident Response Framework
Handles connecting to threat intel sources and enriching detection capabilities
"""

import os
import sys
import json
import pandas as pd
import requests
import hashlib
import ipaddress
import re
import time
import random
from datetime import datetime, timedelta
import sqlite3
import traceback
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password, salt=None):
    """Generate encryption key from password and salt."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_api_key(api_key, encryption_key):
    """Encrypt an API key using Fernet symmetric encryption."""
    f = Fernet(encryption_key)
    encrypted_key = f.encrypt(api_key.encode())
    return encrypted_key

def decrypt_api_key(encrypted_key, encryption_key):
    """Decrypt an API key using Fernet symmetric encryption."""
    f = Fernet(encryption_key)
    decrypted_key = f.decrypt(encrypted_key).decode()
    return decrypted_key

def handle_errors(func):
    """Decorator for standardized error handling"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_info = {
                "status": "error",
                "error_type": type(e).__name__,
                "error_message": str(e)
            }
            sys.stderr.write(json.dumps(error_info) + "\n")
            sys.exit(1)
    return wrapper

def make_api_request(url, headers=None, params=None, timeout=30, max_retries=3):
    """Make robust API requests with timeouts, retries, and rate limit handling"""
    headers = headers or {}
    params = params or {}
    retry_count = 0
    backoff_factor = 2.0
    
    while retry_count < max_retries:
        try:
            # Make request with timeout
            response = requests.get(
                url, 
                headers=headers, 
                params=params,
                timeout=timeout
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                print(f"Rate limited, waiting {retry_after}s")
                time.sleep(retry_after)
                retry_count += 1
                continue
                
            # Handle server errors
            if response.status_code >= 500:
                print(f"Server error {response.status_code}, retrying")
                sleep_time = backoff_factor ** retry_count + random.random()
                time.sleep(sleep_time)
                retry_count += 1
                continue
                
            # Handle client errors
            if response.status_code >= 400:
                print(f"Client error {response.status_code}")
                return None
                
            # Parse JSON with error handling
            try:
                return response.json()
            except ValueError:
                print("Invalid JSON response")
                return None
                
        except requests.Timeout:
            print(f"Request timed out after {timeout}s")
            retry_count += 1
            time.sleep(backoff_factor ** retry_count)
            
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            retry_count += 1
            time.sleep(backoff_factor ** retry_count)
    
    return None

def make_robust_api_request(url, service, api_key_manager, headers=None, params=None, timeout=30, max_retries=3):
    """Make API request with robust error handling and rate limit management."""
    headers = headers or {}
    params = params or {}
    retry_count = 0
    backoff_factor = 2.0
    
    # Check rate limits before making request
    if not api_key_manager.check_rate_limit(service):
        # Get rate reset time
        conn = sqlite3.connect(api_key_manager.keys_db)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT rate_reset FROM api_keys
        WHERE service = ?
        ''', (service,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            rate_reset = datetime.fromisoformat(result[0])
            wait_seconds = max(1, (rate_reset - datetime.now()).total_seconds())
            
            # Sleep until rate limit reset
            if wait_seconds < 300:  # Don't wait more than 5 minutes
                print(f"Waiting {wait_seconds:.0f} seconds for rate limit reset")
                time.sleep(wait_seconds)
            else:
                return {
                    'error': 'rate_limited',
                    'wait_seconds': wait_seconds
                }
    
    while retry_count < max_retries:
        try:
            # Make request with timeout
            response = requests.get(
                url, 
                headers=headers, 
                params=params,
                timeout=timeout
            )
            
            # Update rate limit information
            rate_limit = response.headers.get('X-RateLimit-Limit')
            rate_remaining = response.headers.get('X-RateLimit-Remaining')
            rate_reset = response.headers.get('X-RateLimit-Reset')
            
            if rate_limit and rate_remaining and rate_reset:
                # Convert rate_reset to datetime
                reset_time = datetime.fromtimestamp(int(rate_reset))
                api_key_manager.update_rate_limits(
                    service, 
                    int(rate_limit), 
                    int(rate_remaining), 
                    reset_time.isoformat()
                )
                
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                print(f"Rate limited, waiting {retry_after}s")
                
                # Update rate limit info in database
                api_key_manager.update_rate_limits(
                    service,
                    0, 
                    0, 
                    (datetime.now() + timedelta(seconds=retry_after)).isoformat()
                )
                
                # Sleep if retry_after is reasonable
                if retry_after < 300:  # Don't wait more than 5 minutes
                    time.sleep(retry_after)
                    retry_count += 1
                    continue
                else:
                    return {
                        'error': 'rate_limited',
                        'wait_seconds': retry_after
                    }
                    
            # Handle server errors with exponential backoff
            if response.status_code >= 500:
                sleep_time = backoff_factor ** retry_count + random.random()
                print(f"Server error {response.status_code}, retrying in {sleep_time:.1f}s")
                time.sleep(sleep_time)
                retry_count += 1
                continue
                
            # Handle client errors
            if response.status_code >= 400:
                return {
                    'error': 'client_error',
                    'status_code': response.status_code,
                    'message': response.text
                }
                
            # Parse JSON with error handling
            try:
                return response.json()
            except ValueError:
                return {
                    'error': 'invalid_json',
                    'raw_content': response.text[:1000]  # Truncate long responses
                }
                
        except requests.Timeout:
            print(f"Request timed out after {timeout}s")
            retry_count += 1
            sleep_time = backoff_factor ** retry_count
            time.sleep(sleep_time)
            
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            retry_count += 1
            sleep_time = backoff_factor ** retry_count
            time.sleep(sleep_time)
    
    return {
        'error': 'max_retries_exceeded',
        'retries': max_retries
    }

class ApiKeyManager:
    """Securely manage API keys for threat intelligence services."""
    
    def __init__(self, config=None):
        """Initialize the API key manager with optional configuration."""
        self.config = config or {}
        self.keys_db = os.path.join(
            os.environ.get('IRF_ROOT', '.'), 
            'threat_intel', 
            'keys.db'
        )
        self.master_password = self.config.get('master_password', os.environ.get('IRF_MASTER_PASSWORD'))
        
        # Initialize the database
        self._initialize_db()
        
    def _initialize_db(self):
        """Initialize the API keys database."""
        conn = sqlite3.connect(self.keys_db)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            service TEXT PRIMARY KEY,
            encrypted_key BLOB,
            salt BLOB,
            last_used TIMESTAMP,
            rate_limit INT,
            rate_remaining INT,
            rate_reset TIMESTAMP
        )
        ''')
        
        conn.commit()
        conn.close()
        
    def set_api_key(self, service, api_key):
        """Securely store an API key for a service."""
        if not self.master_password:
            raise ValueError("Master password not configured")
            
        # Generate encryption key
        encryption_key, salt = generate_key(self.master_password)
        
        # Encrypt the API key
        encrypted_key = encrypt_api_key(api_key, encryption_key)
        
        # Store in database
        conn = sqlite3.connect(self.keys_db)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT OR REPLACE INTO api_keys
        (service, encrypted_key, salt, last_used, rate_limit, rate_remaining)
        VALUES (?, ?, ?, datetime('now'), 0, 0)
        ''', (service, encrypted_key, salt))
        
        conn.commit()
        conn.close()
        
    def get_api_key(self, service):
        """Securely retrieve an API key for a service."""
        if not self.master_password:
            raise ValueError("Master password not configured")
            
        # Get encrypted key from database
        conn = sqlite3.connect(self.keys_db)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT encrypted_key, salt FROM api_keys
        WHERE service = ?
        ''', (service,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
            
        encrypted_key, salt = result
        
        # Regenerate encryption key
        encryption_key, _ = generate_key(self.master_password, salt)
        
        # Decrypt the API key
        try:
            api_key = decrypt_api_key(encrypted_key, encryption_key)
            return api_key
        except Exception as e:
            print(f"Error decrypting API key: {e}")
            return None
            
    def update_rate_limits(self, service, rate_limit, rate_remaining, rate_reset):
        """Update rate limit information for a service."""
        conn = sqlite3.connect(self.keys_db)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE api_keys
        SET rate_limit = ?, rate_remaining = ?, rate_reset = ?, last_used = datetime('now')
        WHERE service = ?
        ''', (rate_limit, rate_remaining, rate_reset, service))
        
        conn.commit()
        conn.close()
        
    def check_rate_limit(self, service):
        """Check if rate limit is reached for a service."""
        conn = sqlite3.connect(self.keys_db)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT rate_remaining, rate_reset FROM api_keys
        WHERE service = ?
        ''', (service,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return True  # No rate limit info, assume OK
            
        rate_remaining, rate_reset = result
        
        if rate_remaining <= 0:
            # Check if reset time has passed
            reset_time = datetime.fromisoformat(rate_reset)
            now = datetime.now()
            
            if now < reset_time:
                # Still rate limited
                wait_seconds = (reset_time - now).total_seconds()
                print(f"Rate limit reached for {service}. Reset in {wait_seconds:.0f} seconds")
                return False
                
        return True  # Not rate limited

class ThreatIntelligence:
    def __init__(self, config=None):
        """Initialize the threat intelligence module with optional configuration"""
        self.config = config or {}
        self.cache_dir = self.config.get('cache_dir') or os.path.join(
            os.environ.get('IRF_ROOT', '.'), 'threat_intel')
            
        # Create cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
            
        # Set up cache database
        self.cache_db = os.path.join(self.cache_dir, 'intel_cache.db')
        self._initialize_cache_db()
        
        # Initialize API key manager
        self.api_key_manager = ApiKeyManager(self.config)
        
        # Default sources if not specified
        self.default_sources = ['local_cache', 'otx', 'abuse_ipdb']
    
    def _initialize_cache_db(self):
        """Set up the cache database"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_intel (
            ip TEXT PRIMARY KEY,
            is_malicious INTEGER,
            threat_type TEXT,
            score REAL,
            source TEXT,
            last_updated TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_intel (
            domain TEXT PRIMARY KEY,
            is_malicious INTEGER,
            threat_type TEXT,
            score REAL,
            source TEXT,
            last_updated TIMESTAMP
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS hash_intel (
            hash TEXT PRIMARY KEY,
            is_malicious INTEGER,
            threat_type TEXT,
            score REAL,
            source TEXT,
            last_updated TIMESTAMP
        )
        ''')
        
        # Create index for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_malicious ON ip_intel(is_malicious)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_malicious ON domain_intel(is_malicious)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash_malicious ON hash_intel(is_malicious)')
        
        conn.commit()
        conn.close()
    
    def _get_from_cache(self, indicator_type, indicator):
        """Get threat intel from local cache"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        table_name = f"{indicator_type}_intel"
        cursor.execute(f"SELECT * FROM {table_name} WHERE {indicator_type} = ?", (indicator,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            # Convert to dictionary
            columns = ['indicator', 'is_malicious', 'threat_type', 'score', 'source', 'last_updated']
            intel = dict(zip(columns, result))
            
            # Check if cache is expired (older than 7 days)
            last_updated = datetime.fromisoformat(intel['last_updated'])
            if datetime.now() - last_updated > timedelta(days=7):
                return None
                
            return intel
        
        return None
    
    def _save_to_cache(self, indicator_type, indicator, is_malicious, threat_type, score, source):
        """Save threat intel to local cache"""
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        table_name = f"{indicator_type}_intel"
        last_updated = datetime.now().isoformat()
        
        # Insert or replace
        cursor.execute(f'''
        INSERT OR REPLACE INTO {table_name}
        ({indicator_type}, is_malicious, threat_type, score, source, last_updated)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (indicator, is_malicious, threat_type, score, source, last_updated))
        
        conn.commit()
        conn.close()
    
    def check_ip(self, ip, sources=None):
        """Check if an IP is malicious using threat intelligence sources"""
        sources = sources or self.default_sources
        
        # Validate IP format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {
                'indicator': ip,
                'is_malicious': False,
                'error': 'Invalid IP format',
                'sources_checked': []
            }
        
        # Check cache first
        cached_intel = self._get_from_cache('ip', ip)
        if cached_intel and 'local_cache' in sources:
            return {
                'indicator': ip,
                'is_malicious': cached_intel['is_malicious'],
                'threat_type': cached_intel['threat_type'],
                'score': cached_intel['score'],
                'source': cached_intel['source'],
                'last_updated': cached_intel['last_updated'],
                'sources_checked': ['local_cache']
            }
        
        # Track which sources were checked
        sources_checked = []
        
        # Check AbuseIPDB
        if 'abuse_ipdb' in sources:
            try:
                api_key = self.api_key_manager.get_api_key('abuse_ipdb')
                if not api_key:
                    print("Warning: No API key for AbuseIPDB")
                else:
                    sources_checked.append('abuse_ipdb')
                    
                    url = f"https://api.abuseipdb.com/api/v2/check"
                    headers = {
                        'Key': api_key,
                        'Accept': 'application/json',
                    }
                    params = {
                        'ipAddress': ip,
                        'maxAgeInDays': 90
                    }
                    
                    response = make_robust_api_request(
                        url, 
                        'abuse_ipdb', 
                        self.api_key_manager,
                        headers=headers, 
                        params=params
                    )
                    
                    if 'error' not in response:
                        data = response
                        score = data['data'].get('abuseConfidenceScore', 0)
                        is_malicious = score >= 80  # 80% confidence threshold
                        
                        if is_malicious:
                            threat_type = "Abuse Detection"
                            self._save_to_cache('ip', ip, is_malicious, threat_type, score, 'abuse_ipdb')
                            
                            return {
                                'indicator': ip,
                                'is_malicious': is_malicious,
                                'threat_type': threat_type,
                                'score': score,
                                'source': 'abuse_ipdb',
                                'last_updated': datetime.now().isoformat(),
                                'sources_checked': sources_checked
                            }
            except Exception as e:
                print(f"Error checking AbuseIPDB: {e}")
        
        # Check AlienVault OTX
        if 'otx' in sources:
            try:
                api_key = self.api_key_manager.get_api_key('otx')
                if not api_key:
                    print("Warning: No API key for AlienVault OTX")
                else:
                    sources_checked.append('otx')
                    
                    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
                    headers = {'X-OTX-API-KEY': api_key}
                    
                    response = make_robust_api_request(
                        url, 
                        'otx', 
                        self.api_key_manager,
                        headers=headers
                    )
                    
                    if 'error' not in response:
                        pulse_count = response.get('pulse_info', {}).get('count', 0)
                        is_malicious = pulse_count > 0
                        
                        if is_malicious:
                            threat_type = "OTX Detection"
                            score = min(pulse_count * 10, 100)  # Convert pulse count to score
                            self._save_to_cache('ip', ip, is_malicious, threat_type, score, 'otx')
                            
                            return {
                                'indicator': ip,
                                'is_malicious': is_malicious,
                                'threat_type': threat_type,
                                'score': score,
                                'source': 'otx',
                                'last_updated': datetime.now().isoformat(),
                                'sources_checked': sources_checked
                            }
            except Exception as e:
                print(f"Error checking OTX: {e}")
        
        # No threat found
        self._save_to_cache('ip', ip, False, "", 0, 'multiple')
        
        return {
            'indicator': ip,
            'is_malicious': False,
            'score': 0,
            'source': 'multiple',
            'last_updated': datetime.now().isoformat(),
            'sources_checked': sources_checked
        }
    
    def check_domain(self, domain, sources=None):
        """Check if a domain is malicious using threat intelligence sources"""
        sources = sources or self.default_sources
        
        # Validate domain format
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            return {
                'indicator': domain,
                'is_malicious': False,
                'error': 'Invalid domain format',
                'sources_checked': []
            }
        
        # Check cache first
        cached_intel = self._get_from_cache('domain', domain)
        if cached_intel and 'local_cache' in sources:
            return {
                'indicator': domain,
                'is_malicious': cached_intel['is_malicious'],
                'threat_type': cached_intel['threat_type'],
                'score': cached_intel['score'],
                'source': cached_intel['source'],
                'last_updated': cached_intel['last_updated'],
                'sources_checked': ['local_cache']
            }
        
        # Track which sources were checked
        sources_checked = []
        
        # Check AlienVault OTX
        if 'otx' in sources:
            try:
                api_key = self.api_key_manager.get_api_key('otx')
                if not api_key:
                    print("Warning: No API key for AlienVault OTX")
                else:
                    sources_checked.append('otx')
                    
                    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
                    headers = {'X-OTX-API-KEY': api_key}
                    
                    response = make_robust_api_request(
                        url, 
                        'otx', 
                        self.api_key_manager,
                        headers=headers
                    )
                    
                    if response and 'error' not in response:
                        if 'pulse_info' in response and 'count' in response['pulse_info']:
                            pulse_count = response['pulse_info']['count']
                            is_malicious = pulse_count > 0
                            
                            if is_malicious:
                                threat_type = "OTX Detection"
                                score = min(pulse_count * 10, 100)  # Convert pulse count to score
                                self._save_to_cache('domain', domain, is_malicious, threat_type, score, 'otx')
                                
                                return {
                                    'indicator': domain,
                                    'is_malicious': is_malicious,
                                    'threat_type': threat_type,
                                    'score': score,
                                    'source': 'otx',
                                    'last_updated': datetime.now().isoformat(),
                                    'sources_checked': sources_checked
                                }
            except Exception as e:
                print(f"Error checking OTX: {e}")
        
        # No threat found
        self._save_to_cache('domain', domain, False, "", 0, 'multiple')
        
        return {
            'indicator': domain,
            'is_malicious': False,
            'score': 0,
            'source': 'multiple',
            'last_updated': datetime.now().isoformat(),
            'sources_checked': sources_checked
        }
    
    def check_hash(self, hash_value, sources=None):
        """Check if a file hash is malicious using threat intelligence sources"""
        sources = sources or self.default_sources
        
        # Validate hash format
        hash_patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$'
        }
        
        hash_type = None
        for h_type, pattern in hash_patterns.items():
            if re.match(pattern, hash_value):
                hash_type = h_type
                break
                
        if not hash_type:
            return {
                'indicator': hash_value,
                'is_malicious': False,
                'error': 'Invalid hash format',
                'sources_checked': []
            }
        
        # Check cache first
        cached_intel = self._get_from_cache('hash', hash_value)
        if cached_intel and 'local_cache' in sources:
            return {
                'indicator': hash_value,
                'is_malicious': cached_intel['is_malicious'],
                'threat_type': cached_intel['threat_type'],
                'score': cached_intel['score'],
                'source': cached_intel['source'],
                'last_updated': cached_intel['last_updated'],
                'sources_checked': ['local_cache']
            }
        
        # Track which sources were checked
        sources_checked = []
        
        # Check AlienVault OTX
        if 'otx' in sources:
            try:
                api_key = self.api_key_manager.get_api_key('otx')
                if not api_key:
                    print("Warning: No API key for AlienVault OTX")
                else:
                    sources_checked.append('otx')
                    
                    url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
                    headers = {'X-OTX-API-KEY': api_key}
                    
                    response = make_robust_api_request(
                        url, 
                        'otx', 
                        self.api_key_manager,
                        headers=headers
                    )
                    
                    if response and 'error' not in response:
                        if 'pulse_info' in response and 'count' in response['pulse_info']:
                            pulse_count = response['pulse_info']['count']
                            is_malicious = pulse_count > 0
                            
                            if is_malicious:
                                threat_type = "OTX Detection"
                                score = min(pulse_count * 10, 100)  # Convert pulse count to score
                                self._save_to_cache('hash', hash_value, is_malicious, threat_type, score, 'otx')
                                
                                return {
                                    'indicator': hash_value,
                                    'is_malicious': is_malicious,
                                    'threat_type': threat_type,
                                    'score': score,
                                    'source': 'otx',
                                    'last_updated': datetime.now().isoformat(),
                                    'sources_checked': sources_checked
                                }
            except Exception as e:
                print(f"Error checking OTX: {e}")
        
        # No threat found
        self._save_to_cache('hash', hash_value, False, "", 0, 'multiple')
        
        return {
            'indicator': hash_value,
            'is_malicious': False,
            'score': 0,
            'source': 'multiple',
            'last_updated': datetime.now().isoformat(),
            'sources_checked': sources_checked
        }
    
    def enrich_alerts(self, alerts_data, output_file=None):
        """Enrich alerts with threat intelligence"""
        # Convert to DataFrame if needed
        if not isinstance(alerts_data, pd.DataFrame):
            if isinstance(alerts_data, str) and os.path.exists(alerts_data):
                if alerts_data.endswith('.tsv'):
                    alerts_df = pd.read_csv(alerts_data, sep='\t')
                elif alerts_data.endswith('.csv'):
                    alerts_df = pd.read_csv(alerts_data)
                elif alerts_data.endswith('.json'):
                    alerts_df = pd.read_json(alerts_data)
                else:
                    raise ValueError(f"Unsupported file format: {alerts_data}")
            else:
                raise ValueError("alerts_data must be a DataFrame or path to a data file")
        else:
            alerts_df = alerts_data.copy()
        
        # Add threat intel columns
        alerts_df['threat_intel_result'] = False
        alerts_df['threat_intel_source'] = ''
        alerts_df['threat_intel_score'] = 0
        alerts_df['threat_intel_type'] = ''
        
        # Extract potential indicators from different fields
        for idx, row in alerts_df.iterrows():
            # Check IP addresses
            if 'ip_address' in row and row['ip_address']:
                ip_intel = self.check_ip(row['ip_address'])
                if ip_intel['is_malicious']:
                    alerts_df.at[idx, 'threat_intel_result'] = True
                    alerts_df.at[idx, 'threat_intel_source'] = ip_intel['source']
                    alerts_df.at[idx, 'threat_intel_score'] = ip_intel['score']
                    alerts_df.at[idx, 'threat_intel_type'] = ip_intel['threat_type']
                    continue
            
            # Check for domains in message field
            if 'message' in row and row['message']:
                # Extract potential domains
                domains = re.findall(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', str(row['message']))
                
                for domain_match in domains:
                    domain = domain_match[0]  # Extract matched domain
                    domain_intel = self.check_domain(domain)
                    
                    if domain_intel['is_malicious']:
                        alerts_df.at[idx, 'threat_intel_result'] = True
                        alerts_df.at[idx, 'threat_intel_source'] = domain_intel['source']
                        alerts_df.at[idx, 'threat_intel_score'] = domain_intel['score']
                        alerts_df.at[idx, 'threat_intel_type'] = domain_intel['threat_type']
                        break  # Stop at first malicious domain
        
        # Save results if output file provided
        if output_file:
            if output_file.endswith('.tsv'):
                alerts_df.to_csv(output_file, sep='\t', index=False)
            elif output_file.endswith('.csv'):
                alerts_df.to_csv(output_file, index=False)
            elif output_file.endswith('.json'):
                alerts_df.to_json(output_file, orient='records')
            else:
                # Default to TSV
                alerts_df.to_csv(output_file, sep='\t', index=False)
        
        # Return updated data
        return alerts_df
    
    def update_rules_from_intel(self, rules_dir=None):
        """Update detection rules based on threat intelligence"""
        if not rules_dir:
            rules_dir = os.path.join(os.environ.get('IRF_ROOT', '.'), 'conf/rules')
            
        if not os.path.exists(rules_dir):
            raise ValueError(f"Rules directory not found: {rules_dir}")
            
        # Path for threat intelligence rules
        threat_intel_rules = os.path.join(rules_dir, 'threat-intel.rules')
        
        # Get all malicious IPs from cache
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip FROM ip_intel WHERE is_malicious = 1")
        malicious_ips = [row[0] for row in cursor.fetchall()]
        
        cursor.execute("SELECT domain FROM domain_intel WHERE is_malicious = 1")
        malicious_domains = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        # Create rules file
        with open(threat_intel_rules, 'w') as f:
            f.write("# Threat Intelligence Detection Rules\n")
            f.write("# Format: RULE_ID;DESCRIPTION;PATTERN;SEVERITY;FIELDS\n")
            f.write("#\n")
            f.write("# Fields reference (0-based index):\n")
            f.write("# 0 - timestamp\n")
            f.write("# 1 - source_type\n")
            f.write("# 2 - source_name\n")
            f.write("# 3 - log_level\n")
            f.write("# 4 - username\n")
            f.write("# 5 - hostname\n")
            f.write("# 6 - ip_address\n")
            f.write("# 7 - service\n")
            f.write("# 8 - process_id\n")
            f.write("# 9 - message\n\n")
            
            # Add IP-based rules
            if malicious_ips:
                f.write("# Known malicious IPs\n")
                for i, ip in enumerate(malicious_ips):
                    rule_id = f"TI-IP-{i+1:03d}"
                    description = f"Known Malicious IP: {ip}"
                    pattern = ip.replace('.', '\\.')  # Escape dots for regex
                    severity = "HIGH"
                    fields = "6,9"  # IP address and message fields
                    
                    f.write(f"{rule_id};{description};{pattern};{severity};{fields}\n")
                    
                f.write("\n")
                
            # Add domain-based rules
            if malicious_domains:
                f.write("# Known malicious domains\n")
                for i, domain in enumerate(malicious_domains):
                    rule_id = f"TI-DOM-{i+1:03d}"
                    description = f"Known Malicious Domain: {domain}"
                    pattern = domain.replace('.', '\\.')  # Escape dots for regex
                    severity = "HIGH"
                    fields = "9"  # Message field
                    
                    f.write(f"{rule_id};{description};{pattern};{severity};{fields}\n")
        
        return {
            'rules_file': threat_intel_rules,
            'ip_rules_count': len(malicious_ips),
            'domain_rules_count': len(malicious_domains),
            'last_updated': datetime.now().isoformat()
        }
    
    def fetch_open_source_intel(self, source, output_dir=None):
        """Fetch threat intelligence from open source feeds"""
        if not output_dir:
            output_dir = self.cache_dir
            
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
            
        # Define available feeds
        feeds = {
            'abuse_ch_feodo': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'type': 'ip',
                'comment_char': '#'
            },
            'abuse_ch_ssl': {
                'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
                'type': 'ip',
                'comment_char': '#'
            },
            'emerging_threats': {
                'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                'type': 'ip',
                'comment_char': '#'
            },
            'spamhaus_drop': {
                'url': 'https://www.spamhaus.org/drop/drop.txt',
                'type': 'ip',
                'comment_char': ';'
            },
            'malware_domains': {
                'url': 'https://mirror.cedia.org.ec/malwaredomains/justdomains',
                'type': 'domain',
                'comment_char': '#'
            }
        }
        
        if source not in feeds:
            raise ValueError(f"Unknown threat intel source: {source}")
            
        feed = feeds[source]
        
        try:
            # Download feed
            response = requests.get(feed['url'], timeout=30)
            response.raise_for_status()
            
            content = response.text
            indicators = []
            
            # Parse content
            for line in content.splitlines():
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith(feed['comment_char']):
                    continue
                    
                # Extract indicator based on feed type
                if feed['type'] == 'ip':
                    # Simple IP or CIDR format
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?', line)
                    if match:
                        indicators.append(match.group(0))
                elif feed['type'] == 'domain':
                    # Domain format
                    match = re.search(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', line)
                    if match:
                        indicators.append(match.group(0))
            
            # Save indicators
            output_file = os.path.join(output_dir, f"{source}_feed.txt")
            with open(output_file, 'w') as f:
                f.write(f"# {feed['url']}\n")
                f.write(f"# Downloaded: {datetime.now().isoformat()}\n")
                f.write(f"# Indicator type: {feed['type']}\n")
                f.write(f"# Count: {len(indicators)}\n\n")
                
                for indicator in indicators:
                    f.write(f"{indicator}\n")
            
            # Add to cache
            for indicator in indicators:
                if feed['type'] == 'ip':
                    self._save_to_cache('ip', indicator, True, f"{source} feed", 80, source)
                elif feed['type'] == 'domain':
                    self._save_to_cache('domain', indicator, True, f"{source} feed", 80, source)
            
            return {
                'source': source,
                'type': feed['type'],
                'count': len(indicators),
                'output_file': output_file,
                'last_updated': datetime.now().isoformat()
            }
                
        except Exception as e:
            print(f"Error fetching {source} feed: {e}")
            return {
                'source': source,
                'error': str(e),
                'last_updated': datetime.now().isoformat()
            }

# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IRF Threat Intelligence Integration')
    parser.add_argument('--action', required=True, 
                      choices=['check-ip', 'check-domain', 'check-hash', 'enrich-alerts', 
                               'update-rules', 'fetch-feed'],
                      help='Action to perform')
    parser.add_argument('--indicator', help='Indicator to check (IP, domain, or hash)')
    parser.add_argument('--alerts', help='Path to alerts file to enrich')
    parser.add_argument('--output', help='Path to output file')
    parser.add_argument('--source', help='Threat intel source')
    parser.add_argument('--config', help='Path to configuration file with API keys')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = None
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    intel = ThreatIntelligence(config)
    
    @handle_errors
    def check_ip_action():
        if not args.indicator:
            print("Error: --indicator is required for check-ip action")
            sys.exit(1)
            
        result = intel.check_ip(args.indicator)
        print(json.dumps(result, indent=2))
    
    @handle_errors
    def check_domain_action():
        if not args.indicator:
            print("Error: --indicator is required for check-domain action")
            sys.exit(1)
            
        result = intel.check_domain(args.indicator)
        print(json.dumps(result, indent=2))
    
    @handle_errors
    def check_hash_action():
        if not args.indicator:
            print("Error: --indicator is required for check-hash action")
            sys.exit(1)
            
        result = intel.check_hash(args.indicator)
        print(json.dumps(result, indent=2))
    
    @handle_errors
    def enrich_alerts_action():
        if not args.alerts:
            print("Error: --alerts is required for enrich-alerts action")
            sys.exit(1)
            
        if not args.output:
            args.output = 'enriched_' + os.path.basename(args.alerts)
            
        # Process CLI command for alert enrichment:
        # 1. Reads alert data from the specified file (csv, tsv, or json format)
        # 2. For each alert record, checks IPs and domains against threat intel sources
        # 3. Adds new columns with threat intel results (is_malicious, source, score, type)
        # 4. Saves the enriched dataset to the output file in the same format as input
        # 5. The enriched alerts can be used for prioritization and further investigation
        result = intel.enrich_alerts(args.alerts, args.output)
        print(f"Enriched alerts saved to: {args.output}")
    
    @handle_errors
    def update_rules_action():
        # Process CLI command for rule updates:
        # 1. Retrieves all malicious IPs and domains from the local threat intel cache
        # 2. Generates detection rules in the format: RULE_ID;DESCRIPTION;PATTERN;SEVERITY;FIELDS
        # 3. Creates rules for both IPs and domains with appropriate regex patterns
        # 4. Saves the rules to 'threat-intel.rules' in the specified rules directory
        # 5. Rules can be used by detection engine to identify known malicious indicators
        # 6. Returns statistics about the number of rules generated
        result = intel.update_rules_from_intel()
        print(f"Created {result['ip_rules_count']} IP rules and {result['domain_rules_count']} domain rules")
        print(f"Rules saved to: {result['rules_file']}")
    
    @handle_errors
    def fetch_feed_action():
        if not args.source:
            print("Error: --source is required for fetch-feed action")
            sys.exit(1)
            
        # Process CLI command for fetching threat intelligence:
        # 1. Connects to the specified open source intelligence feed (e.g., abuse_ch_feodo)
        # 2. Downloads the latest threat indicators list from the feed's URL
        # 3. Parses the feed data to extract valid IP addresses or domains
        # 4. Saves the indicators to a local text file for reference
        # 5. Adds each indicator to the local cache database with malicious status
        # 6. The indicators will be used in future threat checks and rule generation
        # 7. Supported feeds: abuse_ch_feodo, abuse_ch_ssl, emerging_threats, 
        #    spamhaus_drop, malware_domains
        result = intel.fetch_open_source_intel(args.source)
        
        if 'error' in result:
            print(f"Error fetching feed: {result['error']}")
        else:
            print(f"Downloaded {result['count']} indicators from {result['source']}")
            print(f"Feed saved to: {result['output_file']}")
    
    # Map actions to handler functions
    action_handlers = {
        'check-ip': check_ip_action,
        'check-domain': check_domain_action,
        'check-hash': check_hash_action,
        'enrich-alerts': enrich_alerts_action,
        'update-rules': update_rules_action,
        'fetch-feed': fetch_feed_action
    }
    
    # Execute the appropriate action
    if args.action in action_handlers:
        action_handlers[args.action]()
    else:
        print(f"Unknown action: {args.action}")
        sys.exit(1)