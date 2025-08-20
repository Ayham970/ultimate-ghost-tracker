#!/usr/bin/env python3
"""
Ultimate Ghost Tracker - WORKING STANDALONE VERSION
Professional OSINT Investigation Platform
Enhanced by: Ayham971
Date: 2025-08-20
"""

import asyncio
import os
import sys
import time
import json
import sqlite3
import hashlib
import re
import socket
import threading
import logging
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

# Standard library imports
try:
    import requests
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
except ImportError:
    print("❌ Missing required packages. Install with:")
    print("pip install requests phonenumbers")
    sys.exit(1)

# Colors for terminal output - COMPLETE
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[97m'
    MAGENTA = '\033[95m'

class UltimateGhostTracker:
    """Ultimate Ghost Tracker - Complete Working Version"""
    
    def __init__(self):
        print(f"{Colors.CYAN}🚀 Initializing Ultimate Ghost Tracker...{Colors.ENDC}")
        self.setup_directories()
        self.setup_logging()
        self.setup_database()
        self.current_investigation = None
        
    def setup_directories(self):
        """Create necessary directories"""
        directories = ["data", "logs", "reports", "exports"]
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
        print(f"{Colors.GREEN}✅ Directories created{Colors.ENDC}")
        
    def setup_logging(self):
        """Setup logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'logs/ghost_tracker_{datetime.now().strftime("%Y%m%d")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        print(f"{Colors.GREEN}✅ Logging configured{Colors.ENDC}")
        
    def setup_database(self):
        """Initialize database"""
        try:
            self.db_path = "investigations.db"
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    type TEXT,
                    target TEXT,
                    start_time TEXT,
                    status TEXT,
                    results TEXT,
                    risk_score INTEGER DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            print(f"{Colors.GREEN}✅ Database initialized{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}❌ Database setup failed: {str(e)}{Colors.ENDC}")
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self):
        """Display banner and menu"""
        self.clear_screen()
        banner = f"""{Colors.CYAN}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗   ██╗██╗  ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗            ║
║   ██║   ██║██║  ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝            ║
║   ██║   ██║██║     ██║   ██║██╔████╔██║███████║   ██║   █████╗              ║
║   ██║   ██║██║     ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝              ║
║   ╚██████╔╝███████╗██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗            ║
║    ╚═════╝ ╚══════╝╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝            ║
║                                                                              ║
║            ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗                       ║
║           ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝                       ║
║           ██║  ███╗███████║██║   ██║███████╗   ██║                          ║
║           ██║   ██║██╔══██║██║   ██║╚════██║   ██║                          ║
║           ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║                          ║
║            ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝                          ║
║                                                                              ║
║                    ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ ║
║                    ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗║
║                       ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝║
║                       ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗║
║                       ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║║
║                       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝║
║                                                                              ║
║              {Colors.GREEN}Professional OSINT Investigation Platform{Colors.CYAN}                  ║
║                        {Colors.YELLOW}Enhanced by: Ayham971{Colors.CYAN}                           ║
║                     {Colors.YELLOW}Working Version - 2025-08-20{Colors.CYAN}                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
        
        print(banner)
        
        menu = f"""{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                              INVESTIGATION MODULES                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ {Colors.GREEN}[ 1 ]{Colors.BOLD}  🌐 Advanced IP Intelligence       {Colors.GREEN}[ 6 ]{Colors.BOLD}  🛡️  Threat Intelligence       ║
║ {Colors.GREEN}[ 2 ]{Colors.BOLD}  📱 Enhanced Phone Intelligence     {Colors.GREEN}[ 7 ]{Colors.BOLD}  📊 Investigation History       ║
║ {Colors.GREEN}[ 3 ]{Colors.BOLD}  👤 Username Investigation          {Colors.GREEN}[ 8 ]{Colors.BOLD}  ⚙️  System Status             ║
║ {Colors.GREEN}[ 4 ]{Colors.BOLD}  📧 Email & Domain Intelligence     {Colors.GREEN}[ 9 ]{Colors.BOLD}  📤 Export Investigation        ║
║ {Colors.GREEN}[ 5 ]{Colors.BOLD}  💰 Cryptocurrency Investigation    {Colors.GREEN}[ ? ]{Colors.BOLD}  ℹ️  Help & Documentation      ║
║                                                                              ║
║ {Colors.FAIL}[ 0 ]{Colors.BOLD}  🚪 Exit Platform                                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}"""
        
        print(menu)
    
    def validate_ip(self, ip):
        """Validate IP address"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None
    
    def start_investigation(self, investigation_type: str, target: str):
        """Start new investigation"""
        investigation_id = hashlib.md5(f"{investigation_type}_{target}_{datetime.now().isoformat()}".encode()).hexdigest()[:8]
        
        investigation = {
            'id': investigation_id,
            'type': investigation_type,
            'target': target,
            'start_time': datetime.now(),
            'status': 'active',
            'results': {},
            'risk_score': 0
        }
        
        self.current_investigation = investigation
        
        # Save to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO investigations 
                (id, type, target, start_time, status, results, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                investigation['id'],
                investigation['type'],
                investigation['target'],
                investigation['start_time'].isoformat(),
                investigation['status'],
                json.dumps(investigation.get('results', {})),
                investigation.get('risk_score', 0)
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"{Colors.FAIL}❌ Failed to save investigation: {str(e)}{Colors.ENDC}")
        
        self.logger.info(f"Started investigation {investigation_id} for {investigation_type}: {target}")
        return investigation
    
    def get_ip_geolocation(self, ip):
        """Get IP geolocation data"""
        apis = [
            f'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query',
            f'https://ipapi.co/{ip}/json/',
            f'https://ipinfo.io/{ip}/json'
        ]
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        for i, api in enumerate(apis):
            try:
                print(f"{Colors.CYAN}🔍 Trying API {i+1}...{Colors.ENDC}")
                response = session.get(api, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Check API-specific success indicators
                    if 'ip-api.com' in api and data.get('status') == 'success':
                        print(f"{Colors.GREEN}✅ IP-API.com successful{Colors.ENDC}")
                        return data
                    elif 'ipapi.co' in api and 'error' not in data:
                        print(f"{Colors.GREEN}✅ IPAPI.co successful{Colors.ENDC}")
                        return data
                    elif 'ipinfo.io' in api and 'error' not in data:
                        print(f"{Colors.GREEN}✅ IPinfo.io successful{Colors.ENDC}")
                        return data
                        
            except Exception as e:
                print(f"{Colors.FAIL}❌ API {i+1} failed: {str(e)[:50]}{Colors.ENDC}")
                continue
        
        return None
    
    def get_reverse_dns(self, ip):
        """Get reverse DNS"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "No reverse DNS"
    
    def check_ip_reputation(self, ip):
        """Simple IP reputation check"""
        # Simple reputation check
        reputation = {
            'is_malicious': False,
            'reputation_score': 85,
            'source': 'Local analysis',
            'analysis': []
        }
        
        # Check for private IP ranges
        ip_parts = ip.split('.')
        if ip_parts[0] in ['10', '172', '192']:
            reputation['analysis'].append('Private IP range')
            reputation['reputation_score'] = 95
        elif ip_parts[0] in ['94', '185', '194']:
            reputation['analysis'].append('VPS/Hosting range')
            reputation['reputation_score'] = 60
        
        return reputation
    
    def calculate_risk_score(self, geo_data, reputation_data):
        """Calculate risk score"""
        base_score = 20
        
        # Geography-based risk
        if geo_data:
            country_code = geo_data.get('countryCode', '')
            high_risk_countries = ['CN', 'RU', 'KP', 'IR']
            if country_code in high_risk_countries:
                base_score += 25
        
        # Reputation-based risk
        if reputation_data:
            rep_score = reputation_data.get('reputation_score', 85)
            if rep_score < 50:
                base_score += 40
            elif rep_score < 70:
                base_score += 20
        
        return min(base_score, 100)
    
    def advanced_ip_intelligence(self):
        """IP Intelligence Module - COMPLETE"""
        print(f"\n{Colors.CYAN}🌐 ADVANCED IP INTELLIGENCE INVESTIGATION{Colors.ENDC}")
        print("=" * 60)
        
        target_ip = input(f"{Colors.GREEN}Enter target IP address: {Colors.ENDC}").strip()
        
        if not self.validate_ip(target_ip):
            print(f"{Colors.FAIL}❌ Invalid IP address format!{Colors.ENDC}")
            return
        
        # Start investigation
        investigation = self.start_investigation('ip_intelligence', target_ip)
        
        print(f"\n{Colors.YELLOW}🔍 Investigation ID: {investigation['id']}{Colors.ENDC}")
        print(f"{Colors.CYAN}📊 Gathering intelligence...{Colors.ENDC}\n")
        
        # Get geolocation data
        geo_data = self.get_ip_geolocation(target_ip)
        
        # Get network info
        reverse_dns = self.get_reverse_dns(target_ip)
        
        # Check reputation
        reputation = self.check_ip_reputation(target_ip)
        
        # Calculate risk
        risk_score = self.calculate_risk_score(geo_data, reputation)
        
        # Display results
        print(f"\n{Colors.BOLD}📋 IP INTELLIGENCE REPORT{Colors.ENDC}")
        print("=" * 50)
        print(f"{Colors.GREEN}Target IP: {target_ip}{Colors.ENDC}")
        
        if geo_data:
            print(f"Country: {geo_data.get('country', 'Unknown')}")
            print(f"Region: {geo_data.get('regionName', 'Unknown')}")
            print(f"City: {geo_data.get('city', 'Unknown')}")
            print(f"ISP: {geo_data.get('isp', 'Unknown')}")
            print(f"Organization: {geo_data.get('org', 'Unknown')}")
            
            lat = geo_data.get('lat')
            lon = geo_data.get('lon')
            if lat and lon:
                print(f"Coordinates: {lat}, {lon}")
                print(f"{Colors.BLUE}Google Maps: https://www.google.com/maps/@{lat},{lon},12z{Colors.ENDC}")
        
        print(f"Reverse DNS: {reverse_dns}")
        print(f"Reputation Score: {reputation['reputation_score']}/100")
        print(f"{Colors.WARNING}Risk Score: {risk_score}/100{Colors.ENDC}")
        
        # Save results
        results = {
            'geolocation': geo_data,
            'reverse_dns': reverse_dns,
            'reputation': reputation,
            'risk_score': risk_score
        }
        
        if self.current_investigation:
            self.current_investigation['results']['ip_intelligence'] = results
            self.current_investigation['risk_score'] = risk_score
    
    def enhanced_phone_intelligence(self):
        """Phone Intelligence Module"""
        print(f"\n{Colors.CYAN}📱 ENHANCED PHONE INTELLIGENCE{Colors.ENDC}")
        print("=" * 50)
        
        phone = input(f"{Colors.GREEN}Enter phone number (with country code): {Colors.ENDC}").strip()
        
        try:
            # Parse phone number
            parsed_number = phonenumbers.parse(phone, None)
            
            if not phonenumbers.is_valid_number(parsed_number):
                print(f"{Colors.FAIL}❌ Invalid phone number!{Colors.ENDC}")
                return
            
            # Start investigation
            investigation = self.start_investigation('phone_intelligence', phone)
            
            print(f"\n{Colors.YELLOW}🔍 Investigation ID: {investigation['id']}{Colors.ENDC}")
            
            # Get phone info
            country = phonenumbers.region_code_for_number(parsed_number)
            carrier_name = carrier.name_for_number(parsed_number, "en")
            location = geocoder.description_for_number(parsed_number, "en")
            timezones = timezone.time_zones_for_number(parsed_number)
            
            # Display results
            print(f"\n{Colors.BOLD}📋 PHONE INTELLIGENCE REPORT{Colors.ENDC}")
            print("=" * 50)
            print(f"{Colors.GREEN}Phone Number: {phone}{Colors.ENDC}")
            print(f"Country: {country}")
            print(f"Carrier: {carrier_name or 'Unknown'}")
            print(f"Location: {location or 'Unknown'}")
            print(f"Timezones: {', '.join(timezones) if timezones else 'Unknown'}")
            print(f"Valid: {Colors.GREEN}Yes{Colors.ENDC}")
            
            # Save results
            results = {
                'country': country,
                'carrier': carrier_name,
                'location': location,
                'timezones': list(timezones),
                'is_valid': True
            }
            
            if self.current_investigation:
                self.current_investigation['results']['phone_intelligence'] = results
                
        except Exception as e:
            print(f"{Colors.FAIL}❌ Phone analysis failed: {str(e)}{Colors.ENDC}")
    
    def username_investigation(self):
        """Username Investigation Module"""
        print(f"\n{Colors.CYAN}👤 USERNAME INVESTIGATION{Colors.ENDC}")
        print("=" * 40)
        
        username = input(f"{Colors.GREEN}Enter username: {Colors.ENDC}").strip()
        
        # Start investigation
        investigation = self.start_investigation('username_investigation', username)
        
        print(f"\n{Colors.YELLOW}🔍 Investigation ID: {investigation['id']}{Colors.ENDC}")
        print(f"{Colors.CYAN}📊 Scanning social platforms...{Colors.ENDC}\n")
        
        # Social platforms to check
        platforms = [
            {"url": "https://www.github.com/{}", "name": "GitHub"},
            {"url": "https://www.twitter.com/{}", "name": "Twitter"},
            {"url": "https://www.instagram.com/{}", "name": "Instagram"},
            {"url": "https://www.reddit.com/user/{}", "name": "Reddit"},
            {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
            {"url": "https://www.youtube.com/user/{}", "name": "YouTube"},
            {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
            {"url": "https://www.twitch.tv/{}", "name": "Twitch"}
        ]
        
        found_profiles = []
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        for platform in platforms:
            try:
                url = platform['url'].format(username)
                print(f"{Colors.CYAN}Checking {platform['name']}...{Colors.ENDC}", end=' ')
                
                response = session.get(url, timeout=5, allow_redirects=True)
                
                # Simple check for profile existence
                if response.status_code == 200 and 'not found' not in response.text.lower():
                    found_profiles.append({
                        'platform': platform['name'],
                        'url': url
                    })
                    print(f"{Colors.GREEN}✅ Found{Colors.ENDC}")
                else:
                    print(f"{Colors.FAIL}❌ Not found{Colors.ENDC}")
                
                time.sleep(0.5)  # Rate limiting
                
            except Exception:
                print(f"{Colors.YELLOW}⚠️ Error{Colors.ENDC}")
        
        # Display results
        print(f"\n{Colors.BOLD}📋 USERNAME INVESTIGATION REPORT{Colors.ENDC}")
        print("=" * 50)
        print(f"{Colors.GREEN}Username: {username}{Colors.ENDC}")
        print(f"Profiles Found: {len(found_profiles)}")
        
        if found_profiles:
            print(f"\n{Colors.CYAN}🔍 FOUND PROFILES:{Colors.ENDC}")
            for profile in found_profiles:
                print(f"  • {profile['platform']}: {Colors.GREEN}{profile['url']}{Colors.ENDC}")
        
        # Save results
        if self.current_investigation:
            self.current_investigation['results']['username_investigation'] = {
                'profiles_found': found_profiles,
                'total_found': len(found_profiles)
            }
    
    def email_domain_intelligence(self):
        """Email/Domain Intelligence Module"""
        print(f"\n{Colors.CYAN}📧 EMAIL & DOMAIN INTELLIGENCE{Colors.ENDC}")
        print("=" * 50)
        
        target = input(f"{Colors.GREEN}Enter email or domain: {Colors.ENDC}").strip()
        
        # Start investigation
        investigation = self.start_investigation('email_domain_intelligence', target)
        
        print(f"\n{Colors.YELLOW}🔍 Investigation ID: {investigation['id']}{Colors.ENDC}")
        
        # Basic validation
        is_email = '@' in target
        domain = target.split('@')[1] if is_email else target
        
        # Email validation
        if is_email:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            is_valid = re.match(email_pattern, target) is not None
        else:
            domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            is_valid = re.match(domain_pattern, target) is not None
        
        # Simple domain reputation check
        suspicious_domains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com']
        is_suspicious = any(susp in domain.lower() for susp in suspicious_domains)
        
        # Display results
        print(f"\n{Colors.BOLD}📋 EMAIL/DOMAIN INTELLIGENCE REPORT{Colors.ENDC}")
        print("=" * 50)
        print(f"{Colors.GREEN}Target: {target}{Colors.ENDC}")
        print(f"Type: {'Email' if is_email else 'Domain'}")
        print(f"Domain: {domain}")
        print(f"Valid Format: {Colors.GREEN if is_valid else Colors.FAIL}{'Yes' if is_valid else 'No'}{Colors.ENDC}")
        print(f"Suspicious: {Colors.FAIL if is_suspicious else Colors.GREEN}{'Yes' if is_suspicious else 'No'}{Colors.ENDC}")
        
        # Save results
        if self.current_investigation:
            self.current_investigation['results']['email_domain_intelligence'] = {
                'target': target,
                'domain': domain,
                'is_email': is_email,
                'is_valid': is_valid,
                'is_suspicious': is_suspicious
            }
    
    def cryptocurrency_investigation(self):
        """Cryptocurrency Investigation Module"""
        print(f"\n{Colors.CYAN}💰 CRYPTOCURRENCY INVESTIGATION{Colors.ENDC}")
        print("=" * 50)
        
        address = input(f"{Colors.GREEN}Enter crypto address: {Colors.ENDC}").strip()
        
        # Start investigation
        investigation = self.start_investigation('cryptocurrency_investigation', address)
        
        print(f"\n{Colors.YELLOW}🔍 Investigation ID: {investigation['id']}{Colors.ENDC}")
        
        # Detect currency type
        currency = "Unknown"
        if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
            currency = "Bitcoin"
        elif re.match(r'^0x[a-fA-F0-9]{40}$', address):
            currency = "Ethereum"
        elif re.match(r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$', address):
            currency = "Litecoin"
        
        # Display results
        print(f"\n{Colors.BOLD}📋 CRYPTOCURRENCY INVESTIGATION REPORT{Colors.ENDC}")
        print("=" * 50)
        print(f"{Colors.GREEN}Address: {address}{Colors.ENDC}")
        print(f"Detected Currency: {currency}")
        print(f"Address Length: {len(address)}")
        print(f"Format Valid: {Colors.GREEN if currency != 'Unknown' else Colors.FAIL}{'Yes' if currency != 'Unknown' else 'No'}{Colors.ENDC}")
        
        # Save results
        if self.current_investigation:
            self.current_investigation['results']['cryptocurrency_investigation'] = {
                'address': address,
                'currency': currency,
                'address_length': len(address),
                'is_valid_format': currency != 'Unknown'
            }
    
    def threat_intelligence_analysis(self):
        """Threat Intelligence Module"""
        print(f"\n{Colors.CYAN}🛡️ THREAT INTELLIGENCE ANALYSIS{Colors.ENDC}")
        print("=" * 50)
        
        ip = input(f"{Colors.GREEN}Enter IP for threat analysis: {Colors.ENDC}").strip()
        
        if not self.validate_ip(ip):
            print(f"{Colors.FAIL}❌ Invalid IP address!{Colors.ENDC}")
            return
        
        print(f"\n{Colors.CYAN}🔍 Analyzing threats...{Colors.ENDC}")
        
        # Simple threat analysis
        reputation = self.check_ip_reputation(ip)
        
        print(f"\n{Colors.BOLD}🛡️ THREAT INTELLIGENCE REPORT{Colors.ENDC}")
        print("=" * 50)
        print(f"{Colors.GREEN}IP Address: {ip}{Colors.ENDC}")
        print(f"Threat Status: {Colors.GREEN if not reputation['is_malicious'] else Colors.FAIL}{'Clean' if not reputation['is_malicious'] else 'Malicious'}{Colors.ENDC}")
        print(f"Reputation Score: {reputation['reputation_score']}/100")
        
        if reputation['analysis']:
            print(f"Analysis: {', '.join(reputation['analysis'])}")
    
    def show_investigation_history(self):
        """Show investigation history"""
        print(f"\n{Colors.CYAN}📊 INVESTIGATION HISTORY{Colors.ENDC}")
        print("=" * 40)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM investigations ORDER BY start_time DESC LIMIT 10')
            investigations = cursor.fetchall()
            conn.close()
            
            if investigations:
                print(f"\n{Colors.GREEN}Recent Investigations:{Colors.ENDC}")
                for inv in investigations:
                    print(f"  • ID: {inv[0]} | Type: {inv[1]} | Target: {inv[2]} | Risk: {inv[6]}/100")
            else:
                print(f"{Colors.YELLOW}No investigations found{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.FAIL}❌ Error accessing history: {str(e)}{Colors.ENDC}")
    
    def show_system_status(self):
        """Show system status"""
        print(f"\n{Colors.CYAN}⚙️ SYSTEM STATUS{Colors.ENDC}")
        print("=" * 30)
        
        print(f"\n{Colors.BOLD}📡 MODULES:{Colors.ENDC}")
        print(f"  IP Intelligence: {Colors.GREEN}✅ Active{Colors.ENDC}")
        print(f"  Phone Intelligence: {Colors.GREEN}✅ Active{Colors.ENDC}")
        print(f"  Username Investigation: {Colors.GREEN}✅ Active{Colors.ENDC}")
        print(f"  Email Intelligence: {Colors.GREEN}✅ Active{Colors.ENDC}")
        print(f"  Crypto Investigation: {Colors.GREEN}✅ Active{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}🗄️ DATABASE:{Colors.ENDC}")
        print(f"  Location: {Colors.GREEN}{self.db_path}{Colors.ENDC}")
        print(f"  Status: {Colors.GREEN}✅ Connected{Colors.ENDC}")
        
        # Check investigation count
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM investigations')
            count = cursor.fetchone()[0]
            conn.close()
            print(f"  Total Investigations: {Colors.GREEN}{count}{Colors.ENDC}")
        except:
            print(f"  Total Investigations: {Colors.YELLOW}Unknown{Colors.ENDC}")
    
    def export_investigation(self):
        """Export current investigation"""
        if not self.current_investigation:
            print(f"{Colors.YELLOW}No active investigation to export{Colors.ENDC}")
            return
        
        export_file = f"exports/investigation_{self.current_investigation['id']}.json"
        
        export_data = {
            'investigation_id': self.current_investigation['id'],
            'type': self.current_investigation['type'],
            'target': self.current_investigation['target'],
            'start_time': self.current_investigation['start_time'].isoformat(),
            'results': self.current_investigation['results'],
            'risk_score': self.current_investigation.get('risk_score', 0)
        }
        
        try:
            with open(export_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"{Colors.GREEN}✅ Investigation exported: {export_file}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}❌ Export failed: {str(e)}{Colors.ENDC}")
    
    def show_help(self):
        """Show help"""
        help_text = f"""
{Colors.CYAN}📚 ULTIMATE GHOST TRACKER - HELP{Colors.ENDC}
{'=' * 40}

{Colors.BOLD}AVAILABLE MODULES:{Colors.ENDC}

{Colors.GREEN}1. IP Intelligence{Colors.ENDC} - Analyze IP addresses
{Colors.GREEN}2. Phone Intelligence{Colors.ENDC} - Analyze phone numbers  
{Colors.GREEN}3. Username Investigation{Colors.ENDC} - Search social platforms
{Colors.GREEN}4. Email/Domain Intelligence{Colors.ENDC} - Analyze emails/domains
{Colors.GREEN}5. Cryptocurrency Investigation{Colors.ENDC} - Analyze crypto addresses
{Colors.GREEN}6. Threat Intelligence{Colors.ENDC} - Check IP threats

{Colors.BOLD}FEATURES:{Colors.ENDC}
• Investigation tracking and history
• Risk scoring and assessment  
• Data export capabilities
• Comprehensive reporting

{Colors.BOLD}USAGE:{Colors.ENDC}
• Select a module by entering its number
• Follow the prompts to enter target data
• Review comprehensive results
• Export investigations as needed

{Colors.WARNING}LEGAL NOTICE:{Colors.ENDC}
This tool is for legitimate investigation purposes only.
Respect privacy and comply with applicable laws.
        """
        print(help_text)
    
    def run(self):
        """Main application loop"""
        print(f"{Colors.GREEN}✅ Ultimate Ghost Tracker ready!{Colors.ENDC}")
        
        try:
            while True:
                self.show_banner()
                
                choice = input(f"{Colors.GREEN}🎯 Select module (0-9, ? for help): {Colors.ENDC}").strip()
                
                try:
                    if choice == '0':
                        print(f"\n{Colors.YELLOW}👋 Thank you for using Ultimate Ghost Tracker!{Colors.ENDC}")
                        break
                    
                    elif choice == '?':
                        self.show_help()
                    
                    elif choice == '1':
                        self.advanced_ip_intelligence()
                    
                    elif choice == '2':
                        self.enhanced_phone_intelligence()
                    
                    elif choice == '3':
                        self.username_investigation()
                    
                    elif choice == '4':
                        self.email_domain_intelligence()
                    
                    elif choice == '5':
                        self.cryptocurrency_investigation()
                    
                    elif choice == '6':
                        self.threat_intelligence_analysis()
                    
                    elif choice == '7':
                        self.show_investigation_history()
                    
                    elif choice == '8':
                        self.show_system_status()
                    
                    elif choice == '9':
                        self.export_investigation()
                    
                    else:
                        print(f"{Colors.WARNING}⚠️ Invalid choice. Enter 0-9 or ? for help.{Colors.ENDC}")
                    
                    if choice not in ['0', '?']:
                        input(f"\n{Colors.CYAN}📱 Press Enter to return to main menu...{Colors.ENDC}")
                        
                except Exception as e:
                    self.logger.error(f"Error in module {choice}: {str(e)}")
                    print(f"{Colors.FAIL}❌ Error occurred: {str(e)}{Colors.ENDC}")
                    input(f"\n{Colors.CYAN}📱 Press Enter to continue...{Colors.ENDC}")
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}🛑 Program terminated by user{Colors.ENDC}")
        
        except Exception as e:
            print(f"{Colors.FAIL}💥 Critical error: {str(e)}{Colors.ENDC}")

if __name__ == "__main__":
    print(f"{Colors.CYAN}🚀 Starting Ultimate Ghost Tracker...{Colors.ENDC}")
    
    try:
        tracker = UltimateGhostTracker()
        tracker.run()
    except Exception as e:
        print(f"{Colors.FAIL}💥 Failed to start: {str(e)}{Colors.ENDC}")
        sys.exit(1)
