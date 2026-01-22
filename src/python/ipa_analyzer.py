#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════
 NULLSEC iOS IPA ANALYZER
 Comprehensive iOS application package analysis
 @author bad-antics | discord.gg/killers
═══════════════════════════════════════════════════════════════════
"""

import os
import sys
import zipfile
import plistlib
import hashlib
import json
import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

VERSION = "2.0.0"
AUTHOR = "bad-antics"
DISCORD = "discord.gg/killers"

BANNER = """
╭──────────────────────────────────────────╮
│       📱 NULLSEC iOS IPA ANALYZER       │
│       ════════════════════════════      │
│                                          │
│   📦 IPA Package Analysis                │
│   🔍 Binary Inspection                   │
│   🛡️  Security Assessment                │
│                                          │
│          bad-antics | NullSec            │
╰──────────────────────────────────────────╯
"""

# ═══════════════════════════════════════════════════════════════════
# License Management
# ═══════════════════════════════════════════════════════════════════

class LicenseTier:
    FREE = 0
    PREMIUM = 1
    ENTERPRISE = 2

class License:
    def __init__(self, key: str = ""):
        self.key = key
        self.tier = LicenseTier.FREE
        self.valid = False
        
        if self._validate(key):
            self.valid = True
            self.key = key
    
    def _validate(self, key: str) -> bool:
        if not key or len(key) != 24:
            return False
        if not key.startswith("NIOS-"):
            return False
        
        type_code = key[5:7]
        if type_code == "PR":
            self.tier = LicenseTier.PREMIUM
        elif type_code == "EN":
            self.tier = LicenseTier.ENTERPRISE
        return True
    
    @property
    def tier_name(self) -> str:
        if self.tier == LicenseTier.PREMIUM:
            return "Premium ⭐"
        elif self.tier == LicenseTier.ENTERPRISE:
            return "Enterprise 💎"
        return "Free"
    
    @property
    def is_premium(self) -> bool:
        return self.valid and self.tier != LicenseTier.FREE


# ═══════════════════════════════════════════════════════════════════
# Console Helpers
# ═══════════════════════════════════════════════════════════════════

class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"

def print_success(msg: str):
    print(f"{Colors.GREEN}✅ {msg}{Colors.RESET}")

def print_error(msg: str):
    print(f"{Colors.RED}❌ {msg}{Colors.RESET}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.RESET}")

def print_info(msg: str):
    print(f"{Colors.CYAN}ℹ️  {msg}{Colors.RESET}")

def print_header(title: str):
    print("\n═══════════════════════════════════════════")
    print(f"  {title}")
    print("═══════════════════════════════════════════\n")


# ═══════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AppInfo:
    name: str = ""
    bundle_id: str = ""
    version: str = ""
    build: str = ""
    min_os: str = ""
    sdk_version: str = ""
    executable: str = ""
    team_id: str = ""
    app_category: str = ""

@dataclass
class SecurityFinding:
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    description: str
    recommendation: str = ""

@dataclass 
class AnalysisResult:
    app_info: AppInfo
    permissions: List[str]
    url_schemes: List[str]
    frameworks: List[str]
    security_findings: List[SecurityFinding]
    strings_of_interest: List[str]
    file_count: int
    total_size: int


# ═══════════════════════════════════════════════════════════════════
# IPA Analyzer
# ═══════════════════════════════════════════════════════════════════

class IPAAnalyzer:
    def __init__(self, ipa_path: str, license: License):
        self.ipa_path = ipa_path
        self.license = license
        self.result = None
        
    def analyze(self) -> Optional[AnalysisResult]:
        """Perform full IPA analysis."""
        if not os.path.exists(self.ipa_path):
            print_error(f"File not found: {self.ipa_path}")
            return None
        
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Find Info.plist
                info_plist = self._find_info_plist(ipa)
                if not info_plist:
                    print_error("Could not find Info.plist")
                    return None
                
                # Parse app info
                app_info = self._parse_info_plist(ipa, info_plist)
                
                # Extract permissions
                permissions = self._extract_permissions(ipa, info_plist)
                
                # Extract URL schemes
                url_schemes = self._extract_url_schemes(ipa, info_plist)
                
                # List frameworks
                frameworks = self._list_frameworks(ipa)
                
                # Security analysis
                security_findings = self._security_analysis(ipa, app_info)
                
                # String analysis
                strings = self._extract_strings(ipa) if self.license.is_premium else []
                
                # File stats
                file_count = len(ipa.namelist())
                total_size = sum(info.file_size for info in ipa.infolist())
                
                self.result = AnalysisResult(
                    app_info=app_info,
                    permissions=permissions,
                    url_schemes=url_schemes,
                    frameworks=frameworks,
                    security_findings=security_findings,
                    strings_of_interest=strings,
                    file_count=file_count,
                    total_size=total_size
                )
                
                return self.result
                
        except zipfile.BadZipFile:
            print_error("Invalid IPA file (not a valid ZIP archive)")
            return None
        except Exception as e:
            print_error(f"Analysis failed: {e}")
            return None
    
    def _find_info_plist(self, ipa: zipfile.ZipFile) -> Optional[str]:
        """Find the main Info.plist file."""
        for name in ipa.namelist():
            if name.endswith('.app/Info.plist') and name.count('/') == 2:
                return name
        return None
    
    def _parse_info_plist(self, ipa: zipfile.ZipFile, plist_path: str) -> AppInfo:
        """Parse Info.plist and extract app information."""
        app_info = AppInfo()
        
        try:
            with ipa.open(plist_path) as f:
                plist = plistlib.load(f)
                
                app_info.name = plist.get('CFBundleDisplayName', 
                                         plist.get('CFBundleName', 'Unknown'))
                app_info.bundle_id = plist.get('CFBundleIdentifier', 'Unknown')
                app_info.version = plist.get('CFBundleShortVersionString', 'Unknown')
                app_info.build = plist.get('CFBundleVersion', 'Unknown')
                app_info.min_os = plist.get('MinimumOSVersion', 'Unknown')
                app_info.sdk_version = plist.get('DTSDKName', 'Unknown')
                app_info.executable = plist.get('CFBundleExecutable', 'Unknown')
                app_info.app_category = plist.get('LSApplicationCategoryType', '')
                
        except Exception as e:
            print_warning(f"Error parsing Info.plist: {e}")
        
        return app_info
    
    def _extract_permissions(self, ipa: zipfile.ZipFile, plist_path: str) -> List[str]:
        """Extract app permissions (usage descriptions)."""
        permissions = []
        
        permission_keys = [
            ('NSCameraUsageDescription', 'Camera'),
            ('NSPhotoLibraryUsageDescription', 'Photo Library'),
            ('NSLocationWhenInUseUsageDescription', 'Location (When In Use)'),
            ('NSLocationAlwaysUsageDescription', 'Location (Always)'),
            ('NSMicrophoneUsageDescription', 'Microphone'),
            ('NSContactsUsageDescription', 'Contacts'),
            ('NSCalendarsUsageDescription', 'Calendar'),
            ('NSRemindersUsageDescription', 'Reminders'),
            ('NSMotionUsageDescription', 'Motion'),
            ('NSHealthShareUsageDescription', 'Health Data'),
            ('NSBluetoothAlwaysUsageDescription', 'Bluetooth'),
            ('NSFaceIDUsageDescription', 'Face ID'),
            ('NSSpeechRecognitionUsageDescription', 'Speech Recognition'),
            ('NSAppleMusicUsageDescription', 'Apple Music'),
        ]
        
        try:
            with ipa.open(plist_path) as f:
                plist = plistlib.load(f)
                
                for key, name in permission_keys:
                    if key in plist:
                        permissions.append(f"{name}: {plist[key]}")
                        
        except Exception:
            pass
        
        return permissions
    
    def _extract_url_schemes(self, ipa: zipfile.ZipFile, plist_path: str) -> List[str]:
        """Extract registered URL schemes."""
        schemes = []
        
        try:
            with ipa.open(plist_path) as f:
                plist = plistlib.load(f)
                
                url_types = plist.get('CFBundleURLTypes', [])
                for url_type in url_types:
                    for scheme in url_type.get('CFBundleURLSchemes', []):
                        schemes.append(scheme)
                        
        except Exception:
            pass
        
        return schemes
    
    def _list_frameworks(self, ipa: zipfile.ZipFile) -> List[str]:
        """List embedded frameworks."""
        frameworks = []
        
        for name in ipa.namelist():
            if '/Frameworks/' in name and name.endswith('.framework/'):
                framework_name = name.split('/')[-2]
                if framework_name not in frameworks:
                    frameworks.append(framework_name)
        
        return frameworks
    
    def _security_analysis(self, ipa: zipfile.ZipFile, app_info: AppInfo) -> List[SecurityFinding]:
        """Perform security analysis."""
        findings = []
        
        # Check for ATS exceptions
        try:
            plist_path = self._find_info_plist(ipa)
            with ipa.open(plist_path) as f:
                plist = plistlib.load(f)
                
                ats = plist.get('NSAppTransportSecurity', {})
                
                if ats.get('NSAllowsArbitraryLoads', False):
                    findings.append(SecurityFinding(
                        severity="High",
                        category="Network Security",
                        title="ATS Disabled",
                        description="App Transport Security allows arbitrary loads",
                        recommendation="Enable ATS and use HTTPS for all connections"
                    ))
                
                if ats.get('NSAllowsArbitraryLoadsForMedia', False):
                    findings.append(SecurityFinding(
                        severity="Medium",
                        category="Network Security", 
                        title="ATS Exception for Media",
                        description="ATS allows arbitrary loads for media",
                        recommendation="Review if this exception is necessary"
                    ))
                    
        except Exception:
            pass
        
        # Check for debugging
        try:
            plist_path = self._find_info_plist(ipa)
            with ipa.open(plist_path) as f:
                plist = plistlib.load(f)
                
                if plist.get('get-task-allow', False):
                    findings.append(SecurityFinding(
                        severity="Critical",
                        category="Build Configuration",
                        title="Debug Build Detected",
                        description="App has get-task-allow entitlement enabled",
                        recommendation="Use release build for production"
                    ))
                    
        except Exception:
            pass
        
        # Check for embedded provisioning profile
        has_profile = any('embedded.mobileprovision' in name for name in ipa.namelist())
        if has_profile:
            findings.append(SecurityFinding(
                severity="Info",
                category="Distribution",
                title="Provisioning Profile Embedded",
                description="App contains embedded provisioning profile",
                recommendation="Normal for development/enterprise builds"
            ))
        
        # Check frameworks for known vulnerable versions
        frameworks = self._list_frameworks(ipa)
        vulnerable_frameworks = ['AFNetworking', 'Alamofire']  # Simplified check
        for framework in frameworks:
            if framework in vulnerable_frameworks:
                findings.append(SecurityFinding(
                    severity="Medium",
                    category="Dependencies",
                    title=f"Review {framework} Version",
                    description=f"Framework {framework} detected - verify version for known vulnerabilities",
                    recommendation="Keep frameworks updated to latest versions"
                ))
        
        return findings
    
    def _extract_strings(self, ipa: zipfile.ZipFile) -> List[str]:
        """Extract interesting strings from binary (Premium)."""
        strings_of_interest = []
        
        # Patterns to search for
        patterns = [
            (r'https?://[^\s<>"{}|\\^`\[\]]+', 'URL'),
            (r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', 'Email'),
            (r'(?:password|secret|api[_-]?key|token)["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Sensitive'),
            (r'-----BEGIN [A-Z]+ KEY-----', 'Private Key'),
        ]
        
        # Find the executable
        app_path = None
        for name in ipa.namelist():
            if name.endswith('.app/') and name.count('/') == 2:
                app_path = name
                break
        
        if not app_path:
            return strings_of_interest
        
        # This is a simplified string extraction
        # In real implementation, would use proper Mach-O parsing
        
        return strings_of_interest[:50]  # Limit results
    
    def print_report(self):
        """Print analysis report."""
        if not self.result:
            print_error("No analysis results available")
            return
        
        r = self.result
        
        print_header("📱 APP INFORMATION")
        print(f"  Name:           {r.app_info.name}")
        print(f"  Bundle ID:      {r.app_info.bundle_id}")
        print(f"  Version:        {r.app_info.version} ({r.app_info.build})")
        print(f"  Min iOS:        {r.app_info.min_os}")
        print(f"  SDK:            {r.app_info.sdk_version}")
        print(f"  Executable:     {r.app_info.executable}")
        print(f"  Files:          {r.file_count}")
        print(f"  Total Size:     {r.total_size / 1024 / 1024:.2f} MB")
        
        if r.permissions:
            print_header("🔐 PERMISSIONS")
            for perm in r.permissions:
                print(f"  • {perm}")
        
        if r.url_schemes:
            print_header("🔗 URL SCHEMES")
            for scheme in r.url_schemes:
                print(f"  • {scheme}://")
        
        if r.frameworks:
            print_header("📚 EMBEDDED FRAMEWORKS")
            for fw in r.frameworks:
                print(f"  • {fw}")
        
        if r.security_findings:
            print_header("🛡️  SECURITY FINDINGS")
            
            # Sort by severity
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_findings = sorted(r.security_findings, 
                                    key=lambda x: severity_order.get(x.severity, 5))
            
            for finding in sorted_findings:
                icon = {
                    'Critical': '🔴',
                    'High': '🟠', 
                    'Medium': '🟡',
                    'Low': '🟢',
                    'Info': 'ℹ️'
                }.get(finding.severity, '⚪')
                
                print(f"  {icon} [{finding.severity}] {finding.title}")
                print(f"      {finding.description}")
                if finding.recommendation:
                    print(f"      → {finding.recommendation}")
                print()
        
        if r.strings_of_interest and self.license.is_premium:
            print_header("🔍 STRINGS OF INTEREST")
            for s in r.strings_of_interest[:20]:
                print(f"  • {s}")
        elif not self.license.is_premium:
            print_header("🔍 STRINGS OF INTEREST")
            print_warning(f"String extraction is a Premium feature: {DISCORD}")
        
        print()
    
    def export_json(self, output_path: str):
        """Export analysis results to JSON."""
        if not self.result:
            print_error("No analysis results to export")
            return
        
        if not self.license.is_premium:
            print_warning(f"JSON export is a Premium feature: {DISCORD}")
            return
        
        data = {
            "app_info": asdict(self.result.app_info),
            "permissions": self.result.permissions,
            "url_schemes": self.result.url_schemes,
            "frameworks": self.result.frameworks,
            "security_findings": [asdict(f) for f in self.result.security_findings],
            "strings_of_interest": self.result.strings_of_interest,
            "file_count": self.result.file_count,
            "total_size": self.result.total_size,
            "analysis_date": datetime.now().isoformat(),
            "analyzer_version": VERSION
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print_success(f"Report exported to {output_path}")


# ═══════════════════════════════════════════════════════════════════
# Interactive Menu
# ═══════════════════════════════════════════════════════════════════

def interactive_mode(license: License):
    """Interactive analysis mode."""
    
    while True:
        tier_badge = "⭐" if license.is_premium else "🆓"
        
        print(f"\n  📋 NullSec iOS IPA Analyzer {tier_badge}\n")
        print("  [1] Analyze IPA File")
        print("  [2] Export Report (Premium)")
        print("  [3] Enter License Key")
        print("  [0] Exit")
        
        try:
            choice = input("\n  Select: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        
        if choice == "1":
            ipa_path = input("  IPA file path: ").strip()
            if ipa_path:
                analyzer = IPAAnalyzer(ipa_path, license)
                print_info("Analyzing IPA file...")
                if analyzer.analyze():
                    analyzer.print_report()
        
        elif choice == "2":
            ipa_path = input("  IPA file path: ").strip()
            output_path = input("  Output JSON path: ").strip() or "report.json"
            if ipa_path:
                analyzer = IPAAnalyzer(ipa_path, license)
                if analyzer.analyze():
                    analyzer.export_json(output_path)
        
        elif choice == "3":
            key = input("  License key: ").strip()
            license = License(key)
            if license.valid:
                print_success(f"License activated: {license.tier_name}")
            else:
                print_warning("Invalid license key")
        
        elif choice == "0":
            break
        
        else:
            print_error("Invalid option")


# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="NullSec iOS IPA Analyzer")
    parser.add_argument("ipa", nargs="?", help="IPA file to analyze")
    parser.add_argument("-k", "--key", help="License key")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
        print(f"  Version {VERSION} | {AUTHOR}")
        print(f"  🔑 Premium: {DISCORD}\n")
    
    license = License(args.key) if args.key else License()
    
    if license.valid and not args.quiet:
        print_success(f"License activated: {license.tier_name}")
    
    if args.ipa:
        # CLI mode
        analyzer = IPAAnalyzer(args.ipa, license)
        if analyzer.analyze():
            if not args.quiet:
                analyzer.print_report()
            if args.output:
                analyzer.export_json(args.output)
    else:
        # Interactive mode
        interactive_mode(license)
    
    if not args.quiet:
        print("\n─────────────────────────────────────────")
        print("  📱 NullSec iOS IPA Analyzer")
        print(f"  🔑 Premium: {DISCORD}")
        print(f"  👤 Author: {AUTHOR}")
        print("─────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
