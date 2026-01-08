"""
CVE Database Module
Educational and Authorized Security Testing Tool
Manages known vulnerabilities from CVE database
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging


class CVEDatabase:
    """Manages CVE vulnerability database for PDF exploits"""
    
    def __init__(self, config: Dict = None):
        """
        Initialize CVE database
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.cve_data = {}
        self.last_update = None
        self.database_file = "cve_database.json"
        
        # Load or initialize database
        self._load_database()
    
    def _load_database(self) -> None:
        """Load CVE database from file or initialize with default data"""
        if os.path.exists(self.database_file):
            try:
                with open(self.database_file, 'r') as f:
                    data = json.load(f)
                    self.cve_data = data.get('cves', {})
                    self.last_update = data.get('last_update')
                    self.logger.info(f"Loaded {len(self.cve_data)} CVE entries")
            except Exception as e:
                self.logger.error(f"Error loading database: {e}")
                self._initialize_default_database()
        else:
            self._initialize_default_database()
    
    def _initialize_default_database(self) -> None:
        """Initialize database with known PDF vulnerabilities"""
        self.cve_data = {
            # Adobe Reader Vulnerabilities
            "CVE-2010-0188": {
                "name": "Adobe Reader libTiff Buffer Overflow",
                "description": "Buffer overflow in libTiff in Adobe Reader",
                "affected_versions": ["Adobe Reader 9.0-9.3.2"],
                "cwe": "CWE-119",
                "cvss": 9.3,
                "type": "buffer_overflow",
                "target_os": ["windows"],
                "exploit_mechanism": "malformed_tiff_image",
                "payload_capacity": "large",
                "reliability": "high",
                "discovery_date": "2010-03-09",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2010-0188",
                    "https://www.exploit-db.com/exploits/11662"
                ]
            },
            
            "CVE-2010-2883": {
                "name": "Adobe Reader Util.printf() Stack Overflow",
                "description": "Stack overflow via Util.printf() JavaScript function",
                "affected_versions": ["Adobe Reader 9.0-9.3.4"],
                "cwe": "CWE-121",
                "cvss": 9.3,
                "type": "stack_overflow",
                "target_os": ["windows", "linux"],
                "exploit_mechanism": "javascript_printf",
                "payload_capacity": "medium",
                "reliability": "high",
                "discovery_date": "2010-08-25",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2010-2883",
                    "https://www.exploit-db.com/exploits/14889"
                ]
            },
            
            "CVE-2011-2462": {
                "name": "Adobe Reader U3D Memory Corruption",
                "description": "Memory corruption in U3D (Universal 3D) parsing",
                "affected_versions": ["Adobe Reader 7.0-10.1.1"],
                "cwe": "CWE-119",
                "cvss": 10.0,
                "type": "memory_corruption",
                "target_os": ["windows"],
                "exploit_mechanism": "malformed_u3d",
                "payload_capacity": "large",
                "reliability": "high",
                "discovery_date": "2011-12-06",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2011-2462",
                    "https://www.exploit-db.com/exploits/18136"
                ]
            },
            
            "CVE-2013-0641": {
                "name": "Adobe Reader JavaScript API Exploit",
                "description": "Vulnerability in JavaScript API for document manipulation",
                "affected_versions": ["Adobe Reader 9.5.3-11.0.1"],
                "cwe": "CWE-20",
                "cvss": 9.3,
                "type": "javascript_exploit",
                "target_os": ["windows", "linux", "macos"],
                "exploit_mechanism": "javascript_api",
                "payload_capacity": "medium",
                "reliability": "medium",
                "discovery_date": "2013-02-13",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2013-0641",
                    "https://www.exploit-db.com/exploits/24619"
                ]
            },
            
            "CVE-2018-4990": {
                "name": "Adobe Acrobat JavaScript Null Pointer",
                "description": "Null pointer dereference in JavaScript engine",
                "affected_versions": ["Adobe Acrobat DC 2018.011.20038"],
                "cwe": "CWE-476",
                "cvss": 7.5,
                "type": "null_pointer",
                "target_os": ["windows", "macos"],
                "exploit_mechanism": "javascript_null_ptr",
                "payload_capacity": "small",
                "reliability": "medium",
                "discovery_date": "2018-04-10",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-4990"
                ]
            },
            
            # Foxit Reader Vulnerabilities
            "CVE-2018-19448": {
                "name": "Foxit Reader GoToE Action Type Confusion",
                "description": "Type confusion in GoToE action handling",
                "affected_versions": ["Foxit Reader 9.0.1.1049"],
                "cwe": "CWE-843",
                "cvss": 8.8,
                "type": "type_confusion",
                "target_os": ["windows"],
                "exploit_mechanism": "action_type_confusion",
                "payload_capacity": "medium",
                "reliability": "high",
                "discovery_date": "2018-11-20",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-19448",
                    "https://www.exploit-db.com/exploits/45988"
                ]
            },
            
            # Sumatra PDF Vulnerabilities
            "CVE-2018-1000141": {
                "name": "Sumatra PDF Use-After-Free",
                "description": "Use-after-free vulnerability in PDF parsing",
                "affected_versions": ["SumatraPDF 3.1.2"],
                "cwe": "CWE-416",
                "cvss": 7.5,
                "type": "use_after_free",
                "target_os": ["windows"],
                "exploit_mechanism": "use_after_free",
                "payload_capacity": "medium",
                "reliability": "medium",
                "discovery_date": "2018-04-06",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-1000141"
                ]
            },
            
            # Rendering Engine Vulnerabilities
            "CVE-2019-13720": {
                "name": "PDF Rendering Heap Overflow",
                "description": "Heap overflow in PDF rendering engine",
                "affected_versions": ["Multiple PDF viewers"],
                "cwe": "CWE-122",
                "cvss": 8.8,
                "type": "heap_overflow",
                "target_os": ["windows", "linux"],
                "exploit_mechanism": "rendering_heap_overflow",
                "payload_capacity": "large",
                "reliability": "high",
                "discovery_date": "2019-11-19",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-13720"
                ]
            },
            
            # JavaScript-Based Exploits
            "CVE-2020-9695": {
                "name": "Acrobat Reader JavaScript Object Confusion",
                "description": "JavaScript object confusion leading to RCE",
                "affected_versions": ["Acrobat Reader DC 2020.009.20063"],
                "cwe": "CWE-843",
                "cvss": 7.8,
                "type": "javascript_exploit",
                "target_os": ["windows", "macos"],
                "exploit_mechanism": "javascript_object_confusion",
                "payload_capacity": "medium",
                "reliability": "high",
                "discovery_date": "2020-06-09",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-9695"
                ]
            }
        }
        
        self.last_update = datetime.now().isoformat()
        self._save_database()
        self.logger.info(f"Initialized database with {len(self.cve_data)} CVE entries")
    
    def _save_database(self) -> None:
        """Save CVE database to file"""
        try:
            data = {
                'cves': self.cve_data,
                'last_update': self.last_update
            }
            with open(self.database_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info("Database saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving database: {e}")
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Get details for a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2010-0188)
            
        Returns:
            Dictionary with CVE details or None if not found
        """
        return self.cve_data.get(cve_id.upper())
    
    def search_vulnerabilities(self, criteria: Dict) -> List[Dict]:
        """
        Search vulnerabilities based on criteria
        
        Args:
            criteria: Search criteria dictionary
                - target_os: Target operating system
                - min_cvss: Minimum CVSS score
                - type: Vulnerability type
                - reliability: Minimum reliability level
                
        Returns:
            List of matching CVE entries
        """
        results = []
        
        for cve_id, details in self.cve_data.items():
            match = True
            
            # Check target OS
            if 'target_os' in criteria:
                if criteria['target_os'].lower() not in [os.lower() for os in details.get('target_os', [])]:
                    match = False
            
            # Check CVSS score
            if 'min_cvss' in criteria:
                if details.get('cvss', 0) < criteria['min_cvss']:
                    match = False
            
            # Check vulnerability type
            if 'type' in criteria:
                if details.get('type') != criteria['type']:
                    match = False
            
            # Check reliability
            if 'reliability' in criteria:
                reliability_levels = {'low': 1, 'medium': 2, 'high': 3}
                if reliability_levels.get(details.get('reliability', 'low'), 0) < \
                   reliability_levels.get(criteria['reliability'], 0):
                    match = False
            
            if match:
                results.append({'cve_id': cve_id, **details})
        
        return sorted(results, key=lambda x: x.get('cvss', 0), reverse=True)
    
    def get_best_vulnerability(self, target_os: str, payload_size: int = None) -> Optional[Dict]:
        """
        Get best vulnerability for given target and constraints
        
        Args:
            target_os: Target operating system
            payload_size: Size of payload in bytes
            
        Returns:
            Best matching vulnerability or None
        """
        results = self.search_vulnerabilities({
            'target_os': target_os,
            'min_cvss': 7.0,
            'reliability': 'high'
        })
        
        if not results:
            return None
        
        # Filter by payload capacity if size specified
        if payload_size:
            capacity_map = {'small': 1024, 'medium': 10240, 'large': 1048576}
            filtered = []
            for vuln in results:
                capacity = capacity_map.get(vuln.get('payload_capacity', 'small'), 1024)
                if payload_size <= capacity:
                    filtered.append(vuln)
            
            if filtered:
                results = filtered
        
        return results[0] if results else None
    
    def list_vulnerabilities(self) -> List[Dict]:
        """List all available vulnerabilities"""
        return [
            {
                'cve_id': cve_id,
                'name': details['name'],
                'cvss': details['cvss'],
                'type': details['type'],
                'target_os': details['target_os']
            }
            for cve_id, details in self.cve_data.items()
        ]
    
    def update_database(self) -> bool:
        """
        Update CVE database from online sources
        
        Returns:
            True if update successful, False otherwise
        """
        self.logger.info("Database update not implemented in offline mode")
        return False
    
    def get_vulnerability_stats(self) -> Dict:
        """Get statistics about vulnerabilities in database"""
        stats = {
            'total_vulnerabilities': len(self.cve_data),
            'by_type': {},
            'by_os': {},
            'by_reliability': {},
            'avg_cvss': 0.0
        }
        
        for details in self.cve_data.values():
            # Count by type
            vuln_type = details.get('type', 'unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # Count by OS
            for os in details.get('target_os', []):
                stats['by_os'][os] = stats['by_os'].get(os, 0) + 1
            
            # Count by reliability
            reliability = details.get('reliability', 'unknown')
            stats['by_reliability'][reliability] = stats['by_reliability'].get(reliability, 0) + 1
            
            stats['avg_cvss'] += details.get('cvss', 0)
        
        if stats['total_vulnerabilities'] > 0:
            stats['avg_cvss'] /= stats['total_vulnerabilities']
        
        return stats
    
    def export_vulnerabilities(self, output_file: str, format: str = 'json') -> bool:
        """
        Export vulnerabilities to file
        
        Args:
            output_file: Output file path
            format: Export format (json/csv)
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            if format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(self.cve_data, f, indent=2)
            elif format.lower() == 'csv':
                import csv
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['CVE ID', 'Name', 'CVSS', 'Type', 'Target OS', 'Reliability'])
                    for cve_id, details in self.cve_data.items():
                        writer.writerow([
                            cve_id,
                            details['name'],
                            details['cvss'],
                            details['type'],
                            ', '.join(details['target_os']),
                            details['reliability']
                        ])
            else:
                return False
            
            self.logger.info(f"Exported {len(self.cve_data)} vulnerabilities to {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting vulnerabilities: {e}")
            return False