"""
PDF Parser Module
Educational and Authorized Security Testing Tool
Handles PDF parsing and manipulation
"""

import os
import re
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import struct


class PDFParser:
    """Handles PDF parsing and manipulation"""
    
    def __init__(self, config: Dict = None):
        """
        Initialize PDF parser
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def load_pdf(self, pdf_path: str) -> Optional[bytes]:
        """
        Load PDF file
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            PDF content bytes or None if loading fails
        """
        try:
            if not os.path.exists(pdf_path):
                self.logger.error(f"PDF file not found: {pdf_path}")
                return None
            
            with open(pdf_path, 'rb') as f:
                pdf_content = f.read()
            
            # Verify PDF structure
            if not self._is_valid_pdf(pdf_content):
                self.logger.error("Invalid PDF file format")
                return None
            
            self.logger.info(f"Loaded PDF: {len(pdf_content)} bytes from {pdf_path}")
            return pdf_content
        
        except Exception as e:
            self.logger.error(f"Error loading PDF: {e}")
            return None
    
    def _is_valid_pdf(self, pdf_content: bytes) -> bool:
        """
        Check if content is a valid PDF
        
        Args:
            pdf_content: Content to check
            
        Returns:
            True if valid PDF, False otherwise
        """
        try:
            # Check PDF header
            if not pdf_content.startswith(b'%PDF-'):
                return False
            
            # Check EOF marker
            if b'%%EOF' not in pdf_content:
                return False
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error validating PDF: {e}")
            return False
    
    def get_pdf_info(self, pdf_content: bytes) -> Dict:
        """
        Get information about PDF
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            Dictionary with PDF information
        """
        info = {
            'version': '',
            'pages': 0,
            'objects': 0,
            'size': len(pdf_content),
            'has_javascript': False,
            'has_embedded_files': False,
            'has_actions': False,
            'encryption': False,
            'creator': '',
            'producer': '',
            'title': '',
            'author': '',
            'creation_date': '',
            'modified_date': ''
        }
        
        try:
            # Get PDF version
            version_match = re.search(b'%PDF-(\d\.\d)', pdf_content)
            if version_match:
                info['version'] = version_match.group(1).decode('ascii')
            
            # Count objects
            info['objects'] = pdf_content.count(b' 0 obj')
            
            # Check for JavaScript
            info['has_javascript'] = b'/JavaScript' in pdf_content or b'/S /JS' in pdf_content
            
            # Check for embedded files
            info['has_embedded_files'] = b'/EmbeddedFile' in pdf_content or b'/Filespec' in pdf_content
            
            # Check for actions
            info['has_actions'] = b'/Action' in pdf_content or b'/OpenAction' in pdf_content
            
            # Check for encryption
            info['encryption'] = b'/Encrypt' in pdf_content
            
            # Extract metadata
            info.update(self._extract_metadata(pdf_content))
            
            # Count pages (simplified)
            info['pages'] = self._count_pages(pdf_content)
            
        except Exception as e:
            self.logger.error(f"Error getting PDF info: {e}")
        
        return info
    
    def _extract_metadata(self, pdf_content: bytes) -> Dict:
        """
        Extract metadata from PDF
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            Dictionary with metadata
        """
        metadata = {}
        
        try:
            # Look for document info dictionary
            info_pattern = rb'/Info\s+(\d+)\s+\d+\s+R'
            info_match = re.search(info_pattern, pdf_content)
            
            if info_match:
                # Extract info object (simplified)
                info_obj = self._extract_info_object(pdf_content, info_match.group(1).decode('ascii'))
                metadata.update(info_obj)
        
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {e}")
        
        return metadata
    
    def _extract_info_object(self, pdf_content: bytes, obj_num: str) -> Dict:
        """
        Extract info object from PDF
        
        Args:
            pdf_content: PDF content bytes
            obj_num: Object number
            
        Returns:
            Dictionary with info object data
        """
        info = {}
        
        try:
            # Find info object
            pattern = f'{obj_num} 0 obj'.encode('ascii')
            start_pos = pdf_content.find(pattern)
            
            if start_pos != -1:
                # Find endobj
                end_pos = pdf_content.find(b'endobj', start_pos)
                
                if end_pos != -1:
                    obj_content = pdf_content[start_pos:end_pos].decode('latin-1', errors='ignore')
                    
                    # Extract common fields
                    fields = {
                        '/Title': 'title',
                        '/Author': 'author',
                        '/Creator': 'creator',
                        '/Producer': 'producer',
                        '/CreationDate': 'creation_date',
                        '/ModDate': 'modified_date'
                    }
                    
                    for field, key in fields.items():
                        field_match = re.search(rf'{field}\s*\(([^)]*)\)', obj_content)
                        if field_match:
                            info[key] = field_match.group(1)
        
        except Exception as e:
            self.logger.error(f"Error extracting info object: {e}")
        
        return info
    
    def _count_pages(self, pdf_content: bytes) -> int:
        """
        Count pages in PDF
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            Number of pages
        """
        try:
            # Look for PageCount in trailer
            page_count_match = re.search(rb'/Count\s+(\d+)', pdf_content)
            if page_count_match:
                return int(page_count_match.group(1))
            
            # Fallback: count /Type /Page occurrences
            return pdf_content.count(b'/Type /Page')
        
        except Exception as e:
            self.logger.error(f"Error counting pages: {e}")
            return 0
    
    def extract_objects(self, pdf_content: bytes) -> List[Dict]:
        """
        Extract all objects from PDF
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            List of object dictionaries
        """
        objects = []
        
        try:
            # Find all objects
            pattern = rb'(\d+)\s+\d+\s+obj(.*?)endobj'
            matches = re.findall(pattern, pdf_content, re.DOTALL)
            
            for match in matches:
                obj_num = match[0].decode('ascii')
                obj_content = match[1].decode('latin-1', errors='ignore')
                
                obj_info = {
                    'number': obj_num,
                    'type': self._get_object_type(obj_content),
                    'content': obj_content[:200]  # Truncated for display
                }
                
                objects.append(obj_info)
        
        except Exception as e:
            self.logger.error(f"Error extracting objects: {e}")
        
        return objects
    
    def _get_object_type(self, content: str) -> str:
        """
        Determine object type from content
        
        Args:
            content: Object content string
            
        Returns:
            Object type string
        """
        if '/Type' in content:
            type_match = re.search(r'/Type\s*/(\w+)', content)
            if type_match:
                return type_match.group(1)
        elif '/Catalog' in content:
            return 'Catalog'
        elif '/Page' in content:
            return 'Page'
        elif '/JavaScript' in content:
            return 'JavaScript'
        
        return 'Unknown'
    
    def find_javascript(self, pdf_content: bytes) -> List[str]:
        """
        Find JavaScript code in PDF
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            List of JavaScript code strings
        """
        javascript_blocks = []
        
        try:
            # Find JavaScript action objects
            pattern = rb'/JavaScript\s*<<(.*?)>>'
            matches = re.findall(pattern, pdf_content, re.DOTALL)
            
            for match in matches:
                js_content = match.decode('latin-1', errors='ignore')
                javascript_blocks.append(js_content)
            
            # Find /JS patterns
            js_pattern = rb'/JS\s*\((.*?)\)'
            js_matches = re.findall(js_pattern, pdf_content, re.DOTALL)
            
            for match in js_matches:
                js_content = match.decode('latin-1', errors='ignore')
                javascript_blocks.append(js_content)
        
        except Exception as e:
            self.logger.error(f"Error finding JavaScript: {e}")
        
        return javascript_blocks
    
    def find_embedded_files(self, pdf_content: bytes) -> List[Dict]:
        """
        Find embedded files in PDF
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            List of embedded file dictionaries
        """
        embedded_files = []
        
        try:
            # Look for file specification objects
            pattern = rb'/Filespec\s*<<(.*?)>>'
            matches = re.findall(pattern, pdf_content, re.DOTALL)
            
            for match in matches:
                fs_content = match.decode('latin-1', errors='ignore')
                
                # Extract filename
                filename_match = re.search(r'/F\s*\(([^)]*)\)', fs_content)
                filename = filename_match.group(1) if filename_match else 'unknown'
                
                embedded_files.append({
                    'filename': filename,
                    'content': fs_content[:100]  # Truncated
                })
        
        except Exception as e:
            self.logger.error(f"Error finding embedded files: {e}")
        
        return embedded_files
    
    def modify_pdf(self, pdf_content: bytes, modifications: Dict) -> Optional[bytes]:
        """
        Apply modifications to PDF
        
        Args:
            pdf_content: Original PDF content
            modifications: Dictionary of modifications to apply
            
        Returns:
            Modified PDF content or None if modification fails
        """
        try:
            modified = pdf_content
            
            # Add JavaScript
            if 'javascript' in modifications:
                modified = self._add_javascript(modified, modifications['javascript'])
            
            # Add embedded file
            if 'embedded_file' in modifications:
                modified = self._add_embedded_file(
                    modified, 
                    modifications['embedded_file'].get('content'),
                    modifications['embedded_file'].get('filename', 'attachment.bin')
                )
            
            # Modify metadata
            if 'metadata' in modifications:
                modified = self._modify_metadata(modified, modifications['metadata'])
            
            return modified
        
        except Exception as e:
            self.logger.error(f"Error modifying PDF: {e}")
            return None
    
    def _add_javascript(self, pdf_content: bytes, javascript: str) -> bytes:
        """
        Add JavaScript to PDF
        
        Args:
            pdf_content: Original PDF content
            javascript: JavaScript code to add
            
        Returns:
            Modified PDF content
        """
        try:
            # In production, would use proper PDF manipulation library
            # This is a simplified version
            
            eof_marker = b'%%EOF'
            eof_pos = pdf_content.rfind(eof_marker)
            
            if eof_pos == -1:
                return pdf_content
            
            # Get next object number
            obj_number = self._get_next_object_number(pdf_content)
            
            # Create JavaScript object
            js_obj = f"\n{obj_number} 0 obj\n<<\n/Type /Action\n/S /JavaScript\n/JS ({javascript})\n>>\nendobj\n"
            
            # Insert before EOF
            modified = pdf_content[:eof_pos] + js_obj.encode('latin-1') + pdf_content[eof_pos:]
            
            return modified
        
        except Exception as e:
            self.logger.error(f"Error adding JavaScript: {e}")
            return pdf_content
    
    def _add_embedded_file(self, pdf_content: bytes, file_content: bytes, filename: str) -> bytes:
        """
        Add embedded file to PDF
        
        Args:
            pdf_content: Original PDF content
            file_content: File content to embed
            filename: Filename for embedded file
            
        Returns:
            Modified PDF content
        """
        try:
            eof_marker = b'%%EOF'
            eof_pos = pdf_content.rfind(eof_marker)
            
            if eof_pos == -1:
                return pdf_content
            
            obj_number = self._get_next_object_number(pdf_content)
            
            # Create embedded file object
            file_obj = f"""
{obj_number} 0 obj
<<
/Type /Filespec
/F ({filename})
/EF << /F {obj_number + 1} 0 R >>
>>
endobj

{obj_number + 1} 0 obj
<<
/Type /EmbeddedFile
/Length {len(file_content)}
>>
stream
"""
            file_obj += file_content.decode('latin-1', errors='replace')
            file_obj += """
endstream
endobj
"""
            
            modified = pdf_content[:eof_pos] + file_obj.encode('latin-1') + pdf_content[eof_pos:]
            
            return modified
        
        except Exception as e:
            self.logger.error(f"Error adding embedded file: {e}")
            return pdf_content
    
    def _modify_metadata(self, pdf_content: bytes, metadata: Dict) -> bytes:
        """
        Modify PDF metadata
        
        Args:
            pdf_content: Original PDF content
            metadata: Metadata dictionary
            
        Returns:
            Modified PDF content
        """
        try:
            # Simplified metadata modification
            # In production, would use proper PDF manipulation
            
            modified = pdf_content
            
            for key, value in metadata.items():
                if isinstance(value, str):
                    # Replace metadata field
                    pattern = f'/{key}\\s*\\([^)]*\\)'.encode('ascii')
                    replacement = f'/{key}({value})'.encode('ascii')
                    modified = re.sub(pattern, replacement, modified)
            
            return modified
        
        except Exception as e:
            self.logger.error(f"Error modifying metadata: {e}")
            return pdf_content
    
    def _get_next_object_number(self, pdf_content: bytes) -> int:
        """
        Get next available object number
        
        Args:
            pdf_content: PDF content
            
        Returns:
            Next object number
        """
        try:
            obj_count = pdf_content.count(b' 0 obj')
            return obj_count + 1
        except Exception:
            return 1
    
    def save_pdf(self, pdf_content: bytes, output_path: str) -> bool:
        """
        Save PDF content to file
        
        Args:
            pdf_content: PDF content bytes
            output_path: Output file path
            
        Returns:
            True if save successful, False otherwise
        """
        try:
            with open(output_path, 'wb') as f:
                f.write(pdf_content)
            
            self.logger.info(f"Saved PDF to {output_path}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error saving PDF: {e}")
            return False
    
    def analyze_pdf_security(self, pdf_content: bytes) -> Dict:
        """
        Analyze PDF security features
        
        Args:
            pdf_content: PDF content bytes
            
        Returns:
            Dictionary with security analysis
        """
        security = {
            'encrypted': False,
            'has_password': False,
            'encryption_level': '',
            'permissions': {},
            'has_javascript': False,
            'has_forms': False,
            'has_annotations': False,
            'has_external_references': False
        }
        
        try:
            # Check encryption
            security['encrypted'] = b'/Encrypt' in pdf_content
            security['has_password'] = b'/Encrypt' in pdf_content
            
            # Check for JavaScript
            security['has_javascript'] = b'/JavaScript' in pdf_content
            
            # Check for forms
            security['has_forms'] = b'/AcroForm' in pdf_content
            
            # Check for annotations
            security['has_annotations'] = b'/Annot' in pdf_content
            
            # Check for external references
            security['has_external_references'] = b'/URI' in pdf_content or b'/Launch' in pdf_content
        
        except Exception as e:
            self.logger.error(f"Error analyzing security: {e}")
        
        return security