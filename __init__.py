"""
PDF Payload Injector Modules
Educational and Authorized Security Testing Tool
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__license__ = "Educational Use Only"

from .cve_database import CVEDatabase
from .exploit_db import ExploitDatabase
from .payload_embedder import PayloadEmbedder
from .pdf_parser import PDFParser
from .vuln_modules import VulnerabilityModules

__all__ = [
    'CVEDatabase',
    'ExploitDatabase', 
    'PayloadEmbedder',
    'PDFParser',
    'VulnerabilityModules'
]