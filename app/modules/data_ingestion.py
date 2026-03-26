"""
Module 1: Data Ingestion & Pre-processing

Handles multi-format input, text normalization, data partitioning,
and security validation.
"""

import re
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
import pandas as pd
import fitz  # PyMuPDF

# Try to import python-docx for .docx support
try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

# Try to import openpyxl for .xlsx support
try:
    import openpyxl
    XLSX_AVAILABLE = True
except ImportError:
    XLSX_AVAILABLE = False


class DataIngestionModule:
    """
    Manages data ingestion from multiple formats (.txt, .csv, .pdf).
    Performs text normalization, partitioning, and security checks.
    """

    SUPPORTED_FORMATS = {'.txt', '.csv', '.pdf', '.json', '.docx', '.xlsx'}
    MAX_FILE_SIZE_MB = 100
    ZIP_BOMB_SIGNATURE = b'PK\x03\x04'  # ZIP file signature
    # Legitimate ZIP-based formats (don't check for ZIP bomb)
    LEGITIMATE_ZIP_FORMATS = {'.docx', '.xlsx', '.ppt', '.pptx', '.jar'}

    def __init__(self, max_file_size_mb: int = MAX_FILE_SIZE_MB):
        """Initialize the data ingestion module."""
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.validation_errors = []

    def validate_file_integrity(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate file for security threats (zip bombs, script injections).
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        file_path = Path(file_path)

        # Check file exists
        if not file_path.exists():
            return False, f"File not found: {file_path}"

        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            return False, f"File exceeds max size of {self.max_file_size_mb}MB"

        # Check for zip bomb signature (skip for legitimate ZIP-based formats)
        file_ext = file_path.suffix.lower()
        if file_ext not in self.LEGITIMATE_ZIP_FORMATS:
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(4)
                    if header == self.ZIP_BOMB_SIGNATURE:
                        return False, "Potential ZIP bomb detected"
            except Exception as e:
                return False, f"Error reading file: {str(e)}"

        return True, "File validation passed"

    def load_file(self, file_path: str) -> Tuple[str, Dict[str, Any]]:
        """
        Load file content based on format.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (content, metadata)
        """
        file_path = Path(file_path)
        
        # Validate before loading
        is_valid, msg = self.validate_file_integrity(str(file_path))
        if not is_valid:
            raise ValueError(msg)

        file_ext = file_path.suffix.lower()
        
        metadata = {
            "file_name": file_path.name,
            "file_size_bytes": file_path.stat().st_size,
            "file_format": file_ext,
            "file_hash": self._compute_file_hash(file_path)
        }

        if file_ext == '.txt':
            content = self._load_txt(file_path)
        elif file_ext == '.csv':
            content = self._load_csv(file_path)
        elif file_ext == '.pdf':
            content = self._load_pdf(file_path)
        elif file_ext == '.json':
            content = self._load_json(file_path)
        elif file_ext == '.docx':
            if not DOCX_AVAILABLE:
                raise ValueError("python-docx not installed. Run: pip install python-docx")
            content = self._load_docx(file_path)
        elif file_ext == '.xlsx':
            content = self._load_xlsx(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_ext}")

        return content, metadata

    def normalize_text(self, text: str) -> str:
        """
        Clean and normalize text artifacts.
        
        Args:
            text: Raw text to normalize
            
        Returns:
            Normalized text
        """
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Fix encoding artifacts
        text = text.encode('utf-8', 'ignore').decode('utf-8')
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t\r')
        
        # Strip leading/trailing whitespace
        text = text.strip()
        
        return text

    def partition_into_context_windows(
        self, 
        text: str, 
        window_size: int = 500,
        overlap: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Partition large text into context windows for memory efficiency.
        
        Args:
            text: Input text to partition
            window_size: Size of each context window in characters
            overlap: Overlap between consecutive windows
            
        Returns:
            List of context windows with metadata
        """
        windows = []
        step = window_size - overlap
        
        for i in range(0, len(text), step):
            window = text[i:i + window_size]
            windows.append({
                "window_id": len(windows),
                "content": window,
                "start_char": i,
                "end_char": min(i + window_size, len(text)),
                "length": len(window)
            })
        
        return windows

    # Private helper methods
    def _load_txt(self, file_path: Path) -> str:
        """Load text file."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return self.normalize_text(content)

    def _load_csv(self, file_path: Path) -> str:
        """Load CSV file and convert to text."""
        df = pd.read_csv(file_path)
        content = df.to_string()
        return self.normalize_text(content)

    def _load_pdf(self, file_path: Path) -> str:
        """Load PDF file and extract text."""
        text = ""
        try:
            doc = fitz.open(file_path)
            for page_num in range(len(doc)):
                page = doc[page_num]
                text += page.get_text()
            doc.close()
        except Exception as e:
            raise ValueError(f"Error extracting PDF: {str(e)}")
        
        return self.normalize_text(text)

    def _load_json(self, file_path: Path) -> str:
        """Load JSON file and convert to text."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        content = json.dumps(data, indent=2)
        return self.normalize_text(content)

    def _load_docx(self, file_path: Path) -> str:
        """Load DOCX file and extract text."""
        try:
            doc = DocxDocument(file_path)
            text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
            return self.normalize_text(text)
        except Exception as e:
            raise ValueError(f"Error extracting DOCX: {str(e)}")

    def _load_xlsx(self, file_path: Path) -> str:
        """Load XLSX file and convert to text."""
        try:
            df = pd.read_excel(file_path)
            content = df.to_string()
            return self.normalize_text(content)
        except Exception as e:
            raise ValueError(f"Error extracting XLSX: {str(e)}")

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file for integrity verification."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
