"""
Module 4: Redaction & Export

Implements masking strategies, pseudonymization,
auditability, and compliance reporting.
"""

import json
import csv
from typing import Dict, List, Any, Tuple
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict

try:
    import fitz  # PyMuPDF
    FITZ_AVAILABLE = True
except Exception:
    FITZ_AVAILABLE = False

try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except Exception:
    DOCX_AVAILABLE = False


@dataclass
class RedactionConfig:
    """Configuration for redaction strategy."""
    mode: str  # 'full', 'placeholder', 'partial'
    pseudonymize: bool = False
    generate_audit_log: bool = True
    compliance_standards: List[str] = None


class RedactionEngine:
    """
    Implements redaction and anonymization with:
    - Multiple masking strategies
    - Pseudonymization with consistent mapping
    - Audit logging for compliance
    """

    def __init__(self, config: RedactionConfig = None):
        """
        Initialize redaction engine.
        
        Args:
            config: RedactionConfig with masking preferences
        """
        self.config = config or RedactionConfig(mode="full")
        self.pseudonym_map = {}  # Maps original values to pseudonyms
        self.audit_log = []
        self.redaction_count = 0

    def redact_entities(
        self,
        text: str,
        entities: List[Any],
        audit_context: Dict[str, Any] = None
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Redact detected entities from text.
        
        Args:
            text: Original text
            entities: List of detected entities to redact
            audit_context: Additional context for audit logging
            
        Returns:
            Tuple of (redacted_text, redaction_metadata)
        """
        # Sort entities by position (reverse to maintain char indices)
        sorted_entities = sorted(entities, key=lambda e: e.start_char, reverse=True)

        redacted_text = text
        redaction_metadata = []

        for entity in sorted_entities:
            replacement = self._get_replacement(entity)
            
            # Track redaction
            metadata = {
                "original_text": entity.text,
                "entity_type": entity.entity_type,
                "replacement": replacement,
                "position": {"start": entity.start_char, "end": entity.end_char},
                "confidence": entity.confidence,
                "timestamp": datetime.now().isoformat()
            }
            redaction_metadata.append(metadata)

            # Apply redaction
            redacted_text = (
                redacted_text[:entity.start_char] +
                replacement +
                redacted_text[entity.end_char:]
            )

            self.redaction_count += 1

            # Log to audit trail
            if self.config.generate_audit_log:
                self._log_redaction(entity, replacement, audit_context)

        return redacted_text, redaction_metadata

    def export_redacted(
        self,
        redacted_text: str,
        metadata: List[Dict[str, Any]],
        output_format: str = "txt",
        output_path: str = "output.txt"
    ) -> bool:
        """
        Export redacted content in specified format.
        
        Args:
            redacted_text: The redacted content
            metadata: Redaction metadata
            output_format: 'txt', 'json', 'csv'
            output_path: Path to save output
            
        Returns:
            Success status
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if output_format == "txt":
                return self._export_txt(redacted_text, output_path)
            elif output_format == "json":
                return self._export_json(redacted_text, metadata, output_path)
            elif output_format == "csv":
                return self._export_csv(metadata, output_path)
            else:
                raise ValueError(f"Unsupported format: {output_format}")
        except Exception as e:
            print(f"Export failed: {e}")
            return False

    def generate_audit_report(
        self,
        output_path: str = "audit_report.json"
    ) -> bool:
        """
        Generate audit report for compliance (GDPR/HIPAA/CCPA).
        
        Args:
            output_path: Path to save audit report
            
        Returns:
            Success status
        """
        report = {
            "report_timestamp": datetime.now().isoformat(),
            "redaction_stats": self._get_redaction_stats(),
            "audit_log": self.audit_log,
            "compliance_certifications": self.config.compliance_standards or []
        }

        try:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            return True
        except Exception as e:
            print(f"Audit report generation failed: {e}")
            return False

    def export_same_format(
        self,
        source_file: str,
        redaction_metadata: List[Dict[str, Any]],
        output_path: str,
    ) -> bool:
        """Export redacted content in the same file type as input for PDF/DOCX."""
        source_path = Path(source_file)
        ext = source_path.suffix.lower()

        try:
            if ext == ".pdf":
                return self._export_pdf_same_format(source_path, redaction_metadata, Path(output_path))
            if ext == ".docx":
                return self._export_docx_same_format(source_path, redaction_metadata, Path(output_path))

            return False
        except Exception as e:
            print(f"Same-format export failed: {e}")
            return False

    def create_pseudonym(self, entity_text: str, entity_type: str) -> str:
        """
        Create consistent pseudonym for entity.
        Ensures same original value always maps to same pseudonym.
        
        Args:
            entity_text: Original entity text
            entity_type: Type of entity
            
        Returns:
            Pseudonym string
        """
        key = (entity_text, entity_type)

        if key not in self.pseudonym_map:
            # Generate pseudonym based on type
            count = len([v for v in self.pseudonym_map.values() 
                        if v.startswith(f"USER_{entity_type[:3].upper()}")])
            self.pseudonym_map[key] = f"USER_{entity_type[:3].upper()}_{count + 1}"

        return self.pseudonym_map[key]

    # Private helper methods
    def _get_replacement(self, entity: Any) -> str:
        """Generate replacement text based on redaction mode."""
        if self.config.mode == "full":
            return self._black_mask(entity.text)
        elif self.config.mode == "placeholder":
            return f"<{entity.entity_type}>"
        elif self.config.mode == "partial":
            return self._partial_mask(entity.text)
        elif self.config.pseudonymize:
            return self.create_pseudonym(entity.text, entity.entity_type)
        else:
            return self._black_mask(entity.text)

    def _black_mask(self, text: str) -> str:
        """Mask content with black blocks while preserving approximate width."""
        if not text:
            return "████"
        return "█" * len(text)

    def _partial_mask(self, text: str) -> str:
        """Apply partial masking (e.g., 98XXX-XXXX for SSN)."""
        if len(text) <= 4:
            return "X" * len(text)
        
        # Show first 2, mask rest
        return text[:2] + "X" * (len(text) - 2)

    def _log_redaction(
        self,
        entity: Any,
        replacement: str,
        context: Dict[str, Any] = None
    ):
        """Log redaction action for audit trail."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "entity_type": entity.entity_type,
            "confidence": entity.confidence,
            "replacement_mode": self.config.mode,
            "context": context or {}
        }
        self.audit_log.append(log_entry)

    def _get_redaction_stats(self) -> Dict[str, Any]:
        """Generate redaction statistics."""
        return {
            "total_redacted": self.redaction_count,
            "audit_entries": len(self.audit_log),
            "pseudonym_mappings": len(self.pseudonym_map),
            "generation_time": datetime.now().isoformat()
        }

    def _export_txt(self, text: str, output_path: Path) -> bool:
        """Export as plain text."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"✓ Exported: {output_path}")
        return True

    def _export_json(
        self,
        text: str,
        metadata: List[Dict[str, Any]],
        output_path: Path
    ) -> bool:
        """Export as JSON with metadata."""
        export_data = {
            "redacted_text": text,
            "redaction_metadata": metadata,
            "pseudonym_map": {
                f"{k[0]}_{k[1]}": v for k, v in self.pseudonym_map.items()
            },
            "export_timestamp": datetime.now().isoformat()
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        print(f"✓ Exported: {output_path}")
        return True

    def _export_csv(self, metadata: List[Dict[str, Any]], output_path: Path) -> bool:
        """Export redaction metadata as CSV."""
        if not metadata:
            return False

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=metadata[0].keys())
            writer.writeheader()
            writer.writerows(metadata)
        print(f"✓ Exported: {output_path}")
        return True

    def _export_pdf_same_format(
        self,
        source_path: Path,
        redaction_metadata: List[Dict[str, Any]],
        output_path: Path,
    ) -> bool:
        """Apply visual text redactions directly to a PDF and save as PDF."""
        if not FITZ_AVAILABLE:
            print("PDF same-format export skipped (PyMuPDF unavailable)")
            return False

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = fitz.open(str(source_path))

        terms = {m.get("original_text", "") for m in redaction_metadata if m.get("original_text")}
        for page in doc:
            for term in terms:
                rects = page.search_for(term)
                for rect in rects:
                    page.add_redact_annot(rect, fill=(0, 0, 0))
            page.apply_redactions()

        doc.save(str(output_path))
        doc.close()
        print(f"✓ Exported: {output_path}")
        return True

    def _export_docx_same_format(
        self,
        source_path: Path,
        redaction_metadata: List[Dict[str, Any]],
        output_path: Path,
    ) -> bool:
        """Replace detected PII terms in DOCX paragraphs and save as DOCX."""
        if not DOCX_AVAILABLE:
            print("DOCX same-format export skipped (python-docx unavailable)")
            return False

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc = DocxDocument(str(source_path))
        terms = sorted(
            {m.get("original_text", "") for m in redaction_metadata if m.get("original_text")},
            key=len,
            reverse=True,
        )

        def docx_replacement(term: str, entity_type: str = "PII") -> str:
            if self.config.mode == "full":
                return self._black_mask(term)
            if self.config.mode == "placeholder":
                return f"<{entity_type}>"
            if self.config.mode == "partial":
                return self._partial_mask(term)
            return self._black_mask(term)

        replacement_by_term = {}
        for item in redaction_metadata:
            original = item.get("original_text", "")
            if not original:
                continue
            replacement_by_term[original] = docx_replacement(
                original,
                str(item.get("entity_type", "PII")),
            )

        for paragraph in doc.paragraphs:
            text = paragraph.text
            if not text:
                continue
            for term in terms:
                text = text.replace(term, replacement_by_term.get(term, self._black_mask(term)))
            paragraph.text = text

        doc.save(str(output_path))
        print(f"✓ Exported: {output_path}")
        return True
