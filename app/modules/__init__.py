"""Smart PII Scrubber - Core Modules"""

from .data_ingestion import DataIngestionModule

# Handle NER engine import with graceful fallback
try:
    from .ner_engine import NEREngine
except Exception as e:
    print(f"Note: NER engine import failed ({e}). Will use regex-only detection.")
    # Create minimal NER engine for fallback
    class NEREngine:
        def __init__(self, confidence_threshold=0.85, use_spacy=False):
            self.confidence_threshold = confidence_threshold
            self.nlp = None
            self.analyzer = None
            self.detected_entities = []
            print("Operating in regex-only mode (limited detection)")
        
        def detect_entities(self, text):
            # Fallback: regex-only detection
            import re
            entities = []
            patterns = {
                'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'PHONE': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            }
            for entity_type, pattern in patterns.items():
                for match in re.finditer(pattern, text):
                    from dataclasses import dataclass
                    @dataclass
                    class Entity:
                        text: str
                        entity_type: str
                        start_char: int
                        end_char: int
                        confidence: float
                        source: str
                    
                    entities.append(Entity(
                        text=match.group(),
                        entity_type=entity_type,
                        start_char=match.start(),
                        end_char=match.end(),
                        confidence=0.95,
                        source='rule-based'
                    ))
            return entities

from .adaptive_learner import AdaptiveLearner
from .redaction_engine import RedactionEngine

__all__ = [
    "DataIngestionModule",
    "NEREngine",
    "AdaptiveLearner",
    "RedactionEngine"
]
