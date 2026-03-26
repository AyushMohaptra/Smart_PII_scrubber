"""
Module 2: Detection & NER Engine

Hybrid identification combining statistical models and deterministic rules.
Performs deep linguistic analysis with confidence scoring.
"""

import re
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

# spaCy import with fallback for compatibility issues
try:
    import spacy
    SPACY_AVAILABLE = True
except Exception as e:
    print(f"Warning: spaCy not available ({e}). NLP features will be limited.")
    SPACY_AVAILABLE = False

try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except Exception:
    print("Warning: Presidio not available. Using Regex-only detection.")
    PRESIDIO_AVAILABLE = False


@dataclass
class Entity:
    """Represents a detected PII entity."""
    text: str
    entity_type: str
    start_char: int
    end_char: int
    confidence: float
    source: str  # 'statistical', 'rule-based'


class NEREngine:
    """
    Named Entity Recognition Engine combining:
    - Statistical models (spaCy/BERT) for names/places
    - Deterministic rules (Regex) for emails, phones, etc.
    """

    # Regex patterns for deterministic detection
    PATTERNS = {
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'PHONE': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
        'AADHAAR': r'\b[0-9]{4}\s?[0-9]{4}\s?[0-9]{4}\b',
        'SSN': r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b',
        'CREDIT_CARD': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        'IP_ADDRESS': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        # Full URL redaction helps when links contain personal handles/IDs.
        # Includes bare profile domains often seen in resumes.
        'URL': r'\b(?:(?:https?://|www\.)[^\s<>()"\']+|(?:linkedin\.com/in|github\.com|x\.com|twitter\.com|facebook\.com|instagram\.com|youtube\.com|medium\.com)/[^\s<>()"\']+)\b',
        # Generic long numeric IDs (useful when statistical NER is unavailable)
        'REGISTRATION_NUMBER': r'\b\d{8,12}\b',
    }

    CONTEXTUAL_PATTERNS = {
        # Capture only the ID part after label-like phrases.
        'REGISTRATION_NUMBER': r'\b(?:reg(?:istration)?\s*(?:no|number)?\s*[:#-]?\s*)([A-Za-z0-9-]{6,24})\b',
        # Label-based person extraction when NLP models are unavailable.
        'PERSON_NAME': r'\b(?:name|candidate|applicant|student|patient)\s*[:\-]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b',
        # Handle-only capture for common profile URLs.
        'PROFILE_HANDLE': r'\b(?:https?://)?(?:www\.)?(?:linkedin\.com/in|github\.com|x\.com|twitter\.com)/([A-Za-z0-9._-]{3,})\b',
    }

    NAME_BLOCKLIST = {
        "engineering", "science", "computer", "institute", "university",
        "technical", "technologies", "department", "project", "skills",
        "education", "certifications", "assistant", "health", "cloud"
    }

    # Keep Presidio focused on high-precision entities to avoid over-redaction.
    PRESIDIO_TARGET_ENTITIES = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "US_SSN",
        "CREDIT_CARD",
        "IP_ADDRESS",
    ]

    def __init__(self, confidence_threshold: float = 0.85, use_spacy: bool = True):
        """
        Initialize NER Engine.
        
        Args:
            confidence_threshold: Minimum confidence to flag entities (0-1)
            use_spacy: Whether to use spaCy for statistical detection
        """
        self.confidence_threshold = confidence_threshold
        self.detected_entities = []

        # Initialize spaCy model
        self.nlp = None
        if use_spacy and SPACY_AVAILABLE:
            try:
                self.nlp = spacy.load("en_core_web_sm")  # Use smaller model for compatibility
            except OSError:
                print("Warning: spaCy model not found. Run: python -m spacy download en_core_web_sm")
        elif use_spacy and not SPACY_AVAILABLE:
            print("Warning: spaCy not available. Statistical detection disabled.")

        # Initialize Presidio analyzer for hybrid detection
        self.analyzer = None
        if PRESIDIO_AVAILABLE:
            try:
                provider = NlpEngineProvider(
                    nlp_configuration={
                        "nlp_engine_name": "spacy",
                        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                    }
                )
                self.analyzer = AnalyzerEngine(
                    nlp_engine=provider.create_engine(),
                    supported_languages=["en"]
                )
            except Exception:
                # Keep Regex + spaCy-only fallback if Presidio init fails.
                self.analyzer = None
        else:
            print("Note: Using Regex-only detection (limited to patterns)")


    def detect_entities(self, text: str) -> List[Entity]:
        """
        Detect PII entities using hybrid approach.
        
        Args:
            text: Input text to analyze
            
        Returns:
            List of detected entities above confidence threshold
        """
        entities = []

        # 1. Rule-based detection (Regex)
        rule_entities = self._detect_with_rules(text)
        entities.extend(rule_entities)

        # 2. Statistical detection (spaCy + Presidio)
        if self.analyzer:
            statistical_entities = self._detect_with_analyzer(text)
            entities.extend(statistical_entities)

        # 3. POS-based contextual detection
        pos_entities = self._detect_with_pos_tagging(text)
        entities.extend(pos_entities)

        # Filter by confidence threshold and remove duplicates
        filtered = self._filter_and_deduplicate(entities)
        
        self.detected_entities = filtered
        return filtered

    def get_confidence_score(self, entity_text: str, entity_type: str) -> float:
        """
        Calculate confidence score for detected entity.
        
        Args:
            entity_text: The detected text
            entity_type: Type of entity
            
        Returns:
            Confidence score (0-1)
        """
        # Higher confidence for perfect matches
        if len(entity_text) > 3:
            base_score = 0.95
        else:
            base_score = 0.70

        return min(base_score, 1.0)

    # Private helper methods
    def _detect_with_rules(self, text: str) -> List[Entity]:
        """Detect entities using regex rules."""
        entities = []

        for entity_type, pattern in self.PATTERNS.items():
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                confidence = 0.98  # High confidence for rule matches
                if confidence >= self.confidence_threshold:
                    entities.append(Entity(
                        text=match.group(),
                        entity_type=entity_type,
                        start_char=match.start(),
                        end_char=match.end(),
                        confidence=confidence,
                        source='rule-based'
                    ))

        # Contextual rules with capture groups for better precision.
        for entity_type, pattern in self.CONTEXTUAL_PATTERNS.items():
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                if match.lastindex and match.lastindex >= 1:
                    start_char, end_char = match.span(1)
                    entity_text = match.group(1)
                else:
                    start_char, end_char = match.span()
                    entity_text = match.group()

                if entity_type == 'PERSON_NAME' and not self._looks_like_person_name(entity_text):
                    continue

                confidence = 0.99
                if confidence >= self.confidence_threshold:
                    entities.append(Entity(
                        text=entity_text,
                        entity_type=entity_type,
                        start_char=start_char,
                        end_char=end_char,
                        confidence=confidence,
                        source='rule-based'
                    ))

        # Heuristic: only capture a name-like token at the very beginning.
        start_match = re.match(r'^\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b', text)
        if start_match:
            candidate = start_match.group(1)
            if self._looks_like_person_name(candidate):
                entities.append(Entity(
                    text=candidate,
                    entity_type='PERSON_NAME',
                    start_char=start_match.start(1),
                    end_char=start_match.end(1),
                    confidence=0.90,
                    source='rule-based'
                ))

        return entities

    def _detect_with_analyzer(self, text: str) -> List[Entity]:
        """Detect entities using Presidio analyzer."""
        entities = []

        if not self.analyzer:
            return entities

        try:
            results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=self.PRESIDIO_TARGET_ENTITIES,
            )
            for result in results:
                if result.score >= self.confidence_threshold:
                    entity_text = text[result.start:result.end]
                    entities.append(Entity(
                        text=entity_text,
                        entity_type=result.entity_type,
                        start_char=result.start,
                        end_char=result.end,
                        confidence=result.score,
                        source='statistical'
                    ))
        except Exception:
            pass  # Fallback if analyzer fails

        return entities

    def _detect_with_pos_tagging(self, text: str) -> List[Entity]:
        """Detect entities using POS tagging for context awareness."""
        entities = []

        if not self.nlp:
            return entities

        doc = self.nlp(text)
        
        # Only keep PERSON from spaCy to reduce broad ORG/GPE false positives.
        for ent in doc.ents:
            if ent.label_ != "PERSON":
                continue

            confidence = 0.90
            
            if confidence >= self.confidence_threshold:
                entities.append(Entity(
                    text=ent.text,
                    entity_type=f"SPACY_{ent.label_}",
                    start_char=ent.start_char,
                    end_char=ent.end_char,
                    confidence=confidence,
                    source='statistical'
                ))

        return entities

    def _filter_and_deduplicate(self, entities: List[Entity]) -> List[Entity]:
        """Remove exact duplicate spans, keeping highest confidence."""
        unique = {}
        
        for entity in entities:
            key = (entity.start_char, entity.end_char)
            if key not in unique or entity.confidence > unique[key].confidence:
                unique[key] = entity

        return sorted(unique.values(), key=lambda e: e.start_char)

    def _looks_like_person_name(self, value: str) -> bool:
        """Basic regex-only heuristic to reduce false positives for person names."""
        tokens = [t.strip() for t in value.split() if t.strip()]
        if len(tokens) < 2 or len(tokens) > 4:
            return False

        for token in tokens:
            if not re.fullmatch(r"[A-Za-z][A-Za-z'-]*", token):
                return False
            if token.lower() in self.NAME_BLOCKLIST:
                return False

        return True
