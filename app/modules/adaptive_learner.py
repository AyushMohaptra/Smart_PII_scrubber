"""
Module 3: Adaptive Concept Layer

Implements contextual proximity boosting, local knowledge store,
feedback integration, and self-evolving logic.
"""

import json
import sqlite3
from typing import Dict, List, Any, Tuple
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class FeedbackRecord:
    """Stores feedback for adaptive learning."""
    timestamp: str
    text: str
    entity: str
    entity_type: str
    feedback_type: str  # 'missed', 'over_scrubbed', 'correct'
    domain: str  # 'medical', 'legal', 'finance', 'general'
    user_id: str


class AdaptiveLearner:
    """
    Implements adaptive concept learning through:
    - Contextual proximity boosting
    - Local knowledge store (JSON/SQLite)
    - Feedback loops for continuous improvement
    """

    # Anchor words that boost nearby numbers as PII
    ANCHOR_WORDS = {
        'salary': ['amount', 'income', 'wage', 'compensation', 'payment'],
        'patient': ['patient', 'medical', 'diagnosis', 'treatment', 'hospital'],
        'account': ['account', 'account_number', 'balance', 'transaction'],
        'identification': ['id', 'passport', 'driver', 'license', 'ssn'],
    }

    def __init__(self, db_path: str = "knowledge_store.db", use_json: bool = False):
        """
        Initialize adaptive learner.
        
        Args:
            db_path: Path to SQLite database for knowledge store
            use_json: Whether to use JSON storage instead of SQLite
        """
        self.use_json = use_json
        self.db_path = db_path
        self.json_path = Path(db_path.replace('.db', '.json'))

        if use_json:
            self._init_json_store()
        else:
            self._init_sqlite_store()

    def detect_contextual_pii(self, text: str, entities: List[Any]) -> List[Dict[str, Any]]:
        """
        Boost detection of PII through contextual proximity.
        
        Args:
            text: Input text
            entities: Pre-detected entities
            
        Returns:
            Enhanced entity list with contextual boosting applied
        """
        enhanced_entities = []
        words = text.lower().split()

        for entity in entities:
            context_boost = 0.0

            # Check for anchor words near entity
            for anchor_category, anchor_words in self.ANCHOR_WORDS.items():
                for word in anchor_words:
                    if word in text[max(0, entity.start_char - 100):entity.end_char + 100].lower():
                        context_boost += 0.05
                        break

            # Apply boost (max 1.0)
            new_confidence = min(entity.confidence + context_boost, 1.0)
            entity.confidence = new_confidence
            enhanced_entities.append(entity)

        return enhanced_entities

    def check_local_knowledge_base(self, entity_text: str) -> Dict[str, Any]:
        """
        Check if entity exists in local knowledge store.
        
        Args:
            entity_text: Entity to look up
            
        Returns:
            Knowledge record if found, empty dict otherwise
        """
        if self.use_json:
            return self._json_lookup(entity_text)
        else:
            return self._sql_lookup(entity_text)

    def add_feedback(
        self,
        text: str,
        entity: str,
        entity_type: str,
        feedback_type: str,
        domain: str = "general",
        user_id: str = "system"
    ) -> bool:
        """
        Record user feedback for adaptive learning.
        
        Args:
            text: Original text context
            entity: Detected entity text
            entity_type: Type of entity
            feedback_type: 'missed', 'over_scrubbed', or 'correct'
            domain: Industry domain
            user_id: User providing feedback
            
        Returns:
            Success status
        """
        feedback = FeedbackRecord(
            timestamp=datetime.now().isoformat(),
            text=text,
            entity=entity,
            entity_type=entity_type,
            feedback_type=feedback_type,
            domain=domain,
            user_id=user_id
        )

        if self.use_json:
            return self._json_add_feedback(feedback)
        else:
            return self._sql_add_feedback(feedback)

    def get_domain_specific_patterns(self, domain: str) -> Dict[str, Any]:
        """
        Retrieve domain-specific PII patterns (medical, legal, finance).
        
        Args:
            domain: Domain type ('medical', 'legal', 'finance', 'general')
            
        Returns:
            Dictionary of patterns and rules for domain
        """
        if self.use_json:
            return self._json_get_domain_patterns(domain)
        else:
            return self._sql_get_domain_patterns(domain)

    def get_feedback_stats(self) -> Dict[str, Any]:
        """Get statistics on feedback for analysis."""
        if self.use_json:
            return self._json_get_stats()
        else:
            return self._sql_get_stats()

    # Private JSON storage methods
    def _init_json_store(self):
        """Initialize JSON knowledge store."""
        if not self.json_path.exists():
            store = {
                "knowledge_base": {},
                "feedback": [],
                "domain_patterns": {
                    "medical": {},
                    "legal": {},
                    "finance": {},
                    "general": {}
                }
            }
            with open(self.json_path, 'w') as f:
                json.dump(store, f, indent=2)

    def _json_lookup(self, entity_text: str) -> Dict[str, Any]:
        """Look up entity in JSON store."""
        with open(self.json_path, 'r') as f:
            store = json.load(f)
        return store["knowledge_base"].get(entity_text, {})

    def _json_add_feedback(self, feedback: FeedbackRecord) -> bool:
        """Add feedback to JSON store."""
        with open(self.json_path, 'r') as f:
            store = json.load(f)
        store["feedback"].append(asdict(feedback))
        with open(self.json_path, 'w') as f:
            json.dump(store, f, indent=2)
        return True

    def _json_get_domain_patterns(self, domain: str) -> Dict[str, Any]:
        """Get domain patterns from JSON store."""
        with open(self.json_path, 'r') as f:
            store = json.load(f)
        return store["domain_patterns"].get(domain, {})

    def _json_get_stats(self) -> Dict[str, Any]:
        """Get feedback statistics from JSON store."""
        with open(self.json_path, 'r') as f:
            store = json.load(f)
        
        feedbacks = store["feedback"]
        return {
            "total_feedback": len(feedbacks),
            "by_type": {
                "missed": len([f for f in feedbacks if f["feedback_type"] == "missed"]),
                "over_scrubbed": len([f for f in feedbacks if f["feedback_type"] == "over_scrubbed"]),
                "correct": len([f for f in feedbacks if f["feedback_type"] == "correct"]),
            },
            "by_domain": {}
        }

    # Private SQLite storage methods
    def _init_sqlite_store(self):
        """Initialize SQLite knowledge store."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id INTEGER PRIMARY KEY,
                entity_text TEXT UNIQUE,
                entity_type TEXT,
                frequency INTEGER DEFAULT 1,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                text TEXT,
                entity TEXT,
                entity_type TEXT,
                feedback_type TEXT,
                domain TEXT,
                user_id TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_patterns (
                id INTEGER PRIMARY KEY,
                domain TEXT,
                pattern_name TEXT,
                pattern_regex TEXT,
                confidence_boost REAL
            )
        """)

        conn.commit()
        conn.close()

    def _sql_lookup(self, entity_text: str) -> Dict[str, Any]:
        """Look up entity in SQLite store."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM knowledge_base WHERE entity_text = ?",
            (entity_text,)
        )
        row = cursor.fetchone()
        conn.close()
        return {"entity": row[1], "type": row[2], "frequency": row[3]} if row else {}

    def _sql_add_feedback(self, feedback: FeedbackRecord) -> bool:
        """Add feedback to SQLite store."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO feedback 
            (timestamp, text, entity, entity_type, feedback_type, domain, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            feedback.timestamp, feedback.text, feedback.entity,
            feedback.entity_type, feedback.feedback_type, feedback.domain, feedback.user_id
        ))
        conn.commit()
        conn.close()
        return True

    def _sql_get_domain_patterns(self, domain: str) -> Dict[str, Any]:
        """Get domain patterns from SQLite store."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM domain_patterns WHERE domain = ?",
            (domain,)
        )
        rows = cursor.fetchall()
        conn.close()
        return {row[2]: {"regex": row[3], "boost": row[4]} for row in rows} if rows else {}

    def _sql_get_stats(self) -> Dict[str, Any]:
        """Get feedback statistics from SQLite store."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM feedback")
        total = cursor.fetchone()[0]

        cursor.execute(
            "SELECT feedback_type, COUNT(*) FROM feedback GROUP BY feedback_type"
        )
        by_type = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()
        return {
            "total_feedback": total,
            "by_type": by_type
        }
