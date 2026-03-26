from pathlib import Path
from typing import Dict, List, Optional

from app.modules.adaptive_learner import AdaptiveLearner
from app.modules.data_ingestion import DataIngestionModule
from app.modules.ner_engine import NEREngine
from app.modules.redaction_engine import RedactionConfig, RedactionEngine


def _entity_distribution(entities):
    distribution = {}
    for e in entities:
        distribution[e.entity_type] = distribution.get(e.entity_type, 0) + 1
    return distribution


def _dedupe_entities_global(entities):
    dedup = {}
    for e in entities:
        key = (e.start_char, e.end_char, e.entity_type, e.text)
        if key not in dedup or e.confidence > dedup[key].confidence:
            dedup[key] = e

    items = sorted(dedup.values(), key=lambda x: (x.start_char, x.end_char))
    cleaned = []
    for e in items:
        if e.entity_type == "PROFILE_HANDLE":
            inside_url = any(
                u.entity_type == "URL" and u.start_char <= e.start_char and u.end_char >= e.end_char
                for u in items
            )
            if inside_url:
                continue
        cleaned.append(e)

    return cleaned


def process_text(text: str, redaction_mode: str = "full") -> Dict:
    """Process a raw text string and return redaction results (no file I/O)."""
    ingest = DataIngestionModule()
    ner = NEREngine(confidence_threshold=0.93, use_spacy=True)
    learner = AdaptiveLearner(db_path="data/knowledge_store.db", use_json=False)
    redaction = RedactionEngine(
        RedactionConfig(
            mode=redaction_mode,
            pseudonymize=False,
            generate_audit_log=True,
            compliance_standards=["gdpr", "hipaa", "ccpa", "dpdp"],
        )
    )

    windows = ingest.partition_into_context_windows(text)

    entities = []
    for w in windows:
        found = ner.detect_entities(w["content"])
        for e in found:
            e.start_char += w["start_char"]
            e.end_char += w["start_char"]
        entities.extend(found)

    entities = _dedupe_entities_global(entities)
    entities = learner.detect_contextual_pii(text, entities)

    redacted_text, redaction_metadata = redaction.redact_entities(
        text,
        entities,
        audit_context={"source": "text_input"},
    )

    return {
        "entities_found": len(entities),
        "redactions_applied": len(redaction_metadata),
        "by_type": _entity_distribution(entities),
        "entities": entities,
        "redacted_text": redacted_text,
    }


def process_file(
    file_path: str,
    output_dir: str = "output",
    redaction_mode: str = "full",
    original_filename: Optional[str] = None,
) -> Dict:
    ingest = DataIngestionModule()
    ner = NEREngine(confidence_threshold=0.93, use_spacy=True)
    learner = AdaptiveLearner(db_path="data/knowledge_store.db", use_json=False)
    redaction = RedactionEngine(
        RedactionConfig(
            mode=redaction_mode,
            pseudonymize=False,
            generate_audit_log=True,
            compliance_standards=["gdpr", "hipaa", "ccpa", "dpdp"],
        )
    )

    source = Path(file_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    text, metadata = ingest.load_file(str(source))
    windows = ingest.partition_into_context_windows(text)

    entities = []
    for w in windows:
        found = ner.detect_entities(w["content"])
        for e in found:
            e.start_char += w["start_char"]
            e.end_char += w["start_char"]
        entities.extend(found)

    entities = _dedupe_entities_global(entities)
    entities = learner.detect_contextual_pii(text, entities)

    redacted_text, redaction_metadata = redaction.redact_entities(
        text,
        entities,
        audit_context={"file": metadata["file_name"]},
    )

    output_stem = source.stem
    if original_filename:
        output_stem = Path(original_filename).stem

    base = out_dir / output_stem
    txt_out = str(base) + "_redacted.txt"
    meta_out = str(base) + "_metadata.json"
    audit_out = str(base) + "_audit.json"

    redaction.export_redacted(redacted_text, redaction_metadata, "txt", txt_out)
    redaction.export_redacted(redacted_text, redaction_metadata, "json", meta_out)
    redaction.generate_audit_report(audit_out)

    same_out: Optional[str] = None
    if source.suffix.lower() in {".pdf", ".docx"}:
        same_out = str(base) + "_redacted" + source.suffix.lower()
        redaction.export_same_format(str(source), redaction_metadata, same_out)

    output_files: List[str] = [txt_out, meta_out, audit_out]
    if same_out:
        output_files.append(same_out)

    return {
        "status": "completed",
        "file": str(source),
        "file_size": metadata["file_size_bytes"],
        "entities_found": len(entities),
        "redactions_applied": len(redaction_metadata),
        "by_type": _entity_distribution(entities),
        "output_files": output_files,
    }
