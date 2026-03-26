"""
Smart PII Scrubber — Streamlit GUI
Paste text or upload a file to detect and redact PII.
Sidebar shows live library / module health status.
"""

import html as _html
import json
from pathlib import Path
import tempfile
import importlib
import sys

import streamlit as st

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Smart PII Scrubber",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── custom CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
        /* text display boxes */
        .pii-box {
            background: #0f1117;
            border: 1px solid #2d2d3a;
            border-radius: 8px;
            padding: 1rem;
            font-family: "Courier New", monospace;
            font-size: 0.88em;
            line-height: 1.65;
            white-space: pre-wrap;
            word-break: break-word;
            min-height: 120px;
        }
        /* colour legend chips */
        .chip {
            display: inline-block;
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 0.75em;
            font-weight: 700;
            margin: 2px 3px;
            color: #000;
        }
        /* metric override */
        div[data-testid="metric-container"] {
            background: #1a1a2e;
            border: 1px solid #2d2d3a;
            border-radius: 8px;
            padding: 0.6rem 1rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── entity colour palette ─────────────────────────────────────────────────────
ENTITY_COLORS: dict[str, str] = {
    "EMAIL": "#fbbf24",
    "PHONE": "#60a5fa",
    "PERSON": "#f87171",
    "SSN": "#c084fc",
    "CREDIT_CARD": "#34d399",
    "IP_ADDRESS": "#fb923c",
    "URL": "#a78bfa",
    "AADHAAR": "#f472b6",
    "LOCATION": "#4ade80",
    "ORG": "#22d3ee",
    "DATE": "#86efac",
    "REGISTRATION_NUMBER": "#e879f9",
    "DEFAULT": "#94a3b8",
}


def _color(entity_type: str) -> str:
    return ENTITY_COLORS.get(entity_type, ENTITY_COLORS["DEFAULT"])


def _highlight_html(text: str, entities: list) -> str:
    """Return HTML with coloured highlight spans over detected entities."""
    out, prev = [], 0
    for e in sorted(entities, key=lambda x: x.start_char):
        s, end = e.start_char, e.end_char
        if s < prev:
            continue
        out.append(_html.escape(text[prev:s]))
        bg = _color(e.entity_type)
        label = _html.escape(e.entity_type)
        span_txt = _html.escape(text[s:end])
        out.append(
            f'<mark style="background:{bg};color:#000;border-radius:3px;'
            f'padding:1px 5px;font-weight:700" title="{label} — confidence {e.confidence:.0%}">'
            f'{span_txt}'
            f'<sup style="font-size:0.6em;margin-left:2px">{label}</sup>'
            f"</mark>"
        )
        prev = end
    out.append(_html.escape(text[prev:]))
    return "".join(out)


# ── library / module health checks (run once, cached) ────────────────────────
@st.cache_resource(show_spinner=False)
def _check_libraries() -> dict[str, tuple[str, str]]:
    """
    Returns dict of  name -> (status, detail)
    status is one of: 'ok', 'warn', 'fail'
    """
    results: dict[str, tuple[str, str]] = {}

    # spaCy core
    if sys.version_info >= (3, 14):
        results["spaCy"] = (
            "warn",
            "Skipped on Python 3.14+ (known pydantic.v1 issue). Use a Python 3.12 environment.",
        )
    else:
        try:
            import spacy  # noqa: F401
            try:
                spacy.load("en_core_web_sm")
                results["spaCy + model"] = ("ok", f"v{spacy.__version__} · en_core_web_sm loaded")
            except OSError:
                results["spaCy (no model)"] = (
                    "warn",
                    f"v{spacy.__version__} · en_core_web_sm missing — run: "
                    "python -m spacy download en_core_web_sm",
                )
        except Exception as exc:
            results["spaCy"] = ("warn", f"Unavailable: {str(exc)[:80]}")

    # Presidio
    try:
        from presidio_analyzer import AnalyzerEngine  # noqa: F401
        results["Presidio Analyzer"] = ("ok", "presidio-analyzer imported ✓")
    except Exception as exc:
        results["Presidio Analyzer"] = (
            "warn",
            f"{str(exc)[:80]} | For Presidio mode use Python 3.12.",
        )

    try:
        from presidio_anonymizer import AnonymizerEngine  # noqa: F401
        results["Presidio Anonymizer"] = ("ok", "presidio-anonymizer imported ✓")
    except Exception as exc:
        results["Presidio Anonymizer"] = (
            "warn",
            f"{str(exc)[:80]} | For Presidio mode use Python 3.12.",
        )

    # Internal modules
    _mods = {
        "Module 1 · Data Ingestion": "app.modules.data_ingestion",
        "Module 2 · NER Engine": "app.modules.ner_engine",
        "Module 3 · Adaptive Learner": "app.modules.adaptive_learner",
        "Module 4 · Redaction Engine": "app.modules.redaction_engine",
    }
    for display, mod_path in _mods.items():
        try:
            importlib.import_module(mod_path)
            results[display] = ("ok", f"{mod_path} imported ✓")
        except Exception as exc:
            results[display] = ("fail", str(exc)[:80])

    # PII service entry point
    try:
        importlib.import_module("app.pii_service")
        results["PII Service"] = ("ok", "app.pii_service ready ✓")
    except Exception as exc:
        results["PII Service"] = ("fail", str(exc)[:80])

    return results


@st.cache_resource(show_spinner=False)
def _load_service():
    try:
        from app.pii_service import process_text, process_file
        return process_text, process_file, None
    except Exception as exc:
        return None, None, str(exc)


# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔒 Smart PII Scrubber")
    st.caption("Adaptive redaction engine")
    st.divider()

    st.markdown("### ⚙️ Settings")
    mode = st.selectbox(
        "Redaction mode",
        ["full", "placeholder", "partial"],
        index=0,
        help=(
            "**full** — replaces with ██████  \n"
            "**placeholder** — replaces with [ENTITY_TYPE]  \n"
            "**partial** — masks middle chars (J*** D***)"
        ),
    )
    out_dir = st.text_input("Output folder", value="output")

    st.divider()
    st.markdown("### 🔬 Library & Module Status")

    with st.spinner("Checking dependencies…"):
        lib_status = _check_libraries()

    _icon_map = {"ok": "✅", "warn": "⚠️", "fail": "❌"}
    _color_map = {"ok": "#22c55e", "warn": "#f59e0b", "fail": "#ef4444"}

    for lib_name, (status, detail) in lib_status.items():
        icon = _icon_map[status]
        clr = _color_map[status]
        st.markdown(
            f"<div style='margin-bottom:6px'>"
            f"<span style='font-size:1em'>{icon}</span> "
            f"<b style='font-size:0.85em'>{lib_name}</b><br>"
            f"<span style='font-size:0.72em;color:{clr};padding-left:20px'>{detail}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

    ok_count = sum(1 for s, _ in lib_status.values() if s == "ok")
    total = len(lib_status)
    overall_color = "#22c55e" if ok_count == total else ("#f59e0b" if ok_count >= total // 2 else "#ef4444")
    st.markdown(
        f"<div style='margin-top:10px;padding:6px 10px;background:{overall_color}22;"
        f"border-left:3px solid {overall_color};border-radius:4px;font-size:0.82em'>"
        f"<b>{ok_count}/{total}</b> components healthy</div>",
        unsafe_allow_html=True,
    )

    st.divider()
    st.markdown("### 🎨 Entity Colour Legend")
    chips = "".join(
        f'<span class="chip" style="background:{c}">{t}</span>'
        for t, c in ENTITY_COLORS.items()
        if t != "DEFAULT"
    )
    st.markdown(f"<div style='line-height:2.2'>{chips}</div>", unsafe_allow_html=True)


# ── main content ──────────────────────────────────────────────────────────────
st.markdown("# 🔒 Smart PII Scrubber")
st.caption("Detect and redact Personally Identifiable Information — paste text or upload a file")

tab_text, tab_file = st.tabs(["✏️  Text Input", "📁  File Upload"])

# ═══════════════════════════════════════════════════════════════════
# TAB 1 — TEXT INPUT
# ═══════════════════════════════════════════════════════════════════
_SAMPLE = (
    "Hello, my name is John Smith. My email is john.smith@example.com "
    "and my phone is +1-555-867-5309. My SSN is 123-45-6789. "
    "I live in New York and work at Acme Corp. "
    "My credit card number is 4111111111111111 and my IP is 192.168.1.100."
)

with tab_text:
    raw_text = st.text_area(
        "Paste text containing PII",
        value=_SAMPLE,
        height=160,
        placeholder="Paste any text here…",
        label_visibility="visible",
    )

    run_text = st.button("🔍  Detect & Redact", type="primary", key="btn_text")

    if run_text:
        if not raw_text.strip():
            st.warning("Please enter some text first.")
        else:
            process_text_fn, _, svc_err = _load_service()
            if svc_err:
                st.error(f"Service could not load: {svc_err}")
            else:
                with st.spinner("Scanning for PII…"):
                    try:
                        result = process_text_fn(raw_text, redaction_mode=mode)
                        err = None
                    except Exception as exc:
                        result = None
                        err = str(exc)

                if err:
                    st.error(f"Processing error: {err}")
                elif result:
                    # ── metrics row ──
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Entities detected", result["entities_found"])
                    m2.metric("Redactions applied", result["redactions_applied"])
                    m3.metric("Unique entity types", len(result["by_type"]))
                    m4.metric("Characters processed", len(raw_text))

                    st.divider()

                    # ── side-by-side view ──
                    col_orig, col_redacted = st.columns(2, gap="medium")

                    with col_orig:
                        st.markdown("#### 🔍 Original  *(PII highlighted)*")
                        highlighted = _highlight_html(raw_text, result["entities"])
                        st.markdown(
                            f'<div class="pii-box">{highlighted}</div>',
                            unsafe_allow_html=True,
                        )

                    with col_redacted:
                        st.markdown("#### 🔒 Redacted text")
                        safe_redacted = _html.escape(result["redacted_text"])
                        st.markdown(
                            f'<div class="pii-box">{safe_redacted}</div>',
                            unsafe_allow_html=True,
                        )

                    st.divider()

                    # ── entity breakdown ──
                    if result["by_type"]:
                        st.markdown("#### 📊 Entity breakdown")
                        n = min(len(result["by_type"]), 6)
                        cols = st.columns(n)
                        for i, (etype, cnt) in enumerate(result["by_type"].items()):
                            bg = _color(etype)
                            cols[i % n].markdown(
                                f'<div style="background:{bg};color:#000;border-radius:8px;'
                                f'padding:10px;text-align:center">'
                                f'<div style="font-size:1.6em;font-weight:800">{cnt}</div>'
                                f'<div style="font-size:0.78em;font-weight:600">{etype}</div>'
                                f"</div>",
                                unsafe_allow_html=True,
                            )

                    with st.expander("📋 Full JSON result"):
                        display = {k: v for k, v in result.items() if k != "entities"}
                        st.json(display)

# ═══════════════════════════════════════════════════════════════════
# TAB 2 — FILE UPLOAD
# ═══════════════════════════════════════════════════════════════════
with tab_file:
    uploaded = st.file_uploader(
        "Upload a file",
        type=["txt", "csv", "pdf", "json", "docx", "xlsx"],
        accept_multiple_files=False,
        help="Supported: TXT · CSV · PDF · JSON · DOCX · XLSX",
    )

    if uploaded is not None:
        st.info(f"Loaded **{uploaded.name}** — {uploaded.size:,} bytes")

        suffix = Path(uploaded.name).suffix.lower()
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        if st.button("🔍  Run PII Scrub", type="primary", key="btn_file"):
            _, process_file_fn, svc_err = _load_service()
            if svc_err:
                st.error(f"Service could not load: {svc_err}")
            else:
                with st.spinner("Processing file…"):
                    try:
                        result = process_file_fn(
                            tmp_path,
                            output_dir=out_dir,
                            redaction_mode=mode,
                            original_filename=uploaded.name,
                        )
                        err = None
                    except Exception as exc:
                        result = None
                        err = str(exc)

                if err:
                    st.error(f"Processing failed: {err}")
                elif result:
                    st.success("✅ Done!")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Entities found", result["entities_found"])
                    m2.metric("Redactions applied", result["redactions_applied"])
                    m3.metric("File size (bytes)", result["file_size"])

                    st.divider()

                    if result["by_type"]:
                        st.markdown("#### 📊 Entity distribution")
                        st.json(result["by_type"])

                    st.markdown("#### ⬇️ Download outputs")
                    _mime_map = {
                        ".json": "application/json",
                        ".txt": "text/plain",
                        ".pdf": "application/pdf",
                        ".docx": (
                            "application/vnd.openxmlformats-officedocument"
                            ".wordprocessingml.document"
                        ),
                    }
                    for p in result["output_files"]:
                        out_path = Path(p)
                        if out_path.exists():
                            mime = _mime_map.get(
                                out_path.suffix.lower(), "application/octet-stream"
                            )
                            with open(out_path, "rb") as f:
                                st.download_button(
                                    label=f"⬇️  {out_path.name}",
                                    data=f.read(),
                                    file_name=out_path.name,
                                    mime=mime,
                                    key=f"dl_{out_path.name}",
                                )

                    with st.expander("📋 Run summary"):
                        st.json(result)
    else:
        st.info("Upload a file (TXT, CSV, PDF, JSON, DOCX, XLSX) to get started.")
