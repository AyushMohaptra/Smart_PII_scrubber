# Smart PII Scrubber

Smart PII Scrubber is a local-first PII detection and redaction tool built with Python and Streamlit.
It can process text directly or uploaded files and generate redacted output with metadata and audit logs.

This project is useful for privacy-safe document handling, data anonymization workflows, and compliance-focused preprocessing (for example GDPR/HIPAA-style redaction pipelines).

Keywords
- pii redaction
- data anonymization
- streamlit app
- document privacy
- nlp entity detection
- gdpr hipaa compliance support

Features
- Interactive Streamlit UI for text and file workflows
- Hybrid detection approach (regex + NLP stack where available)
- Multiple redaction modes: full, placeholder, partial
- Same-format export support for PDF and DOCX redaction outputs
- Audit metadata generation for traceability
- Adaptive learner data store for contextual improvements

Typical Use Cases
- Redacting resumes before sharing publicly
- Masking sensitive fields in legal and financial documents
- Preparing datasets for demos, testing, or model training without exposing personal data

Supported Input Formats
- txt
- csv
- pdf
- json
- docx
- xlsx

Project Structure
- [app/gui_app.py](app/gui_app.py): Streamlit interface
- [app/pii_service.py](app/pii_service.py): end-to-end orchestration service
- [app/modules](app/modules): ingestion, detection, adaptive learner, redaction engines
- [app/process_my_file.py](app/process_my_file.py): CLI runner
- [data](data): runtime local database folder (git-kept as empty placeholder)
- [output](output): generated outputs (git-kept as empty placeholder)
- [requirements.txt](requirements.txt): Python dependencies

Quick Start (Recommended)
Prerequisite: Python 3.12

1. Create virtual environment
	py -3.12 -m venv .venv312

2. Install dependencies
	.venv312\\Scripts\\python.exe -m pip install -r requirements.txt

3. Install spaCy English model
	.venv312\\Scripts\\python.exe -m spacy download en_core_web_sm

4. Run Streamlit UI
	.venv312\\Scripts\\python.exe -m streamlit run app/gui_app.py

5. Open in browser
	http://localhost:8501

CLI Usage
1. Edit input path in [app/process_my_file.py](app/process_my_file.py)
2. Run
	.venv312\\Scripts\\python.exe -m app.process_my_file

Outputs
Generated files are written to [output](output), typically including:
- _redacted.txt
- _metadata.json
- _audit.json
- _redacted.pdf or _redacted.docx (when same-format export is available)

Troubleshooting
- If spaCy/Presidio warnings appear, confirm Python 3.12 is being used.
- If port 8501 is busy, stop previous process or run with a different port.

License
MIT. See [LICENSE](LICENSE).
