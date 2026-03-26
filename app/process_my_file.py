"""Single-file CLI runner for Smart PII Scrubber."""

from app.pii_service import process_file

# ==================== EDIT THIS ====================
YOUR_FILE = r"sample_input.pdf"
# ====================================================
def main():
    print("=" * 70)
    print("Smart PII Scrubber - Process File")
    print("=" * 70)

    try:
        result = process_file(YOUR_FILE, output_dir="output", redaction_mode="full")

        print("\n" + "=" * 70)
        print("✅ PROCESSING COMPLETE")
        print("=" * 70)
        print(f"Status: {result['status'].upper()}")
        print(f"File size: {result['file_size']} bytes")
        print(f"Entities found: {result['entities_found']}")
        print(f"By type: {result['by_type']}")
        print(f"Redactions applied: {result['redactions_applied']}")
        print("Output files:")
        for path in result["output_files"]:
            print(f"- {path}")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")


if __name__ == "__main__":
    main()
