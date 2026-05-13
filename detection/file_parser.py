"""
File text extraction for multiple formats: TXT, LOG, CSV, PDF, DOCX.
"""
import os


def extract_text(file_path):
    """
    Extract readable text content from a file.

    Supports: .txt, .log, .csv, .pdf, .docx
    Returns empty string for unsupported formats.
    """
    ext = os.path.splitext(file_path)[1].lower()

    try:
        if ext in (".txt", ".log"):
            return _read_text_file(file_path)

        elif ext == ".csv":
            return _read_csv_file(file_path)

        elif ext == ".pdf":
            return _read_pdf_file(file_path)

        elif ext == ".docx":
            return _read_docx_file(file_path)

        else:
            return ""

    except Exception as e:
        print(f"[file_parser] Error reading {file_path}: {e}")
        return ""


def _read_text_file(file_path):
    """Read plain text or log files."""
    encodings = ["utf-8", "utf-16", "latin-1", "ascii"]
    for enc in encodings:
        try:
            with open(file_path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    return ""


def _read_csv_file(file_path):
    """Read CSV and concatenate all text cells."""
    import pandas as pd
    try:
        df = pd.read_csv(file_path, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(file_path, encoding="latin-1")

    # Concatenate all string columns into one big text block
    text_parts = []
    for col in df.columns:
        if df[col].dtype == object:
            text_parts.extend(df[col].dropna().astype(str).tolist())
    return " ".join(text_parts)


def _read_pdf_file(file_path):
    """Extract text from PDF using PyPDF2."""
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        print("[file_parser] PyPDF2 not installed. Skipping PDF.")
        return ""

    reader = PdfReader(file_path)
    text_parts = []
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            text_parts.append(page_text)
    return " ".join(text_parts)


def _read_docx_file(file_path):
    """Extract text from DOCX using python-docx."""
    try:
        from docx import Document
    except ImportError:
        print("[file_parser] python-docx not installed. Skipping DOCX.")
        return ""

    doc = Document(file_path)
    return " ".join(para.text for para in doc.paragraphs if para.text.strip())


# Supported file extensions
SUPPORTED_EXTENSIONS = {".txt", ".log", ".csv", ".pdf", ".docx"}


def is_supported(file_path):
    """Check if a file has a supported extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return ext in SUPPORTED_EXTENSIONS
