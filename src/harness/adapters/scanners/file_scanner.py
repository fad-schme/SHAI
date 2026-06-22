"""FileScanner — structural file checks for the scan_file boundary.

Two-pass design:
  Pass 1 (structural): MIME type, extension, file size, filename patterns,
                       PDF embedded JavaScript, image EXIF metadata,
                       ZIP structure, Office macro detection.
  Pass 2 (content):    Text extracted from the file is run through a
                       companion text scanner (YamlRuleScanner by default).

All external dependencies are optional and gracefully skipped if not
installed. The scanner degrades to extension/size checks only.

Optional dependencies:
  python-magic   — MIME type detection (pip install python-magic)
  pypdf          — PDF text extraction and JS detection
  Pillow         — image EXIF metadata inspection
  python-docx    — DOCX text extraction
  oletools       — Office VBA macro detection (pip install oletools)

The scanner never includes file content, matched text, or EXIF values
in Finding.detail — only category and short description.
"""
from __future__ import annotations

import logging
import os
import re
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ── Threat lists ──────────────────────────────────────────────────────────

_SUSPICIOUS_MIME = frozenset({
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-executable",
    "application/x-elf",
    "application/octet-stream",
})

_SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".bat", ".sh", ".scr", ".php", ".js", ".bin",
    ".dll", ".vbs", ".docm", ".xlsm", ".pptm",
})

_LLM_TRIGGER_RE = [
    re.compile(r"ignore.*instruction", re.I),
    re.compile(r"simulate.*response", re.I),
    re.compile(r"act\s+as", re.I),
    re.compile(r"pretend\s+to\s+be", re.I),
    re.compile(r"<\|system\|>", re.I),
    re.compile(r"\[system\]", re.I),
    re.compile(r"unfiltered", re.I),
    re.compile(r"/JavaScript", re.I),
]

_BASE64_RE = re.compile(r"([A-Za-z0-9+/=]{100,})")


# ── Text extraction helpers ───────────────────────────────────────────────

def _extract_pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(str(path))
        return "\n".join(p.extract_text() or "" for p in reader.pages)
    except ImportError:
        try:
            from PyPDF2 import PdfReader  # type: ignore
            reader = PdfReader(str(path))
            return "\n".join(
                p.extract_text() or "" for p in reader.pages
            )
        except ImportError:
            return ""
    except Exception as e:
        log.debug("pdf text extraction failed: %s", e)
        return ""


def _extract_docx_text(path: Path) -> str:
    try:
        import docx  # type: ignore
        doc = docx.Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs)
    except ImportError:
        return ""
    except Exception as e:
        log.debug("docx text extraction failed: %s", e)
        return ""


def _extract_text(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".pdf":
        return _extract_pdf_text(path)
    if ext in {".docx"}:
        return _extract_docx_text(path)
    if ext in {".txt", ".md", ".csv", ".json", ".xml", ".html", ".yaml", ".yml"}:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
    return ""


# ── Structural check helpers ──────────────────────────────────────────────

def _check_mime(path: Path, findings: list[Finding]) -> None:
    try:
        import magic  # type: ignore
        mime = magic.from_file(str(path), mime=True)
        if mime in _SUSPICIOUS_MIME:
            findings.append(Finding(
                scanner="file_scanner",
                category="file.suspicious_mime",
                severity=Severity.HIGH,
                detail=f"MIME type flagged: {mime}",
            ))
    except ImportError:
        pass  # python-magic not installed — skip
    except Exception as e:
        log.debug("MIME check failed: %s", e)


def _check_extension(path: Path, findings: list[Finding]) -> None:
    ext = path.suffix.lower()
    if ext in _SUSPICIOUS_EXTENSIONS:
        findings.append(Finding(
            scanner="file_scanner",
            category="file.suspicious_extension",
            severity=Severity.HIGH,
            detail=f"Extension flagged: {ext}",
        ))


def _check_size(path: Path, max_mb: float, findings: list[Finding]) -> None:
    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > max_mb:
        findings.append(Finding(
            scanner="file_scanner",
            category="file.size_exceeded",
            severity=Severity.MEDIUM,
            detail=f"File size exceeds {max_mb:.0f} MB limit",
        ))


def _check_filename(path: Path, findings: list[Finding]) -> None:
    name = path.name.lower()
    for pat in _LLM_TRIGGER_RE:
        if pat.search(name):
            findings.append(Finding(
                scanner="file_scanner",
                category="file.suspicious_filename",
                severity=Severity.MEDIUM,
                detail="Filename matches injection pattern",
            ))
            return


def _check_pdf(path: Path, findings: list[Finding]) -> None:
    try:
        raw = path.read_bytes()
        if b"/JavaScript" in raw or b"/JS " in raw:
            findings.append(Finding(
                scanner="file_scanner",
                category="file.pdf_javascript",
                severity=Severity.HIGH,
                detail="Embedded JavaScript detected in PDF",
            ))
    except Exception as e:
        log.debug("PDF JS check failed: %s", e)


def _check_exif(path: Path, findings: list[Finding]) -> None:
    try:
        from PIL import Image  # type: ignore
        from PIL.ExifTags import TAGS  # type: ignore
        img = Image.open(str(path))
        exif = getattr(img, "_getexif", lambda: None)()
        if not exif:
            return
        for tag, val in exif.items():
            tag_name = TAGS.get(tag, str(tag))
            if isinstance(val, str):
                for pat in _LLM_TRIGGER_RE:
                    if pat.search(val):
                        findings.append(Finding(
                            scanner="file_scanner",
                            category="file.exif_injection",
                            severity=Severity.HIGH,
                            detail=f"Injection pattern in EXIF field: {tag_name}",
                        ))
                        return
    except ImportError:
        pass
    except Exception as e:
        log.debug("EXIF check failed: %s", e)


def _check_zip(path: Path, findings: list[Finding]) -> None:
    try:
        with zipfile.ZipFile(str(path), "r") as z:
            names = z.namelist()
            if len(names) > 1000:
                findings.append(Finding(
                    scanner="file_scanner",
                    category="file.zip_bomb",
                    severity=Severity.HIGH,
                    detail="Archive contains excessive number of entries",
                ))
    except Exception as e:
        log.debug("ZIP check failed: %s", e)


def _check_office_macros(path: Path, findings: list[Finding]) -> None:
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
        vba = VBA_Parser(str(path))
        if vba.detect_vba_macros():
            findings.append(Finding(
                scanner="file_scanner",
                category="file.office_macros",
                severity=Severity.HIGH,
                detail="VBA macros detected in Office file",
            ))
            for (_, _, vba_code) in vba.extract_macros():
                for pat in _LLM_TRIGGER_RE:
                    if pat.search(vba_code):
                        findings.append(Finding(
                            scanner="file_scanner",
                            category="file.macro_injection",
                            severity=Severity.CRITICAL,
                            detail="Injection pattern detected in macro code",
                        ))
                        return
    except ImportError:
        pass
    except Exception as e:
        log.debug("Office macro check failed: %s", e)


def _check_ooxml(path: Path, findings: list[Finding]) -> None:
    """Scan OOXML packages (docx/xlsx/pptx) for base64 blobs and LLM triggers."""
    try:
        with zipfile.ZipFile(str(path), "r") as z:
            for name in z.namelist():
                if not name.endswith((".xml", ".rels")):
                    continue
                try:
                    with z.open(name) as xf:
                        content = xf.read().decode("utf-8", errors="ignore")
                    if _BASE64_RE.search(content):
                        findings.append(Finding(
                            scanner="file_scanner",
                            category="file.ooxml_base64",
                            severity=Severity.MEDIUM,
                            detail=f"Base64 payload found in {name}",
                        ))
                    for pat in _LLM_TRIGGER_RE:
                        if pat.search(content):
                            findings.append(Finding(
                                scanner="file_scanner",
                                category="file.ooxml_injection",
                                severity=Severity.HIGH,
                                detail=f"Injection pattern found in {name}",
                            ))
                            return
                except Exception:
                    pass
    except Exception as e:
        log.debug("OOXML scan failed: %s", e)


# ── Main scanner ──────────────────────────────────────────────────────────

class FileScanner:
    """Structural file scanner for the scan_file boundary.

    Satisfies Scanner Protocol structurally (scan takes text: str but
    scan_file passes the path as the text argument — see boundaries/_scan.py).

    For the scan_file boundary, text is the file path string.
    """

    name = "file_scanner"

    def __init__(
        self,
        max_size_mb: float = 100.0,
        text_scanner: object | None = None,
    ) -> None:
        """
        max_size_mb:   block files larger than this.
        text_scanner:  optional Scanner to run on extracted text content.
                       Typically YamlRuleScanner(patterns_for_doc.yaml).
        """
        self._max_size_mb  = max_size_mb
        self._text_scanner = text_scanner

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        """text is the file path (str) — passed by run_file_scan."""
        path = Path(text)
        if not path.exists():
            return ScanResult(findings=[Finding(
                scanner=self.name,
                category="file.not_found",
                severity=Severity.HIGH,
                detail="File path does not exist",
            )])

        findings: list[Finding] = []
        ext = path.suffix.lower()

        # ── Pass 1: structural checks ─────────────────────────────────────
        _check_mime(path, findings)
        _check_extension(path, findings)
        _check_size(path, self._max_size_mb, findings)
        _check_filename(path, findings)

        if ext == ".pdf":
            _check_pdf(path, findings)
        elif ext in {".jpg", ".jpeg", ".png", ".tiff", ".webp"}:
            _check_exif(path, findings)
        elif ext == ".zip":
            _check_zip(path, findings)
        elif ext in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"}:
            _check_office_macros(path, findings)
        elif ext in {".docx", ".xlsx", ".pptx"}:
            _check_ooxml(path, findings)

        # ── Pass 2: content scan ──────────────────────────────────────────
        if self._text_scanner is not None:
            extracted = _extract_text(path)
            if extracted.strip():
                try:
                    text_result = await self._text_scanner.scan(extracted, ctx)
                    findings.extend(text_result.findings)
                except Exception as e:
                    log.error("text scanner failed during file content scan: %s", e)

        return ScanResult(findings=findings)
