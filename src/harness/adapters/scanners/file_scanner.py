"""FileScanner — structural file checks for the scan_file boundary.

Two-pass design:
  Pass 1 (structural): MIME type, extension, file size, filename patterns,
                       PDF embedded JavaScript, image EXIF metadata,
                       ZIP structure, Office macro detection.
  Pass 2 (content):    Text extracted from the file is run through a
                       companion text scanner (InjectionScanner by default).

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

Error-handling contract
-----------------------
Each individual file check (PDF markers, SVG, EXIF, ZIP, OOXML, Office
macros, …) is wrapped in `try/except Exception: log.debug(…)`. This is
deliberate: an attacker-controlled input can be arbitrarily malformed,
and one check crashing must not abort the remaining checks. Failures
degrade the scan (fewer signals) but never crash it. Exceptions that
should abort — an unusable file path, an OOM — surface as unhandled
because they are not caught by these narrow debug-log handlers.
"""
from __future__ import annotations

import logging
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
    # script / auto-exec vectors
    ".svg", ".svgz", ".jar", ".hta", ".wsf", ".ps1", ".lnk", ".iso",
    ".jse", ".vbe", ".cmd", ".com", ".msi", ".reg",
})

# Known document/media extensions — used to flag double-extension disguises
# like "invoice.pdf.exe" where the *inner* extension is a benign lure.
_LURE_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".zip",
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


def _check_double_extension(path: Path, findings: list[Finding]) -> None:
    """Flag files whose inner stem carries a benign lure extension in front of
    an executable one, e.g. invoice.pdf.exe / photo.jpg.scr."""
    parts = path.name.lower().split(".")
    if len(parts) < 3:
        return
    inner = "." + parts[-2]
    outer = "." + parts[-1]
    if inner in _LURE_EXTENSIONS and outer in _SUSPICIOUS_EXTENSIONS:
        findings.append(Finding(
            scanner="file_scanner",
            category="file.double_extension",
            severity=Severity.HIGH,
            detail=f"Double extension: lure {inner} before {outer}",
        ))


# PDF auto-execute and embedded-payload markers. /JavaScript and /JS are code;
# /OpenAction and /AA fire actions on open; /Launch runs external programs;
# /EmbeddedFile and /RichMedia carry embedded payloads.
_PDF_MARKERS = [
    (b"/JavaScript", "file.pdf_javascript", Severity.HIGH,  "Embedded JavaScript"),
    (b"/JS",         "file.pdf_javascript", Severity.HIGH,  "Embedded JavaScript"),
    (b"/OpenAction", "file.pdf_open_action", Severity.HIGH, "Auto-run OpenAction"),
    (b"/AA",         "file.pdf_open_action", Severity.MEDIUM, "Additional-actions dictionary"),
    (b"/Launch",     "file.pdf_launch",     Severity.HIGH,  "Launch action (external program)"),
    (b"/EmbeddedFile", "file.pdf_embedded", Severity.MEDIUM, "Embedded file"),
    (b"/RichMedia",  "file.pdf_richmedia",  Severity.MEDIUM, "RichMedia/Flash payload"),
]


def _check_pdf(path: Path, findings: list[Finding]) -> None:
    try:
        raw = path.read_bytes()
        seen: set[str] = set()
        for marker, category, severity, desc in _PDF_MARKERS:
            if marker in raw and category not in seen:
                seen.add(category)
                findings.append(Finding(
                    scanner="file_scanner",
                    category=category,
                    severity=severity,
                    detail=f"PDF marker: {desc}",
                ))
    except Exception as e:
        log.debug("PDF marker check failed: %s", e)


_SVG_SCRIPT_RE = [
    re.compile(rb"(?i)<script\b"),
    re.compile(rb"(?i)\bon\w+\s*="),          # inline event handlers (onload=, onclick=)
    re.compile(rb"(?i)javascript:"),
    re.compile(rb"(?i)<foreignObject\b"),
]


def _check_svg(path: Path, findings: list[Finding]) -> None:
    """SVG is XML that can carry <script>, event handlers, and javascript: URIs."""
    try:
        raw = path.read_bytes()
        for pat in _SVG_SCRIPT_RE:
            if pat.search(raw):
                findings.append(Finding(
                    scanner="file_scanner",
                    category="file.svg_script",
                    severity=Severity.HIGH,
                    detail="Script or event handler embedded in SVG",
                ))
                return
    except Exception as e:
        log.debug("SVG check failed: %s", e)


def _check_exif(path: Path, findings: list[Finding]) -> str:
    """Inspect EXIF metadata, append structural findings, and return a
    concatenated blob of string EXIF values for the content pass to route
    through the full scanner set.

    The blob is what closes OWASP's multimodal-injection gap: previously we
    only compared EXIF strings to the local `_LLM_TRIGGER_RE`, which is a
    subset of the injection catalog. Returning the blob lets the caller run
    `_text_scanners` (injection + jailbreak + identity_spoof) against the
    same metadata surface.

    Returns "" when PIL is unavailable or no EXIF is present.
    """
    blob_parts: list[str] = []
    try:
        from PIL import Image  # type: ignore
        from PIL.ExifTags import TAGS  # type: ignore
        img = Image.open(str(path))
        exif = getattr(img, "_getexif", lambda: None)()
        if not exif:
            return ""
        for tag, val in exif.items():
            if not isinstance(val, str):
                continue
            tag_name = TAGS.get(tag, str(tag))
            blob_parts.append(f"{tag_name}: {val}")
            # Fast local trigger check — a definite injection pattern in EXIF
            # is HIGH-severity structural evidence, so emit a finding right
            # here even before the content pass runs.
            for pat in _LLM_TRIGGER_RE:
                if pat.search(val):
                    findings.append(Finding(
                        scanner="file_scanner",
                        category="file.exif_injection",
                        severity=Severity.HIGH,
                        detail=f"Injection pattern in EXIF field: {tag_name}",
                    ))
                    break
    except ImportError:
        pass
    except Exception as e:
        log.debug("EXIF check failed: %s", e)
    return "\n".join(blob_parts)


# XMP is embedded XML metadata carried in JPEG APP1, PNG iTXt, TIFF, etc.
# Extract by grepping the raw bytes for the xmpmeta envelope rather than
# adding a dependency on defusedxml/libxmp — good enough to catch payloads
# hidden in dc:description / dc:title / xmp:CreatorTool / photoshop:Instructions.
_XMP_BLOB_RE = re.compile(rb"<x:xmpmeta\b.*?</x:xmpmeta>", re.DOTALL | re.IGNORECASE)
_XMP_TEXT_RE = re.compile(rb">([^<]{4,})<", re.DOTALL)


def _extract_xmp(path: Path) -> str:
    """Pull string values from any XMP block embedded in the file. Returns
    "" when no XMP is present. Kept dependency-free."""
    try:
        raw = path.read_bytes()
    except Exception:
        return ""
    blocks = _XMP_BLOB_RE.findall(raw)
    if not blocks:
        return ""
    strings: list[str] = []
    for b in blocks:
        for m in _XMP_TEXT_RE.findall(b):
            try:
                s = m.decode("utf-8", errors="ignore").strip()
            except Exception:
                continue
            # Skip pure-numeric / boolean / GUID-shaped values that dominate XMP
            if len(s) >= 8 and any(c.isalpha() for c in s):
                strings.append(s)
    return "\n".join(strings)


def _check_zip(path: Path, findings: list[Finding]) -> None:
    try:
        with zipfile.ZipFile(str(path), "r") as z:
            infos = z.infolist()
            if len(infos) > 1000:
                findings.append(Finding(
                    scanner="file_scanner",
                    category="file.zip_bomb",
                    severity=Severity.HIGH,
                    detail="Archive contains excessive number of entries",
                ))
            # Compression-ratio bomb: a small compressed size expanding to a
            # very large uncompressed total is the actual zip-bomb signature
            # (a 42 KB bomb has few entries but expands enormously).
            comp = sum(i.compress_size for i in infos)
            uncomp = sum(i.file_size for i in infos)
            if comp > 0 and uncomp / comp > 100 and uncomp > 50 * 1024 * 1024:
                findings.append(Finding(
                    scanner="file_scanner",
                    category="file.zip_bomb",
                    severity=Severity.HIGH,
                    detail=f"Compression ratio {uncomp // comp}:1 exceeds safe bound",
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
                except Exception as entry_err:  # nosec B110 — malformed OOXML entry; skip and continue scanning
                    log.debug("OOXML entry scan error in %s: %s", name, entry_err)
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
        text_scanners: list | None = None,
        text_scanner: object | None = None,
    ) -> None:
        """
        max_size_mb:    block files larger than this.
        text_scanners:  Scanners to run on extracted text content — the full
                        content pass. Typically [injection_doc, jailbreak,
                        identity_spoof] so a poisoned document is checked for
                        injection, guardrail attacks, and authority claims,
                        not injection alone.
        text_scanner:   single-scanner form. Accepted so the existing
                        _build_file_scanners call site keeps working without a
                        harness change; folded into text_scanners internally.
                        To activate the full content pass, pass text_scanners
                        (see the _build_file_scanners snippet in the patch notes).
        """
        self._max_size_mb   = max_size_mb
        scanners: list = []
        if text_scanners:
            scanners.extend(text_scanners)
        if text_scanner is not None:
            scanners.append(text_scanner)
        self._text_scanners = scanners

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
        _check_double_extension(path, findings)
        _check_size(path, self._max_size_mb, findings)
        _check_filename(path, findings)

        image_metadata_blob = ""
        if ext == ".pdf":
            _check_pdf(path, findings)
        elif ext in {".svg", ".svgz"}:
            _check_svg(path, findings)
        elif ext in {".jpg", ".jpeg", ".png", ".tiff", ".webp"}:
            # EXIF and XMP contribute a metadata blob for the content pass —
            # OWASP multimodal-injection coverage. Structural EXIF findings
            # (fast trigger check) still go straight into findings.
            exif_blob = _check_exif(path, findings)
            xmp_blob  = _extract_xmp(path)
            image_metadata_blob = "\n".join(b for b in (exif_blob, xmp_blob) if b)
        elif ext == ".zip":
            _check_zip(path, findings)
        elif ext in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"}:
            _check_office_macros(path, findings)
        elif ext in {".docx", ".xlsx", ".pptx"}:
            _check_ooxml(path, findings)

        # ── Pass 2: content scan (full scanner set) ───────────────────────
        # Routes extracted document text AND image metadata through the same
        # injection + jailbreak + identity_spoof chain, closing the gap where
        # EXIF/XMP was previously only checked against a small regex subset.
        if self._text_scanners:
            payloads: list[tuple[str, str]] = []
            extracted = _extract_text(path)
            if extracted.strip():
                payloads.append(("content", extracted))
            if image_metadata_blob.strip():
                payloads.append(("image_metadata", image_metadata_blob))
            for surface, payload in payloads:
                for scanner in self._text_scanners:
                    try:
                        text_result = await scanner.scan(payload, ctx)
                        for f in text_result.findings:
                            # Prefix category with surface so the audit trail
                            # distinguishes document-body hits from image-
                            # metadata hits without losing the original.
                            if surface == "image_metadata":
                                findings.append(Finding(
                                    scanner=f.scanner,
                                    category=f"file.image_metadata.{f.category}",
                                    severity=f.severity,
                                    detail=f.detail,
                                ))
                            else:
                                findings.append(f)
                    except Exception as e:
                        log.error("text scanner %s failed on %s: %s",
                                  getattr(scanner, "name", "?"), surface, e)

        return ScanResult(findings=findings)
