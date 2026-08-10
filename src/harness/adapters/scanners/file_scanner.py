"""File scanners for the scan_file boundary.

Two scanners, independent so a failure in one cannot discard the other's
findings and each is governed by the boundary's on_error policy on its own:

  FileScanner        — structural: MIME type, extension, file size, filename
                       patterns, PDF embedded JavaScript, SVG scripts and
                       external references, image EXIF metadata, archive
                       inspection, Office macros.
  FileContentScanner — runs the configured scanner chain over text extracted
                       from the file and over the image EXIF/XMP blob.

Archive handling covers the zip family (zip, OOXML, jar), single-stream
compression (gzip, bzip2, xz), and tar including compressed tars. Bombs are
detected from zip metadata where possible and by a bounded decompression probe
where the format declares no reliable size; tar is additionally checked for
path traversal and symlink escapes. Formats with no stdlib reader (7z, rar)
are reported as uninspectable rather than passed silently.

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

import asyncio
import logging
import re
import zipfile
from pathlib import Path, PurePosixPath
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

# ── Archive bomb bounds ───────────────────────────────────────────────────
# A decompression bomb is small on disk, so the size gate cannot see it. Two
# detection strategies, picked per format:
#   zip family    — read the central directory; detects without decompressing
#   stream family — bounded decompression probe; these declare no reliable
#                   uncompressed size (gzip's ISIZE is mod 2^32 and
#                   attacker-controlled), so measuring real output is the only
#                   honest test
_ARCHIVE_MAX_ENTRIES      = 1000
_ARCHIVE_MAX_RATIO        = 100
_ARCHIVE_MAX_UNCOMPRESSED = 50 * 1024 * 1024
# Ceiling on a single entry read. The central directory is attacker-controlled
# and can under-report file_size, so the ratio check cannot be the only bound.
_ARCHIVE_ENTRY_READ_CAP   = 1024 * 1024
# Bounded probe: read output in chunks, stop once past the uncompressed bound.
_ARCHIVE_PROBE_CHUNK      = 1024 * 1024
# An archive nested inside an archive is checked, but not indefinitely — the
# recursion is itself an attack surface.
_ARCHIVE_MAX_DEPTH        = 2

_ZIP_FAMILY_EXTS   = frozenset({".zip", ".docx", ".xlsx", ".pptx", ".jar"})
# Single-stream compression. .svgz is gzip; bomb bounds apply to it like any
# other gzip stream, independently of SVG content handling.
_STREAM_COMP_EXTS  = frozenset({".gz", ".bz2", ".xz", ".svgz"})
_TAR_EXTS          = frozenset({".tar"})
# Containers with no stdlib reader. Reported rather than passed silently — an
# archive SHAI cannot see inside is a decision an operator should make.
_UNSCANNABLE_EXTS  = frozenset({".7z", ".rar"})
# File types whose content extraction means decompressing an archive.
_ARCHIVE_BACKED_EXTS = _ZIP_FAMILY_EXTS | _STREAM_COMP_EXTS | _TAR_EXTS


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


def _svg_bytes(path: Path) -> bytes:
    """SVG source, decompressing `.svgz`.

    `.svgz` is gzip, so its expansion is attacker-controlled — the read is
    capped here rather than trusting anything the container declares. The
    archive probe bounds the same file independently; this bound is what makes
    the structural pass safe on its own, since it runs before any of that.
    """
    if path.suffix.lower() == ".svgz":
        import gzip
        with gzip.open(str(path), "rb") as fh:
            return fh.read(_ARCHIVE_ENTRY_READ_CAP)
    return path.read_bytes()


def _extract_svg_text(path: Path) -> str:
    """SVG source as text, for the content chain.

    The whole document, not just `<text>`/`<title>`/`<desc>` — the same
    treatment `.xml` and `.html` already get, and an injection payload in SVG
    is as likely to sit in a comment or an attribute as in a text node.
    """
    try:
        return _svg_bytes(path).decode("utf-8", errors="ignore")
    except Exception as e:
        log.debug("SVG text extraction failed: %s", e)
        return ""


def _extract_text(path: Path) -> str:
    ext = path.suffix.lower()
    if ext == ".pdf":
        return _extract_pdf_text(path)
    if ext in {".docx"}:
        return _extract_docx_text(path)
    if ext in {".svg", ".svgz"}:
        return _extract_svg_text(path)
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

# An entity declaration is the entity-expansion vector, and it is the one piece
# of hostile XML a parser cannot be handed safely. Its presence gates the tree
# pass; an external DTD reference does not, because ElementTree never fetches
# one.
_SVG_ENTITY_DECL_RE = re.compile(rb"(?i)<!ENTITY\b")

# Elements that execute, whatever namespace prefix carries them.
_SVG_ACTIVE_TAGS = frozenset({"script", "foreignobject"})
# Elements that fetch on render — an SSRF probe and an exfiltration channel for
# whatever opens the file.
_SVG_REF_TAGS    = frozenset({"image", "use", "feimage"})
_SVG_REF_ATTRS   = frozenset({"href", "src"})

# Matched against attribute values after the parser has resolved numeric
# character references, so `&#106;avascript:` is already `javascript:` here.
_JS_URI_RE       = re.compile(r"^[\s\x00-\x20]*javascript:", re.I)
# scheme://host or protocol-relative //host. `data:` and fragment refs have no
# authority component and are not external fetches.
_EXTERNAL_URI_RE = re.compile(r"^\s*(?:[a-z][a-z0-9+.\-]*:)?//", re.I)


def _localname(name: str) -> str:
    """Namespace-stripped, lowercased element or attribute name.

    ElementTree reports `{http://www.w3.org/2000/svg}script`, so matching on the
    local name is what sees through `<svg:script>` and any other prefix.
    """
    return name.rpartition("}")[2].lower()


def _svg_tree_findings(raw: bytes, findings: list[Finding], seen: set[str]) -> None:
    """Structural inspection of the parsed SVG.

    Byte patterns cannot see what ordinary XML expresses — a namespace-prefixed
    `<svg:script>`, a CDATA-wrapped handler body, a numeric character reference
    in an href. The tree sees element and attribute names themselves, whatever
    the serialisation.

    Only reached once the source is known to declare no entities, so expat has
    nothing to expand; ElementTree neither retrieves external DTDs nor resolves
    external entities, so no XXE surface remains and no new dependency is needed
    — the same call `_extract_xmp` makes.
    """
    # Entity-free source, gated by the caller — see the checks above.
    import xml.etree.ElementTree as ET  # nosec B405

    def flag(category: str, severity: Severity, detail: str) -> None:
        if category in seen:
            return
        seen.add(category)
        findings.append(Finding(
            scanner="file_scanner",
            category=category,
            severity=severity,
            detail=detail,
        ))

    # Entity-free source, gated by the caller — see the checks above.
    root = ET.fromstring(raw)  # nosec B314
    for el in root.iter():
        # Comments and processing instructions carry a callable tag.
        tag = _localname(el.tag) if isinstance(el.tag, str) else ""
        if tag in _SVG_ACTIVE_TAGS:
            flag("file.svg_script", Severity.HIGH,
                 "Script or event handler embedded in SVG")
        for raw_attr, value in el.attrib.items():
            attr = _localname(raw_attr)
            if attr.startswith("on") or _JS_URI_RE.match(value):
                flag("file.svg_script", Severity.HIGH,
                     "Script or event handler embedded in SVG")
            if (tag in _SVG_REF_TAGS
                    and attr in _SVG_REF_ATTRS
                    and _EXTERNAL_URI_RE.match(value)):
                flag("file.svg_external_ref", Severity.MEDIUM,
                     f"External reference fetched on render by <{tag}>")


def _check_svg(path: Path, findings: list[Finding]) -> None:
    """SVG is XML that can carry <script>, event handlers, javascript: URIs and
    references that fetch on render.

    Two passes over one source. The byte patterns are the floor: they still fire
    on a document too malformed for an XML parser, which a lenient HTML parser
    would render anyway. The tree pass then catches what byte patterns
    structurally cannot.

    `.svgz` is gzip, so the source is decompressed before either pass — a
    script-carrying `.svgz` was previously indistinguishable from a benign one.
    """
    try:
        raw = _svg_bytes(path)
    except Exception as e:
        log.debug("SVG read failed for %s: %s", path.name, e)
        return

    seen: set[str] = set()
    for pat in _SVG_SCRIPT_RE:
        if pat.search(raw):
            seen.add("file.svg_script")
            findings.append(Finding(
                scanner="file_scanner",
                category="file.svg_script",
                severity=Severity.HIGH,
                detail="Script or event handler embedded in SVG",
            ))
            break

    if _SVG_ENTITY_DECL_RE.search(raw):
        # Report rather than parse — the same call `_check_archive` makes for a
        # container it has no safe reader for.
        findings.append(Finding(
            scanner="file_scanner",
            category="file.svg_entity_decl",
            severity=Severity.MEDIUM,
            detail="XML entity declaration in SVG — tree inspection skipped",
        ))
        return

    if len(raw) > _ARCHIVE_ENTRY_READ_CAP:
        # A parsed tree costs several times the bytes it came from, and the
        # structural pass has no size gate ahead of it. Same ceiling the .svgz
        # read uses, so both paths hand the parser the same bounded input. The
        # byte pass above already ran on the whole file and is unaffected.
        log.debug("SVG too large for tree inspection: %s", path.name)
        return

    try:
        _svg_tree_findings(raw, findings, seen)
    except Exception as e:
        # Malformed XML, or a parser limit. The byte pass already ran and stands
        # on its own, so this degrades the scan rather than losing it.
        log.debug("SVG tree inspection failed for %s: %s", path.name, e)


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


def _zip_metadata_reasons(source, depth: int, max_mb: float) -> list[str]:
    """Bomb signatures from a zip central directory. Decompresses nothing.

    `source` is a path or a file-like object, so the same check runs against a
    nested archive already read into memory.
    """
    try:
        with zipfile.ZipFile(source, "r") as z:
            infos = z.infolist()
            names = z.namelist()
            reasons: list[str] = []
            if len(infos) > _ARCHIVE_MAX_ENTRIES:
                reasons.append("Archive contains excessive number of entries")
            comp   = sum(i.compress_size for i in infos)
            uncomp = sum(i.file_size for i in infos)
            # Absolute ceiling first: a ratio test alone lets a big-but-
            # proportionate archive through, and unpacking it still costs
            # whatever it costs.
            if uncomp > max_mb * 1024 * 1024:
                reasons.append(
                    f"Declared uncompressed size {uncomp // (1024 * 1024)} MB "
                    f"exceeds the {max_mb:.0f} MB boundary limit"
                )
            # A small compressed size expanding to a very large uncompressed
            # total is the zip-bomb signature — a 42 KB bomb has few entries
            # but expands enormously.
            elif (comp > 0
                    and uncomp / comp > _ARCHIVE_MAX_RATIO
                    and uncomp > _ARCHIVE_MAX_UNCOMPRESSED):
                reasons.append(
                    f"Compression ratio {uncomp // comp}:1 exceeds safe bound"
                )
            if reasons:
                return reasons
            # The outer ratio of a nested bomb looks ordinary — the inner
            # archive is the payload. Bounded read, bounded depth.
            if depth < _ARCHIVE_MAX_DEPTH:
                reasons.extend(_nested_reasons(z, names, depth, max_mb))
            return reasons
    except Exception as e:
        log.debug("zip inspection failed: %s", e)
        return []


def _nested_reasons(
    z: zipfile.ZipFile, names: list[str], depth: int, max_mb: float,
) -> list[str]:
    """Inspect archive entries inside an archive, one bounded level at a time."""
    import io

    for name in names:
        if not name.lower().endswith(tuple(_ZIP_FAMILY_EXTS)):
            continue
        try:
            with z.open(name) as entry:
                blob = entry.read(_ARCHIVE_ENTRY_READ_CAP)
        # Malformed entry; keep scanning the rest of the archive.
        except Exception as e:  # nosec B112
            log.debug("nested entry read failed for %s: %s", name, e)
            continue
        inner = _zip_metadata_reasons(io.BytesIO(blob), depth + 1, max_mb)
        if inner:
            return [f"Nested archive is a bomb: {inner[0]}"]
    return []


def _stream_bomb_reasons(path: Path, ext: str, max_mb: float) -> list[str]:
    """Bounded decompression probe for single-stream formats.

    Two independent bounds, because a ratio test alone does not limit absolute
    expansion — a 3 MB file expanding to 203 MB is only 63:1 and would pass:

      * expansion ceiling — the operator's own `max_size_mb`. A file expanding
        past what they accept as an upload is refused whatever its ratio. This
        is also what caps the work done here.
      * ratio — catches a clearly disproportionate file below that ceiling.
    """
    if ext in {".gz", ".svgz"}:
        import gzip as _mod
    elif ext == ".bz2":
        import bz2 as _mod
    elif ext == ".xz":
        import lzma as _mod
    else:
        return []

    ceiling = int(max_mb * 1024 * 1024)
    try:
        on_disk  = max(1, path.stat().st_size)
        produced = 0
        ended    = False
        with _mod.open(str(path), "rb") as fh:
            while produced <= ceiling:
                chunk = fh.read(_ARCHIVE_PROBE_CHUNK)
                if not chunk:
                    ended = True
                    break
                produced += len(chunk)
    except Exception as e:
        log.debug("stream probe failed for %s: %s", path.name, e)
        return []

    if not ended:
        return [f"Decompressed size exceeds the {max_mb:.0f} MB boundary limit"]

    ratio = produced / on_disk
    if produced > _ARCHIVE_MAX_UNCOMPRESSED and ratio > _ARCHIVE_MAX_RATIO:
        return [
            f"Compression ratio exceeds safe bound "
            f"({int(ratio)}:1 at {produced // (1024 * 1024)} MB decompressed)"
        ]
    return []


def _archive_bomb_reasons(path: Path, max_mb: float) -> list[str]:
    """Bomb signatures for any container format this scanner understands.

    Safe to call before extraction: the zip family is inspected from metadata
    alone, and the stream probe is bounded by _ARCHIVE_MAX_UNCOMPRESSED.
    """
    ext = path.suffix.lower()
    if ext in _ZIP_FAMILY_EXTS:
        return _zip_metadata_reasons(str(path), depth=0, max_mb=max_mb)
    if ext in _STREAM_COMP_EXTS:
        return _stream_bomb_reasons(path, ext, max_mb)
    return []


def _archive_escape_reasons(path: Path) -> list[str]:
    """Path traversal and symlink escapes in a tar. Not a bomb — a different
    attack class, so the caller reports it under its own category.

    Members are enumerated from headers without extracting. For a compressed
    tar this still decompresses, so callers must run the bomb probe first.
    """
    sfx = [s.lower() for s in path.suffixes]
    if path.suffix.lower() not in _TAR_EXTS and ".tar" not in sfx:
        return []

    import tarfile

    reasons: list[str] = []
    try:
        with tarfile.open(str(path), "r:*") as tf:
            for member in tf.getmembers():
                parts = PurePosixPath(member.name).parts
                if member.name.startswith("/") or ".." in parts:
                    reasons.append("Archive member path escapes the extraction root")
                    break
            for member in tf.getmembers():
                if member.issym() or member.islnk():
                    reasons.append("Archive contains a symbolic or hard link")
                    break
    except Exception as e:
        log.debug("tar inspection failed for %s: %s", path.name, e)
    return reasons


def _is_archive(path: Path) -> bool:
    """True for any container format, including compound suffixes like .tar.gz.

    Path.suffix alone reports ".gz" for "a.tar.gz", so the tar layer is only
    visible through the full suffix list.
    """
    sfx = {s.lower() for s in path.suffixes}
    ext = path.suffix.lower()
    return bool(
        ext in _ZIP_FAMILY_EXTS
        or ext in _STREAM_COMP_EXTS
        or ext in _TAR_EXTS
        or ext in _UNSCANNABLE_EXTS
        or sfx & _TAR_EXTS
    )


def _safe_to_extract(path: Path, max_mb: float) -> bool:
    """False when an archive-backed file shows bomb signatures.

    The structural scanner emits the finding; this only stops the content
    scanner decompressing the same file. Boundary scanners run concurrently, so
    the content scanner cannot wait on the structural verdict.
    """
    if _is_archive(path):
        return not _archive_bomb_reasons(path, max_mb)
    return True


def _check_archive(path: Path, findings: list[Finding], max_mb: float) -> None:
    """Structural checks for every container format the scanner recognises.

    Bomb detection first — for compressed tars, enumerating members means
    decompressing, so the bound has to be established before that happens.
    """
    ext = path.suffix.lower()
    if ext in _UNSCANNABLE_EXTS:
        findings.append(Finding(
            scanner="file_scanner",
            category="file.unscannable_archive",
            severity=Severity.MEDIUM,
            detail=f"No reader available for {ext} — contents were not inspected",
        ))
        return

    bomb = _archive_bomb_reasons(path, max_mb)
    for reason in bomb:
        findings.append(Finding(
            scanner="file_scanner",
            category="file.archive_bomb",
            severity=Severity.HIGH,
            detail=reason,
        ))
    if bomb:
        return   # do not enumerate members of a suspected bomb

    for reason in _archive_escape_reasons(path):
        findings.append(Finding(
            scanner="file_scanner",
            category="file.archive_escape",
            severity=Severity.HIGH,
            detail=reason,
        ))


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


def _check_ooxml(path: Path, findings: list[Finding], max_mb: float) -> None:
    """Scan OOXML packages (docx/xlsx/pptx) for base64 blobs and LLM triggers.

    OOXML files are zips, so `_check_archive` has already run the bomb checks
    and reported anything it found. This only declines to unpack a package that
    tripped them — the whole point of the check is not to decompress it.
    """
    if _archive_bomb_reasons(path, max_mb):
        return

    try:
        with zipfile.ZipFile(str(path), "r") as z:
            for name in z.namelist():
                if not name.endswith((".xml", ".rels")):
                    continue
                try:
                    with z.open(name) as xf:
                        # Bounded read: the central directory can under-report
                        # file_size, so the ratio check alone cannot cap what a
                        # single entry expands to.
                        raw = xf.read(_ARCHIVE_ENTRY_READ_CAP)
                    content = raw.decode("utf-8", errors="ignore")
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
                # Malformed OOXML entry; skip it and continue scanning the rest.
                except Exception as entry_err:  # nosec B110
                    log.debug("OOXML entry scan error in %s: %s", name, entry_err)
    except Exception as e:
        log.debug("OOXML scan failed: %s", e)


# ── Main scanner ──────────────────────────────────────────────────────────

def _image_metadata_blob(path: Path) -> str:
    """EXIF + XMP string values, for routing through the content chain.

    Structural EXIF findings come from _check_exif on the structural scanner;
    this only collects the text so the content scanner can scan it.
    """
    ext = path.suffix.lower()
    if ext not in {".jpg", ".jpeg", ".png", ".tiff", ".webp"}:
        return ""
    exif_blob = _check_exif(path, [])   # findings discarded — structural owns them
    xmp_blob  = _extract_xmp(path)
    return "\n".join(b for b in (exif_blob, xmp_blob) if b)


def _within_size_limit(path: Path, max_mb: float) -> bool:
    """Cheap stat() gate. The structural scanner emits the size finding; this
    only stops the content scanner reading a file it already knows is oversized.
    """
    try:
        return path.stat().st_size / (1024 * 1024) <= max_mb
    except OSError:
        return False


class FileScanner:
    """Structural file scanner for the scan_file boundary.

    Satisfies Scanner Protocol structurally (scan takes text: str but
    scan_file passes the path as the text argument — see boundaries/_scan.py).

    Structural checks only — MIME, extension, size, filename, PDF markers, SVG
    scripts, EXIF triggers, ZIP bombs, Office macros. Content scanning lives in
    FileContentScanner so that a failing content scanner cannot discard these
    findings: they are independent scanners at the boundary, each governed by
    on_error on its own.
    """

    name = "file_scanner"
    # Deterministic structural inspection of the container — a distinct
    # technique from the content chain, so the two corroborate rather than
    # counting as one method when they flag the same category.
    method_family = "structural_file"

    def __init__(self, max_size_mb: float = 100.0) -> None:
        """max_size_mb: files larger than this are flagged."""
        self._max_size_mb = max_size_mb

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        """text is the file path (str) — passed by run_file_scan.

        Every structural check is blocking CPU or disk work — MIME sniffing,
        PDF parsing, archive decompression. Boundary scanners run under
        asyncio.gather on the shared event loop, so doing it inline stalls
        every other agent turn in the process. Offloaded, as FileSink does for
        its writes.
        """
        return await asyncio.to_thread(self._scan_blocking, text)

    def _scan_blocking(self, text: str) -> ScanResult:
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

        _check_mime(path, findings)
        _check_extension(path, findings)
        _check_double_extension(path, findings)
        _check_size(path, self._max_size_mb, findings)
        _check_filename(path, findings)

        # Archive checks run for every container format, and are keyed off the
        # full suffix list: Path("a.tar.gz").suffix is ".gz", so a single-suffix
        # test cannot tell a compressed tar from a plain gzip stream.
        if _is_archive(path):
            _check_archive(path, findings, self._max_size_mb)

        if ext == ".pdf":
            _check_pdf(path, findings)
        elif ext in {".svg", ".svgz"}:
            _check_svg(path, findings)
        elif ext in {".jpg", ".jpeg", ".png", ".tiff", ".webp"}:
            _check_exif(path, findings)
        elif ext in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"}:
            _check_office_macros(path, findings)
        elif ext in {".docx", ".xlsx", ".pptx"}:
            _check_ooxml(path, findings, self._max_size_mb)

        return ScanResult(findings=findings)


class FileContentScanner:
    """Runs the configured scanner chain over a file's extracted content.

    Receives the file path like every scan_file scanner, then routes two
    surfaces through the chain: text extracted from the document, and the
    EXIF/XMP blob for images — OWASP multimodal-injection coverage.

    Separate from FileScanner so the two failure domains stay independent.
    Boundary scanners run concurrently, so this re-checks the size limit
    itself: without it an oversized file would be read here while the
    structural scanner was still deciding to reject it.
    """

    name = "file_content_scan"
    # Composite: every finding is produced by a scanner in the chain, and is
    # stamped below with that scanner's own family. This value is the Protocol
    # fallback and should never reach a finding.
    method_family = "unknown"

    def __init__(
        self,
        text_scanners: list | None = None,
        max_size_mb: float = 100.0,
    ) -> None:
        self._text_scanners = list(text_scanners) if text_scanners else []
        self._max_size_mb   = max_size_mb

    def _payloads_blocking(self, text: str) -> list[tuple[str, str]]:
        """Extract the surfaces to scan. Blocking — run off the event loop."""
        path = Path(text)
        if not self._text_scanners or not path.exists():
            return []
        if not _within_size_limit(path, self._max_size_mb):
            # Structural scanner reports file.size_exceeded; do not read it.
            return []
        if not _safe_to_extract(path, self._max_size_mb):
            # Archive bomb. A size gate cannot catch these — they are small on
            # disk. Structural scanner reports file.archive_bomb; do not unpack.
            return []

        payloads: list[tuple[str, str]] = []
        extracted = _extract_text(path)
        if extracted.strip():
            payloads.append(("content", extracted))
        metadata = _image_metadata_blob(path)
        if metadata.strip():
            payloads.append(("image_metadata", metadata))
        return payloads

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        """text is the file path (str) — passed by run_file_scan."""
        # Extraction is blocking (archive decompression, PDF parsing); the
        # chain itself is async and stays on the event loop.
        payloads = await asyncio.to_thread(self._payloads_blocking, text)

        findings: list[Finding] = []
        for surface, payload in payloads:
            for scanner in self._text_scanners:
                # Exceptions propagate. run_scan owns the on_error policy, and
                # a failure here no longer costs the structural findings —
                # those come from a different scanner.
                text_result = await scanner.scan(payload, ctx)
                # Carry the producing scanner's technique, not this composite's.
                # run_scan only fills in families a scanner left unset, so a
                # regex-catalog hit inside a document stays distinguishable from
                # the structural pass and the two can corroborate each other.
                family = getattr(scanner, "method_family", "unknown")
                for f in text_result.findings:
                    # Prefix with the surface so the audit trail distinguishes
                    # document-body hits from EXIF/XMP hits without losing the
                    # underlying category.
                    if surface == "image_metadata":
                        findings.append(Finding(
                            scanner=f.scanner,
                            category=f"file.image_metadata.{f.category}",
                            severity=f.severity,
                            detail=f.detail,
                            method_family=family,
                        ))
                    else:
                        findings.append(f.model_copy(update={"method_family": family}))

        return ScanResult(findings=findings)
