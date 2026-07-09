"""
forensics_engine.py — Offline PDF tampering & fraud-detection engine.

Pure Python (PyMuPDF + pikepdf + Pillow). No system binaries, so it deploys on
Streamlit Cloud from requirements.txt alone.

Design:
  * Layer functions extract RAW SIGNALS from a PDF.
  * A rules layer turns signals into FINDINGS, each labelled with:
        severity  : High | Medium | Low | Info
        status    : CONFIRMED (reproducible byte/metadata fact)
                    REVIEW    (anomaly needing human judgment)
                    VERIFY    (needs source files / external check)
        page, section (nearest preceding heading), detail, evidence
  * analyze_document()  -> findings for one file
  * correlate_documents() -> cross-file findings (reused sig/stamp, export clusters)

Nothing here proves intent. Findings SURFACE anomalies for a human examiner.
"""

from __future__ import annotations
import io, os, re, hashlib, datetime
from collections import defaultdict, Counter

import fitz  # PyMuPDF
from PIL import Image

try:
    import pikepdf
except Exception:
    pikepdf = None


# Producers that rewrite the whole file in one pass (destroy revision history)
FLATTENING_PRODUCERS = [
    "quartz pdfcontext", "skia/pdf", "chrome", "chromium", "ghostscript",
    "microsoft: print to pdf", "microsoft print to pdf", "wkhtmltopdf",
    "cairo", "google", "ios ", "macos ",
]
PLACEHOLDER_RE = re.compile(
    r"^(text|click here|enter (date|text|name)|type here|xxx+|lorem ipsum|<[^>]+>|\[[^\]]+\])$",
    re.I,
)
SECTION_NUM_RE = re.compile(r"^(\d{1,2}(?:\.\d{1,3}){0,3})(?:[.\)\s]|$)")
SECTION_KW_RE = re.compile(
    r"^(section|article|exhibit|clause|schedule|annex|appendix|part)\s+([A-Za-z0-9][\w.\-]*)",
    re.I,
)
DATE_RE = re.compile(
    r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}\b",
    re.I,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _finding(layer, severity, status, title, detail, page=None, section=None, evidence=None):
    return {"layer": layer, "severity": severity, "status": status, "title": title,
            "detail": detail, "page": page, "section": section, "evidence": evidence}


def _parse_pdf_date(s):
    if not s:
        return None
    m = re.search(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", str(s))
    if not m:
        return None
    try:
        return datetime.datetime(*[int(x) for x in m.groups()])
    except Exception:
        return None


def _dhash(img, hs=16):
    im = img.convert("L").resize((hs + 1, hs))
    px = im.load()
    return [1 if px[x, y] > px[x + 1, y] else 0 for y in range(hs) for x in range(hs)]


def _hamming(a, b):
    return sum(1 for x, y in zip(a, b) if x != y)


def _lum(color_int):
    r, g, b = (color_int >> 16) & 255, (color_int >> 8) & 255, color_int & 255
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255.0, (r, g, b)


# ---------------------------------------------------------------------------
# section map — nearest preceding heading for any (page, y)
# ---------------------------------------------------------------------------
def build_section_map(doc):
    headings = []  # (page, y_top, label)
    for pno, page in enumerate(doc):
        for b in page.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                spans = l.get("spans", [])
                if not spans:
                    continue
                text = "".join(s["text"] for s in spans).strip()
                if not text or len(text) > 90:
                    continue
                y = l["bbox"][1]
                m = SECTION_KW_RE.match(text)
                if m:
                    headings.append((pno + 1, y, f"{m.group(1).title()} {m.group(2)}"))
                    continue
                m = SECTION_NUM_RE.match(text)
                if m and (spans[0].get("flags", 0) & 16 or len(text) < 70):  # bold-ish or short
                    headings.append((pno + 1, y, m.group(1)))
    headings.sort(key=lambda h: (h[0], h[1]))
    return headings


def nearest_section(section_map, page, y):
    if not section_map or page is None:
        return None
    best = None
    for (p, hy, label) in section_map:
        if (p, hy) <= (page, y if y is not None else 1e9):
            best = label
        else:
            break
    return best


# ---------------------------------------------------------------------------
# raw signal layers
# ---------------------------------------------------------------------------
def layer_identity(path):
    data = open(path, "rb").read()
    last_eof = data.rfind(b"%%EOF")
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header": data[:8].decode("latin1", "replace"),
        "trailing_after_eof": (len(data) - (last_eof + 5)) if last_eof != -1 else None,
    }


def layer_structure(path):
    data = open(path, "rb").read()
    return {
        "eof": data.count(b"%%EOF"),
        "startxref": data.count(b"startxref"),
        "xref_tables": len(re.findall(rb"\nxref\b", data)),
        "trailer_prev": len(re.findall(rb"trailer[\s\S]{0,400}?/Prev", data)),
        "has_sig": bool(re.search(rb"/Type\s*/Sig|/SubFilter\s*/adbe", data)),
    }


def layer_metadata(path):
    md = {"info": {}, "xmp": {}}
    doc = fitz.open(path)
    md["info"] = {k: v for k, v in (doc.metadata or {}).items() if v}
    if pikepdf:
        try:
            pdf = pikepdf.open(path)
            for k, v in (pdf.docinfo or {}).items():
                md["info"].setdefault(str(k).lstrip("/").lower(), str(v))
            try:
                with pdf.open_metadata() as m:
                    md["xmp"] = {k: str(v) for k, v in dict(m).items()}
            except Exception:
                pass
            pdf.close()
        except Exception:
            pass
    return md


def layer_fonts(doc):
    xref_pages = defaultdict(set)
    basefonts = {}
    for pno, page in enumerate(doc):
        for f in page.get_fonts(full=True):
            xref = f[0]
            xref_pages[xref].add(pno + 1)
            basefonts[xref] = f[3]  # basefont name
    return {"xref_pages": {k: sorted(v) for k, v in xref_pages.items()},
            "basefonts": basefonts}


def layer_text(doc, section_map):
    counts = defaultdict(int)
    spans = []
    for pno, page in enumerate(doc):
        for b in page.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                for s in l["spans"]:
                    t = s["text"].strip()
                    if not t:
                        continue
                    counts[s["font"]] += len(t)
                    spans.append((pno + 1, l["bbox"][1], t, s["font"],
                                  round(s["size"], 1), s["color"]))
    dominant = max(counts, key=counts.get) if counts else None
    return {"dominant": dominant, "counts": counts, "spans": spans}


def layer_images(path):
    doc = fitz.open(path)
    out = []
    for pno, page in enumerate(doc):
        parea = abs(page.rect.width * page.rect.height)
        for img in page.get_images(full=True):
            xref = img[0]
            try:
                raw = doc.extract_image(xref)
            except Exception:
                continue
            data = raw["image"]
            try:
                dh = _dhash(Image.open(io.BytesIO(data)))
            except Exception:
                dh = None
            # coverage of the page by this image (full-page-raster test)
            cover = 0.0
            try:
                for r in page.get_image_rects(xref):
                    cover = max(cover, abs(r.width * r.height) / parea if parea else 0)
            except Exception:
                pass
            out.append({"page": pno + 1, "xref": xref, "w": raw.get("width"),
                        "h": raw.get("height"), "ext": raw.get("ext"),
                        "bytes": len(data), "sha16": hashlib.sha256(data).hexdigest()[:16],
                        "dhash": dh, "coverage": cover})
    return out


def layer_drawings(doc, section_map):
    """Fake-redaction & hidden-text detection."""
    findings = []
    for pno, page in enumerate(doc):
        # dark filled boxes with dark text underneath = fake redaction
        try:
            drawings = page.get_drawings()
        except Exception:
            drawings = []
        for d in drawings:
            fill = d.get("fill")
            if not fill:
                continue
            if max(fill) > 0.25:  # not dark
                continue
            r = d.get("rect")
            if not r or r.width < 40 or r.height < 6:
                continue
            try:
                sub = page.get_text("dict", clip=r)
            except Exception:
                continue
            for bb in sub.get("blocks", []):
                for ll in bb.get("lines", []):
                    for ss in ll.get("spans", []):
                        if ss["text"].strip():
                            lum, _ = _lum(ss["color"])
                            if lum < 0.4:  # dark text under a dark box
                                findings.append(_finding(
                                    "Text", "High", "REVIEW",
                                    "Possible fake redaction",
                                    f"Dark fill box on page {pno+1} covers extractable dark "
                                    f"text: '{ss['text'].strip()[:50]}'. Text is still in the "
                                    f"layer and can be recovered.",
                                    page=pno + 1,
                                    section=nearest_section(section_map, pno + 1, r.y0),
                                    evidence=ss["text"].strip()[:80]))
    return findings


# ---------------------------------------------------------------------------
# rules -> findings for a single document
# ---------------------------------------------------------------------------
def analyze_document(path, filename=None):
    filename = filename or os.path.basename(path)
    doc = fitz.open(path)
    section_map = build_section_map(doc)

    ident = layer_identity(path)
    struct = layer_structure(path)
    meta = layer_metadata(path)
    fonts = layer_fonts(doc)
    text = layer_text(doc, section_map)
    imgs = layer_images(path)

    findings = []

    # ---- STRUCTURE ----
    if struct["eof"] > 1 or struct["startxref"] > 1 or struct["trailer_prev"] > 0:
        findings.append(_finding(
            "Structure", "High", "CONFIRMED", "Incremental updates present",
            f"The file contains {struct['eof']} %%EOF markers / "
            f"{struct['startxref']} startxref entries — content was saved in multiple "
            f"generations (edits appended after the original save). Reconstruct and diff "
            f"the revisions to see what changed.",
            evidence=f"eof={struct['eof']} startxref={struct['startxref']} "
                     f"trailer/Prev={struct['trailer_prev']}"))
    if ident["trailing_after_eof"] and ident["trailing_after_eof"] > 4:
        findings.append(_finding(
            "File", "Medium", "REVIEW", "Data after end-of-file marker",
            f"{ident['trailing_after_eof']} bytes follow the final %%EOF. Could be an "
            f"appended payload or a second document stitched on — inspect the tail bytes.",
            evidence=f"{ident['trailing_after_eof']} trailing bytes"))
    if struct["has_sig"]:
        findings.append(_finding(
            "Signature", "Info", "VERIFY", "Digital signature object present",
            "A /Sig object exists. Validate the certificate chain and confirm the "
            "signature covers the whole file (not just an earlier revision) with a PKI "
            "validator — that can't be confirmed offline here.",
            evidence="/Sig present"))

    # ---- METADATA ----
    info = meta["info"]
    producer = (info.get("producer") or "").strip()
    creator = (info.get("creator") or "").strip()
    author = (info.get("author") or "").strip()
    title = (info.get("title") or "").strip()
    cdate = _parse_pdf_date(info.get("creationDate") or info.get("creationdate"))
    mdate = _parse_pdf_date(info.get("modDate") or info.get("moddate"))

    if cdate and mdate and mdate < cdate:
        findings.append(_finding(
            "Metadata", "Medium", "REVIEW", "Modified before created",
            f"ModDate ({mdate}) precedes CreationDate ({cdate}) — inconsistent timestamps.",
            evidence=f"created {cdate} / modified {mdate}"))

    prod_l = producer.lower()
    is_flat = any(p in prod_l for p in FLATTENING_PRODUCERS)
    if is_flat and struct["eof"] <= 1:
        findings.append(_finding(
            "Metadata", "Info", "VERIFY", "Flattened by a print-to-PDF engine",
            f"Producer '{producer}' rewrites the file in one pass, which erases any "
            f"prior revision history. Absence of incremental updates is therefore not "
            f"proof the content was never edited — request the source file "
            f"(.docx/.xlsx) to see the real edit history.",
            evidence=f"Producer={producer}"))

    # internal title reveals a source name / DMS id different from the filename
    if title and (".docx" in title.lower() or ".doc" in title.lower() or
                  re.search(r"\(\d{5,}\)", title) or re.search(r"\brev\s*\d+\b", title, re.I)):
        stem = re.sub(r"[^a-z0-9]", "", os.path.splitext(filename)[0].lower())
        tnorm = re.sub(r"[^a-z0-9]", "", title.lower())
        note = ("Internal document title differs from the file name and exposes source/"
                "template provenance (a source filename, revision, or document-management "
                "number). Confirm the named source matches the represented party and that "
                "no unrelated party/template is embedded.")
        findings.append(_finding(
            "Metadata", "Medium", "VERIFY", "Internal title exposes source provenance",
            note, evidence=f"Title: {title}"))

    if creator and producer and creator.lower() not in prod_l and "word" in creator.lower():
        findings.append(_finding(
            "Metadata", "Info", "REVIEW", "Authored and rendered by different tools",
            f"Created in '{creator}' then written to PDF by '{producer}' (print-to-PDF). "
            f"Normal on its own; relevant as corroboration when combined with other flags.",
            evidence=f"Creator={creator} / Producer={producer}"))

    # ---- FONTS ----
    ids = list(fonts["xref_pages"].keys())
    if len(ids) >= 4:
        srt = sorted(ids)
        med = srt[len(srt) // 2]
        mx = max(ids)
        if mx > med * 5 and mx > 200:
            pages = fonts["xref_pages"][mx]
            bf = fonts["basefonts"].get(mx, "?")
            findings.append(_finding(
                "Fonts", "Medium", "REVIEW", "Late-added font (possible overlay)",
                f"Font '{bf}' sits at object id {mx} while the rest cluster near {med}. "
                f"It appears on page(s) {pages} — content set in a font added late in the "
                f"object stream, which often marks an inserted text box / stamp / overlay.",
                page=pages[0] if pages else None,
                section=nearest_section(section_map, pages[0] if pages else None, 0),
                evidence=f"{bf} @ obj {mx}, pages {pages}"))
    # multiple base body fonts
    fam = Counter()
    for f, n in text["counts"].items():
        base = re.sub(r"^[A-Z]{6}\+", "", f).split("-")[0].split(",")[0]
        fam[base] += n
    big = [b for b, n in fam.items() if n > 800]
    serif = {"TimesNewRomanPSMT", "TimesNewRoman", "Cambria", "Georgia"}
    sans = {"Calibri", "Arial", "ArialMT", "Aptos", "Helvetica", "Verdana"}
    if any(b in serif for b in big) and any(b in sans for b in big):
        findings.append(_finding(
            "Fonts", "Low", "REVIEW", "Mixed base fonts across the document",
            f"Substantial text in both serif and sans-serif base families "
            f"({', '.join(big)}). Consistent with a document assembled from more than one "
            f"source/template — corroborate with headers/footers and logos.",
            evidence=", ".join(big)))

    # ---- TEXT OVERLAYS ----
    # A styled heading reuses the same non-black colour many times (design). A
    # filled field / stamp caption uses a colour on very few spans. Gate overlay
    # detection on RARE colours so headings aren't flagged.
    dom = text["dominant"]
    color_freq = Counter()
    for (_p, _y, _t, _f, _s, color) in text["spans"]:
        _l, (r, g, b) = _lum(color)
        if (r, g, b) != (0, 0, 0):
            color_freq[color] += 1
    seen_overlay = 0
    overlay_dedupe = set()
    for (pno, y, t, font, size, color) in text["spans"]:
        lum, (r, g, b) = _lum(color)
        placeholder = bool(PLACEHOLDER_RE.match(t))
        nonblack = (r, g, b) != (0, 0, 0) and not (abs(r - g) < 20 and abs(g - b) < 20 and lum > 0.25)
        rare_color = color_freq.get(color, 0) <= 4          # one-off colour
        odd_font = dom and font != dom and text["counts"][font] < 400
        if placeholder:
            findings.append(_finding(
                "Text", "High", "CONFIRMED", "Leftover template placeholder",
                f"Placeholder text '{t}' remains on page {pno} — a template field that "
                f"was filled by overlay (or never filled).",
                page=pno, section=nearest_section(section_map, pno, y), evidence=t))
        elif nonblack and rare_color and odd_font and seen_overlay < 25:
            key = (pno, t[:40])
            if key in overlay_dedupe:
                continue
            overlay_dedupe.add(key)
            seen_overlay += 1
            findings.append(_finding(
                "Text", "Medium", "REVIEW", "Overlaid / inserted text",
                f"'{t[:60]}' on page {pno} is set in {font} at {size}pt in a rare non-black "
                f"colour (RGB {r},{g},{b}) used almost nowhere else, unlike the body font "
                f"({dom}). Likely dropped on as a text box or form field rather than typed "
                f"into the document body.",
                page=pno, section=nearest_section(section_map, pno, y),
                evidence=f"{t[:40]} | {font} | rgb({r},{g},{b})"))
        # hidden white-on-white text
        if lum > 0.92 and t and len(t) > 2:
            findings.append(_finding(
                "Text", "Low", "REVIEW", "Near-white (possibly hidden) text",
                f"Very light text '{t[:40]}' on page {pno} (RGB {r},{g},{b}). Verify it "
                f"isn't hidden content over a light background.",
                page=pno, section=nearest_section(section_map, pno, y), evidence=t[:40]))

    # ---- fake redaction / drawings ----
    findings.extend(layer_drawings(doc, section_map))

    # ---- multi-vintage footer/header dates ----
    page_dates = defaultdict(set)
    for pno, page in enumerate(doc):
        for m in DATE_RE.finditer(page.get_text("text")):
            page_dates[m.group(0).strip().lower()].add(pno + 1)
    repeated = {d: ps for d, ps in page_dates.items() if len(ps) >= 3}
    if len(repeated) >= 2:
        listing = "; ".join(f"'{d}' on {len(ps)} pages" for d, ps in
                            sorted(repeated.items(), key=lambda x: -len(x[1]))[:5])
        findings.append(_finding(
            "Text", "Medium", "CONFIRMED", "Multiple template vintages",
            f"Several distinct dates each recur across many pages (footer/header lines): "
            f"{listing}. A single document carrying multiple template dates suggests parts "
            f"were assembled from different template versions.",
            evidence=listing))

    # ---- full-page raster inside a text PDF ----
    for im in imgs:
        if im["coverage"] > 0.8:
            txt_len = len(doc[im["page"] - 1].get_text("text").strip())
            if txt_len < 60:
                findings.append(_finding(
                    "Image", "Low", "REVIEW", "Page is a full-page image",
                    f"Page {im['page']} is a single raster image ({im['w']}x{im['h']}) with "
                    f"almost no text layer — a scanned or image-only page inside an "
                    f"otherwise digital document. Apply image-splice checks (ELA/noise) to it.",
                    page=im["page"], evidence=f"{im['w']}x{im['h']} covers "
                                              f"{int(im['coverage']*100)}% of page"))

    summary = {
        "file": filename,
        "pages": doc.page_count,
        "producer": producer, "creator": creator, "author": author, "title": title,
        "created": str(cdate) if cdate else info.get("creationDate", ""),
        "sha256": ident["sha256"],
        "size": ident["size"],
    }
    return {"summary": summary, "findings": findings, "_images": imgs,
            "_created_dt": cdate, "_producer": producer, "_author": author}


# ---------------------------------------------------------------------------
# cross-document correlation
# ---------------------------------------------------------------------------
def correlate_documents(results):
    """results: dict filename -> analyze_document() output. Returns list of findings."""
    findings = []
    names = list(results.keys())

    # exact image reuse across files
    by_sha = defaultdict(list)
    for fn, r in results.items():
        for im in r["_images"]:
            by_sha[im["sha16"]].append((fn, im))
    for sha, locs in by_sha.items():
        files = {fn for fn, _ in locs}
        if len(files) > 1:
            where = "; ".join(f"{fn} p{im['page']}" for fn, im in locs)
            findings.append(_finding(
                "Cross-document", "High", "CONFIRMED", "Identical image reused across files",
                f"The same image (byte-identical, sha {sha}) appears in multiple files: "
                f"{where}. A byte-identical graphic pasted across documents.",
                evidence=where))

    # perceptual reuse across files (reused signature/stamp)
    flat = [(fn, im) for fn, r in results.items() for im in r["_images"] if im["dhash"]]
    seen = set()
    for i in range(len(flat)):
        for j in range(i + 1, len(flat)):
            f1, a = flat[i]; f2, b = flat[j]
            if f1 == f2 or a["sha16"] == b["sha16"]:
                continue
            d = _hamming(a["dhash"], b["dhash"])
            if d <= 20:
                key = tuple(sorted([a["sha16"], b["sha16"]]))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding(
                    "Cross-document", "High", "CONFIRMED",
                    "Reused signature/stamp/graphic across files",
                    f"A near-identical graphic (perceptual distance {d}/256) appears in "
                    f"{f1} p{a['page']} ({a['w']}x{a['h']}) and {f2} p{b['page']} "
                    f"({b['w']}x{b['h']}) with different bytes/sizes — the same underlying "
                    f"asset re-scaled/re-compressed, not an independently produced signature. "
                    f"Applying a signature stamp can be legitimate; treat these as ONE reused "
                    f"asset, not independent signatures.",
                    evidence=f"dist {d}: {f1} p{a['page']} <-> {f2} p{b['page']}"))

    # export-session clustering: same producer, close times, different authors
    items = [(fn, r["_producer"], r["_created_dt"], r["_author"])
             for fn, r in results.items() if r["_created_dt"]]
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            f1, p1, t1, a1 = items[i]; f2, p2, t2, a2 = items[j]
            if p1 and p1 == p2 and abs((t1 - t2).total_seconds()) <= 15 * 60 and a1 != a2:
                findings.append(_finding(
                    "Cross-document", "Medium", "REVIEW",
                    "Files re-exported in one session from different sources",
                    f"{f1} (author '{a1}') and {f2} (author '{a2}') were written by the same "
                    f"engine within "
                    f"{int(abs((t1-t2).total_seconds()))}s, but carry different authors — "
                    f"consistent with one person re-exporting a pack assembled from several "
                    f"source files. These PDFs are re-prints, not independent originals.",
                    evidence=f"{f1} vs {f2}: {abs((t1-t2).total_seconds()):.0f}s apart"))
                break
    return findings


# ---------------------------------------------------------------------------
# image fetch for UI display
# ---------------------------------------------------------------------------
def get_image_png(path, xref):
    doc = fitz.open(path)
    raw = doc.extract_image(xref)
    data = raw["image"]
    im = Image.open(io.BytesIO(data)).convert("RGB")
    buf = io.BytesIO(); im.save(buf, "PNG")
    return buf.getvalue()


MANUAL_CHECKLIST = [
    ("Source files", "Obtain and analyse the source .docx/.xlsx (their own metadata and "
     "tracked changes reveal edit history that print-to-PDF flattening erases)."),
    ("Original from issuer", "Compare against the original document obtained directly from "
     "the issuing party/authority, not a re-saved copy."),
    ("Company / entity registration", "Verify each party's registration, officers and "
     "incorporation date on the relevant authoritative register."),
    ("Signatory authority", "Confirm each signatory had authority to bind their entity on "
     "the stated date."),
    ("Reused signatures/stamps", "For any reused signature/stamp flagged, confirm it was "
     "applied with authorisation for each document."),
    ("Cryptographic signatures", "If a /Sig object is present, validate the certificate "
     "chain and that it covers the whole file with a PKI validator."),
    ("Dates vs reality", "Cross-check all dates against known events (incorporation, "
     "approvals, prior correspondence)."),
    ("Scanned/image pages", "Run ELA / noise / copy-move analysis on any full-page raster "
     "or photographed image."),
    ("Amounts & terms", "Reconcile figures/terms across all documents in the pack for "
     "internal consistency."),
]
