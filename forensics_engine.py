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

# Generic words that show up in document titles but are NOT company/brand names, so
# they should not be treated as a "foreign brand" leaking through the internal title.
GENERIC_TITLE_WORDS = {
    "microsoft", "word", "excel", "powerpoint", "adobe", "acrobat", "pages", "quartz",
    "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "rtf",
    "final", "draft", "copy", "rev", "revision", "version", "ver", "signed", "stamped",
    "clean", "master", "template", "form",
    "agreement", "distribution", "international", "term", "sheet", "firm", "commitment",
    "deal", "summary", "memorandum", "association", "certificate", "incorporation",
    "contract", "letter", "invoice", "statement", "report", "schedule", "exhibit",
    "annex", "appendix", "addendum", "amendment", "the", "and", "for", "of", "to", "in",
    "a", "an", "document", "new", "with",
    "january", "february", "march", "april", "may", "june", "july", "august",
    "september", "october", "november", "december",
}


# Place names and web/legal-suffix words that look brand-like but are not a company,
# so the entity-comparison (esp. on OCR'd stamp text) doesn't false-positive on them.
PLACE_WORDS = {
    "london", "munich", "delhi", "newdelhi", "singapore", "jakarta", "dubai", "india",
    "uae", "emirates", "abudhabi", "california", "mumbai", "york", "newyork", "paris",
    "tokyo", "beijing", "shanghai", "germany", "france", "england", "britain", "usa",
    "america", "kingdom", "united", "states", "county", "street", "road", "avenue",
    "crescent", "house", "floor", "suite",
}
WEB_SUFFIX_WORDS = {
    "www", "http", "https", "com", "org", "net", "email", "info", "mail", "tel", "fax",
    "phone", "ltd", "limited", "inc", "incorporated", "llc", "gmbh", "plc", "corp",
    "corporation", "company", "group", "holdings", "global",
}


def _title_tokens(s):
    """Word-ish tokens from a string, lowercased, length >= 3."""
    return [w for w in re.split(r"[^A-Za-z0-9]+", s or "") if len(w) >= 3]


def _foreign_brand(text, reference_norm, extra_stop=()):
    """Return a brand-like token in `text` that is absent from `reference_norm`
    (a normalised, alnum-only reference string), or None. Mixed-case tokens like
    'MagnetTx' and unusual capitalised words are the strongest signals. Generic,
    place, and web/suffix words are ignored so it doesn't fire on cities/URLs."""
    for raw in re.split(r"[^A-Za-z0-9]+", text or ""):
        if len(raw) < 4:
            continue
        low = raw.lower()
        if (low in GENERIC_TITLE_WORDS or low in PLACE_WORDS or low in WEB_SUFFIX_WORDS
                or low in extra_stop or raw.isdigit()):
            continue
        # brand-like: mixed-case (MagnetTx) OR a capitalised alphabetic word
        mixed_case = raw != raw.lower() and raw != raw.upper()
        capitalised = raw[:1].isupper() and raw.isalpha()
        if not (mixed_case or capitalised):
            continue
        if low not in reference_norm:              # not present in the reference text
            return raw
    return None


def _foreign_brand_in_title(title, filename):
    """Foreign brand in the internal title vs the file name (used by metadata checks)."""
    fname_norm = re.sub(r"[^a-z0-9]", "", os.path.splitext(filename or "")[0].lower())
    return _foreign_brand(title, fname_norm)


# ---------------------------------------------------------------------------
# OCR — read text INSIDE images (stamps, signatures, scanned pages). RapidOCR is
# pure-pip (no system binary) and light enough for the Streamlit free tier. The
# model is loaded once per process (lazy) so reruns don't reload it.
# ---------------------------------------------------------------------------
_OCR = None
_OCR_TRIED = False


def _get_ocr():
    global _OCR, _OCR_TRIED
    if _OCR_TRIED:
        return _OCR
    _OCR_TRIED = True
    try:
        from rapidocr_onnxruntime import RapidOCR
        _OCR = RapidOCR()
    except Exception:
        _OCR = None
    return _OCR


def _ocr_foreign_entity(text, native_words):
    """Find a distinctive company/brand name inside OCR'd image text that is NOT in the
    document. Robust to OCR noise: only MIXED-CASE brandmarks (stamps/seals/cities come
    out ALL-CAPS, so they're skipped), and fuzzy-matched against the document's words so
    an OCR misread of a name that IS in the document doesn't false-positive."""
    import difflib
    for raw in re.split(r"[^A-Za-z0-9]+", text or ""):
        if len(raw) < 4 or raw.isdigit():
            continue
        low = raw.lower()
        if low in GENERIC_TITLE_WORDS or low in PLACE_WORDS or low in WEB_SUFFIX_WORDS:
            continue
        # distinctive brandmark = mixed case (has both cases); reject ALL-CAPS / all-lower
        if raw == raw.upper() or raw == raw.lower():
            continue
        if low in native_words:
            continue
        if difflib.get_close_matches(low, list(native_words), n=1, cutoff=0.84):
            continue                              # likely an OCR misread of a doc word
        return raw
    return None


def _fuzzy_in(word, hay):
    """Is `word` approximately present as a substring of `hay`? Tolerant of the OCR
    concatenation/misreads that turn 'RADIOSURGERY GLOBAL' into 'RADIOSURCERYGLOBAL'."""
    if len(word) < 5 or not hay:
        return False
    if word in hay:
        return True
    import difflib
    L = len(word)
    for i in range(0, max(len(hay) - L + 1, 1)):
        if difflib.SequenceMatcher(None, word, hay[i:i + L + 2]).ratio() >= 0.8:
            return True
    return False


def _stamp_name_overlap(text, native_text):
    """Distinctive document entity words that appear (fuzzily) inside a stamp's text —
    i.e. the stamp names a party the document is actually about. Checks every distinctive
    long word (>=8 chars) so it works whether the party name is frequent or rare, and is
    tolerant of the OCR concatenation/misreads in stamp text."""
    stamp_norm = re.sub(r"[^a-z0-9]", "", (text or "").lower())
    words = {w for w in re.split(r"[^a-z0-9]+", (native_text or "").lower())
             if len(w) >= 8 and w not in GENERIC_TITLE_WORDS
             and w not in PLACE_WORDS and w not in WEB_SUFFIX_WORDS}
    return sorted({w for w in words if _fuzzy_in(w, stamp_norm)})[:3]


def _ocr_image(pil_img, max_dim=1600):
    """Run OCR on a PIL image; return [(text, confidence), ...]. Caps resolution to
    keep memory/CPU bounded on the free tier."""
    ocr = _get_ocr()
    if ocr is None:
        return []
    import numpy as np
    im = pil_img.convert("RGB")
    if max(im.size) > max_dim:
        r = max_dim / max(im.size)
        im = im.resize((max(int(im.width * r), 1), max(int(im.height * r), 1)))
    try:
        res, _ = ocr(np.asarray(im))
    except Exception:
        return []
    out = []
    for item in (res or []):
        try:
            out.append((str(item[1]), float(item[2])))
        except Exception:
            pass
    return out


def layer_ocr(imgs, native_text, extract_pil, max_images=20):
    """Read text inside images and compare stamp/logo text against the document's own
    entities. Returns (findings, {sha16: ocr_text}).
      * logo/stamp images  -> flag a company/brand named in the image but NOT in the doc
      * full-page scans     -> surface the OCR'd text so it can be read/checked
    """
    if _get_ocr() is None:
        return [], {}
    native_words = {w for w in re.split(r"[^a-z0-9]+", (native_text or "").lower())
                    if len(w) >= 4}
    findings, ocr_texts, seen, n = [], {}, set(), 0
    for im in imgs:
        sha = im.get("sha16")
        if sha in seen:
            continue
        seen.add(sha)
        w, h = im.get("w") or 0, im.get("h") or 0
        if w * h < 40 * 40:                      # skip tiny icons
            continue
        if n >= max_images:
            break
        pil = extract_pil(im)
        if pil is None:
            continue
        toks = _ocr_image(pil)
        text = " ".join(t for t, _c in toks).strip()
        if not text:
            continue
        n += 1
        ocr_texts[sha] = text
        page = im.get("page")
        ref = (page, im.get("xref")) if im.get("xref") is not None else None
        png = im.get("_png")                     # Office images carry their own bytes
        if im.get("coverage", 0) > 0.8:
            snippet = re.sub(r"\s+", " ", text)[:220]
            findings.append(_finding(
                "Image", "Info", "REVIEW", "Text read from a scanned page (OCR)",
                f"Page {page} is a scanned image with no digital text, so OCR was used to read "
                f"it. It reads: \"{snippet}\". OCR can misread characters, so treat exact "
                f"figures and names as read-with-care, not certified.",
                page=page, evidence=f"OCR ({len(text)} chars): {snippet}",
                image_ref=ref, image_png=png))
        else:
            foreign = _ocr_foreign_entity(text, native_words)
            where = f" on page {page}" if page else " in this file"
            if foreign:
                findings.append(_finding(
                    "Image", "Medium", "REVIEW",
                    "A logo or stamp names a company not in the document",
                    f"OCR read the text inside a graphic{where} and it names '{foreign}', which "
                    f"does not appear anywhere in the document's own text. A logo or stamp for a "
                    f"different company than the document is about is a strong provenance flag — "
                    f"you can see it on the page, not just in the metadata.",
                    page=page,
                    evidence=f"image text reads '{text[:60]}'; '{foreign}' not in document text",
                    image_ref=ref, image_png=png))
            else:
                # Positive read-out for a signature/stamp (mid-page image, not a header
                # logo): always show what it says, and whether the name(s) match the doc.
                rel_y = im.get("rel_y")
                is_stamp = rel_y is None or rel_y > 0.2
                if is_stamp and len(text.split()) >= 2 and re.search(r"[A-Za-z]{4}", text):
                    overlap = _stamp_name_overlap(text, native_text)
                    snippet = re.sub(r"\s+", " ", text)[:90]
                    if overlap:
                        title = "Signature/stamp read — name matches the document"
                        verdict = (f"The name(s) it contains ({', '.join(overlap)}) do appear in "
                                   f"this document, so the stamp is consistent with the party "
                                   f"the document is about.")
                    else:
                        title = "Signature/stamp read — confirm the name"
                        verdict = ("We could not automatically match a company/party name on it "
                                   "to this document's text — confirm the name on the stamp is "
                                   "the party this document is meant to be from.")
                    findings.append(_finding(
                        "Image", "Info", "REVIEW", title,
                        f"A signature or stamp{where} was read by OCR. It reads: \"{snippet}\". "
                        f"{verdict} (A reused signature can still be legitimate — this only "
                        f"checks the name printed on it.)",
                        page=page, evidence=f"stamp text: {snippet}",
                        image_ref=ref, image_png=png))
    return findings, ocr_texts


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _finding(layer, severity, status, title, detail, page=None, section=None, evidence=None,
             image_ref=None, image_refs=None, image_png=None):
    # image_ref:  optional (page, xref) pointing at the single image this finding is about.
    # image_refs: optional list of (page, xref) when a finding is about several images
    #             (e.g. multiple distinct logos) — reports render them as a thumbnail row.
    # image_png:  optional raw PNG bytes of a GENERATED image (e.g. an ELA heatmap) to embed
    #             directly. Not serialised to JSON.
    return {"layer": layer, "severity": severity, "status": status, "title": title,
            "detail": detail, "page": page, "section": section, "evidence": evidence,
            "image_ref": image_ref, "image_refs": image_refs, "image_png": image_png}


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


# Editing-software names that should not appear inside a "scanned"/original image
IMAGE_EDITORS = [
    "photoshop", "gimp", "illustrator", "affinity", "pixelmator", "snapseed",
    "lightroom", "coreldraw", "paint.net", "photopea", "canva", "figma",
    "inkscape", "acorn", "sketch",
]


def _ela(pil_img, quality=90, grid=8):
    """Error-Level Analysis. Re-save as JPEG and diff; genuinely uniform (untouched)
    scans show even, low residuals, while a pasted/edited region compresses
    differently and lights up. Returns (heatmap_png_bytes, hotspot_ratio, max_block).
    ELA is meaningful only for scanned/photographed rasters, not born-digital text.
    """
    from PIL import ImageChops, ImageEnhance
    im = pil_img.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf)
    ela = ImageChops.difference(im, resaved)
    extrema = ela.getextrema()
    max_diff = max(e[1] for e in extrema) or 1
    ela = ImageEnhance.Brightness(ela).enhance(min(255.0 / max_diff, 20))
    # localized-hotspot score: compare the brightest grid block to the median block
    g = ela.convert("L").resize((grid, grid))
    vals = sorted(g.tobytes())
    median = vals[len(vals) // 2] or 1
    max_block = vals[-1]
    ratio = max_block / max(median, 1)
    png = io.BytesIO()
    ela.save(png, "PNG")
    return png.getvalue(), ratio, max_block


def _copy_move(pil_img, min_cluster=50):
    """Copy-move forgery detection (roadmap #8): find a region duplicated elsewhere in
    the SAME image by matching ORB keypoints against themselves and looking for many
    matches that share the same translation offset (a pasted block moves as one).
    The threshold sits well above the baseline that ordinary repeated text/layout
    produces (~20) but below a real cloned block (hundreds). Returns match count or 0."""
    import cv2
    import numpy as np
    arr = np.asarray(pil_img.convert("L"))
    if arr.shape[0] < 80 or arr.shape[1] < 80:
        return 0
    orb = cv2.ORB_create(nfeatures=5000)
    kp, des = orb.detectAndCompute(arr, None)
    if des is None or len(kp) < 20:
        return 0
    bf = cv2.BFMatcher(cv2.NORM_HAMMING)
    knn = bf.knnMatch(des, des, k=4)
    offsets = defaultdict(int)
    for group in knn:
        for cand in group:
            if cand.queryIdx == cand.trainIdx or cand.distance > 30:
                continue
            p1 = kp[cand.queryIdx].pt
            p2 = kp[cand.trainIdx].pt
            dx, dy = p1[0] - p2[0], p1[1] - p2[1]
            if (dx * dx + dy * dy) ** 0.5 < 40:      # too close = same feature
                continue
            offsets[(round(dx / 8), round(dy / 8))] += 1   # quantise the offset
    if not offsets:
        return 0
    best = max(offsets.values()) // 2      # each pair counted from both ends
    return best if best >= min_cluster else 0


def _noise_map(pil_img, grid=8):
    """Estimate local sensor/compression noise across the image. A region pasted from
    another source usually has a different noise profile than its surroundings.
    Returns (heatmap_png_bytes, outlier_ratio). numpy-based (roadmap #10)."""
    import numpy as np
    from PIL import ImageFilter
    g = pil_img.convert("L")
    hp = np.asarray(g, dtype=np.float32) - np.asarray(
        g.filter(ImageFilter.GaussianBlur(2)), dtype=np.float32)  # high-pass = noise
    h, w = hp.shape
    bh, bw = max(h // grid, 1), max(w // grid, 1)
    blocks = np.zeros((grid, grid), dtype=np.float32)
    for i in range(grid):
        for j in range(grid):
            blk = hp[i * bh:(i + 1) * bh, j * bw:(j + 1) * bw]
            blocks[i, j] = float(blk.std()) if blk.size else 0.0
    med = float(np.median(blocks)) or 1e-3
    mx = float(blocks.max())
    ratio = mx / med
    # heatmap: normalise block std, upscale to a small image
    norm = (blocks - blocks.min()) / (blocks.ptp() or 1) * 255.0
    heat = Image.fromarray(norm.astype("uint8")).resize((256, 256), Image.NEAREST)
    buf = io.BytesIO()
    heat.convert("L").save(buf, "PNG")
    return buf.getvalue(), ratio


def _exif_summary(img):
    """Pull the forensically interesting EXIF tags out of a PIL image, if any."""
    try:
        exif = img.getexif()
    except Exception:
        return {}
    if not exif:
        return {}
    # tag ids: 0x0131 Software, 0x0132 DateTime, 0x010F Make, 0x0110 Model, 0x8825 GPSInfo
    out = {}
    software = exif.get(0x0131)
    if software:
        out["software"] = str(software).strip()
    dt = exif.get(0x0132)
    if dt:
        out["datetime"] = str(dt).strip()
    make = exif.get(0x010F)
    model = exif.get(0x0110)
    if make or model:
        out["camera"] = " ".join(str(x).strip() for x in (make, model) if x)
    if 0x8825 in exif:
        out["gps"] = True
    return out


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


def layer_signatures(path):
    """Validate embedded cryptographic (PKI) signatures with pyhanko (roadmap #9):
    is the signed content intact, does the signature cover the WHOLE file, and who
    signed. Trust-chain validation needs online roots, so we report what can be
    established offline and say so. Returns a list of findings."""
    findings = []
    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext
    except Exception:
        return findings
    try:
        with open(path, "rb") as fh:
            reader = PdfFileReader(fh)
            embedded = list(reader.embedded_signatures)
            if not embedded:
                return findings
            vc = ValidationContext(allow_fetching=False)
            for i, sig in enumerate(embedded):
                intact = covers = signer = None
                try:
                    status = validate_pdf_signature(sig, vc)
                    intact = getattr(status, "intact", None)
                    cov = getattr(status, "coverage", None)
                    covers = "ENTIRE_FILE" in str(cov).upper() if cov is not None else None
                    cert = getattr(status, "signing_cert", None)
                    if cert is not None:
                        signer = cert.subject.human_friendly
                except Exception:
                    pass
                if intact is False:
                    findings.append(_finding(
                        "Signature", "High", "CONFIRMED",
                        "Digital signature is broken (content changed after signing)",
                        f"Signature {i+1} does not match the content it covers — the signed "
                        f"bytes were altered after signing. This is a definitive sign the "
                        f"document was changed after it was signed. Signer as stated: "
                        f"{signer or 'unknown'}.",
                        evidence=f"pyhanko: intact=False signer={signer}"))
                elif covers is False:
                    findings.append(_finding(
                        "Signature", "High", "REVIEW",
                        "Signature covers only part of the file",
                        f"Signature {i+1} is intact but does NOT cover the whole file — content "
                        f"was added after this revision was signed (the classic 'sign then "
                        f"append' attack). Signer: {signer or 'unknown'}.",
                        evidence=f"pyhanko: intact=True covers_whole_file=False signer={signer}"))
                else:
                    findings.append(_finding(
                        "Signature", "Info", "VERIFY",
                        "Digital signature present and internally intact",
                        f"Signature {i+1} is cryptographically intact and (as far as can be "
                        f"checked offline) covers the file. Signer as stated: "
                        f"{signer or 'unknown'}. Whether that signer is TRUSTED still needs an "
                        f"online certificate/revocation check against trusted roots.",
                        evidence=f"pyhanko: intact={intact} covers_whole={covers} signer={signer}"))
    except Exception:
        pass
    return findings


def layer_revisions(path):
    """Reconstruct each saved generation of an incrementally-updated PDF by truncating
    the file at each %%EOF and reopening it, then return the extracted text per
    revision (oldest first). Lets us DIFF revisions to show what actually changed."""
    data = open(path, "rb").read()
    ends = [m.end() for m in re.finditer(rb"%%EOF", data)]
    if len(ends) < 2:
        return []
    texts = []
    for end in ends:
        prefix = data[:end]
        try:
            d = fitz.open(stream=prefix, filetype="pdf")
            texts.append("\n".join(p.get_text("text") for p in d))
            d.close()
        except Exception:
            texts.append(None)
    return [t for t in texts if t is not None]


def layer_metadata(path):
    md = {"info": {}, "xmp": {}}
    doc = fitz.open(path)
    md["info"] = {k: v for k, v in (doc.metadata or {}).items() if v}
    try:
        if hasattr(doc, 'get_xml_metadata'):
            xml = doc.get_xml_metadata()
            if xml:
                md["xmp_raw"] = xml
    except Exception:
        pass
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
    size_counts = defaultdict(int)
    spans = []
    for pno, page in enumerate(doc):
        for b in page.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                for s in l["spans"]:
                    t = s["text"].strip()
                    if not t:
                        continue
                    counts[s["font"]] += len(t)
                    size_counts[round(s["size"], 1)] += len(t)
                    spans.append((pno + 1, l["bbox"][1], t, s["font"],
                                  round(s["size"], 1), s["color"]))
    dominant = max(counts, key=counts.get) if counts else None
    dominant_size = max(size_counts, key=size_counts.get) if size_counts else None
    return {"dominant": dominant, "dominant_size": dominant_size,
            "counts": counts, "spans": spans}


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
            exif = {}
            try:
                _pi = Image.open(io.BytesIO(data))
                dh = _dhash(_pi)
                exif = _exif_summary(_pi)
            except Exception:
                dh = None
            # coverage of the page by this image (full-page-raster test) and its
            # top position on the page (0 = page top, 1 = bottom) to tell a header
            # logo from a mid-page signature.
            cover = 0.0
            top_y = None
            try:
                ph = page.rect.height or 1
                for r in page.get_image_rects(xref):
                    cover = max(cover, abs(r.width * r.height) / parea if parea else 0)
                    ry = r.y0 / ph
                    top_y = ry if top_y is None else min(top_y, ry)
            except Exception:
                pass
            out.append({"page": pno + 1, "xref": xref, "w": raw.get("width"),
                        "h": raw.get("height"), "ext": raw.get("ext"),
                        "bytes": len(data), "sha16": hashlib.sha256(data).hexdigest()[:16],
                        "dhash": dh, "coverage": cover, "exif": exif, "rel_y": top_y})
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


def _font_source_id(buf):
    """A 'source fingerprint' for an embedded font, based on the actual font DESIGN
    (units-per-em + design revision + the outline table format). Two same-named fonts
    with different fingerprints are genuinely different font programs (different
    version/foundry) — a real splice. Subsetting the SAME font does NOT change these,
    so it won't false-positive on ordinary re-embedding."""
    from fontTools.ttLib import TTFont
    ft = TTFont(io.BytesIO(buf), fontNumber=0, lazy=True)
    upm = ft["head"].unitsPerEm if "head" in ft else 0
    rev = round(float(ft["head"].fontRevision), 3) if "head" in ft else 0
    outline = "cff" if "CFF " in ft else ("glyf" if "glyf" in ft else "?")
    return (upm, rev, outline)


def layer_font_glyphs(doc):
    """Compare embedded fonts that share a name: identical name + different source
    fingerprint = a splice (roadmap #3). Uses fonttools on the embedded font program."""
    findings = []
    # collect pages per font xref, and the font's display name
    xref_pages = defaultdict(set)
    xref_name = {}
    for pno in range(doc.page_count):
        for f in doc[pno].get_fonts(full=True):
            xref = f[0]
            xref_pages[xref].add(pno + 1)
            xref_name[xref] = re.sub(r"^[A-Z]{6}\+", "", f[3] or "")
    by_name = defaultdict(dict)   # name -> {source_fingerprint: set(pages)}
    for xref, pages in xref_pages.items():
        try:
            _n, ext, _t, buf = doc.extract_font(xref)
        except Exception:
            continue
        if not buf or ext not in ("ttf", "otf", "cff", "woff"):
            continue
        try:
            sid = _font_source_id(buf)
        except Exception:
            continue
        by_name[xref_name[xref]].setdefault(sid, set()).update(pages)
    for name, sources in by_name.items():
        if len(sources) >= 2:
            descs = "; ".join(f"source {i+1} on pages {sorted(p)[:6]}"
                              for i, (s, p) in enumerate(sources.items()))
            findings.append(_finding(
                "Fonts", "Medium", "REVIEW", "Same font name but two different font sources",
                f"The font '{name}' appears in this document built from {len(sources)} different "
                f"sources (different foundry/version fingerprints), even though the name is "
                f"identical. Passing off the same font name is how an inserted clause is hidden "
                f"— genuine single-source text uses one identical font program throughout. "
                f"{descs}.",
                page=min(min(p) for p in sources.values()),
                evidence=f"'{name}': {len(sources)} distinct font fingerprints"))
    return findings


def layer_watermarks(doc, text):
    """Detect large, faint, repeated text (a watermark) and flag it if it appears on
    only SOME pages — an inconsistent watermark can mean pages were swapped in/out."""
    findings = []
    if doc.page_count < 2:
        return findings
    body_size = text.get("dominant_size") or 10
    # candidate watermark spans: large + light-grey (not black, not near-white)
    wm_pages = defaultdict(set)
    for (pno, y, t, font, size, color) in text["spans"]:
        lum, (r, g, b) = _lum(color)
        greyish = abs(r - g) < 25 and abs(g - b) < 25
        if size >= body_size + 4 and greyish and 0.45 < lum < 0.9 and len(t) >= 3:
            wm_pages[t.strip().lower()].add(pno)
    for wtext, pages in wm_pages.items():
        if len(pages) < 2:
            continue
        covered = len(pages)
        total = doc.page_count
        if covered < total:  # present on some but not all pages
            findings.append(_finding(
                "Watermark", "Medium", "REVIEW", "Watermark appears on only some pages",
                f"A faint, large repeated mark reading '{wtext[:40]}' looks like a watermark, "
                f"but it appears on {covered} of {total} pages rather than all of them. An "
                f"inconsistent watermark can mean pages were added or replaced after the "
                f"watermark was applied.",
                evidence=f"'{wtext[:40]}' on {covered}/{total} pages"))
    return findings


def layer_signature_blocks(doc):
    """Detect signature blocks a named party has NOT completed (no signature image and
    no date). Position-aware so two-column blocks are attributed to the right person.
    An agreement executed by only some parties is a first-order underwriting flag."""
    findings = []
    NON_SIGNATORY = re.compile(
        r"\b(ltd|inc|llc|limited|gmbh|corp|company|investments|global|representative|"
        r"contact|quality|authorized|authorised|print|below)\b|[()]", re.I)
    for pno, page in enumerate(doc):
        ptext = page.get_text("text")
        # signature context: explicit signature words, or a By:/Title: execution block
        if not (re.search(r"signature|signed|on behalf of|\(signature\)", ptext, re.I) or
                (re.search(r"\bby\s*:", ptext, re.I) and re.search(r"\btitle\s*[:.]", ptext, re.I))):
            continue
        ph = page.rect.height or 1
        names, dates = [], []
        for b in page.get_text("dict")["blocks"]:
            for l in b.get("lines", []):
                t = "".join(s["text"] for s in l["spans"]).strip()
                if not t:
                    continue
                x, y = l["bbox"][0], l["bbox"][1]
                mn = re.match(r"name\s*[:.]?\s*(.+)$", t, re.I)
                md = re.match(r"date\s*[:.]?\s*(.*)$", t, re.I)
                if mn:
                    v = mn.group(1).strip()
                    if (v and 1 <= len(v.split()) <= 4 and re.search(r"[A-Za-z]{3}", v)
                            and not NON_SIGNATORY.search(v)):
                        names.append((x, y, v))
                elif md and re.search(r"\d{2}", md.group(1) or ""):
                    dates.append((x, y))
        if not names:
            continue
        sig_imgs = []           # small (non-full-page) images = candidate signatures/stamps
        for im in page.get_images(full=True):
            try:
                for r in page.get_image_rects(im[0]):
                    if r.height / ph < 0.5:
                        sig_imgs.append((r.x0, r.y0, r.y1))
            except Exception:
                pass
        unsigned = []
        for nx, ny, name in names:
            dated = any(abs(dx - nx) < 110 and ny - 10 < dy < ny + 95 for dx, dy in dates)
            has_img = any(abs(ix - nx) < 130 and (ny - 135 < iy1 and iy0 < ny + 175)
                          for ix, iy0, iy1 in sig_imgs)
            if not (dated or has_img):
                unsigned.append(name)
        unsigned = list(dict.fromkeys(unsigned))
        if unsigned:
            one = len(unsigned) == 1
            findings.append(_finding(
                "Signature", "High", "REVIEW", "Signature block appears unsigned",
                f"On page {pno+1}, the signature block for {', '.join(unsigned)} has no "
                f"signature and no date filled in — {'this party appears' if one else 'these parties appear'} "
                f"not to have executed the document. An agreement signed by only some of its "
                f"parties may not be binding.",
                page=pno + 1,
                evidence=f"unsigned/undated: {', '.join(unsigned)} (page {pno+1})"))
    return findings


def layer_redactions(doc, section_map):
    """Redaction verification: a redaction annotation that still has extractable text
    under it means the redaction was never actually applied (text is recoverable)."""
    findings = []
    for pno, page in enumerate(doc):
        try:
            annots = page.annots() or []
        except Exception:
            continue
        for a in annots:
            try:
                atype = a.type[1].lower()
            except Exception:
                atype = ""
            if "redact" not in atype:
                continue
            try:
                sub = page.get_text("text", clip=a.rect).strip()
            except Exception:
                sub = ""
            if sub:
                findings.append(_finding(
                    "Text", "High", "CONFIRMED", "Redaction not applied (text recoverable)",
                    f"Page {pno+1} has a redaction mark, but the text underneath is still in "
                    f"the file and can be copied out: '{sub[:50]}'. The redaction was marked "
                    f"but never actually applied, so the 'hidden' information is fully "
                    f"recoverable.",
                    page=pno + 1, section=nearest_section(section_map, pno + 1, a.rect.y0),
                    evidence=sub[:80]))
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
        # Reconstruct the revisions and show WHAT changed between them (#5)
        try:
            revs = layer_revisions(path)
            for i in range(1, len(revs)):
                old = revs[i - 1].split("\n")
                new = revs[i].split("\n")
                added = [l.strip() for l in new if l.strip() and l not in old][:6]
                removed = [l.strip() for l in old if l.strip() and l not in new][:6]
                if not added and not removed:
                    continue
                bits = []
                if removed:
                    bits.append("removed: " + " | ".join(removed[:4]))
                if added:
                    bits.append("added: " + " | ".join(added[:4]))
                findings.append(_finding(
                    "Structure", "High", "CONFIRMED", "Content changed between saved revisions",
                    f"Comparing revision {i} with revision {i+1} of this file shows text that "
                    f"was changed after an earlier save. {'; '.join(bits)}. Edits made after "
                    f"a document was 'finalised' or signed are the classic tampering pattern.",
                    evidence="; ".join(bits)[:200]))
        except Exception:
            pass
    if ident["trailing_after_eof"] and ident["trailing_after_eof"] > 4:
        findings.append(_finding(
            "File", "Medium", "REVIEW", "Data after end-of-file marker",
            f"{ident['trailing_after_eof']} bytes follow the final %%EOF. Could be an "
            f"appended payload or a second document stitched on — inspect the tail bytes.",
            evidence=f"{ident['trailing_after_eof']} trailing bytes"))
    if struct["has_sig"]:
        sig_findings = layer_signatures(path)   # actually validate with pyhanko (#9)
        if sig_findings:
            findings.extend(sig_findings)
        else:
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
            
    xmp_raw = meta.get("xmp_raw", "")
    if xmp_raw:
        history_tags = re.findall(r'<stEvt:action>saved</stEvt:action>', xmp_raw)
        if len(history_tags) > 1:
            findings.append(_finding(
                "Metadata", "Medium", "REVIEW", "Document history shows past editing",
                f"The XMP metadata contains a history trail showing the document was edited and saved {len(history_tags)} times by editing software. A born-digital fresh print usually has no history.",
                evidence=f"{len(history_tags)} save events in XMP history"))

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

    # Internal title exposes source provenance. Distinguish a FOREIGN COMPANY/BRAND
    # embedded in the title (serious - rebranded template) from just a source
    # filename / revision number that matches the document's own branding (minor).
    title_l = title.lower()
    exposes_source = title and (
        ".docx" in title_l or ".doc" in title_l or ".xls" in title_l or ".ppt" in title_l
        or re.search(r"\(\d{5,}\)", title) or re.search(r"\brev\s*\d+\b", title, re.I))
    if exposes_source:
        foreign = _foreign_brand_in_title(title, filename)
        if foreign:
            findings.append(_finding(
                "Metadata", "High", "CONFIRMED", "Internal name reveals a different company",
                f"The document's hidden internal title names '{foreign}', which does not "
                f"appear in the document's own file name or visible branding. That the name is "
                f"embedded is a reproducible fact; the reading — that it is a template belonging "
                f"to one party reused/rebranded for another — is the classic interpretation.",
                evidence=f"Foreign name '{foreign}' in title: {title}"))
        else:
            findings.append(_finding(
                "Metadata", "Low", "REVIEW", "Internal name reveals the source file / revision",
                "The document's hidden internal title exposes its source (a Word/Excel "
                "filename, a revision number, or a document-management id). The names match "
                "the document's own branding, so this is minor — it mainly confirms the PDF "
                "is a re-exported working file (for example a 'rev N' draft) rather than an "
                "original.",
                evidence=f"Title: {title}"))

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
    body_size = text.get("dominant_size")
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
        # A heading/title is LARGER than the body text; a dropped-on field/value is
        # body-sized or smaller. Skip clearly-larger spans so coloured headings
        # (e.g. a blue document title) aren't mistaken for inserted text.
        looks_heading = bool(body_size) and size >= body_size + 2.0
        if placeholder:
            findings.append(_finding(
                "Text", "High", "CONFIRMED", "Leftover template placeholder",
                f"Placeholder text '{t}' remains on page {pno} — a template field that "
                f"was filled by overlay (or never filled).",
                page=pno, section=nearest_section(section_map, pno, y), evidence=t))
        elif nonblack and rare_color and odd_font and not looks_heading and seen_overlay < 25:
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

    # ---- multi-vintage footer/header dates (with position, so we can say WHERE) ----
    page_dates = defaultdict(set)          # date_lower -> set of pages
    date_regions = defaultdict(Counter)    # date_lower -> Counter(footer/header/body)
    date_display = {}                      # date_lower -> original-case text
    for pno, page in enumerate(doc):
        ph = page.rect.height or 1
        for m in DATE_RE.finditer(page.get_text("text")):
            d = m.group(0).strip()
            dl = d.lower()
            page_dates[dl].add(pno + 1)
            date_display.setdefault(dl, d)
            try:
                rects = page.search_for(d)
                if rects:
                    ry = rects[0].y0 / ph
                    region = "footer" if ry > 0.82 else ("header" if ry < 0.14 else "body")
                    date_regions[dl][region] += 1
            except Exception:
                pass
    repeated = {d: ps for d, ps in page_dates.items() if len(ps) >= 3}
    if len(repeated) >= 2:
        allreg = Counter()
        for dl in repeated:
            allreg.update(date_regions[dl])
        where = allreg.most_common(1)[0][0] if allreg else "footer/header"
        parts = []
        for dl, ps in sorted(repeated.items(), key=lambda x: -len(x[1]))[:5]:
            reg = date_regions[dl].most_common(1)[0][0] if date_regions[dl] else where
            parts.append(f"'{date_display[dl]}' in the {reg} of {len(ps)} pages")
        listing = "; ".join(parts)
        findings.append(_finding(
            "Text", "Medium", "CONFIRMED", "Multiple template vintages",
            f"The page {where}s carry several different fixed dates - these are running "
            f"{where} dates (version/template stamps), NOT dates written in the body text: "
            f"{listing}. When one document's {where}s show several different version-dates, it "
            f"usually means the document was assembled from templates of different vintages "
            f"(for example a main body plus exhibits taken from different source documents).",
            evidence=listing))

    # ---- full-page raster inside a text PDF (+ ELA on the scan) ----
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
                                              f"{int(im['coverage']*100)}% of page",
                    image_ref=(im["page"], im["xref"])))
                # Error-Level Analysis on this scanned page (ELA is only meaningful
                # on rasters like this, not on born-digital text).
                try:
                    raw = doc.extract_image(im["xref"])
                    _pim = Image.open(io.BytesIO(raw["image"]))
                    # Copy-move forgery within the page (#8)
                    try:
                        cm = _copy_move(_pim)
                        if cm:
                            findings.append(_finding(
                                "Image", "Medium", "REVIEW",
                                "Duplicated region within a scanned page (copy-move)",
                                f"Part of scanned page {im['page']} appears to have been "
                                f"copied and pasted elsewhere on the same page ({cm} matching "
                                f"feature points move together as a block). This is how a "
                                f"value or a stamp is cloned to cover or fake another. Note "
                                f"that pages with heavily repeated layout can also trigger "
                                f"this, so confirm visually.",
                                page=im["page"], evidence=f"{cm} consistent copy-move matches"))
                    except Exception:
                        pass
                    # Noise-inconsistency analysis (#10)
                    try:
                        nheat, nratio = _noise_map(_pim)
                        if nratio >= 6.0:
                            findings.append(_finding(
                                "Image", "Medium", "REVIEW",
                                "Uneven noise across a scanned page",
                                f"The noise pattern on scanned page {im['page']} is uneven — "
                                f"one area is much noisier (or much smoother) than the rest. "
                                f"A region pasted in from another source typically carries a "
                                f"different noise signature, so an outlier can mark an inserted "
                                f"patch. Inspect the bright area on the heatmap.",
                                page=im["page"], evidence=f"noise outlier ratio {nratio:.1f}",
                                image_png=nheat))
                    except Exception:
                        pass
                    heat, ratio, mx = _ela(_pim)
                    if ratio >= 4.0 and mx >= 25:
                        findings.append(_finding(
                            "Image", "Medium", "REVIEW",
                            "Possible edited region in a scanned page (ELA)",
                            f"Error-Level Analysis of the scanned page {im['page']} shows an "
                            f"uneven compression pattern (one area is markedly brighter than "
                            f"the rest). On a genuine single scan the pattern is even; a "
                            f"localised bright patch can mean part of the page was pasted in "
                            f"or edited. The heatmap is shown — a human should judge whether "
                            f"the bright area lines up with text/numbers that could have been "
                            f"altered.",
                            page=im["page"], evidence=f"ELA hotspot ratio {ratio:.1f} "
                                                      f"(max block {mx})",
                            image_png=heat))
                    else:
                        findings.append(_finding(
                            "Image", "Info", "REVIEW",
                            "Error-Level Analysis heatmap (scanned page)",
                            f"Error-Level Analysis was run on the scanned page {im['page']}. "
                            f"The compression pattern looks fairly even (no strong localised "
                            f"anomaly), which is consistent with a single untouched scan. The "
                            f"heatmap is included so a human can still inspect it — bright "
                            f"edges can be normal, bright patches over text warrant a look.",
                            page=im["page"], evidence=f"ELA hotspot ratio {ratio:.1f} "
                                                      f"(max block {mx})",
                            image_png=heat))
                except Exception:
                    pass

    # ---- EXIF metadata inside embedded images (signatures / stamps / logos) ----
    # The same edited graphic (logo/stamp) can repeat on many pages; group by the
    # image's identity so one reused asset is ONE finding listing all its pages.
    edited_imgs = defaultdict(lambda: {"pages": set(), "w": None, "h": None,
                                       "xref": None, "ref_page": None})
    gps_imgs = defaultdict(set)
    for im in imgs:
        ex = im.get("exif") or {}
        soft = (ex.get("software") or "").strip()
        if soft and any(tool in soft.lower() for tool in IMAGE_EDITORS):
            key = (im["sha16"], soft)
            info = edited_imgs[key]
            info["pages"].add(im["page"])
            info["w"] = im["w"]
            info["h"] = im["h"]
            if info["xref"] is None:
                info["xref"] = im["xref"]
                info["ref_page"] = im["page"]
        elif ex.get("gps"):
            gps_imgs[im["sha16"]].add(im["page"])
    for (sha, soft), info in edited_imgs.items():
        pages = sorted(info["pages"])
        pg_txt = (f"page {pages[0]}" if len(pages) == 1
                  else f"{len(pages)} pages ({pages[0]}-{pages[-1]})")
        findings.append(_finding(
            "Image", "Medium", "REVIEW", "Image-editing software tag inside an embedded image",
            f"A graphic ({info['w']}x{info['h']}) on {pg_txt} carries the editing-software "
            f"tag '{soft}' in its own EXIF metadata. A genuinely scanned or camera-original "
            f"graphic would not normally record an image editor. Consistent with a "
            f"signature/stamp/logo that was edited in image software before being placed.",
            page=pages[0],
            section=nearest_section(section_map, pages[0], 0),
            evidence=f"EXIF Software={soft}; {info['w']}x{info['h']}; pages {pages}",
            image_ref=(info["ref_page"], info["xref"])))
    for sha, pgs in gps_imgs.items():
        pages = sorted(pgs)
        findings.append(_finding(
            "Image", "Low", "REVIEW", "Location data inside an embedded image",
            f"An image on page{'s' if len(pages) > 1 else ''} {', '.join(map(str, pages))} "
            f"carries GPS location data in its EXIF metadata. Usually harmless, but worth "
            f"noting for provenance.",
            page=pages[0], evidence=f"EXIF GPS present; pages {pages}"))

    # ---- multiple distinct logos / letterheads (possible multi-source assembly) ----
    # Header graphics = small images sitting near the top of a page. A single-source
    # document reuses one logo; several visually different header marks suggest the
    # document was stitched from more than one source/template (or a rebrand left an
    # older logo behind on some pages). Signatures sit mid-page, so they're excluded.
    header_imgs = [im for im in imgs if im.get("dhash") and im["coverage"] < 0.5
                   and im.get("rel_y") is not None and im["rel_y"] < 0.20]
    logo_clusters = []
    for im in header_imgs:
        for c in logo_clusters:
            if _hamming(c["rep"]["dhash"], im["dhash"]) <= 10:
                c["pages"].add(im["page"])
                break
        else:
            logo_clusters.append({"rep": im, "pages": {im["page"]}})
    if len(logo_clusters) >= 2:
        logo_clusters.sort(key=lambda c: min(c["pages"]))
        parts = []
        for c in logo_clusters:
            ps = sorted(c["pages"])
            rng = f"page {ps[0]}" if len(ps) == 1 else f"pages {ps[0]}-{ps[-1]}"
            parts.append(f"{c['rep']['w']}x{c['rep']['h']} on {rng}")
        refs = [(c["rep"]["page"], c["rep"]["xref"]) for c in logo_clusters]
        findings.append(_finding(
            "Image", "Medium", "REVIEW",
            "Multiple distinct logos / letterheads in one document",
            f"This document uses {len(logo_clusters)} visually different header graphics "
            f"(logos/letterheads): {'; '.join(parts)}. A single-source document normally "
            f"reuses one logo throughout. Several different marks — especially across "
            f"different page ranges — suggest the document was assembled from more than one "
            f"source or template, or that a rebrand left an older brand's logo behind on "
            f"some pages. Check each logo below and confirm they all belong to the "
            f"represented party.",
            page=min(min(c["pages"]) for c in logo_clusters),
            evidence="; ".join(parts), image_refs=refs))

    # ---- font glyph-level splice check ----
    try:
        findings.extend(layer_font_glyphs(doc))
    except Exception:
        pass

    # ---- OCR: read text inside images (stamps/logos/scans) & compare to entities ----
    ocr_texts = {}
    try:
        native = " ".join(sp[2] for sp in text["spans"])

        def _pil_from_pdf(im):
            try:
                return Image.open(io.BytesIO(doc.extract_image(im["xref"])["image"]))
            except Exception:
                return None
        ocr_findings, ocr_texts = layer_ocr(imgs, native, _pil_from_pdf)
        findings.extend(ocr_findings)
    except Exception:
        pass

    # ---- watermark consistency ----
    findings.extend(layer_watermarks(doc, text))

    # ---- redaction verification (annotations that didn't remove the text) ----
    findings.extend(layer_redactions(doc, section_map))

    # ---- signature-block completion (who signed vs left it blank) ----
    try:
        findings.extend(layer_signature_blocks(doc))
    except Exception:
        pass

    summary = {
        "file": filename,
        "pages": doc.page_count,
        "producer": producer, "creator": creator, "author": author, "title": title,
        "created": str(cdate) if cdate else info.get("creationDate", ""),
        "sha256": ident["sha256"],
        "size": ident["size"],
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"summary": summary, "findings": findings, "_images": imgs,
            "_created_dt": cdate, "_producer": producer, "_author": author,
            "_ocr_texts": ocr_texts, "_xmp_raw": meta.get("xmp_raw", "")}


# ---------------------------------------------------------------------------
# Office formats (.docx / .xlsx / .pptx) — roadmap #13
# OOXML files are ZIPs of XML; they carry richer forensic metadata than PDFs
# (author vs last-editor, revision count, editing time, tracked changes).
# ---------------------------------------------------------------------------
def _ooxml_props(path):
    import zipfile, xml.etree.ElementTree as ET
    props, names = {}, set()
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        for member in ("docProps/core.xml", "docProps/app.xml"):
            if member not in names:
                continue
            try:
                root = ET.fromstring(z.read(member))
            except Exception:
                continue
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                if el.text and el.text.strip():
                    props[tag] = el.text.strip()
        blobs = {}
        for member in ("word/document.xml", "xl/sharedStrings.xml", "ppt/presentation.xml"):
            if member in names:
                try:
                    blobs[member] = z.read(member).decode("utf-8", "ignore")
                except Exception:
                    pass
    return props, names, blobs


def _iso(s):
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _office_images(path):
    """Extract embedded images from an OOXML file (word/xl/ppt media) so the same
    image pipeline (EXIF, perceptual hash, OCR, cross-doc reuse) runs on them."""
    import zipfile
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not re.search(r"(word|xl|ppt)/media/", name, re.I):
                    continue
                if not name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp")):
                    continue                      # skip emf/wmf (PIL can't open)
                try:
                    data = z.read(name)
                    pil = Image.open(io.BytesIO(data))
                    out.append({
                        "page": None, "xref": None, "name": name,
                        "w": pil.width, "h": pil.height, "coverage": 0.0, "rel_y": None,
                        "sha16": hashlib.sha256(data).hexdigest()[:16],
                        "dhash": _dhash(pil), "exif": _exif_summary(pil), "_png": data,
                    })
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _office_meta_findings(creator, last_by, company, template, revision, created, modified,
                          filename):
    """Shared Office metadata checks — used by both modern (.docx) and legacy (.doc)
    files: author-vs-last-editor, modified-before-created, foreign template/company,
    and heavy revision counts."""
    findings = []
    if creator and last_by and creator.strip().lower() != last_by.strip().lower():
        findings.append(_finding(
            "Metadata", "Medium", "REVIEW", "Last editor differs from the author",
            f"The document was created by '{creator}' but last saved by '{last_by}'. More than "
            f"one person handled the file — normal for collaboration, relevant if the parties "
            f"are meant to be independent.",
            evidence=f"creator={creator}; lastModifiedBy={last_by}"))

    if created and modified and modified < created:
        findings.append(_finding(
            "Metadata", "Medium", "REVIEW", "Modified before created",
            f"The file says it was last modified ({modified}) before it was created ({created}) "
            f"— impossible for an untouched file, so a timestamp was changed.",
            evidence=f"created={created}; modified={modified}"))

    if template and template.lower() not in ("normal.dotm", "normal.dot", "normal", ""):
        foreign = _foreign_brand_in_title(template, filename)
        if foreign:
            findings.append(_finding(
                "Metadata", "High", "CONFIRMED", "Internal name reveals a different company",
                f"The document is built on a template named '{template}', which carries the "
                f"name '{foreign}' — a company/brand that isn't this document's own. A template "
                f"from another party is a classic rebrand fingerprint.",
                evidence=f"Foreign name '{foreign}' in title: {template}"))

    if company and _foreign_brand_in_title(company, filename):
        findings.append(_finding(
            "Metadata", "Medium", "REVIEW", "Embedded company name",
            f"The file's Company property is '{company}'. Confirm it matches the party this "
            f"document is meant to be from.",
            evidence=f"Company={company}"))

    try:
        if revision and int(revision) >= 20:
            findings.append(_finding(
                "Metadata", "Info", "REVIEW", "Many save cycles",
                f"The document has been saved {revision} times (revision counter). Not a "
                f"problem by itself, but useful context for how much it was worked on.",
                evidence=f"revision={revision}"))
    except Exception:
        pass
    return findings


def analyze_legacy_office(path, filename=None):
    """Legacy binary Office (.doc/.xls/.ppt = OLE compound files). We can't read the
    body/tracked-changes, but the OLE SummaryInformation stream gives the forensic
    metadata (author, last-editor, dates, revision, application, company, template)."""
    filename = filename or os.path.basename(path)
    import olefile
    if not olefile.isOleFile(path):
        raise ValueError("not a valid legacy Office (OLE) file")
    data = open(path, "rb").read()
    ole = olefile.OleFileIO(path)
    m = ole.get_metadata()

    def s(v):
        if isinstance(v, bytes):
            return v.decode("latin-1", "replace").strip()
        return str(v).strip() if v else ""

    creator, last_by = s(m.author), s(m.last_saved_by)
    company, template = s(m.company), s(m.template)
    application, revision = s(m.creating_application), s(m.revision_number)
    created = m.create_time if isinstance(m.create_time, datetime.datetime) else None
    modified = m.last_saved_time if isinstance(m.last_saved_time, datetime.datetime) else None
    ole.close()

    findings = _office_meta_findings(creator, last_by, company, template, revision,
                                     created, modified, filename)
    summary = {
        "file": filename, "pages": s(m.num_pages) or "-", "producer": application or "-",
        "creator": creator, "author": creator, "title": s(m.title) or template,
        "created": str(created) if created else "",
        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_modified_by": last_by, "revision": revision,
    }
    return {"summary": summary, "findings": findings, "_images": [],
            "_created_dt": created, "_producer": application, "_author": creator,
            "_ocr_texts": {}}


def analyze_image(path, filename=None):
    """A standalone image upload (.jpg/.png/scan): treat it as one page and run the
    image-forensics battery — EXIF, OCR, ELA, noise, copy-move — plus a perceptual
    hash so a reused signature/stamp still cross-matches PDFs in the same pack."""
    filename = filename or os.path.basename(path)
    data = open(path, "rb").read()
    pil = Image.open(io.BytesIO(data))
    if pil.mode not in ("RGB", "L"):
        pil = pil.convert("RGB")
    w, h = pil.size
    sha = hashlib.sha256(data).hexdigest()
    exif = _exif_summary(pil)
    findings, ocr_texts = [], {}

    soft = (exif.get("software") or "").strip()
    if soft and any(t in soft.lower() for t in IMAGE_EDITORS):
        findings.append(_finding(
            "Image", "Medium", "REVIEW", "Image-editing software tag inside an embedded image",
            f"This image carries the editing-software tag '{soft}' in its own EXIF metadata. A "
            f"genuinely scanned or camera-original image would not normally record an image "
            f"editor.", page=1, evidence=f"EXIF Software={soft}", image_png=data))
    if exif.get("gps"):
        findings.append(_finding(
            "Image", "Low", "REVIEW", "Location data inside an embedded image",
            "This image carries GPS location data in its EXIF metadata.",
            page=1, evidence="EXIF GPS present", image_png=data))

    if _get_ocr() is not None:
        toks = _ocr_image(pil)
        text = " ".join(t for t, _c in toks).strip()
        if text:
            ocr_texts[sha[:16]] = text
            snippet = re.sub(r"\s+", " ", text)[:220]
            findings.append(_finding(
                "Image", "Info", "REVIEW", "Text read from a scanned page (OCR)",
                f"This upload is an image, not selectable text, so OCR was used to read it. It "
                f"reads: \"{snippet}\". OCR can misread characters, so treat exact figures and "
                f"names as read-with-care.", page=1, evidence=f"OCR: {snippet}", image_png=data))

    try:
        cm = _copy_move(pil)
        if cm:
            findings.append(_finding(
                "Image", "Medium", "REVIEW", "Duplicated region within a scanned page (copy-move)",
                f"Part of this image appears to be a duplicate of another area of the same image "
                f"({cm} matching feature points move together as a block) — the fingerprint of "
                f"copy-move editing. Images with very repetitive layout can also trigger this.",
                page=1, evidence=f"{cm} consistent copy-move matches"))
    except Exception:
        pass
    try:
        nheat, nratio = _noise_map(pil)
        if nratio >= 6.0:
            findings.append(_finding(
                "Image", "Medium", "REVIEW", "Uneven noise across a scanned page",
                "The noise pattern across this image is uneven - one area is much noisier (or "
                "smoother) than the rest, which can mark a region pasted in from another source.",
                page=1, evidence=f"noise outlier ratio {nratio:.1f}", image_png=nheat))
    except Exception:
        pass
    try:
        heat, ratio, mx = _ela(pil)
        if ratio >= 4.0 and mx >= 25:
            findings.append(_finding(
                "Image", "Medium", "REVIEW", "Possible edited region in a scanned page (ELA)",
                "Error-Level Analysis of this image shows an uneven compression pattern (one "
                "area much brighter than the rest), which can mean part of it was pasted in or "
                "edited. The heatmap is shown for a human to judge.",
                page=1, evidence=f"ELA hotspot ratio {ratio:.1f} (max block {mx})", image_png=heat))
        else:
            findings.append(_finding(
                "Image", "Info", "REVIEW", "Error-Level Analysis heatmap (scanned page)",
                "Error-Level Analysis was run on this image and found no strong localised "
                "anomaly, consistent with a single untouched image. The heatmap is included so "
                "a human can still inspect it.",
                page=1, evidence=f"ELA hotspot ratio {ratio:.1f} (max block {mx})", image_png=heat))
    except Exception:
        pass

    imgs = [{"page": 1, "xref": None, "w": w, "h": h, "coverage": 1.0, "rel_y": 0.0,
             "sha16": sha[:16], "dhash": _dhash(pil), "exif": exif, "_png": data}]
    summary = {
        "file": filename, "pages": 1, "producer": "-", "creator": "", "author": "",
        "title": "", "created": "", "sha256": sha, "size": len(data),
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return {"summary": summary, "findings": findings, "_images": imgs,
            "_created_dt": None, "_producer": "", "_author": "", "_ocr_texts": ocr_texts}


def analyze_office(path, filename=None):
    filename = filename or os.path.basename(path)
    data = open(path, "rb").read()
    props, names, blobs = _ooxml_props(path)

    creator = props.get("creator", "")
    last_by = props.get("lastModifiedBy", "")
    company = props.get("Company", "")
    template = props.get("Template", "")
    application = props.get("Application", "")
    revision = props.get("revision", "")
    total_time = props.get("TotalTime", "")
    created = _iso(props.get("created"))
    modified = _iso(props.get("modified"))
    title = props.get("title", "")

    findings = _office_meta_findings(creator, last_by, company, template, revision,
                                     created, modified, filename)

    # tracked changes still in a Word doc
    docxml = blobs.get("word/document.xml", "")
    ins, dele = docxml.count("<w:ins "), docxml.count("<w:del ")
    if ins or dele:
        findings.append(_finding(
            "Text", "High", "REVIEW", "Unaccepted tracked changes in the document",
            f"The Word file still contains tracked changes ({ins} insertions, {dele} deletions) "
            f"that were never accepted or rejected. The 'final' text you see may differ from "
            f"what prints, and the change history reveals what was edited.",
            evidence=f"w:ins={ins} w:del={dele}"))

    # ---- embedded images: EXIF + OCR + populate _images for cross-doc reuse ----
    imgs = _office_images(path)
    ocr_texts = {}
    for im in imgs:
        soft = ((im.get("exif") or {}).get("software") or "").strip()
        if soft and any(tool in soft.lower() for tool in IMAGE_EDITORS):
            findings.append(_finding(
                "Image", "Medium", "REVIEW",
                "Image-editing software tag inside an embedded image",
                f"An embedded graphic ({im['w']}x{im['h']}) in this Office file carries the "
                f"editing-software tag '{soft}' in its EXIF metadata. A scanned or "
                f"camera-original graphic would not normally record an image editor.",
                evidence=f"EXIF Software={soft} ({im['name']})", image_png=im.get("_png")))
    try:
        # visible document text (from the OOXML) as the entity reference for OCR
        native = " ".join(re.findall(r"<[wa]:t[^>]*>([^<]+)</[wa]:t>",
                                     blobs.get("word/document.xml", "") +
                                     blobs.get("ppt/presentation.xml", ""))) or \
                 blobs.get("xl/sharedStrings.xml", "")
        ocr_findings, ocr_texts = layer_ocr(
            imgs, native, lambda im: Image.open(io.BytesIO(im["_png"])))
        findings.extend(ocr_findings)
    except Exception:
        pass

    cdate = created
    summary = {
        "file": filename,
        "pages": props.get("Pages") or props.get("Slides") or props.get("Sheets") or "-",
        "producer": application or "-",
        "creator": creator, "author": creator, "title": title or template,
        "created": str(created) if created else "",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_modified_by": last_by, "revision": revision,
        "editing_minutes": total_time,
    }
    return {"summary": summary, "findings": findings, "_images": imgs,
            "_created_dt": cdate, "_producer": application, "_author": creator,
            "_ocr_texts": ocr_texts}


def _unreadable_result(path, filename, ext, err):
    """A safe result for a file that could not be opened/parsed, so one bad upload
    never crashes the whole batch or the app."""
    try:
        data = open(path, "rb").read()
        sha, size = hashlib.sha256(data).hexdigest(), len(data)
    except Exception:
        sha, size = "", 0
    kind = (ext.lstrip(".") or "document").upper()
    finding = _finding(
        "File", "High", "REVIEW", "File could not be analysed",
        f"This file could not be opened or parsed as a valid {kind} "
        f"({type(err).__name__}). It may be corrupt, password-protected/encrypted, or not "
        f"actually a {kind} despite its name. A file that won't open cleanly is itself worth "
        f"questioning — ask the sender for a clean copy.",
        evidence=f"{type(err).__name__}: {str(err)[:140]}")
    summary = {"file": filename, "pages": "-", "producer": "-", "creator": "", "author": "",
               "title": "", "created": "", "sha256": sha, "size": size,
               "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    return {"summary": summary, "findings": [finding], "_images": [],
            "_created_dt": None, "_producer": "", "_author": "", "_ocr_texts": {}}


def analyze_file(path, filename=None):
    """Dispatch to the right analyser by file type (PDF vs Office). Never raises:
    an unreadable file returns a graceful 'could not analyse' result instead."""
    filename = filename or os.path.basename(path)
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
            return analyze_office(path, filename)
        if ext in (".doc", ".xls", ".ppt"):
            return analyze_legacy_office(path, filename)
        if ext in (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif", ".webp"):
            return analyze_image(path, filename)
        return analyze_document(path, filename)
    except Exception as err:
        return _unreadable_result(path, filename, ext, err)


# ---------------------------------------------------------------------------
# cross-document correlation
# ---------------------------------------------------------------------------
def correlate_documents(results):
    """results: dict filename -> analyze_document() output. Returns list of findings."""
    findings = []

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


# ===========================================================================
# PLAIN-LANGUAGE LAYER
# Turns the technical findings above into wording a non-technical reader
# (client, lawyer, compliance officer) can act on. Everything here is copy —
# no analysis — so the UI and every exporter share one voice.
# ===========================================================================

# Friendlier words for the internal severity / status codes.
HUMAN_SEVERITY = {
    "High": "Needs attention",
    "Medium": "Worth a closer look",
    "Low": "Minor note",
    "Info": "Background context",
}
HUMAN_STATUS = {
    "CONFIRMED": "Established fact",
    "REVIEW": "Needs a human judgment",
    "VERIFY": "Needs outside confirmation",
}

# title -> (plain headline, what it means, what to do)
PLAIN_LANGUAGE = {
    "Incremental updates present": (
        "The file was edited and re-saved after its first save",
        "This PDF stores more than one saved version inside it, which means content was "
        "changed and appended after the document was first written. The earlier version "
        "is still hidden in the file.",
        "Have a specialist reconstruct the earlier version and compare it with the current "
        "one to see exactly what changed (for example a date or an amount)."),
    "Content changed between saved revisions": (
        "We can see what was changed after an earlier save",
        "This file kept its earlier version inside it, so we could compare the two. The text "
        "listed actually changed between saves - something was edited after the document was "
        "first written (and possibly after it was 'finalised' or signed).",
        "Look at exactly what changed - a date, an amount, a name. Editing after finalising or "
        "signing is the classic tampering pattern; confirm the change was legitimate."),
    "File could not be analysed": (
        "This file wouldn't open properly",
        "The file could not be opened or read as a valid document. It may be corrupt, "
        "password-protected, or not actually the type of file its name claims.",
        "Ask the sender for a clean, openable copy. A document that won't open cleanly is "
        "itself worth questioning."),
    "Data after end-of-file marker": (
        "Extra hidden data is attached after the document's end",
        "There are extra bytes tacked on after the point where the PDF is supposed to end. "
        "This can be harmless leftover data, or it can be a second file hidden inside this one.",
        "Have someone inspect the trailing bytes to confirm whether anything is hidden there."),
    "Signature block appears unsigned": (
        "A party hasn't signed the document",
        "One of the named signatories has an empty signature block - no signature and no date "
        "filled in - while another party has signed. A contract executed by only some of its "
        "parties may not be legally binding, and an underwriter checks this first.",
        "Confirm whether a fully-executed copy exists. If this is the only version, the "
        "document is not fully signed and should not be relied on as a binding agreement."),
    "Digital signature is broken (content changed after signing)": (
        "The digital signature is broken - the file was changed after signing",
        "This document carries a real cryptographic signature, and it no longer matches the "
        "content. That means the file was altered after it was signed. Unlike most findings "
        "here, this is definitive, not just a lead.",
        "Do not rely on this document. Get the originally signed version from the signer."),
    "Signature covers only part of the file": (
        "The signature only covers part of the document",
        "The document is signed and the signature itself is intact, but it only covers an "
        "earlier version - content was added afterwards. This 'sign, then append more' pattern "
        "is a classic way to make added material look signed when it isn't.",
        "Treat anything beyond the signed portion as unsigned. Confirm the added content with "
        "the signer."),
    "Digital signature present and internally intact": (
        "The document has a digital signature that checks out (so far)",
        "This document has a real cryptographic signature, it matches the content, and it "
        "appears to cover the whole file. That's good - but 'intact' isn't the same as "
        "'trusted': we still can't confirm offline that the signer's certificate is genuine.",
        "Do an online certificate/revocation check to confirm the signer is who they claim and "
        "that the certificate is valid and not revoked."),
    "Digital signature object present": (
        "The file contains a digital signature",
        "This PDF includes a cryptographic (digital) signature. Whether that signature is "
        "actually valid, and whether it covers the whole document, cannot be confirmed by "
        "this offline tool.",
        "Validate the signature and its certificate with a proper signature-checking tool "
        "before relying on it."),
    "Modified before created": (
        "The 'modified' date is earlier than the 'created' date",
        "The document's own timestamps contradict each other: it claims it was last modified "
        "before it was created, which is impossible for an untouched file.",
        "Treat the timestamps as unreliable and confirm the real dates from another source."),
    "Flattened by a print-to-PDF engine": (
        "This is a 'printed-to-PDF' copy, not the original working file",
        "The document was produced by a print-to-PDF process (such as macOS, Chrome, or a "
        "phone). That process rewrites the file in one pass and erases the edit history, so "
        "we cannot tell from the PDF whether the content was changed earlier. This does not "
        "mean it was edited - only that the PDF alone can't show us.",
        "Ask the sender for the original source file (the Word or Excel document), which keeps "
        "its real edit history."),
    "Internal name reveals a different company": (
        "A different company's name is hidden inside the file",
        "The document's internal title (metadata you don't see on the page) names a company "
        "or brand that isn't the one this document is supposed to be from, and isn't in its "
        "file name. That is a classic fingerprint of one party's template being reused or "
        "rebranded for another - the strongest version of this signal.",
        "Confirm who that other company is and why its name is embedded. Treat it as a strong "
        "lead until explained."),
    "Internal name reveals the source file / revision": (
        "The file's hidden internal name shows it's a re-exported working draft",
        "The document's internal title exposes its source - a Word/Excel filename, a revision "
        "number, or a document-management id. Here the names match the document's own party, "
        "so it's minor: it mostly confirms this PDF is a re-exported working file (e.g. a "
        "'rev 3' draft) rather than an original.",
        "Low concern by itself. If it matters, ask for the original source file to confirm the "
        "final content matches."),
    "Internal title exposes source provenance": (
        "The document's hidden internal name points to a different source",
        "Inside the file, the document's internal title names a different company, a source "
        "filename, or a document-management number that doesn't match how the document is "
        "branded on the page. This commonly happens when one party's template is rebranded "
        "for another.",
        "Confirm the named source is legitimate and that no unrelated company or template is "
        "embedded in the document."),
    "Last editor differs from the author": (
        "Created by one person, last saved by another",
        "The Office file records who created it and who last saved it, and they're different "
        "people. That's normal for collaboration, but it matters if the two are supposed to be "
        "independent parties.",
        "Confirm both names are expected. If the parties should be independent, ask why one "
        "edited the other's document."),
    "Unaccepted tracked changes in the document": (
        "The Word file still has un-finalised edits inside it",
        "The document contains tracked changes that were never accepted or rejected. The text "
        "on screen may not be the real final text, and the change history shows exactly what "
        "was edited and by whom.",
        "Open it in Word with tracked changes shown to see what was altered before trusting the "
        "'final' wording."),
    "Many save cycles": (
        "The document was saved many times",
        "The file's revision counter is high, meaning it went through many save cycles. Purely "
        "contextual - it just indicates how heavily the document was worked on.",
        "No action needed; use as background context."),
    "Embedded company name": (
        "A company name is stored in the file's properties",
        "The Office file records a Company name in its properties. Worth a glance to confirm it "
        "matches the party the document is supposed to be from.",
        "Confirm the company name is the expected one."),
    "Authored and rendered by different tools": (
        "Written in one program and converted to PDF by another",
        "The document was authored in one tool (for example Microsoft Word) and turned into a "
        "PDF by a different tool. On its own this is completely normal; it matters only as "
        "supporting context alongside other findings.",
        "No action needed by itself - note it only if other findings point the same way."),
    "Late-added font (possible overlay)": (
        "A font was added late, suggesting text was dropped on afterwards",
        "One font was added much later than the others inside the file's structure. That "
        "pattern often means a piece of text - a box, a stamp, or an overlay - was placed on "
        "the page after the rest was written.",
        "Look at the page named below to see whether that text was inserted on top rather than "
        "typed into the document."),
    "Same font name but two different font sources": (
        "The same-named font actually comes from two different sources",
        "A font with one name (say 'Arial') is embedded here from two different origins - "
        "different foundry or version. Genuine single-source text uses one identical font "
        "program throughout, so this is a sign that text from another document was spliced in "
        "while keeping the same font name to hide it.",
        "Look at the pages/sections using the second font source - that's where inserted or "
        "pasted text is most likely."),
    "Mixed base fonts across the document": (
        "The document mixes fonts from more than one source",
        "Substantial amounts of text use different underlying font families. This can be "
        "perfectly normal, but it can also mean the document was assembled from more than one "
        "source or template.",
        "Cross-check the headers, footers and logos to see whether the parts come from "
        "different sources."),
    "Leftover template placeholder": (
        "An unfilled template placeholder was left in the document",
        "A placeholder word from a template (such as 'Text', 'Click here', or 'XXXX') is still "
        "sitting in the document next to where a real value should be. This is a strong sign a "
        "template field was filled by dropping a value on top rather than typing it in.",
        "Check the nearby field - the real value may have been overlaid rather than genuinely "
        "entered."),
    "Overlaid / inserted text": (
        "Some text looks dropped-on rather than typed in",
        "A piece of text is styled differently (unusual colour and font) from the surrounding "
        "body text, which can mean it was placed on top as a separate box or form field rather "
        "than typed into the document. Note that coloured headings and titles can trigger this "
        "too, so it is not proof on its own.",
        "Look at the highlighted text in context and judge whether it was genuinely part of the "
        "document or added on top."),
    "Near-white (possibly hidden) text": (
        "Very faint, near-invisible text is present",
        "There is text that is almost white, which may be invisible when the page is viewed or "
        "printed. Sometimes this is harmless; sometimes it is deliberately hidden content.",
        "Confirm the faint text is not hidden content sitting over a light background."),
    "Possible fake redaction": (
        "A blacked-out area still has readable text underneath",
        "A black box has been drawn over some text, but the text underneath is still in the file "
        "and can be copied out. The information was not actually removed - only visually covered.",
        "Recover the text under the box to see what was meant to be hidden, and treat the "
        "redaction as ineffective."),
    "Multiple template vintages": (
        "Different sections carry different footer/version dates",
        "The small fixed dates printed in the page footers (the template/version dates, not "
        "dates in the actual text) are not the same on all pages. Different footer dates on "
        "different pages usually mean the document was stitched together from templates of "
        "different vintages - e.g. the main body and the exhibits came from different sources.",
        "Check which pages carry which footer date, and confirm that mixing those sections is "
        "expected for this document."),
    "Page is a full-page image": (
        "A page is a scanned/flat image, not real text",
        "One page is a single picture rather than selectable text - typically a scan or a "
        "photographed page placed inside an otherwise digital document.",
        "Apply image-tampering checks to that page and, where possible, obtain the original of "
        "that page."),
    "Identical image reused across files": (
        "The exact same image appears in more than one document",
        "A byte-for-byte identical image was copied and pasted across multiple documents. When "
        "that image is a signature or stamp, it means the same graphic - not an independent "
        "signing - was placed on each document.",
        "Confirm the graphic was authorised for use on each document separately."),
    "Reused signature/stamp/graphic across files": (
        "The same signature/stamp was reused across documents",
        "The same signature-and-stamp graphic appears on several documents that are each "
        "presented as separately signed. A real wet signature looks slightly different every "
        "time; an identical one means one image was reused as a digital asset. Reusing a "
        "signature stamp can be legitimate, but these should be treated as one reused image, "
        "not as independent signatures.",
        "Confirm whether each document was genuinely signed, and that reuse of the signature "
        "was authorised in each case."),
    "Files re-exported in one session from different sources": (
        "These documents are re-prints made in one sitting, not independent originals",
        "Several documents were produced by the same computer within seconds of each other, yet "
        "each names a different original author. That is consistent with one person exporting a "
        "bundle assembled from several different source files - so these PDFs are re-prints, not "
        "independently produced originals.",
        "Ask for the independent originals of each document from their respective sources."),
    "Watermark appears on only some pages": (
        "A watermark is on some pages but not others",
        "A faint background watermark shows up on part of the document but not all of it. If a "
        "watermark was applied to the whole original, pages missing it may have been inserted "
        "or swapped in afterwards.",
        "Check the pages without the watermark - confirm they belong to the same original "
        "document."),
    "Redaction not applied (text recoverable)": (
        "A 'redacted' area can still be read",
        "The document has a redaction mark, but the text underneath was never actually removed "
        "- it's still in the file and can be copied straight out. Whatever was meant to be "
        "hidden is fully readable.",
        "Recover the text to see what was meant to be hidden, and treat the redaction as "
        "failed. Do not rely on it."),
    "Duplicated region within a scanned page (copy-move)": (
        "Part of a scanned page looks copied-and-pasted onto itself",
        "An area of this scanned page appears to be a duplicate of another area on the same "
        "page - the fingerprint of 'copy-move' editing, where a value, box, or stamp is cloned "
        "to cover or fake something. Documents with very repetitive layouts can also trigger "
        "this, so it needs a visual check.",
        "Compare the two matching areas on the page; if a number, signature, or stamp was "
        "cloned, get the original."),
    "Uneven noise across a scanned page": (
        "Part of a scanned page is noisier than the rest",
        "Every scan or photo has a fine, even 'grain' of noise. Here one area's grain is "
        "clearly different from the rest of the page. A patch pasted in from another source "
        "usually brings its own noise, so an uneven area can mark an inserted or edited region.",
        "Look at the heatmap and check whether the odd area sits over text, a figure, or a "
        "signature that could have been swapped; if so, get the original page."),
    "Possible edited region in a scanned page (ELA)": (
        "A scanned page may have been edited in one spot",
        "We ran Error-Level Analysis (a standard image-tampering test) on this scanned page. "
        "An untouched scan compresses evenly all over; here one area stands out, which can mean "
        "part of the page - a number, a name, a stamp - was pasted in or altered. It is a lead, "
        "not proof.",
        "Look at the heatmap: if the bright area sits over text or figures that matter, get the "
        "original of that page and compare."),
    "Error-Level Analysis heatmap (scanned page)": (
        "We checked this scanned page for signs of editing",
        "We ran Error-Level Analysis (an image-tampering test) on this scanned page and did not "
        "find a strong localised anomaly - consistent with a single untouched scan. The heatmap "
        "is included so you can still eyeball it.",
        "No action needed unless a bright patch lines up with important text; then obtain the "
        "original page to compare."),
    "Signature/stamp read — name matches the document": (
        "We read the signature/stamp and the company name checks out",
        "We used OCR to read the text printed inside a signature or stamp on the page. The "
        "company/party name on it does appear in the document, so the stamp is consistent with "
        "who the document is meant to be from. This is a positive check, shown so you can see "
        "the stamp was read and verified.",
        "No action needed on the name itself. If the same stamp is reused across several "
        "'separately signed' documents, still confirm each use was authorised."),
    "Signature/stamp read — confirm the name": (
        "We read the signature/stamp — please confirm the company name",
        "We used OCR to read the text inside a signature or stamp on the page, but couldn't "
        "automatically match a company/party name on it to the document's own text. That may "
        "just be OCR noise, or the stamp may name a different party.",
        "Read the stamp text shown and confirm the company on it is the party this document is "
        "meant to be from."),
    "A logo or stamp names a company not in the document": (
        "A stamp/logo names a company the document never mentions",
        "We read the text printed inside a stamp or logo on the page (using OCR) and it names a "
        "company that appears nowhere in the document's own wording. A mark for a different "
        "company than the one the document is about is a strong sign of a reused or rebranded "
        "template - and unlike the metadata hints, this is visible right on the page.",
        "Look at the stamp/logo named and confirm which company it really belongs to and why "
        "it is on this document."),
    "Text read from a scanned page (OCR)": (
        "We read the text off a scanned page",
        "One page is a picture (a scan), not real text, so we used OCR to read what it says - "
        "this makes its figures and names available for checking against the rest of the pack. "
        "OCR can misread the odd character, so treat exact numbers as read-with-care.",
        "Compare the figures and names read from the scan against the same items elsewhere in "
        "the document set; get the original page if anything looks off."),
    "Multiple distinct logos / letterheads in one document": (
        "The document uses more than one logo / letterhead",
        "The pages don't all carry the same logo. A document produced from a single source "
        "normally uses one letterhead throughout. Several different header logos - especially "
        "on different page ranges - suggest the document was assembled from more than one "
        "source or template, or that a rebrand left an old brand's logo behind on some pages.",
        "Look at the logos shown and confirm they all belong to the party this document is "
        "meant to be from. An unexpected brand is a strong lead."),
    "Image-editing software tag inside an embedded image": (
        "An embedded image was touched by photo-editing software",
        "An image inside the document (such as a signature, stamp or logo) still records that it "
        "passed through image-editing software. A genuinely scanned or camera-original graphic "
        "would not normally carry that tag.",
        "Check what that image is and whether editing it was legitimate."),
    "Location data inside an embedded image": (
        "An embedded image contains GPS location data",
        "An image inside the document carries GPS coordinates in its own metadata. Usually "
        "harmless, but occasionally useful for tracing where a photo came from.",
        "Note the location if provenance is in question; otherwise no action needed."),
}


def humanize(finding):
    """Return a plain-language view of a finding for non-technical readers."""
    title = finding.get("title", "")
    pl = PLAIN_LANGUAGE.get(title)
    if pl:
        headline, means, action = pl
    else:
        headline, means, action = title, finding.get("detail", ""), "Review this finding."
    return {
        "headline": headline,
        "means": means,
        "action": action,
        "severity_label": HUMAN_SEVERITY.get(finding.get("severity"), finding.get("severity")),
        "status_label": HUMAN_STATUS.get(finding.get("status"), finding.get("status")),
    }


# Definitive, non-hedged statements for the findings that are reproducible FACTS
# (status == CONFIRMED). These are stated flatly — no "possibly/consistent with".
FACT_STATEMENTS = {
    "Incremental updates present":
        "was edited and re-saved after its first save — an earlier version is still inside it.",
    "Content changed between saved revisions":
        "had text changed between saved versions — content was edited after an earlier save.",
    "Leftover template placeholder":
        "still contains an unfilled template placeholder next to a value that should be typed in.",
    "Multiple template vintages":
        "carries several different version-dates in its page footers, so parts came from "
        "different template versions.",
    "Identical image reused across files":
        "shares a byte-for-byte identical image with other documents in the set.",
    "Reused signature/stamp/graphic across files":
        "The same signature/stamp image appears on multiple documents — it is one reused image, "
        "not independent signatures.",
    "Redaction not applied (text recoverable)":
        "has a redaction whose text was never removed — it is still in the file and readable.",
    "Digital signature is broken (content changed after signing)":
        "The cryptographic signature does not match the content — the file was changed after "
        "it was signed.",
}


def build_executive_summary(results, cross):
    """Plain-English overview: a headline, definitive facts, narrative points, next steps.

    Returns a dict the UI and exporters render however they like.
    """
    all_ff = [f for r in results.values() for f in r["findings"]] + list(cross)
    titles = [f["title"] for f in all_ff]
    n_high = sum(1 for f in all_ff if f["severity"] == "High")
    n_confirmed = sum(1 for f in all_ff if f["status"] == "CONFIRMED")

    # Established facts: the CONFIRMED findings, stated flatly (definitive tier).
    established_facts, seen_fact = [], set()
    for fn, r in results.items():
        for f in r["findings"]:
            if f["status"] != "CONFIRMED":
                continue
            if f["title"] == "Internal name reveals a different company":
                m = re.search(r"Foreign name '([^']+)'", f.get("evidence", ""))
                nm = m.group(1) if m else "another company"
                sentence = (f"{fn} has the name '{nm}' — a different company — embedded in its "
                            f"own internal metadata (not its visible brand).")
            elif f["title"] in FACT_STATEMENTS:
                stmt = FACT_STATEMENTS[f["title"]]
                sentence = (stmt if stmt[0].isupper() else f"{fn} {stmt}")
            else:
                continue
            if sentence not in seen_fact:
                seen_fact.add(sentence)
                established_facts.append(sentence)
    for f in cross:
        if f["status"] == "CONFIRMED" and f["title"] in FACT_STATEMENTS:
            stmt = FACT_STATEMENTS[f["title"]]
            if stmt not in seen_fact:
                seen_fact.add(stmt)
                established_facts.append(stmt)

    def has(t):
        return t in titles

    themes = []

    # (Reused signatures / identical images are CONFIRMED facts — they appear in the
    #  "Established facts" tier above, so they are deliberately NOT repeated here.)

    # 2. Single-session re-export from different sources
    if has("Files re-exported in one session from different sources"):
        themes.append(
            "Several documents were produced on the same computer within seconds of each other "
            "but name different authors - consistent with re-prints assembled from several "
            "source files, rather than independent originals.")

    # (Edited-after-save / incremental updates is a CONFIRMED fact — shown in the
    #  "Established facts" tier above, not repeated here.)

    # (A different company embedded in the internal name is now a CONFIRMED fact,
    #  shown in the "Established facts" tier above — not repeated here.)

    # 5. Overlaid values (judgment). The leftover placeholder itself is a CONFIRMED
    #    fact shown above; the "value looks dropped-on" reading is the judgment part.
    if has("Overlaid / inserted text"):
        themes.append(
            "At least one document has a value that looks dropped onto the page rather than "
            "typed in - a possible sign a field was filled by overlay rather than genuinely "
            "entered.")

    # 6. Fake redaction
    if has("Possible fake redaction"):
        themes.append(
            "At least one document has a blacked-out area whose text is still readable "
            "underneath - the information was covered, not actually removed.")

    # 6b. Multiple distinct logos / letterheads
    multilogo = [fn for fn, r in results.items()
                 if any(f["title"] == "Multiple distinct logos / letterheads in one document"
                        for f in r["findings"])]
    if multilogo:
        themes.append(
            f"{', '.join(multilogo)} uses more than one logo/letterhead across its pages, "
            f"which suggests it was assembled from more than one source or template (or a "
            f"rebrand left an older brand's logo behind). The logos are shown in the report.")

    # (Multiple template vintages is a CONFIRMED fact — shown in the "Established
    #  facts" tier above, not repeated here.)

    # 8. Scanned / re-generated copy
    scanned = [fn for fn, r in results.items()
               if any(f["title"] == "Page is a full-page image" for f in r["findings"])]
    if scanned:
        themes.append(
            f"{', '.join(scanned)} contains a scanned image page inside an otherwise digital "
            f"document. If it is presented as an official certificate, note it is a re-generated "
            f"copy that cannot vouch for itself - verify the underlying record directly with the "
            f"issuing authority.")

    # Headline
    if established_facts:
        headline = (f"This analysis establishes {len(established_facts)} definitive, reproducible "
                    f"fact(s) about these documents (listed first below), alongside further "
                    f"anomalies that require human judgment.")
    elif n_high:
        headline = ("Several findings need your attention before these documents can be relied "
                    "on.")
    elif any(f["severity"] == "Medium" for f in all_ff):
        headline = "A few things are worth a closer look, but nothing here is conclusive."
    else:
        headline = "Nothing significant stood out in the automated checks."

    # Next steps: actions from the most serious findings, de-duplicated, plus staples
    actions, seen = [], set()
    for f in sorted(all_ff, key=lambda x: ["High", "Medium", "Low", "Info"].index(x["severity"])):
        a = humanize(f)["action"]
        if a and a not in seen and "No action needed" not in a:
            seen.add(a)
            actions.append(a)
        if len(actions) >= 6:
            break
    for staple in ("Ask for the original source files (Word/Excel) behind each document.",
                   "Verify each party's registration and each signatory's authority with an "
                   "authoritative source."):
        if staple not in seen:
            actions.append(staple)

    return {
        "n_files": len(results),
        "n_findings": len(all_ff),
        "n_high": n_high,
        "n_confirmed": n_confirmed,
        "headline": headline,
        "established_facts": established_facts,
        "themes": themes,
        "actions": actions,
    }


def document_verdict(fn, r, cross):
    """One plain-language sentence summarising a single document."""
    involved = [f for f in cross if fn in (f.get("evidence") or "")]
    combined = list(r["findings"]) + involved
    if not combined:
        return "No automated flags - nothing stood out on this document."
    rank = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    top = min(combined, key=lambda f: rank.get(f["severity"], 9))
    headline = humanize(top)["headline"]
    if top["severity"] == "High":
        lead = "Needs attention"
    elif top["severity"] == "Medium":
        lead = "Worth a closer look"
    else:
        lead = "Minor notes only"
    return f"{lead}: {headline.lower()}."


# ---------------------------------------------------------------------------
# Batch CLI  (roadmap #14) — analyse files/folders without the web UI.
#   python forensics_engine.py *.pdf --json report.json
# Self-contained: uses only the engine (no Streamlit), so it runs in a pipeline.
# ---------------------------------------------------------------------------
def _cli():
    import argparse, glob, json
    ap = argparse.ArgumentParser(
        description="Offline PDF tampering / fraud triage (batch mode).")
    ap.add_argument("inputs", nargs="+", help="PDF files and/or directories")
    ap.add_argument("--json", metavar="FILE", help="write full findings to this JSON file")
    ap.add_argument("--quiet", action="store_true", help="only print the risk headline")
    args = ap.parse_args()

    paths = []
    exts = (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
            ".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp")
    for inp in args.inputs:
        if os.path.isdir(inp):
            for e in exts:
                paths += sorted(glob.glob(os.path.join(inp, "*" + e)))
        elif inp.lower().endswith(exts):
            paths.append(inp)
    if not paths:
        print("No analysable files found.")
        raise SystemExit(1)

    results = {}
    for p in paths:
        name = os.path.basename(p)
        try:
            results[name] = analyze_document(p, name)
        except Exception as e:
            print(f"  ! failed to analyse {name}: {e}")
    cross = correlate_documents(results)
    summ = build_executive_summary(results, cross)

    print("=" * 70)
    print("DOCUMENT FORENSICS - BATCH REPORT")
    print("=" * 70)
    print(f"Files: {summ['n_files']}   Findings: {summ['n_findings']}   "
          f"Need attention: {summ['n_high']}")
    print(f"\n{summ['headline']}\n")
    if not args.quiet:
        if summ["themes"]:
            print("What we found:")
            for t in summ["themes"]:
                print(f"  - {t}")
        print("\nDocument-by-document:")
        for fn, r in results.items():
            print(f"  - {fn}: {document_verdict(fn, r, cross)}")
            print(f"      sha256={r['summary']['sha256']}  "
                  f"analyzed_at={r['summary'].get('analyzed_at','')}")

    if args.json:
        def _clean(ff):
            return [{k: v for k, v in f.items() if k != "image_png"} for f in ff]
        blob = {fn: {"summary": r["summary"], "findings": _clean(r["findings"])}
                for fn, r in results.items()}
        blob["_cross_document"] = _clean(cross)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(blob, fh, indent=2, default=str)
        print(f"\nJSON written to {args.json}")


if __name__ == "__main__":
    _cli()
