"""
app.py — Streamlit front end for the offline document forensics engine.

Run locally:   streamlit run app.py
Deploy:        push this repo to GitHub, then Streamlit Community Cloud ->
               "New app" -> point at app.py. requirements.txt does the rest.
"""

import io, os, json, hashlib, tempfile, datetime
import streamlit as st
import pandas as pd

import forensics_engine as fe

# --------------------------------------------------------------------------- #
# page + light styling (investigator's console: calm, evidence-first)
# --------------------------------------------------------------------------- #
st.set_page_config(page_title="Document Forensics — Tampering & Fraud Triage",
                   page_icon="🔎", layout="wide")

SEV_COLOR = {"High": "#c0392b", "Medium": "#c77d0a", "Low": "#3b6ea5", "Info": "#6b7280"}
STATUS_HELP = {
    "CONFIRMED": "Reproducible byte / metadata fact.",
    "REVIEW": "Anomaly that needs human judgment.",
    "VERIFY": "Needs source files or an external check.",
}

st.markdown("""
<style>
  .block-container {padding-top: 2rem; max-width: 1250px;}
  .hdr {font-size: 1.9rem; font-weight: 700; letter-spacing:-.02em; margin-bottom:.1rem;}
  .sub {color:#5b6470; margin-bottom:1rem;}
  .disc {background:#fff8e6; border:1px solid #f0d99b; color:#7a5a12;
         padding:.6rem .9rem; border-radius:8px; font-size:.9rem; margin-bottom:1rem;}
  .card {border-left:5px solid #ccc; background:#fafbfc; border:1px solid #eceef1;
         border-left-width:5px; border-radius:6px; padding:.7rem .9rem; margin-bottom:.6rem;}
  .card .t {font-weight:600; font-size:1rem;}
  .card .d {color:#374151; font-size:.9rem; margin-top:.25rem;}
  .chip {display:inline-block; font-size:.72rem; font-weight:700; padding:.08rem .5rem;
         border-radius:20px; margin-right:.4rem; vertical-align:middle;}
  .ev {font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.78rem;
       color:#4b5563; background:#f2f3f5; padding:.15rem .4rem; border-radius:4px;
       display:inline-block; margin-top:.35rem;}
  .meta {font-family:ui-monospace,monospace; font-size:.8rem; opacity:.7;}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hdr">Document Forensics — Tampering &amp; Fraud Triage</div>',
            unsafe_allow_html=True)
st.markdown('<div class="sub">Offline PDF analysis across nine layers: file, structure, '
            'metadata, fonts, text, annotations, image, cross-document, and a verification '
            'checklist for what can only be confirmed externally.</div>',
            unsafe_allow_html=True)
st.markdown('<div class="disc"><b>Read this first.</b> This tool <b>surfaces anomalies for a '
            'human examiner — it does not prove fraud or intent.</b> A flag is a question. '
            'Confirmed items are reproducible facts; Review / Verify items need your judgment '
            'or the source files.</div>', unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def chip(text, bg, fg="#fff"):
    return f'<span class="chip" style="background:{bg};color:{fg}">{text}</span>'


@st.cache_data(show_spinner=False)
def run_analysis(file_sigs):
    """file_sigs: tuple of (name, sha, path). Cached by content so filtering is instant."""
    results = {}
    for name, _sha, path in file_sigs:
        results[name] = fe.analyze_document(path, name)
    cross = fe.correlate_documents(results)
    return results, cross


def persist(uploaded):
    """Write uploads to a stable temp dir keyed by content hash; return sigs + path map."""
    root = os.path.join(tempfile.gettempdir(), "docforensics")
    os.makedirs(root, exist_ok=True)
    sigs, paths = [], {}
    for uf in uploaded:
        data = uf.getvalue()
        sha = hashlib.sha256(data).hexdigest()[:16]
        path = os.path.join(root, f"{sha}.pdf")
        if not os.path.exists(path):
            open(path, "wb").write(data)
        sigs.append((uf.name, sha, path))
        paths[uf.name] = path
    return tuple(sigs), paths


def all_findings_rows(results, cross):
    rows = []
    for fn, r in results.items():
        for f in r["findings"]:
            rows.append({"File": fn, "Severity": f["severity"], "Status": f["status"],
                         "Layer": f["layer"], "Page": f["page"] or "",
                         "Section": f["section"] or "", "Finding": f["title"]})
    for f in cross:
        rows.append({"File": "(across files)", "Severity": f["severity"],
                     "Status": f["status"], "Layer": f["layer"], "Page": "", "Section": "",
                     "Finding": f["title"]})
    return rows


def render_card(f):
    sev = f["severity"]; color = SEV_COLOR.get(sev, "#999")
    loc = []
    if f.get("page"):
        loc.append(f"page {f['page']}")
    if f.get("section"):
        loc.append(f"§{f['section']}")
    loc = f'<span style="color:#6b7280;font-size:.82rem;"> · {" · ".join(loc)}</span>' if loc else ""
    ev = f'<div class="ev">{f["evidence"]}</div>' if f.get("evidence") else ""
    st.markdown(
        f'<div class="card" style="border-left-color:{color}">'
        f'{chip(sev, color)}{chip(f["status"], "#fff", SEV_COLOR["Info"])}'
        f'<span class="t">{f["title"]}</span>{loc}'
        f'<div class="d">{f["detail"]}</div>{ev}</div>', unsafe_allow_html=True)


def build_markdown(results, cross):
    L = ["# Document Forensics Report",
         f"_Generated {datetime.datetime.now():%Y-%m-%d %H:%M} · offline analysis · "
         f"anomalies surfaced for human review, not proof of fraud._\n"]
    # cross first
    if cross:
        L.append("## Cross-document findings\n")
        for f in cross:
            L.append(f"- **[{f['severity']}/{f['status']}] {f['title']}** — {f['detail']}"
                     f"{'  `'+f['evidence']+'`' if f.get('evidence') else ''}")
        L.append("")
    for fn, r in results.items():
        s = r["summary"]
        L.append(f"## {fn}")
        L.append(f"- Pages: {s['pages']} · SHA256: `{s['sha256']}`")
        L.append(f"- Producer: {s['producer'] or '—'} · Author: {s['author'] or '—'} · "
                 f"Created: {s['created'] or '—'}")
        if s.get("title"):
            L.append(f"- Internal title: `{s['title']}`")
        L.append("")
        for f in sorted(r["findings"], key=lambda x: ["High","Medium","Low","Info"].index(x["severity"])):
            loc = (f" (page {f['page']}" + (f", §{f['section']}" if f.get("section") else "") + ")") \
                if f.get("page") else ""
            L.append(f"- **[{f['severity']}/{f['status']}] {f['title']}**{loc} — {f['detail']}"
                     f"{'  `'+f['evidence']+'`' if f.get('evidence') else ''}")
        L.append("")
    L.append("## Manual verification checklist")
    for title, desc in fe.MANUAL_CHECKLIST:
        L.append(f"- [ ] **{title}** — {desc}")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.header("How it reads a document")
    st.caption("Bytes upward — each layer sees what the others can't.")
    st.markdown(
        "1. **File / byte** — integrity, hidden trailing data\n"
        "2. **Structure** — edits appended after saving\n"
        "3. **Metadata** — author, tool, timestamps, provenance\n"
        "4. **Fonts** — spliced / inserted text\n"
        "5. **Text** — overlaid fields, fake redactions, hidden text\n"
        "6. **Annotations / signatures**\n"
        "7. **Image** — reused / pasted signatures & stamps\n"
        "8. **Cross-document** — shared assets, export clusters\n"
        "9. **Verify checklist** — what needs external proof")
    st.divider()
    st.subheader("Severity")
    for s, c in SEV_COLOR.items():
        st.markdown(chip(s, c) + {"High": "act now", "Medium": "investigate",
                    "Low": "note", "Info": "context"}[s], unsafe_allow_html=True)
    st.subheader("Status")
    for s, h in STATUS_HELP.items():
        st.markdown(f"**{s}** — {h}")


# --------------------------------------------------------------------------- #
# upload + run
# --------------------------------------------------------------------------- #
uploaded = st.file_uploader("Upload one or more PDFs (a full deal pack works best)",
                            type=["pdf"], accept_multiple_files=True)

if not uploaded:
    st.info("Upload PDFs to begin. Uploading a whole set enables cross-document checks "
            "(reused signatures/stamps, export-session clustering).")
    st.stop()

sigs, paths = persist(uploaded)
with st.spinner("Analysing…"):
    results, cross = run_analysis(sigs)

# ---- summary metrics ----
rows = all_findings_rows(results, cross)
df = pd.DataFrame(rows)
n_high = sum(r["Severity"] == "High" for r in rows)
n_conf = sum(r["Status"] == "CONFIRMED" for r in rows)
n_verify = sum(r["Status"] == "VERIFY" for r in rows)
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Files", len(results))
c2.metric("Findings", len(rows))
c3.metric("High severity", n_high)
c4.metric("Confirmed facts", n_conf)
c5.metric("To verify", n_verify)

# ---- reused-graphic gallery (strong signal, show the actual crops) ----
reuse = [f for f in cross if "Reused signature" in f["title"] or "Identical image" in f["title"]]
if reuse:
    st.subheader("Reused signatures / stamps / graphics")
    st.caption("The same graphic asset appears across files. A genuine wet signature differs "
               "every time; a reused one was applied as an image. Legitimate uses exist — "
               "confirm authorisation per document.")
    shown = set()
    for f in reuse:
        # evidence like "dist 14: A.pdf p1 <-> B.pdf p3"
        try:
            body = f["evidence"].split(":", 1)[1]
            left, right = [x.strip() for x in body.split("<->")]
            pairs = []
            for side in (left, right):
                fname = side.rsplit(" p", 1)[0].strip()
                pageno = int(side.rsplit(" p", 1)[1].split()[0])
                pairs.append((fname, pageno))
        except Exception:
            continue
        cols = st.columns(len(pairs) + 1)
        cols[0].markdown(f"**{f['title']}**\n\n{chip(f['severity'], SEV_COLOR[f['severity']])}"
                         f"{chip(f['status'], '#fff', SEV_COLOR['Info'])}", unsafe_allow_html=True)
        for i, (fname, pageno) in enumerate(pairs):
            path = paths.get(fname)
            if not path:
                continue
            # find the signature-ish image on that page (largest non-header image)
            imgs = [im for im in results[fname]["_images"] if im["page"] == pageno]
            imgs = sorted(imgs, key=lambda x: -(x["w"] * x["h"]))
            for im in imgs:
                if im["coverage"] < 0.6:  # skip full-page rasters
                    try:
                        cols[i + 1].image(fe.get_image_png(path, im["xref"]),
                                          caption=f"{fname} · p{pageno}", use_container_width=True)
                    except Exception:
                        pass
                    break
    st.divider()

# ---- consolidated findings table (filterable) ----
st.subheader("All findings")
fc1, fc2, fc3 = st.columns(3)
sev_sel = fc1.multiselect("Severity", ["High", "Medium", "Low", "Info"],
                          default=["High", "Medium", "Low", "Info"])
sta_sel = fc2.multiselect("Status", ["CONFIRMED", "REVIEW", "VERIFY"],
                          default=["CONFIRMED", "REVIEW", "VERIFY"])
file_sel = fc3.multiselect("File", sorted(set(r["File"] for r in rows)),
                           default=sorted(set(r["File"] for r in rows)))
fdf = df[df["Severity"].isin(sev_sel) & df["Status"].isin(sta_sel) & df["File"].isin(file_sel)]
sev_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
fdf = fdf.sort_values(by="Severity", key=lambda s: s.map(sev_order))
st.dataframe(fdf, use_container_width=True, hide_index=True)

# ---- cross-document detail ----
if cross:
    st.subheader("Cross-document findings")
    for f in cross:
        render_card(f)

# ---- per-file detail ----
st.subheader("Per-file detail")
for fn, r in results.items():
    s = r["summary"]
    n = len(r["findings"])
    with st.expander(f"📄 {fn} — {n} finding{'s' if n != 1 else ''} · {s['pages']} pages"):
        st.markdown(
            f'<div class="meta">Producer: {s["producer"] or "—"}<br>'
            f'Author: {s["author"] or "—"} · Created: {s["created"] or "—"}<br>'
            f'Internal title: {s["title"] or "—"}<br>'
            f'SHA256: {s["sha256"]}</div>', unsafe_allow_html=True)
        st.write("")
        if not r["findings"]:
            st.success("No automated flags on this file.")
        for f in sorted(r["findings"], key=lambda x: sev_order.get(x["severity"], 9)):
            render_card(f)

# ---- manual verification checklist ----
st.subheader("Manual verification checklist")
st.caption("What the tool cannot confirm offline. Work through these to close the case.")
verify_findings = [f for r in results.values() for f in r["findings"] if f["status"] == "VERIFY"]
verify_findings += [f for f in cross if f["status"] == "VERIFY"]
for f in verify_findings:
    st.checkbox(f"{f['title']} — {f['detail'][:120]}", key=f"vf_{id(f)}")
for title, desc in fe.MANUAL_CHECKLIST:
    st.checkbox(f"{title} — {desc}", key=f"mc_{title}")

# ---- downloads ----
st.subheader("Export report")
d1, d2 = st.columns(2)
md = build_markdown(results, cross)
json_blob = json.dumps(
    {fn: {"summary": r["summary"], "findings": r["findings"]} for fn, r in results.items()}
    | {"_cross_document": cross}, indent=2, default=str)
d1.download_button("Download Markdown report", md, file_name="forensics_report.md",
                   mime="text/markdown", use_container_width=True)
d2.download_button("Download JSON report", json_blob, file_name="forensics_report.json",
                   mime="application/json", use_container_width=True)
