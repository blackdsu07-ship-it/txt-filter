import html
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(page_title="SPF / DMARC Filter", layout="wide")
st.title("SPF / DMARC Filter")

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
SPF_OPTIONS = ["+all", "none", "~all", "-all", "?all", "no-all"]
DMARC_OPTIONS = ["none", "missing", "quarantine", "reject"]
MAX_DOMAINS = 500_000
CHUNK = 1000
PREVIEW_ROWS = 2000

CFG = {"nameservers": None}
_local = threading.local()


def get_resolver():
    r = getattr(_local, "r", None)
    if r is None:
        r = dns.resolver.Resolver()
        r.lifetime = 5
        r.timeout = 3
        if CFG["nameservers"]:
            r.nameservers = CFG["nameservers"]
        _local.r = r
    return r


def get_txt(name):
    try:
        answers = get_resolver().resolve(name, "TXT")
    except Exception:
        return []
    return ["".join(s.decode("utf-8", "ignore") for s in r.strings) for r in answers]


def check_spf(domain):
    for t in get_txt(domain):
        if re.match(r"^\s*v=spf1(\s|$)", t, re.I):
            status = "no-all"
            m = re.findall(r"(?:^|\s)([+\-~?]?)all(?=\s|$)", t, re.I)
            if m:
                status = {"": "+all", "+": "+all", "-": "-all", "~": "~all", "?": "?all"}[m[-1]]
            return status, t
    return "none", ""


def check_dmarc(domain):
    for t in get_txt(f"_dmarc.{domain}"):
        if re.match(r"^\s*v=DMARC1", t, re.I):
            m = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", t, re.I)
            return (m.group(1).lower() if m else "none"), t
    return "missing", ""


def check(domain):
    spf, spf_rec = check_spf(domain)
    dmarc, dmarc_rec = check_dmarc(domain)
    return {
        "domain": domain,
        "spf": spf,
        "dmarc_p": dmarc,
        "spf_record": spf_rec,
        "dmarc_record": dmarc_rec,
    }


def parse(text):
    seen, out = set(), []
    for d in re.split(r"[\s,;]+", text.lower()):
        d = re.sub(r"^https?://", "", d)
        d = re.sub(r"^.*@", "", d)
        d = d.split("/")[0].rstrip(".")
        if d and DOMAIN_RE.match(d) and d not in seen:
            seen.add(d)
            out.append(d)
    return out[:MAX_DOMAINS]


def read_upload(f) -> str:
    name = f.name.lower()
    if name.endswith((".xlsx", ".xlsm")):
        from openpyxl import load_workbook

        wb = load_workbook(f, read_only=True, data_only=True)
        parts = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                for c in row:
                    if isinstance(c, str):
                        parts.append(c)
        return "\n".join(parts)
    return f.getvalue().decode("utf-8", "ignore")


def copy_button(text, label="Copy domains"):
    safe = html.escape(text)
    components.html(
        f"""
        <textarea id="t" style="position:absolute;left:-9999px">{safe}</textarea>
        <button id="b" style="padding:8px 16px;cursor:pointer;border:1px solid #999;
                border-radius:6px;background:#fff;font-size:14px">{label}</button>
        <script>
        const b = document.getElementById('b');
        b.onclick = async () => {{
          const t = document.getElementById('t');
          try {{ await navigator.clipboard.writeText(t.value); }}
          catch (e) {{ t.select(); document.execCommand('copy'); }}
          b.textContent = 'Copied!';
          setTimeout(() => b.textContent = '{label}', 1500);
        }};
        </script>
        """,
        height=50,
    )


# ---------- Input ----------
text = st.text_area("Domains (one per line)", height=140)
uploads = st.file_uploader(
    "Or upload file(s): .xlsx, .csv, .txt (all sheets/cells are scanned)",
    type=["xlsx", "xlsm", "csv", "txt"],
    accept_multiple_files=True,
)
c1, c2 = st.columns(2)
threads = c1.slider("Threads", 1, 200, 50)
resolver_choice = c2.selectbox("DNS resolver", ["System default", "Google + Cloudflare"])

if st.button("Check", type="primary"):
    combined = text
    for f in uploads or []:
        combined += "\n" + read_upload(f)
    domains = parse(combined)
    if not domains:
        st.warning("No valid domains.")
    else:
        CFG["nameservers"] = (
            ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]
            if resolver_choice != "System default"
            else None
        )
        st.info(f"{len(domains):,} unique domains")
        bar = st.progress(0.0)
        status = st.empty()
        results = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for i in range(0, len(domains), CHUNK):
                results.extend(ex.map(check, domains[i : i + CHUNK]))
                done = len(results)
                bar.progress(done / len(domains))
                status.text(f"{done:,} / {len(domains):,}")
        st.session_state["df"] = pd.DataFrame(results)
        status.empty()

# ---------- Results ----------
df = st.session_state.get("df")
if df is not None:
    st.subheader("Choose category")
    s1, s2 = st.columns(2)
    spf_sel = s1.multiselect("SPF", SPF_OPTIONS, default=["+all", "none"],
                             help="none = no SPF record")
    dmarc_sel = s2.multiselect("DMARC policy (p=)", DMARC_OPTIONS, default=["none", "missing"],
                               help="missing = no DMARC record")

    filtered = df[df["spf"].isin(spf_sel) & df["dmarc_p"].isin(dmarc_sel)]
    st.subheader(f"Matches: {len(filtered):,} of {len(df):,}")
    out_text = "\n".join(filtered["domain"])

    preview = "\n".join(filtered["domain"].head(PREVIEW_ROWS))
    if len(filtered) > PREVIEW_ROWS:
        st.caption(f"Preview shows first {PREVIEW_ROWS:,}. Copy/download include all.")
    st.text_area("Domains", preview, height=160)

    b1, b2, b3 = st.columns([1, 1, 5])
    with b1:
        copy_button(out_text)
    with b2:
        st.download_button("Download .txt", out_text, "domains.txt")
    with b3:
        st.download_button("Download .csv", filtered.to_csv(index=False), "matches.csv")

    st.subheader("Details")
    st.dataframe(filtered.head(PREVIEW_ROWS), use_container_width=True, hide_index=True)
