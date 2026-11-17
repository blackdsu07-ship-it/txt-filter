import html
import re
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


def get_txt(name, resolver):
    try:
        answers = resolver.resolve(name, "TXT")
    except Exception:
        return []
    return ["".join(s.decode("utf-8", "ignore") for s in r.strings) for r in answers]


def check_spf(domain, resolver):
    for t in get_txt(domain, resolver):
        if re.match(r"^\s*v=spf1(\s|$)", t, re.I):
            status = "no-all"
            m = re.findall(r"(?:^|\s)([+\-~?]?)all(?=\s|$)", t, re.I)
            if m:
                status = {"": "+all", "+": "+all", "-": "-all", "~": "~all", "?": "?all"}[m[-1]]
            return status, t
    return "none", ""


def check_dmarc(domain, resolver):
    for t in get_txt(f"_dmarc.{domain}", resolver):
        if re.match(r"^\s*v=DMARC1", t, re.I):
            m = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", t, re.I)
            return (m.group(1).lower() if m else "none"), t
    return "missing", ""


def check(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    spf, spf_rec = check_spf(domain, resolver)
    dmarc, dmarc_rec = check_dmarc(domain, resolver)
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
    return out[:2000]


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


text = st.text_area("Domains (one per line)", height=180)
threads = st.slider("Threads", 1, 50, 20)

if st.button("Check", type="primary"):
    domains = parse(text)
    if not domains:
        st.warning("No valid domains.")
    else:
        bar = st.progress(0.0)
        results = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for i, r in enumerate(ex.map(check, domains), 1):
                results.append(r)
                bar.progress(i / len(domains))
        st.session_state["df"] = pd.DataFrame(results)

df = st.session_state.get("df")
if df is not None:
    st.subheader("Choose category")
    c1, c2 = st.columns(2)
    spf_sel = c1.multiselect("SPF", SPF_OPTIONS, default=["+all", "none"],
                             help="none = no SPF record")
    dmarc_sel = c2.multiselect("DMARC policy (p=)", DMARC_OPTIONS, default=["none", "missing"],
                               help="missing = no DMARC record")

    filtered = df[df["spf"].isin(spf_sel) & df["dmarc_p"].isin(dmarc_sel)]
    st.subheader(f"Matches: {len(filtered)} of {len(df)}")
    out_text = "\n".join(filtered["domain"])
    st.text_area("Domains", out_text, height=160)

    b1, b2 = st.columns([1, 6])
    with b1:
        copy_button(out_text)
    with b2:
        st.download_button("Download .txt", out_text, "domains.txt")

    st.subheader("Details")
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button("Download matches (.csv)", filtered.to_csv(index=False), "matches.csv")
