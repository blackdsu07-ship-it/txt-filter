import re
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import pandas as pd
import streamlit as st

st.set_page_config(page_title="SPF / DMARC Filter", layout="wide")
st.title("SPF / DMARC Filter")

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def get_txt(name: str, resolver: dns.resolver.Resolver) -> list[str]:
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
            return (m.group(1).lower() if m else "none"), t, True
    return "none", "", False


def check(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 3
    spf, spf_rec = check_spf(domain, resolver)
    dmarc, dmarc_rec, exists = check_dmarc(domain, resolver)
    weak = spf in ("+all", "none") and dmarc == "none"
    return {
        "domain": domain,
        "spf": spf,
        "dmarc_p": dmarc,
        "dmarc_record_exists": exists,
        "category": "Category 1" if weak else "Other",
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
    weak = df[df["category"] == "Category 1"]
    st.subheader(f"Category 1: SPF +all / none & DMARC none ({len(weak)})")
    weak_text = "\n".join(weak["domain"])
    st.text_area("Category 1 domains", weak_text, height=140)
    st.download_button("Download Category 1 (.txt)", weak_text, "spf-dmarc-weak.txt")

    st.subheader(f"Details ({len(df)} checked)")
    st.dataframe(
        df.sort_values("category"),
        use_container_width=True,
        hide_index=True,
    )
    st.download_button("Download all (.csv)", df.to_csv(index=False), "spf-dmarc-all.csv")
