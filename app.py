import sqlite3
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

import streamlit as st

from detection import RULES, analyze_prompt
from storage import DB_PATH, clear_scans, get_scans, save_scan


st.set_page_config(
    page_title="Prompt Shelter | AI Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAVIGATION = [
    "Overview",
    "Prompt Scanner",
    "Detection Rules",
    "Scan History",
    "Analytics",
    "Research Documentation",
    "Settings",
]
CLASSIFICATIONS = ["SAFE", "SUSPICIOUS", "MALICIOUS"]

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    :root {
        --bg: #0B1120;
        --sidebar: #0F192B;
        --card: #151F32;
        --surface: #1B2940;
        --border: #263650;
        --blue: #3B82F6;
        --green: #22C55E;
        --amber: #F59E0B;
        --red: #EF4444;
        --text: #F1F5F9;
        --muted: #94A3B8;
    }
    html, body, [class*="css"], [data-testid="stAppViewContainer"] {
        font-family: Inter, sans-serif;
    }
    .stApp { background: var(--bg); color: var(--text); }
    [data-testid="stSidebar"] {
        background: var(--sidebar);
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] > div:first-child { padding-top: 1.4rem; }
    .block-container {
        max-width: 1440px;
        padding: 2rem 2.5rem 3rem;
    }
    h1, h2, h3, h4 { color: var(--text) !important; letter-spacing: -0.035em; }
    p, label, [data-testid="stCaptionContainer"] { color: var(--muted); }
    [data-testid="stMarkdownContainer"] p { line-height: 1.65; }
    [data-testid="stRadio"] label { color: #CBD5E1; }
    [data-testid="stRadio"] > label { display: none; }
    [data-testid="stMetric"] {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 18px 20px;
    }
    [data-testid="stMetricLabel"] { color: var(--muted); }
    [data-testid="stMetricValue"] { color: var(--text); }
    .brand {
        font-size: 19px;
        font-weight: 700;
        letter-spacing: -0.04em;
        color: var(--text);
        margin: 0 0 3px;
    }
    .brand-mark {
        color: var(--blue);
        font-weight: 700;
        margin-right: 8px;
    }
    .eyebrow {
        color: var(--muted);
        font-size: 10px;
        letter-spacing: .14em;
        text-transform: uppercase;
        margin-bottom: 22px;
    }
    .prototype-pill, .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 7px;
        padding: 6px 10px;
        border: 1px solid var(--border);
        border-radius: 999px;
        color: #CBD5E1;
        background: var(--card);
        font-size: 11px;
        font-weight: 600;
        white-space: nowrap;
    }
    .status-dot {
        display: inline-block;
        width: 7px;
        height: 7px;
        background: var(--green);
        border-radius: 50%;
    }
    .section-card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 20px 22px;
        margin-bottom: 14px;
    }
    .section-kicker {
        color: var(--muted);
        font-size: 11px;
        font-weight: 600;
        letter-spacing: .1em;
        text-transform: uppercase;
    }
    .result-banner {
        border-radius: 12px;
        padding: 16px 18px;
        margin: 12px 0 18px;
        border: 1px solid var(--border);
        background: var(--card);
    }
    .result-banner.safe { border-color: #166534; background: #10251F; }
    .result-banner.suspicious { border-color: #854D0E; background: #2A2112; }
    .result-banner.malicious { border-color: #7F1D1D; background: #2B171D; }
    .result-banner strong { color: var(--text); }
    .rule-row {
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 13px 15px;
        margin: 8px 0;
    }
    .muted-small { color: var(--muted); font-size: 12px; }
    .top-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 4px;
    }
    .top-header-title { font-size: 24px; font-weight: 700; color: var(--text); }
    .top-header-context { color: var(--muted); font-size: 12px; margin-top: 5px; }
    .stTextArea textarea {
        background: #0D1728 !important;
        color: var(--text) !important;
        border: 1px solid #34445E !important;
        border-radius: 10px !important;
        line-height: 1.7 !important;
    }
    .stTextArea textarea:focus {
        border-color: var(--blue) !important;
        box-shadow: 0 0 0 1px var(--blue) !important;
    }
    .stButton button, .stFormSubmitButton button {
        border-radius: 9px;
        min-height: 42px;
        font-weight: 600;
    }
    .stButton button[kind="primary"], .stFormSubmitButton button {
        background: var(--blue);
        border-color: var(--blue);
        color: white;
    }
    [data-testid="stProgressBar"] > div { background: var(--surface); }
    [data-testid="stProgressBar"] > div > div { background: var(--blue); }
    hr { border-color: var(--border); }
    footer { visibility: hidden; }
    @media (max-width: 800px) {
        .block-container { padding: 1.2rem 1rem 2rem; }
        .top-header { align-items: flex-start; gap: 12px; flex-direction: column; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_history():
    try:
        return get_scans()
    except sqlite3.Error as error:
        st.error(f"Could not read local scan history: {error}")
        return None


def metric_cards(history):
    counts = Counter(record["classification"] for record in history)
    columns = st.columns(4)
    values = [
        ("Total prompts scanned", len(history)),
        ("Safe", counts["SAFE"]),
        ("Suspicious", counts["SUSPICIOUS"]),
        ("Malicious", counts["MALICIOUS"]),
    ]
    for column, (label, value) in zip(columns, values):
        column.metric(label, value)


def render_distribution(history):
    if not history:
        st.info("Charts will appear here after the first prompt is scanned.")
        return
    counts = Counter(record["classification"] for record in history)
    st.bar_chart(
        {label: [counts[label]] for label in CLASSIFICATIONS},
        color=["#22C55E", "#F59E0B", "#EF4444"],
        x_label="",
        y_label="Scans",
    )


def render_risk_bands(history):
    if not history:
        st.info("Risk distribution is unavailable until scans are recorded.")
        return
    bands = Counter(
        "Low · 0–24" if record["risk_score"] < 25 else
        "Medium · 25–59" if record["risk_score"] < 60 else
        "High · 60–100"
        for record in history
    )
    st.bar_chart(
        {
            "Low · 0–24": [bands["Low · 0–24"]],
            "Medium · 25–59": [bands["Medium · 25–59"]],
            "High · 60–100": [bands["High · 60–100"]],
        },
        color=["#22C55E", "#F59E0B", "#EF4444"],
        x_label="",
        y_label="Scans",
    )


def render_trend(history):
    daily = Counter(
        datetime.fromisoformat(record["scanned_at"]).date().isoformat()
        for record in history
    )
    if len(daily) < 2:
        st.info("Scan trends appear after scans are recorded on at least two different days.")
        return
    st.line_chart(
        {"Scans": dict(sorted(daily.items()))},
        x_label="Date",
        y_label="Scans",
    )


def render_recent_scans(history, limit=5):
    if not history:
        st.info("No scan activity yet. Start by analyzing a prompt.")
        return
    for record in history[:limit]:
        timestamp = datetime.fromisoformat(record["scanned_at"]).astimezone()
        preview = escape(record["prompt_preview"] or "Prompt preview not stored")
        st.markdown(
            f"""
            <div class="rule-row">
                <strong>{record["classification"]}</strong>
                <span style="float:right;color:#94A3B8">
                    {record["risk_score"]}/100 · {timestamp:%b %d, %H:%M}
                </span><br>
                <span class="muted-small">{preview}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_scan_details(record):
    st.markdown(
        f"**Risk score:** {record['risk_score']}/100  \n"
        f"**Classification:** {record['classification']}  \n"
        f"**Scanned:** {datetime.fromisoformat(record['scanned_at']).astimezone():%Y-%m-%d %H:%M:%S %Z}"
    )
    st.write("**Prompt preview:**", record["prompt_preview"] or "Not stored")
    st.write(
        "**Matched indicators:**",
        ", ".join(record["matched_rules"]) if record["matched_rules"] else "None",
    )


def render_analysis(score, classification, matched, prompt):
    st.markdown("### Analysis results")
    first, second = st.columns([1, 2])
    with first:
        st.metric("Risk score", f"{score} / 100")
    with second:
        st.metric("Classification", classification)
    st.progress(score / 100, text=f"Rule-based risk score · {score}%")

    banner_class = classification.lower()
    if matched:
        summary = (
            "Configured prompt-injection indicators were detected. "
            "Review the matched rules and their individual contributions below."
        )
    else:
        summary = (
            "No configured threat patterns matched. This is not a guarantee "
            "that the prompt is safe."
        )
    st.markdown(
        f'<div class="result-banner {banner_class}"><strong>'
        f'{classification} · {score}/100</strong><br>{summary}</div>',
        unsafe_allow_html=True,
    )
    st.markdown("#### Matched threat patterns")
    if not matched:
        st.info("No configured threat patterns matched.")
    for item in matched:
        st.markdown(
            f"""
            <div class="rule-row">
                <strong>{item["name"]}</strong>
                <span style="float:right;color:#F1F5F9">+{item["weight"]} points</span><br>
                <span class="muted-small">{item["category"]} · {item["description"]}</span><br>
                <span class="muted-small">Pattern: <code>{item["pattern"]}</code></span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    if matched:
        st.caption(
            f"Score is the sum of matched rule weights, capped at 100. "
            f"{len(matched)} configured indicator(s) matched."
        )
    st.caption(
        f"Analysis method: local case-insensitive regular-expression rules · "
        f"{len(prompt)} input characters. Scores are not calibrated probabilities."
    )


def clear_scanner():
    st.session_state["prompt_input"] = ""
    st.session_state.pop("last_result", None)


def navigate_to_scanner():
    st.session_state["navigation"] = "Prompt Scanner"


history = load_history()
if history is None:
    st.error(
        "History-dependent pages are unavailable because stored scan data could not be read. "
        "No zero-count analytics are shown."
    )
    st.stop()
st.session_state.setdefault("navigation", "Overview")

with st.sidebar:
    st.markdown(
        '<div class="brand"><span class="brand-mark">◈</span>Prompt Shelter</div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="eyebrow">AI prompt security</div>', unsafe_allow_html=True)
    st.markdown("#### WORKSPACE")
    page = st.radio(
        "Navigation",
        NAVIGATION,
        key="navigation",
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown("#### SYSTEM STATUS")
    st.markdown(
        '<span class="status-pill"><span class="status-dot"></span>'
        'Rule engine available</span>',
        unsafe_allow_html=True,
    )
    st.caption("Local research prototype · v0.3")
    st.divider()
    st.caption("GROUP B19 · PROMPT INJECTION RESEARCH")

st.markdown(
    f"""
    <div class="top-header">
        <div>
            <div class="top-header-title">{page}</div>
            <div class="top-header-context">
                Prompt Shelter <span style="color:#475569">/</span>
                AI security research workspace
            </div>
        </div>
        <span class="prototype-pill">RESEARCH PROTOTYPE</span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.divider()

if page == "Overview":
    st.markdown("### Security overview")
    st.caption("Operational summaries are calculated only from locally recorded scans.")
    metric_cards(history)

    left, right = st.columns([1.3, 1])
    with left:
        st.markdown("#### Threat distribution")
        render_distribution(history)
    with right:
        st.markdown("#### Risk distribution")
        render_risk_bands(history)

    activity, access = st.columns([1.5, 1])
    with activity:
        st.markdown("#### Recent scan activity")
        render_recent_scans(history)
    with access:
        st.markdown("#### Detection engine")
        st.markdown(
            f"""
            <div class="section-card">
                <div class="section-kicker">Engine status</div>
                <h3 style="margin:8px 0 4px">Active · rule-based</h3>
                <div class="muted-small">{len(RULES)} configured patterns · no ML model</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.button(
            "Open prompt scanner",
            type="primary",
            use_container_width=True,
            on_click=navigate_to_scanner,
        )

elif page == "Prompt Scanner":
    st.markdown("### Analyze a prompt")
    st.caption(
        "Run a prompt through the local rule-based detector. Input is not sent to a service."
    )
    prompt = st.text_area(
        "PROMPT INPUT",
        key="prompt_input",
        placeholder=(
            "Paste a prompt to inspect for configured injection indicators…\n\n"
            "Your input is analyzed locally and is not stored in full."
        ),
        height=230,
        max_chars=20000,
        help="Up to 20,000 characters. Only scan metadata is kept in local history.",
    )
    store_preview = st.checkbox(
        "Store a short, redacted prompt preview in local scan history",
        value=False,
        help="Off by default. Full prompt text is never persisted.",
    )
    st.caption(f"{len(prompt):,} / 20,000 characters")
    analyze_col, clear_col, _ = st.columns([1.35, 1, 3])
    submitted = analyze_col.button(
        "Analyze prompt",
        type="primary",
        use_container_width=True,
    )
    clear_col.button(
        "Clear input",
        use_container_width=True,
        on_click=clear_scanner,
    )
    if submitted:
        if not prompt.strip():
            st.warning("Enter a prompt before starting analysis.")
            st.session_state.pop("last_result", None)
        else:
            with st.spinner("Scanning with local detection rules…"):
                score, classification, matched = analyze_prompt(prompt)
                try:
                    save_scan(
                        prompt,
                        score,
                        classification,
                        [item["name"] for item in matched],
                        store_preview=store_preview,
                    )
                except sqlite3.Error as error:
                    st.error(f"Analysis completed, but history could not be saved: {error}")
                st.session_state["last_result"] = {
                    "score": score,
                    "classification": classification,
                    "matched": matched,
                    "prompt": prompt,
                }
            st.rerun()

    result = st.session_state.get("last_result")
    if result:
        st.divider()
        render_analysis(
            result["score"],
            result["classification"],
            result["matched"],
            result["prompt"],
        )
    st.caption(
        "Security limitation: this prototype uses a small set of explicit patterns. "
        "Unmatched attacks may exist; a SAFE result is not a security guarantee."
    )

elif page == "Detection Rules":
    st.markdown("### Detection rule library")
    st.caption("All listed rules are implemented and active in the current detector.")
    for index, rule in enumerate(RULES, start=1):
        st.markdown(
            f"""
            <div class="section-card">
                <div class="section-kicker">RULE {index:02d} · {rule["category"]}</div>
                <h3 style="margin:8px 0">{rule["name"]}</h3>
                <div>{rule["description"]}</div>
                <div class="muted-small" style="margin-top:10px">
                    Pattern: <code>{rule["pattern"]}</code>
                    &nbsp; · &nbsp; Risk weight: +{rule["weight"]}
                    &nbsp; · &nbsp; Status: Active
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.caption(
        "A rule contributes its configured weight once when its pattern matches. "
        "The total score is capped at 100."
    )

elif page == "Scan History":
    st.markdown("### Scan history")
    st.caption("History is stored in a local SQLite database. Full prompt text is never saved.")
    search_col, filter_col = st.columns([2, 1])
    query = search_col.text_input("Search preview or matched rule", placeholder="Search history…")
    classification_filter = filter_col.selectbox(
        "Classification",
        ["All classifications", *CLASSIFICATIONS],
    )
    filtered = history
    if classification_filter != "All classifications":
        filtered = [
            record for record in filtered
            if record["classification"] == classification_filter
        ]
    if query.strip():
        normalized_query = query.casefold()
        filtered = [
            record for record in filtered
            if normalized_query in (record["prompt_preview"] or "").casefold()
            or any(normalized_query in name.casefold() for name in record["matched_rules"])
        ]
    if not history:
        st.info("No scans have been recorded yet.")
    elif not filtered:
        st.info("No scan records match these filters.")
    else:
        for record in filtered:
            time_label = datetime.fromisoformat(record["scanned_at"]).astimezone()
            with st.expander(
                f'{time_label:%Y-%m-%d %H:%M} · {record["classification"]} · '
                f'{record["risk_score"]}/100'
            ):
                render_scan_details(record)
    st.divider()
    confirm_clear = st.checkbox("I understand this permanently deletes all local scan history.")
    if st.button("Clear scan history", disabled=not confirm_clear):
        try:
            clear_scans()
        except sqlite3.Error as error:
            st.error(f"Could not clear scan history: {error}")
        else:
            st.success("Local scan history cleared.")
            st.rerun()

elif page == "Analytics":
    st.markdown("### Scan analytics")
    st.caption("Visualizations use recorded scan data only; no sample or inferred data is included.")
    metric_cards(history)
    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown("#### Classification distribution")
        render_distribution(history)
    with chart_right:
        st.markdown("#### Risk score bands")
        render_risk_bands(history)
    st.markdown("#### Scan trends")
    render_trend(history)
    if history:
        scores = [record["risk_score"] for record in history]
        st.caption(
            f"Recorded scans: {len(scores)} · Mean risk score: "
            f"{sum(scores) / len(scores):.1f}/100 · "
            f"Range: {min(scores)}–{max(scores)}"
        )

elif page == "Research Documentation":
    st.markdown("### Research documentation")
    st.markdown(
        """
        <div class="section-card">
            <div class="section-kicker">Research objective</div>
            <h3>Study practical prompt-injection indicators</h3>
            <div>Prompt Shelter is a Group B19 research prototype for inspecting text
            prompts, reporting configured threat indicators, and exploring a transparent
            local risk-scoring workflow.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("#### Implemented in this prototype")
    st.write(
        "- Case-insensitive regular-expression matching against a small, explicit rule set."
    )
    st.write("- Weighted score capped at 100, with SAFE / SUSPICIOUS / MALICIOUS thresholds.")
    st.write("- Rule-level categories, weights, and match explanations.")
    st.write("- Local SQLite scan metadata with optional short, redacted previews.")
    st.write("- Analytics derived from the application's actual local scan history.")
    st.markdown("#### Planned research roadmap")
    st.write("- **Hybrid detection (planned):** combine transparent rules with separately evaluated signals.")
    st.write("- **Machine learning integration (planned):** train and validate on a documented, labeled dataset.")
    st.write("- **Indirect injection evaluation (planned):** assess retrieved documents and other external content.")
    st.write("- **Benchmarking (planned):** report Precision, Recall, F1-score, and Accuracy against labeled data.")
    st.info(
        "No machine-learning classifier, training data, benchmark results, or evaluation metrics "
        "are implemented in the current prototype."
    )
    st.markdown("#### Methodology and limitations")
    st.write(
        "Each configured regular expression is tested once against the submitted text. "
        "A match contributes its fixed weight; weights are summed and capped. Scores are "
        "heuristic indicators, not probabilities or calibrated confidence."
    )
    st.warning(
        "The rule set is intentionally limited and can produce false positives and false "
        "negatives. It does not understand context, obfuscation, multilingual attacks, or "
        "indirect prompt injection reliably. Do not rely on it as a production security control."
    )

elif page == "Settings":
    st.markdown("### Settings")
    st.markdown("#### Local data")
    st.write("**Storage:** SQLite on this device")
    st.code(str(Path(DB_PATH).resolve()), language="text")
    st.write(f"**Recorded scans:** {len(history)}")
    st.write("**Prompt retention:** Full prompts are never saved.")
    st.write(
        "Prompt previews are optional, off by default, truncated to 120 characters, "
        "and redact common email and credential formats. Redaction cannot guarantee "
        "that all sensitive content is removed."
    )
    st.markdown("#### Detection configuration")
    st.write(f"**Configured rules:** {len(RULES)}")
    st.write("**Detection engine:** Local regular-expression rules · no ML model")
    st.caption(
        "Prototype settings are intentionally minimal. Scan history can be permanently "
        "removed from the Scan History page."
    )

st.divider()
st.markdown(
    '<div style="text-align:center;color:#64748B;font-size:11px">'
    'PROMPT SHELTER · GROUP B19 · RESEARCH PROTOTYPE'
    '<br>Experimental detection only · not a production security guarantee'
    '</div>',
    unsafe_allow_html=True,
)
