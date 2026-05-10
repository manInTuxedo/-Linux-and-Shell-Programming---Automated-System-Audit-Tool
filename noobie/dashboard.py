import streamlit as st
import subprocess
import os
import glob
import re
from datetime import datetime

st.set_page_config(
    page_title="System Audit Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ── Styling ───────────────────────────────────
st.markdown("""
<style>
.critical { background:#ff4b4b22; border-left:4px solid #ff4b4b; padding:10px 16px; border-radius:4px; margin:6px 0; }
.warning  { background:#ffa50022; border-left:4px solid #ffa500; padding:10px 16px; border-radius:4px; margin:6px 0; }
.ok       { background:#00c85322; border-left:4px solid #00c853; padding:10px 16px; border-radius:4px; margin:6px 0; }
.ai       { background:#7c4dff22; border-left:4px solid #7c4dff; padding:10px 16px; border-radius:4px; margin:6px 0; }
.info     { background:#0088ff22; border-left:4px solid #0088ff; padding:10px 16px; border-radius:4px; margin:6px 0; }
</style>
""", unsafe_allow_html=True)

# ── Parse report file ─────────────────────────
def parse_report(filepath):
    findings = {"CRITICAL": [], "WARNING": [], "OK": [], "AI": [], "INFO": []}
    current_section = "General"
    sections = {}

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Detect section headers
            if line.startswith("MODULE") or line.startswith("AUDIT"):
                current_section = line
                sections[current_section] = []
                continue

            # Categorize lines
            if "[CRITICAL]" in line:
                msg = line.replace("[CRITICAL]", "").strip()
                findings["CRITICAL"].append((current_section, msg))
                sections.setdefault(current_section, []).append(("CRITICAL", msg))
            elif "[WARNING]" in line:
                msg = line.replace("[WARNING]", "").strip()
                findings["WARNING"].append((current_section, msg))
                sections.setdefault(current_section, []).append(("WARNING", msg))
            elif "[OK]" in line:
                msg = line.replace("[OK]", "").strip()
                findings["OK"].append((current_section, msg))
                sections.setdefault(current_section, []).append(("OK", msg))
            elif "[AI ADVICE]" in line:
                msg = line.replace("[AI ADVICE]", "").strip()
                findings["AI"].append((current_section, msg))
                sections.setdefault(current_section, []).append(("AI", msg))
            elif "[INFO]" in line:
                msg = line.replace("[INFO]", "").strip()
                findings["INFO"].append((current_section, msg))
                sections.setdefault(current_section, []).append(("INFO", msg))

    return findings, sections

# ── Run audit and return output path ─────────
def run_audit(script_path):
    result = subprocess.run(
        ["sudo", "bash", script_path],
        capture_output=True, text=True
    )
    # Find the latest report file
    reports = sorted(glob.glob("audit_report_*.txt"), reverse=True)
    return reports[0] if reports else None

# ════════════════════════════════════════════
#   DASHBOARD
# ════════════════════════════════════════════

st.title("🛡️ System Audit Dashboard")
st.caption(f"Red Hat Linux — {datetime.now().strftime('%A, %B %d %Y  %H:%M')}")

st.divider()

# ── Sidebar ───────────────────────────────────
with st.sidebar:
    st.header("⚙️ Controls")

    # Find audit script
    script_path = st.text_input("Path to audit.sh", value="~/Project/audit.sh")
    script_path = os.path.expanduser(script_path)

    if st.button("▶ Run Audit Now", use_container_width=True, type="primary"):
        with st.spinner("Running audit... this may take a minute"):
            report_path = run_audit(script_path)
            if report_path:
                st.success(f"Done! Report: {report_path}")
                st.session_state["report"] = report_path
            else:
                st.error("Audit ran but no report file was found.")

    st.divider()

    # Load existing report
    st.subheader("📂 Load Existing Report")
    reports = sorted(glob.glob("audit_report_*.txt"), reverse=True)
    if reports:
        selected = st.selectbox("Choose a report", reports)
        if st.button("Load Report", use_container_width=True):
            st.session_state["report"] = selected
    else:
        st.info("No reports found yet. Run an audit first.")

# ── Main content ──────────────────────────────
if "report" not in st.session_state:
    st.info("👈 Click **Run Audit Now** in the sidebar to start, or load an existing report.")
    st.stop()

report_path = st.session_state["report"]

if not os.path.exists(report_path):
    st.error(f"Report file not found: {report_path}")
    st.stop()

findings, sections = parse_report(report_path)

# ── Summary cards ─────────────────────────────
st.subheader("Summary")
col1, col2, col3, col4 = st.columns(4)

col1.metric("🔴 Critical", len(findings["CRITICAL"]),
            delta="Immediate action" if findings["CRITICAL"] else None,
            delta_color="inverse")
col2.metric("🟡 Warnings", len(findings["WARNING"]),
            delta="Review soon" if findings["WARNING"] else None,
            delta_color="inverse")
col3.metric("🟢 Passed", len(findings["OK"]))
col4.metric("🤖 AI Recommendations", len(findings["AI"]))

st.divider()

# ── Chart ─────────────────────────────────────
st.subheader("Findings Overview")
chart_data = {
    "Category": ["Critical", "Warning", "Passed", "Info"],
    "Count": [
        len(findings["CRITICAL"]),
        len(findings["WARNING"]),
        len(findings["OK"]),
        len(findings["INFO"])
    ]
}

col_chart, col_space = st.columns([2, 1])
with col_chart:
    st.bar_chart(
        data={"Critical": [len(findings["CRITICAL"])],
              "Warning":  [len(findings["WARNING"])],
              "Passed":   [len(findings["OK"])],
              "Info":     [len(findings["INFO"])]},
        color=["#ff4b4b", "#ffa500", "#00c853", "#0088ff"]
    )

st.divider()

# ── Detailed findings by module ───────────────
st.subheader("Detailed Findings")

MODULE_ICONS = {
    "MODULE 1": "🔌",
    "MODULE 2": "📁",
    "MODULE 3": "👤",
    "MODULE 4": "📦",
}

for section_name, items in sections.items():
    if not items:
        continue

    icon = next((v for k, v in MODULE_ICONS.items() if k in section_name), "📋")
    with st.expander(f"{icon}  {section_name}", expanded=True):
        for level, msg in items:
            if level == "CRITICAL":
                st.markdown(f'<div class="critical">🔴 <b>Critical:</b> {msg}</div>', unsafe_allow_html=True)
            elif level == "WARNING":
                st.markdown(f'<div class="warning">🟡 <b>Warning:</b> {msg}</div>', unsafe_allow_html=True)
            elif level == "OK":
                st.markdown(f'<div class="ok">🟢 <b>OK:</b> {msg}</div>', unsafe_allow_html=True)
            elif level == "AI":
                # Split issue → advice
                parts = msg.split("→", 1)
                issue = parts[0].strip()
                advice = parts[1].strip() if len(parts) > 1 else ""
                st.markdown(f'<div class="ai">🤖 <b>AI Advice for:</b> {issue}<br><i>{advice}</i></div>', unsafe_allow_html=True)
            elif level == "INFO":
                st.markdown(f'<div class="info">ℹ️ {msg}</div>', unsafe_allow_html=True)

st.divider()

# ── Raw report viewer ─────────────────────────
with st.expander("📄 View Raw Report"):
    with open(report_path, "r") as f:
        st.code(f.read(), language="bash")

# ── Download button ───────────────────────────
with open(report_path, "r") as f:
    st.download_button(
        label="⬇️ Download Report",
        data=f.read(),
        file_name=os.path.basename(report_path),
        mime="text/plain"
    )
