import difflib
import streamlit as st
from core import SunShineAgent, SIMULATED_HONEYPOT_LOG, NEBIUS_API_KEY, SANDBOX_UNAVAILABLE, CycleResult

st.set_page_config(page_title="SunShine", page_icon=None, layout="centered")

SUNSHINE_LOGO = """
<svg width="60" height="60" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="sunGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#3B82F6"/>
      <stop offset="35%" stop-color="#A855F7"/>
      <stop offset="65%" stop-color="#EC4899"/>
      <stop offset="100%" stop-color="#EF4444"/>
    </linearGradient>
  </defs>
  <g fill="url(#sunGradient)">
    <g id="rays"><polygon points="50,2 54,20 46,20"/></g>
    <use href="#rays" transform="rotate(30 50 50)"/>
    <use href="#rays" transform="rotate(60 50 50)"/>
    <use href="#rays" transform="rotate(90 50 50)"/>
    <use href="#rays" transform="rotate(120 50 50)"/>
    <use href="#rays" transform="rotate(150 50 50)"/>
    <use href="#rays" transform="rotate(180 50 50)"/>
    <use href="#rays" transform="rotate(210 50 50)"/>
    <use href="#rays" transform="rotate(240 50 50)"/>
    <use href="#rays" transform="rotate(270 50 50)"/>
    <use href="#rays" transform="rotate(300 50 50)"/>
    <use href="#rays" transform="rotate(330 50 50)"/>
  </g>
  <circle cx="50" cy="50" r="22" fill="url(#sunGradient)"/>
</svg>
"""

st.markdown("""
<style>
    .stApp { background-color: #0E1117; color: #E6E6E6; }
    .header-row { display: flex; align-items: center; gap: 14px; margin-bottom: 4px; }
    .header-title {
        font-size: 42px; font-weight: 700; letter-spacing: -1px;
        background: linear-gradient(90deg, #3B82F6, #A855F7, #EC4899, #EF4444);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .subtitle { color: #8B949E; font-size: 15px; margin-bottom: 30px; }
    .status-card { padding: 16px 20px; border-radius: 8px; margin: 10px 0; font-weight: 500; white-space: pre-line; }
    .status-attack { background-color: rgba(220,38,38,0.1); border-left: 4px solid #DC2626; color: #F87171; }
    .status-defense { background-color: rgba(22,163,74,0.1); border-left: 4px solid #16A34A; color: #4ADE80; }
    .status-pending { background-color: rgba(234,179,8,0.1); border-left: 4px solid #EAB308; color: #FACC15; }
    .status-purple { background-color: rgba(168,85,247,0.1); border-left: 4px solid #A855F7; color: #C084FC; }
    .status-pink { background-color: rgba(236,72,153,0.1); border-left: 4px solid #EC4899; color: #F9A8D4; }
    .section-label {
        color: #8B949E; font-size: 13px; text-transform: uppercase;
        letter-spacing: 1px; margin-top: 24px; margin-bottom: 8px;
        border-left: 3px solid #3B3B3B; padding-left: 8px;
    }
    .role-tag { display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; margin-right: 6px; }
    .tag-attack { background: #DC2626; color: white; }
    .tag-defense { background: #16A34A; color: white; }
    .tag-analyst { background: #A855F7; color: white; }
    .tag-hunter { background: #EC4899; color: white; }
    .duration { color: #6B7280; font-size: 12px; }
    .stButton button {
        background: linear-gradient(90deg, #3B82F6, #A855F7, #EC4899, #EF4444);
        color: white; border: none; border-radius: 6px; padding: 10px 24px; font-weight: 600;
    }
    .stButton button:hover { opacity: 0.9; }
    .stButton button:disabled { opacity: 0.4; }
</style>
""", unsafe_allow_html=True)

st.markdown(f'<div class="header-row">{SUNSHINE_LOGO}<span class="header-title">SunShine</span></div>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">One autonomous agent, four roles — Attacker, Defender, Analyst, Threat Hunter — verifying every claim with evidence before reporting it.</p>', unsafe_allow_html=True)

if not NEBIUS_API_KEY:
    st.markdown('<div class="status-card status-pending">NEBIUS_API_KEY is not set.</div>', unsafe_allow_html=True)

for key, default in [("running", False), ("result", None), ("report", None), ("pink_result", None)]:
    if key not in st.session_state:
        st.session_state[key] = default

run_clicked = st.button("Run Full Cycle", disabled=st.session_state.running)
if run_clicked:
    st.session_state.running = True
    st.session_state.result = None
    st.session_state.report = None
    st.session_state.pink_result = None

if st.session_state.running:
    agent = SunShineAgent()
    try:
        with st.spinner("Running the full cycle..."):
            st.session_state.result = agent.run_full_cycle()
            if st.session_state.result.exploit_code and st.session_state.result.status != SANDBOX_UNAVAILABLE:
                try:
                    st.session_state.report = agent.generate_report(st.session_state.result)
                except RuntimeError as e:
                    st.session_state.report = f"__ERROR__{e}"
                try:
                    st.session_state.pink_result = agent.honeypot_scan()
                except RuntimeError as e:
                    st.session_state.pink_result = f"__ERROR__{e}"
    except Exception as e:
        if st.session_state.result is None:
            st.session_state.result = CycleResult()
        st.session_state.result.errors.append(f"Unexpected error: {e}")
    finally:
        st.session_state.running = False

result = st.session_state.result

if result is not None:
    if result.status == SANDBOX_UNAVAILABLE:
        st.markdown('<p class="section-label"><span class="role-tag tag-attack">SYSTEM</span>Execution sandbox</p>', unsafe_allow_html=True)
        st.markdown(f'<div class="status-card status-pending">{result.errors[0] if result.errors else "Sandbox unavailable."}</div>', unsafe_allow_html=True)
    else:
        if result.analysis:
            st.markdown('<p class="section-label"><span class="role-tag tag-analyst">ANALYST</span>Initial triage</p>', unsafe_allow_html=True)
            st.write(result.analysis)
            st.markdown(f'<span class="duration">{result.durations.get("analysis", 0):.1f}s</span>', unsafe_allow_html=True)

        if not result.exploit_code:
            st.markdown('<p class="section-label"><span class="role-tag tag-attack">SYSTEM</span>Error</p>', unsafe_allow_html=True)
            st.markdown(f'<div class="status-card status-pending">{result.errors[-1] if result.errors else result.status_detail}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<p class="section-label"><span class="role-tag tag-attack">ATTACKER</span>Exploit written and executed</p>', unsafe_allow_html=True)
            st.code(result.exploit_code, language="python")
            with st.expander("View pre-patch test output"):
                st.code(result.pre_patch_log)

            if result.pre_patch_exploit_confirmed:
                st.markdown('<div class="status-card status-attack">Vulnerability confirmed — the exploit succeeded (verified by test result AND attack artifact)</div>', unsafe_allow_html=True)

                st.markdown(f'<p class="section-label"><span class="role-tag tag-defense">DEFENDER</span>Patch and verification ({result.attempts} attempt(s))</p>', unsafe_allow_html=True)
                with st.expander("View post-patch exploit test output"):
                    st.code(result.post_patch_exploit_log)
                with st.expander("View functional test output"):
                    st.code(result.functional_log)

                if result.patch_verified:
                    st.markdown(f'<div class="status-card status-defense">Patch verified — exploit blocked AND functionality preserved ({result.status_detail})</div>', unsafe_allow_html=True)
                    st.code(result.patched_code, language="python")
                    diff = difflib.unified_diff(
                        result.original_code.splitlines(),
                        result.patched_code.splitlines(),
                        lineterm="", fromfile="before", tofile="after",
                    )
                    with st.expander("View code diff (before vs after)"):
                        st.code("\n".join(diff), language="diff")
                else:
                    st.markdown(f'<div class="status-card status-pending">{result.status_detail}</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="status-card status-pending">Exploit did not reproduce the vulnerability</div>', unsafe_allow_html=True)

            if st.session_state.report:
                st.markdown('<p class="section-label"><span class="role-tag tag-analyst">ANALYST</span>Final report</p>', unsafe_allow_html=True)
                if st.session_state.report.startswith("__ERROR__"):
                    st.markdown(f'<div class="status-card status-pending">Report generation failed: {st.session_state.report[9:]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="status-card status-purple">{st.session_state.report}</div>', unsafe_allow_html=True)
                    st.download_button("Download report", st.session_state.report, file_name="sunshine_report.txt")

            st.markdown('<p class="section-label"><span class="role-tag tag-hunter">THREAT HUNTER</span>Simulated honeypot analysis</p>', unsafe_allow_html=True)
            st.caption("The traffic below is fictional sample data written for this demo, not real captured traffic.")
            with st.expander("View simulated honeypot traffic"):
                st.code("\n".join(SIMULATED_HONEYPOT_LOG))
            if st.session_state.pink_result:
                if st.session_state.pink_result.startswith("__ERROR__"):
                    st.markdown(f'<div class="status-card status-pending">Threat hunter analysis failed: {st.session_state.pink_result[9:]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="status-card status-pink">{st.session_state.pink_result}</div>', unsafe_allow_html=True)

            if result.errors:
                with st.expander("View non-fatal errors encountered during this run"):
                    for e in result.errors:
                        st.write("- " + e)
