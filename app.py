# app.py
import streamlit as st
from waf_engine import analyze_input

# UI Configuration 
st.set_page_config(
    page_title="WAF Rule Recommender",
    page_icon="🛡️",
    layout="centered"
)

# Header Section
st.title("🛡️ WAF Rule Recommender")
st.markdown("""
**System Status:** Online | **Engine:** Rule-Based Heuristic  
*Objective:* Detect web attack patterns and recommend blocking rules.
""")
st.markdown("---")

#  Sidebar Documentation 
with st.sidebar:
    st.header("📋 System Info")
    st.info("""
    **Architecture:** Classical Expert System
    **Logic:** Forward Chaining
    **Knowledge Base:** 22 Signatures
    """)
    st.write("Supported Attacks:")
    st.markdown("- SQL Injection (SQLi)\n- Cross-Site Scripting (XSS)\n- Command Injection\n- LFI/Path Traversal\n- CSRF & CORS")

# Main Input Section 
st.subheader("🔍 Threat Analysis Console")
user_query = st.text_area(
    "Enter Suspicious Log or Request String:", 
    height=150, 
    placeholder="e.g., /search.php?id=1' OR 1=1"
)

# Execution Logic 
if st.button("Analyze Input", type="primary"):
    if user_query:
        with st.spinner("Scanning Knowledge Base..."):
            # Call the Inference Engine
            results = analyze_input(user_query)
        
        # Result Display
        if not results:
            st.success("✅ CLEAN: No known attack signatures detected.")
            st.caption("Traffic appears safe based on current rules.")
        else:
            st.error(f"🚨 ALERT: {len(results)} Threat(s) Identified!")
            
            for threat in results:
                # Visual grouping for each threat
                with st.expander(f"🔴 {threat['attack_type']} (Rule ID: {threat['rule_id']})", expanded=True):
                    col1, col2 = st.columns([1, 3])
                    
                    with col1:
                        st.metric("Risk Level", threat['risk_level'])
                    
                    with col2:
                        st.markdown(f"**Description:** {threat['description']}")
                        st.markdown(f"**Triggered By:** `{threat['match_found']}`")
                        st.warning(f"**Action:** BLOCK request & Log Rule #{threat['rule_id']}")
    else:
        st.warning("⚠️ Input buffer is empty. Please paste a log string.")