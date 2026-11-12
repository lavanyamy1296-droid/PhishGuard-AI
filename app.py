import streamlit as st
import pandas as pd
from phishguard.detector import analyze_url, train_model, get_model_metrics

st.set_page_config(page_title="PhishGuard AI", page_icon="🛡️", layout="wide")
st.title("🛡️ PhishGuard AI")
st.caption("A machine-learning-assisted phishing URL risk checker")
st.warning("Educational demo only. It analyzes the URL text and does not visit the website. A low-risk result does not guarantee a site is safe.")

@st.cache_resource
def load_model():
    return train_model()

model = load_model()

with st.sidebar:
    st.header("About this project")
    st.write("PhishGuard extracts URL characteristics, combines a Random Forest classifier with transparent risk indicators, and explains its result.")
    st.write("No URL is opened, crawled, or submitted to a third-party service.")
    st.caption("The included training examples are synthetic demonstration data, not a production-grade threat-intelligence dataset.")

url = st.text_input("Enter a website URL", placeholder="https://example.com/login")
if st.button("Analyze URL", type="primary", use_container_width=True):
    if not url.strip():
        st.error("Please enter a URL first.")
    else:
        result = analyze_url(url, model)
        st.session_state["last_result"] = result

if "last_result" in st.session_state:
    r = st.session_state["last_result"]
    st.divider()
    col1, col2, col3 = st.columns(3)
    col1.metric("Risk score", f'{r["risk_score"]}/100')
    col2.metric("ML phishing probability", f'{r["ml_probability"]:.1%}')
    col3.metric("Detected indicators", len(r["indicators"]))
    if r["risk_score"] >= 65:
        st.error("HIGH RISK — Treat this URL as suspicious.")
    elif r["risk_score"] >= 35:
        st.warning("CAUTION — Review the URL carefully.")
    else:
        st.success("LOWER RISK — No strong warning signs were detected.")
    st.subheader("Why this result?")
    if r["indicators"]:
        for item in r["indicators"]:
            st.write(f"• {item}")
    else:
        st.write("No common suspicious URL patterns were detected.")
    st.subheader("Extracted URL features")
    st.dataframe(pd.DataFrame([r["features"]]).T.rename(columns={0:"Value"}), use_container_width=True)
    st.caption("The score is an educational heuristic. Attackers can use clean-looking URLs, and legitimate sites can have unusual URLs.")

with st.expander("Model information"):
    metrics = get_model_metrics(model)
    st.write(f"Model: Random Forest classifier | Demonstration holdout accuracy: {metrics['accuracy']:.1%}")
    st.write(f"Training examples: {metrics['samples']} synthetic URLs")
    st.write("Do not use this demo as the sole basis for security decisions.")
