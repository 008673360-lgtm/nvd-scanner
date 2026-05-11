#!/usr/bin/env python3
"""
NVD CVE Scanner - Search for vulnerabilities by software name & version
Uses NIST NVD API v2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import os
import requests
import pandas as pd
import gradio as gr
from datetime import datetime

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY", "")  # Optional: Get at https://nvd.nist.gov/developers

def search_cves(product_name: str, version: str = "") -> pd.DataFrame:
    """Query NVD API for CVEs matching product name and optional version"""
    if not product_name.strip():
        return pd.DataFrame(columns=["CVE ID", "Severity", "CVSS Score", "Description", "Published Date", "Link"])
    
    # Build keyword search query
    keyword = product_name.strip()
    if version.strip():
        keyword += f" {version.strip()}"
    
    headers = {"apiKey": API_KEY} if API_KEY else {}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
        "startIndex": 0
    }
    
    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        results = []
        for cve in data.get("vulnerabilities", []):
            cve_item = cve["cve"]
            cve_id = cve_item["id"]
            
            # Extract description
            descriptions = cve_item.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")
            # Truncate long descriptions for table display
            if len(desc_text) > 200:
                desc_text = desc_text[:197] + "..."
            
            # Extract CVSS metrics (prefer v3.1 > v3.0 > v2)
            metrics = cve_item.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics and metrics[version_key]:
                    metric = metrics[version_key][0]
                    if "cvssData" in metric:
                        cvss_data = metric["cvssData"]
                        cvss_score = cvss_data.get("baseScore", "N/A")
                        severity = cvss_data.get("baseSeverity", "N/A").upper()
                        break
            
            # Extract published date
            published = cve_item.get("published", "")[:10] if cve_item.get("published") else "N/A"
            
            # NVD detail link
            nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            
            results.append({
                "CVE ID": cve_id,
                "Severity": severity,
                "CVSS Score": cvss_score,
                "Description": desc_text,
                "Published Date": published,
                "Link": nvd_link
            })
        
        return pd.DataFrame(results)
        
    except requests.exceptions.RequestException as e:
        error_msg = str(e)
        if "403" in error_msg or "rate limit" in error_msg.lower():
            error_msg = "⚠️ Rate limit exceeded. Wait 30 seconds or add an API key via NVD_API_KEY env var."
        return pd.DataFrame([{
            "CVE ID": "Error",
            "Severity": "",
            "CVSS Score": "",
            "Description": f"API request failed: {error_msg}",
            "Published Date": "",
            "Link": ""
        }])
    except Exception as e:
        return pd.DataFrame([{
            "CVE ID": "Error",
            "Severity": "",
            "CVSS Score": "",
            "Description": f"Unexpected error: {str(e)}",
            "Published Date": "",
            "Link": ""
        }])


def format_severity(severity: str) -> str:
    """Add color coding for severity levels"""
    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠", 
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "N/A": "⚪"
    }
    color = colors.get(severity.upper(), "⚪")
    return f"{color} {severity}"


def create_gradio_app():
    """Build and launch the Gradio interface"""
    
    def run_search(name, version):
        df = search_cves(name, version)
        if df.empty or df.iloc[0]["CVE ID"] == "Error":
            return df, df.iloc[0]["Description"] if not df.empty else "No CVEs found or error occurred."
        
        # Format severity with emojis
        df["Severity"] = df["Severity"].apply(format_severity)
        # Make links clickable in Gradio table
        df["Link"] = df["Link"].apply(lambda x: f"<a href='{x}' target='_blank'>🔗 View</a>")
        return df, f"✅ Found {len(df)} CVE(s) for '{name} {version}'. Click 🔗 to view details on NVD."
    
    with gr.Blocks(title="🔐 NVD CVE Scanner", theme=gr.themes.Soft()) as demo:
        gr.Markdown("""
        ## 🔐 NVD CVE Scanner
        Search for known vulnerabilities (CVEs) using the [NIST NVD API](https://nvd.nist.gov/).
        """)
        
        with gr.Row():
            with gr.Column(scale=1):
                product_input = gr.Textbox(
                    label="Software/Product Name *",
                    placeholder="e.g., apache tomcat, openssl, log4j",
                    info="Enter the software name to search for CVEs"
                )
                version_input = gr.Textbox(
                    label="Version (optional)",
                    placeholder="e.g., 9.0.65, 1.1.1, 2.14.1"
                )
                search_btn = gr.Button("🔍 Search CVEs", variant="primary")
                
                gr.Examples(
                    examples=[
                        ["apache tomcat", "9.0.0"],
                        ["openssl", "1.1.1"],
                        ["log4j", "2.14.1"],
                        ["wordpress", "5.8"],
                        ["nginx", "1.18.0"]
                    ],
                    inputs=[product_input, version_input],
                    label="Try these examples:"
                )
                
                gr.Markdown("""
                > ℹ️ **Tips**  
                > • No API key? Limited to 5 requests/30 seconds [[16]]  
                > • Get free API key: https://nvd.nist.gov/developers/request-an-api-key [[18]]  
                > • Set env var: `export NVD_API_KEY="your-key"`  
                > • Results update in real-time from NVD
                """)
            
            with gr.Column(scale=2):
                status_output = gr.Markdown()
                results_table = gr.Dataframe(
                    headers=["CVE ID", "Severity", "CVSS Score", "Description", "Published Date", "Link"],
                    datatype=["str", "str", "str", "str", "str", "html"],
                    interactive=False,
                    wrap=True
                )
        
        search_btn.click(
            fn=run_search,
            inputs=[product_input, version_input],
            outputs=[results_table, status_output]
        )
        
        # Allow Enter key to trigger search
        product_input.submit(run_search, inputs=[product_input, version_input], outputs=[results_table, status_output])
        version_input.submit(run_search, inputs=[product_input, version_input], outputs=[results_table, status_output])
        
        gr.Markdown("""
        ---
        <center>
        <small>
        🔐 NVD CVE Scanner | Uses NVD API v2.0 | 
        <a href="https://nvd.nist.gov/vuln/data-feeds" target="_blank">NVD Data Feeds</a> | 
        Not endorsed by NIST NVD
        </small>
        </center>
        """)
    
    return demo


if __name__ == "__main__":
    print("🚀 Starting NVD CVE Scanner...")
    print("📡 Using NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0")
    if API_KEY:
        print("✅ API key detected (higher rate limits)")
    else:
        print("⚠️ No API key set - limited to 5 requests/30 seconds")
        print("💡 Get free key: https://nvd.nist.gov/developers/request-an-api-key")
    
    demo = create_gradio_app()
    # share=True creates a public URL valid for 72 hours [[21]][[24]]
    demo.launch(share=True, server_name="0.0.0.0", server_port=7860)