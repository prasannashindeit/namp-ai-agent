import streamlit as st
import requests
import google.generativeai as genai
import json
import os
from dotenv import load_dotenv

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# ------------------------------
# Gemini Setup
# ------------------------------
model = None
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.5-flash")
    except Exception as e:
        st.error(f"Failed to initialize Gemini model: {e}")
else:
    st.error("GEMINI_API_KEY not set. Add it to mcp-nmap-agent/.env and restart the app.")

MCP_SERVER_URL = "http://127.0.0.1:8000"

# ------------------------------
# Streamlit UI
# ------------------------------
st.set_page_config(page_title="Nmap Agent", page_icon="🛡️", layout="wide")
st.title("🤖 Natural Language Nmap Agent")

st.write("Type your request in plain English, e.g.: *'Scan scanme.nmap.org and check ports 22 and 80'*")

user_input = st.text_area("💬 Your command", "Scan scanme.nmap.org and check common ports")
show_analysis = st.checkbox("Show AI analysis (description)", value=False)
vapt_view = st.checkbox("Show results in VAPT report format", value=True)
show_raw_json = st.checkbox("Show raw JSON", value=False)

# AI Auto Plan Mode
auto_plan = st.checkbox("Let AI plan the entire scan (target, ports, flags)", value=True)

# Advanced Options (used when Auto Plan is OFF)
with st.expander("⚙️ Advanced Nmap Options", expanded=not auto_plan):
    st.caption("These map to Nmap flags. You can also pass raw arguments.")
    col1, col2, col3 = st.columns(3)
    with col1:
        service_version = st.checkbox("-sV Version detection", value=False)
        os_detection = st.checkbox("-O OS detection", value=False)
        aggressive = st.checkbox("-A Aggressive", value=False)
        udp = st.checkbox("-sU UDP", value=False)
        no_ping = st.checkbox("-Pn No ping", value=False)
        ipv6 = st.checkbox("-6 IPv6", value=False)
    with col2:
        timing_template = st.selectbox("-T Timing", options=["", 0,1,2,3,4,5], index=0, help="Empty means default")
        verbose = st.selectbox("-v Verbosity", options=["",1,2], index=0)
        top_ports = st.number_input("--top-ports", min_value=0, step=10, value=0)
        source_port = st.number_input("-g Source port", min_value=0, max_value=65535, step=1, value=0)
    with col3:
        ports_override = st.text_input("Ports (-p)")
        scripts = st.text_input("--script")
        min_rate = st.number_input("--min-rate", min_value=0, step=100, value=0)
        max_rate = st.number_input("--max-rate", min_value=0, step=100, value=0)
        max_retries = st.number_input("--max-retries", min_value=0, step=1, value=0)
    dns_servers = st.text_input("--dns-servers (comma-separated)")
    interface = st.text_input("-e Interface")
    raw_arguments = st.text_input("Raw arguments (advanced)", placeholder="e.g. -sC --reason")

    st.markdown("**Manual target/ports fallback** (used if parsing fails or Auto Plan is off):")
    manual_target = st.text_input("Target override", value="")
    manual_ports = st.text_input("Ports override (e.g. 22,80 or 1-1024)", value="")

if st.button("Run Command"):
    with st.spinner("Interpreting command with Gemini..."):
        try:
            planned = {"target": None, "ports": "", "arguments": "", "rationale": ""}
            target = None
            ports = ""
            args_str = ""

            if auto_plan:
                if model is None:
                    st.error("AI planning requires GEMINI_API_KEY. Disable Auto Plan or set the key and reload.")
                    st.stop()
                plan_prompt = f"""
                You are an expert network security engineer. Design an optimal nmap scan for the user's intent.
                Produce STRICT JSON only (no markdown) in this schema:
                {{
                  "target": "<single target or CIDR or list-compatible string>",
                  "ports": "<optional -p value, e.g. 22,80 or 1-1024>",
                  "arguments": "<space-separated nmap flags excluding -p and target>",
                  "rationale": "<short explanation of why these options>"
                }}

                Rules:
                - Prefer safe defaults: start with top ports or 1-1024 unless the user asks otherwise.
                - Use -Pn if host discovery may be blocked.
                - Use -sV for service detection when services are needed.
                - Use -O or -A only when beneficial; -A implies heavier scan.
                - For UDP needs, add -sU with limited ports unless asked for full.
                - Include --script only when explicitly helpful.
                - Do not include the word nmap or the target in arguments.

                User request: {user_input}
                """
                plan_resp = model.generate_content(plan_prompt)
                raw_text = (plan_resp.text or "").strip()
                js_start = raw_text.find("{")
                js_end = raw_text.rfind("}")
                if js_start != -1 and js_end != -1 and js_end > js_start:
                    try:
                        planned = json.loads(raw_text[js_start:js_end+1])
                    except Exception:
                        pass
                target = (planned.get("target") or "").strip()
                ports = (planned.get("ports") or "").strip()
                args_str = (planned.get("arguments") or "").strip()

                # Show plan in a cleaner UI (no raw JSON)
                st.subheader("🧭 Planned Scan")
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**Target**")
                    st.code(target or "N/A")
                    st.markdown("**Ports**")
                    st.code(ports or "Default/Auto")
                with col_b:
                    st.markdown("**Arguments**")
                    st.code(args_str or "None")
                    rationale_text = (planned.get("rationale") or "").strip()
                    if rationale_text:
                        st.markdown("**Rationale**")
                        st.info(rationale_text)
                preview = f"nmap {args_str} {'-p ' + ports if ports else ''} {target}".replace("  ", " ").strip()
                st.code(preview, language="bash")
            else:
                # Manual/advanced mode
                if model is None:
                    st.info("Gemini not initialized. Proceeding with manual parameters.")
                # no LLM parse when auto_plan is False
                target = (manual_target or "").strip()
                ports = (ports_override or manual_ports or "").strip()
                args_str = (raw_arguments or "").strip()
                if not target:
                    st.error("No target specified. Provide it in Advanced Options.")
                    st.stop()

            # Call MCP backend
            params = {"target": target}
            if ports:
                params["ports"] = ports
            if args_str:
                params["arguments"] = args_str

            # If Auto Plan is off, also pass mapped flags from Advanced Options
            if not auto_plan:
                if service_version:
                    params["service_version"] = True
                if os_detection:
                    params["os_detection"] = True
                if aggressive:
                    params["aggressive"] = True
                if udp:
                    params["udp"] = True
                if no_ping:
                    params["no_ping"] = True
                if ipv6:
                    params["ipv6"] = True
                if isinstance(timing_template, int):
                    params["timing_template"] = timing_template
                if isinstance(verbose, int):
                    params["verbose"] = verbose
                if top_ports and top_ports > 0:
                    params["top_ports"] = int(top_ports)
                if scripts:
                    params["scripts"] = scripts
                if min_rate and min_rate > 0:
                    params["min_rate"] = int(min_rate)
                if max_rate and max_rate > 0:
                    params["max_rate"] = int(max_rate)
                if max_retries and max_retries > 0:
                    params["max_retries"] = int(max_retries)
                if dns_servers:
                    params["dns_servers"] = dns_servers
                if interface:
                    params["interface"] = interface
                if source_port and source_port > 0:
                    params["source_port"] = int(source_port)

            response = requests.get(f"{MCP_SERVER_URL}/scan", params=params)

            if response.status_code == 200:
                result = response.json()

                # Helper: build a simple VAPT report from Nmap-like results
                def build_vapt_report(data: dict) -> str:
                    # Expected keys: target, ports, hosts, scaninfo, scan_result
                    target = data.get("target", "")
                    ports_req = data.get("ports", "")
                    cmdline = data.get("command_line", "")
                    arguments = data.get("arguments", "")
                    scan_result = data.get("scan_result", {})
                    hosts = data.get("hosts", [])

                    # Normalize scan_result to a dict of hosts
                    if isinstance(scan_result, dict) and any(k for k in scan_result.keys() if isinstance(k, str)):
                        host_dict = scan_result
                    else:
                        host_dict = {}

                    # Heuristic risk mapping for common ports
                    risk_by_port = {
                        21: ("High", "FTP may allow anonymous login or cleartext creds"),
                        22: ("Medium", "SSH exposure; enforce key auth and limit access"),
                        23: ("High", "Telnet is insecure; disable or replace with SSH"),
                        25: ("Medium", "SMTP; check for open relay and STARTTLS"),
                        53: ("Medium", "DNS; ensure recursion disabled for external"),
                        80: ("Medium", "HTTP; enforce HTTPS, check for outdated apps"),
                        110:("High", "POP3 cleartext; prefer POP3S/IMAPS"),
                        139:("Medium", "NetBIOS/SMB; limit exposure"),
                        143:("Medium", "IMAP; prefer IMAPS"),
                        389:("High", "LDAP cleartext; prefer LDAPS"),
                        443:("Low", "HTTPS; ensure modern TLS and ciphers"),
                        445:("High", "SMB; known exploits, restrict access"),
                        3389:("High", "RDP; enforce MFA/NLA, restrict access"),
                    }

                    findings = []
                    for host, hdata in host_dict.items():
                        # hdata may be a dict with 'tcp'/'udp' keys
                        if not isinstance(hdata, dict):
                            continue
                        for proto in ("tcp", "udp"):
                            pdata = hdata.get(proto, {})
                            if isinstance(pdata, dict):
                                for p, meta in pdata.items():
                                    try:
                                        port = int(p)
                                    except Exception:
                                        continue
                                    state = (meta.get("state") if isinstance(meta, dict) else None) or meta.get("state", "") if isinstance(meta, dict) else ""
                                    if state != "open":
                                        continue
                                    name = meta.get("name", "") if isinstance(meta, dict) else ""
                                    product = meta.get("product", "") if isinstance(meta, dict) else ""
                                    version = meta.get("version", "") if isinstance(meta, dict) else ""
                                    risk, rec = risk_by_port.get(port, ("Informational", "Review service configuration and limit exposure"))
                                    service = "/".join([s for s in [name, product, version] if s])
                                    findings.append({
                                        "host": host,
                                        "proto": proto,
                                        "port": port,
                                        "service": service or name or "unknown",
                                        "risk": risk,
                                        "recommendation": rec,
                                    })

                    # Sort findings by risk then port
                    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
                    findings.sort(key=lambda x: (risk_order.get(x["risk"], 9), x["host"], x["port"]))

                    # Build markdown report
                    lines = []
                    lines.append(f"# VAPT Report")
                    lines.append("")
                    lines.append(f"**Scope**: {target or ','.join(hosts) or 'N/A'}")
                    if ports_req:
                        lines.append(f"**Requested Ports**: {ports_req}")
                    if arguments:
                        lines.append(f"**Arguments**: {arguments}")
                    if cmdline:
                        lines.append(f"**Command**: `{cmdline}`")
                    lines.append("")
                    lines.append("## Findings")
                    if not findings:
                        lines.append("- No open ports detected in the provided scope.")
                    else:
                        current_host = None
                        for f in findings:
                            if f["host"] != current_host:
                                current_host = f["host"]
                                lines.append("")
                                lines.append(f"### Host: {current_host}")
                            lines.append(f"- [{f['risk']}] {f['proto']}/{f['port']} - {f['service']}")
                            lines.append(f"  - Recommendation: {f['recommendation']}")
                    lines.append("")
                    lines.append("## Methodology")
                    lines.append("- Network discovery and port enumeration performed with Nmap.")
                    lines.append("- Service identification uses banner/version detection when enabled.")
                    lines.append("- Risk ratings are heuristic and depend on context and exposure.")
                    return "\n".join(lines)

                # Helper: flatten scan results for a clean table view
                def build_results_rows(data: dict):
                    rows = []
                    scan_result = data.get("scan_result", {})
                    if not isinstance(scan_result, dict):
                        return rows
                    for host, hdata in scan_result.items():
                        if not isinstance(hdata, dict):
                            continue
                        for proto in ("tcp", "udp"):
                            pdata = hdata.get(proto, {})
                            if isinstance(pdata, dict):
                                for p, meta in pdata.items():
                                    # meta may be dict with fields: state, name, product, version, extrainfo
                                    try:
                                        port = int(p)
                                    except Exception:
                                        port = p
                                    if isinstance(meta, dict):
                                        rows.append({
                                            "host": host,
                                            "proto": proto,
                                            "port": port,
                                            "state": meta.get("state", ""),
                                            "service": meta.get("name", ""),
                                            "product": meta.get("product", ""),
                                            "version": meta.get("version", ""),
                                            "extrainfo": meta.get("extrainfo", ""),
                                        })
                    # Sort rows by host, proto, port
                    rows.sort(key=lambda r: (r.get("host", ""), r.get("proto", ""), r.get("port", 0)))
                    return rows

                # Beautiful results summary and table
                st.subheader("📊 Scan Results")
                cols = st.columns(3)
                with cols[0]:
                    st.markdown("**Target**")
                    st.code(result.get("target") or "N/A")
                with cols[1]:
                    hosts = result.get("hosts", []) or []
                    st.markdown("**Hosts Found**")
                    st.code(str(len(hosts)))
                with cols[2]:
                    rows = build_results_rows(result)
                    open_ports = sum(1 for r in rows if r.get("state") == "open")
                    st.markdown("**Open Ports**")
                    st.code(str(open_ports))

                # Command preview for executed scan
                cmdline = result.get("command_line")
                if cmdline:
                    st.markdown("**Executed Command**")
                    st.code(cmdline, language="bash")

                # Results table with filter
                if rows:
                    st.markdown("**Ports and Services**")
                    only_open = st.checkbox("Show only open ports", value=True)
                    table_rows = [r for r in rows if (r.get("state") == "open")] if only_open else rows
                    st.dataframe(table_rows, use_container_width=True)
                else:
                    st.info("No port data available in results.")

                if vapt_view:
                    st.subheader("📄 VAPT Report")
                    report_md = build_vapt_report(result)
                    st.markdown(report_md)
                    st.download_button(
                        label="Download VAPT report (Markdown)",
                        data=report_md,
                        file_name="vapt_report.md",
                        mime="text/markdown",
                    )

                if show_raw_json:
                    with st.expander("Show raw JSON (advanced)"):
                        st.json(result)
                        st.download_button(
                            label="Download raw results (JSON)",
                            data=json.dumps(result, indent=2),
                            file_name="scan_result.json",
                            mime="application/json",
                        )

                # Ask Gemini to analyze results
                if show_analysis and "scan_result" in result:
                    scan_text = str(result["scan_result"])
                    st.subheader("🔎 Gemini Security Analysis")
                    analysis_prompt = f"""
                    Analyze these Nmap results and explain:
                    - Which ports are open
                    - Possible services/vulnerabilities
                    - Security recommendations

                    Results:
                    {scan_text}
                    """
                    gemini_response = model.generate_content(analysis_prompt)
                    st.write(gemini_response.text)

            else:
                st.error(f"Backend error: {response.status_code}")

        except Exception as e:
            st.error(f"Failed: {e}")
