# 🛡️ Nmap AI Agent (MCP Server + Streamlit UI)

## 📌 Introduction

**Nmap AI Agent** is a modern security tool that lets you perform **Nmap scans using natural language commands**.  
It integrates:

- **MCP Nmap Server (FastAPI)** → exposes Nmap as an API with advanced scan options.  
- **Streamlit Frontend** → user-friendly UI where you can type commands in plain English.  
- **Google Gemini AI** → interprets natural language, plans the scan, and even provides security analysis of results.  
- **Automated VAPT Reporting** → generates vulnerability assessment style reports from Nmap results.

This makes it easier for **pentesters, security analysts, and developers** to run scans without memorizing Nmap flags.

---

## 🚀 Features

- 🌐 **Natural Language Scans** → “Scan `scanme.nmap.org` on ports 22 and 80”  
- ⚡ **FastAPI MCP Server** → exposes `/scan` and `/version` endpoints  
- 🔧 **Advanced Nmap Options** → service detection, OS detection, UDP, scripts, timing, etc.  
- 🤖 **AI-Powered Planning** → Gemini decides the best Nmap arguments for your intent  
- 📊 **Interactive Results** → filterable tables, open ports summary, command preview  
- 📝 **VAPT Report Generation** → auto-build markdown reports with risk ratings & recommendations  
- 🔒 **Security-Focused Analysis** → Gemini highlights possible vulnerabilities  

---

