# AI-Powered SOC Alert Triage Tool

**Author:** Pranali Koshti | MS MIS, University at Buffalo, May 2026  
**Stack:** Python 3.11 · Splunk REST API · VirusTotal API · Ollama (Phi3)  
**Platform:** Windows 11  
**Cost:** $0 — Splunk free tier, VirusTotal free tier, Ollama fully local  

---

## Overview

An automated SOC alert triage pipeline that connects to Splunk, enriches every external IP via VirusTotal, and uses a local LLM (Phi3 via Ollama) to generate a structured analyst brief for each alert. Output is a priority-ranked HTML report that opens in the browser automatically.

Built on experience doing incident response across a 10,000+ node network at Samsung Electronics, where manual alert-by-alert triage is structurally impossible at scale. This tool automates the repetitive Tier 1 work so analysts can focus on the alerts that actually matter.

**Human-in-the-loop by design.** The AI recommends, the analyst decides. Every card in the report shows the AI brief alongside raw evidence. No automated blocking or ticket creation.

---

## How it works

```
Splunk REST API (port 8089)
  |
  |-- pulls HIGH and CRITICAL alerts (last 24 hours)
  v
IOC Extractor
  |
  |-- regex extracts all external public IPs and domains
  v
VirusTotal API
  |
  |-- malicious count, suspicious count, threat categories per IOC
  v
Ollama / Phi3 (local LLM)
  |
  |-- generates structured analyst brief per alert:
  |     summary, MITRE technique, threat level,
  |     IOC assessment, recommended action, FP likelihood
  v
HTML Triage Report
  |
  |-- priority ranked by composite score
  |-- color coded by severity
  |-- opens in browser automatically
```

---

## Priority scoring

Alerts are ranked by a composite score rather than raw severity alone.

```
score = severity_weight + (vt_malicious x 5) + (vt_suspicious x 1)

severity weights:
  CRITICAL = 30
  HIGH     = 20
  MEDIUM   = 10
  LOW      =  5
```

A HIGH alert with a VirusTotal-confirmed malicious IP outranks a CRITICAL alert with a clean IP. Signature-based severity alone does not reflect actual threat. IOC reputation does.

---

## Sample output

| Alert | AI threat level | MITRE technique | VT malicious | Score |
|-------|----------------|-----------------|--------------|-------|
| ET MALWARE CobaltStrike Beacon | CRITICAL | T1071.001 App Layer Protocol | 5/6 vendors | 56 |
| DNS Tunneling High Query Volume | CRITICAL | T1132 Data Encoding | 9/11 vendors | 75 |
| ET EXPLOIT Log4Shell CVE-2021-44228 | CRITICAL | T1210 Exploit Public App | 9/10 vendors | 65 |
| ET SCAN SSH Brute Force | HIGH | T1110 Brute Force | 16/19 vendors | 103 |
| Multiple Failed SMB Auth | HIGH | T1208 Kerberoasting | 0 (internal IP) | 20 |

All four external IPs in the test dataset were confirmed malicious by VirusTotal at time of run.

---

## Repository structure

```
ai-soc-triage/
├── main.py               -- entry point, runs the full pipeline
├── triage_tool.py        -- Splunk connection and VirusTotal enrichment
├── ai_layer.py           -- Ollama/OpenAI LLM integration
├── report_gen.py         -- HTML report generator
├── test_alerts.json      -- sample Splunk events for testing
├── env.example           -- .env template with no real values
├── .gitignore            -- .env and reports/ excluded
├── docs/
│   └── analysis.md       -- findings analysis and AI accuracy review
└── README.md
```

---

## Quick start

### Prerequisites

- Python 3.11 (python.org or Microsoft Store)
- Splunk Enterprise free tier (splunk.com/download)
- VirusTotal free account and API key (virustotal.com)
- Ollama installed with Phi3 model (ollama.com)

### Setup

```powershell
git clone https://github.com/[yourhandle]/ai-soc-triage
cd ai-soc-triage
python -m venv venv
venv\Scripts\activate
pip install requests python-dotenv openai

copy env.example .env
notepad .env
```

Fill in your `.env` values:

```
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USER=your-splunk-username
SPLUNK_PASS=your-splunk-password
SPLUNK_INDEX=alerts

VT_API_KEY=your-virustotal-api-key

AI_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=phi3
```

### Upload test data to Splunk

1. Open Splunk at http://localhost:8000
2. Settings > Add Data > Upload > select `test_alerts.json`
3. Source type: `_json`
4. Index: create new index named `alerts`
5. Submit

### Run

Open two PowerShell windows.

Window 1 (keep open):
```powershell
ollama serve
```

Window 2:
```powershell
cd ai-soc-triage
venv\Scripts\activate
python main.py
```

The HTML report opens in your browser automatically when complete.

---

## AI provider options

| Provider | Cost | Speed | Setup |
|----------|------|-------|-------|
| Ollama Phi3 (local) | Free, no internet | 5-15s per alert | Install Ollama, run `ollama pull phi3` |
| Ollama Llama 3.1 (local) | Free, no internet | 20-60s per alert | Needs 8+ GB RAM free |
| OpenAI GPT-4o-mini | ~$0 (free credit) | 1s per alert | API key from platform.openai.com |

Switch providers by changing `AI_PROVIDER` in `.env` to `openai` or `ollama`.

---

## Key design decisions

**Why Phi3 over Llama 3.1**  
Phi3 (2.2 GB) is significantly faster than Llama 3.1 (4.7 GB) on consumer hardware with 8 GB RAM. Output quality for structured JSON generation is comparable. Llama 3.1 caused system hangs on machines with limited available RAM.

**Why basic auth over token auth**  
Splunk token authentication requires KVStore to be healthy. KVStore has a known instability on fresh Windows installs. Basic username/password auth against the REST API works without KVStore and is equally secure for a local lab environment.

**Why composite scoring over raw severity**  
Splunk and Suricata assign severity based on rule metadata, not on real-time threat intelligence. A HIGH-severity signature matching a known CobaltStrike C2 IP with 16 VirusTotal detections is more urgent than a CRITICAL signature matching a clean internal IP. The composite score reflects this.

**Why not automate the response**  
Automated blocking based on LLM output introduces risk of false-positive-driven outages. The correct architecture for a production SOC tool is AI-assisted triage with human approval for all response actions. This tool is built to that standard.

---

## Limitations and known gaps

- VirusTotal free tier allows 4 requests per minute. With many alerts the enrichment phase is slow. A paid VT key or the Intelligence API removes this constraint.
- Phi3 occasionally returns malformed JSON despite prompt instructions. The parser includes fallback extraction logic but if all else fails it returns a manual review placeholder.
- The Splunk SPL query is written for the `test_alerts.json` field names. Real home lab data from Suricata or Zeek will have different field names and the query will need adjusting.
- The tool does not currently write back to Splunk or create tickets. Integration with JIRA or ServiceNow would be the next production step.

---

## Skills demonstrated

- Python scripting (REST API integration, regex, JSON parsing)
- Splunk REST API and SPL query authoring
- VirusTotal threat intelligence enrichment
- LLM prompt engineering for structured security output
- Ollama local model deployment
- MITRE ATT&CK technique identification
- Composite risk scoring logic
- HTML report generation
- Secrets management (.env, .gitignore)

---

## Background

3 years as Network Security Engineer at Samsung Electronics, including incident response across 10,000+ network infrastructure nodes and IAM design for enterprise-scale environments. This tool addresses a gap observed at that scale: when alert volume exceeds human triage capacity, you need automation that prioritizes correctly, not just automation that runs fast.
