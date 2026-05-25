import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

AI_PROVIDER = os.getenv("AI_PROVIDER", "openai").lower()

if AI_PROVIDER == "ollama":
    # Ollama exposes an OpenAI-compatible API at localhost:11434
    # The openai Python package works with it using base_url override
    client = OpenAI(
        base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434") + "/v1",
        api_key="ollama"   # Ollama doesn't need a real key
    )
    MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
else:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    MODEL  = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


SYSTEM_PROMPT = """You are a Tier 2 SOC analyst assistant. You receive structured 
alert data and produce concise, actionable analyst briefs.

Your output must be a JSON object with exactly these fields:
{
  "summary": "1-2 sentence plain English description of what this alert indicates",
  "mitre_technique": "Most likely ATT&CK technique ID and name (e.g. T1110 - Brute Force)",
  "threat_level": "CRITICAL / HIGH / MEDIUM / LOW",
  "ioc_assessment": "1 sentence on whether the source IP/domain appears malicious based on VT data",
  "recommended_action": "Single most important action the analyst should take right now",
  "false_positive_likelihood": "Low / Medium / High — with one-sentence reason"
}

Be direct and specific. Do not hedge. If the VT data shows malicious detections, 
say so explicitly. If it looks like a false positive, say that too.
Output ONLY the JSON object. No preamble, no explanation, no markdown fences."""


def analyze_alert(alert, vt_data):
    """
    Send one alert + its VT enrichment to the LLM.
    Returns parsed dict with analyst brief fields.
    """
    # Build context block — everything the AI needs to make a judgment
    context = {
        "alert_time":   alert.get("_time", "unknown"),
        "severity":     alert.get("severity", "unknown"),
        "signature":    alert.get("sig") or alert.get("alert_signature", "unknown"),
        "source_ip":    alert.get("src") or alert.get("src_ip", "unknown"),
        "dest_ip":      alert.get("dest") or alert.get("dest_ip", "unknown"),
        "dest_port":    alert.get("dest_port", "unknown"),
        "host":         alert.get("host", "unknown"),
        "sourcetype":   alert.get("sourcetype", "unknown"),
        "category":     alert.get("category", "unknown"),
        "vt_enrichment": vt_data   # VirusTotal results for IOCs in this alert
    }

    user_msg = f"""Analyze this security alert and provide your assessment:

{_format_context(context)}

VirusTotal enrichment for IOCs in this alert:
{_format_vt(vt_data)}"""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg}
            ],
            temperature=0.1,   # low temp = consistent, factual output
            max_tokens=400
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown fences if model added them despite instruction
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw)

    except json.JSONDecodeError:
        # Model returned non-JSON — return a fallback
        return {
            "summary": "AI analysis unavailable — JSON parse error",
            "mitre_technique": "Unknown",
            "threat_level": alert.get("severity", "UNKNOWN").upper(),
            "ioc_assessment": "See VirusTotal data",
            "recommended_action": "Manual analyst review required",
            "false_positive_likelihood": "Unknown"
        }
    except Exception as e:
        return {
            "summary": f"AI analysis error: {str(e)[:80]}",
            "mitre_technique": "Unknown",
            "threat_level": alert.get("severity", "UNKNOWN").upper(),
            "ioc_assessment": "VT data available in report",
            "recommended_action": "Manual review required",
            "false_positive_likelihood": "Unknown"
        }


def analyze_all(alerts, enriched_iocs):
    """Run AI analysis on all alerts. Returns list of (alert, ai_result) tuples."""
    print(f"\n[*] Running AI analysis on {len(alerts)} alerts via {AI_PROVIDER.upper()}...")
    results = []
    for i, alert in enumerate(alerts):
        # Filter enriched IOCs to only those appearing in this alert
        alert_text = str(alert)
        relevant_vt = {k: v for k, v in enriched_iocs.items() if k in alert_text}
        print(f"    [{i+1}/{len(alerts)}] {alert.get('sig','alert')[:50]}...")
        ai = analyze_alert(alert, relevant_vt)
        results.append((alert, ai))
    return results


def _format_context(ctx):
    return "\n".join(f"  {k}: {v}" for k, v in ctx.items()
                     if k != "vt_enrichment")

def _format_vt(vt_data):
    if not vt_data:
        return "  No external IOCs found in this alert"
    lines = []
    for val, data in vt_data.items():
        lines.append(f"  {data.get('type','ioc')} {val}: "
                     f"malicious={data.get('malicious',0)}, "
                     f"suspicious={data.get('suspicious',0)}, "
                     f"categories={data.get('categories',[])}")
    return "\n".join(lines)
