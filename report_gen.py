"""
report_gen.py - Fixed version
Clean HTML report with proper styling
"""
import os
import json
from datetime import datetime
from pathlib import Path


def severity_border(sev):
    colors = {
        "CRITICAL": "#e24b4a",
        "HIGH":     "#ef9f27",
        "MEDIUM":   "#639922",
        "LOW":      "#888888"
    }
    return colors.get(sev.upper(), "#cccccc")


def severity_badge_style(sev):
    styles = {
        "CRITICAL": "background:#fcebeb;color:#a32d2d",
        "HIGH":     "background:#faeeda;color:#854f0b",
        "MEDIUM":   "background:#eaf3de;color:#3b6d11",
        "LOW":      "background:#f0f0f0;color:#555555"
    }
    return styles.get(sev.upper(), "background:#f0f0f0;color:#333333")


def fp_color(fp):
    word = fp.split()[0] if fp else ""
    colors = {"Low": "#3b6d11", "Medium": "#854f0b", "High": "#a32d2d"}
    return colors.get(word, "#555555")


def render_vt_pills(relevant_vt):
    if not relevant_vt:
        return '<span style="font-size:11px;padding:2px 8px;border-radius:12px;border:1px solid #ddd;background:#fff">No external IOCs</span>'
    pills = []
    for val, data in relevant_vt.items():
        m = data.get("malicious", 0)
        if m > 0:
            style = "font-size:11px;padding:2px 8px;border-radius:12px;border:1px solid #f7c1c1;background:#fcebeb;color:#a32d2d"
            label = val + " - " + str(m) + " malicious"
        else:
            style = "font-size:11px;padding:2px 8px;border-radius:12px;border:1px solid #ddd;background:#fff;color:#333"
            label = val + " - clean"
        pills.append('<span style="' + style + '">' + label + '</span>')
    return " ".join(pills)


def build_alert_card(rank, alert, ai, score, enriched_iocs):
    sev      = ai.get("threat_level", alert.get("severity", "UNKNOWN")).upper()
    sig      = alert.get("sig") or alert.get("alert_signature") or alert.get("source", "Alert")
    src      = alert.get("src") or alert.get("src_ip") or "unknown"
    dest     = alert.get("dest") or alert.get("dest_ip") or "unknown"
    port     = alert.get("dest_port") or "unknown"
    host     = alert.get("host") or "unknown"
    ts       = str(alert.get("_time") or "")[:19]
    stype    = alert.get("sourcetype") or "unknown"
    fp       = ai.get("false_positive_likelihood") or "Unknown"
    summary  = ai.get("summary") or "No summary"
    mitre    = ai.get("mitre_technique") or "Unknown"
    ioc_ass  = ai.get("ioc_assessment") or "No assessment"
    action   = ai.get("recommended_action") or "Manual review required"

    alert_text  = json.dumps(alert)
    relevant_vt = {k: v for k, v in enriched_iocs.items() if k in alert_text}

    border  = severity_border(sev)
    bstyle  = severity_badge_style(sev)
    fcolor  = fp_color(fp)
    vt_html = render_vt_pills(relevant_vt)

    card = """
    <div style="background:#ffffff;border:1px solid #e0e0e0;border-radius:10px;
                padding:20px;margin-bottom:16px;border-left:5px solid """ + border + """">

      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px">
        <div style="font-size:15px;font-weight:600;color:#1a1a1a;flex:1;padding-right:12px">
          #""" + str(rank) + """ &nbsp; """ + sig + """
        </div>
        <div style="display:flex;gap:8px;flex-shrink:0">
          <span style="font-size:11px;padding:3px 10px;border-radius:4px;font-weight:600;""" + bstyle + """">
            """ + sev + """
          </span>
          <span style="font-size:11px;padding:3px 10px;border-radius:4px;
                       background:#f0f0f0;color:#444;font-weight:500">
            Score: """ + str(score) + """
          </span>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px">
        <div>
          <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:3px">Source IP</div>
          <div style="font-size:12px;color:#1a1a1a;font-weight:500">""" + src + """</div>
        </div>
        <div>
          <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:3px">Destination</div>
          <div style="font-size:12px;color:#1a1a1a;font-weight:500">""" + dest + ":" + port + """</div>
        </div>
        <div>
          <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:3px">Host / Sensor</div>
          <div style="font-size:12px;color:#1a1a1a;font-weight:500">""" + host + """</div>
        </div>
        <div>
          <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:3px">Time</div>
          <div style="font-size:12px;color:#1a1a1a">""" + ts + """</div>
        </div>
        <div>
          <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:3px">Source type</div>
          <div style="font-size:12px;color:#1a1a1a">""" + stype + """</div>
        </div>
        <div>
          <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:3px">FP likelihood</div>
          <div style="font-size:12px;font-weight:600;color:""" + fcolor + """">""" + fp + """</div>
        </div>
      </div>

      <div style="margin-bottom:12px">
        <div style="font-size:10px;color:#999;text-transform:uppercase;margin-bottom:6px">VirusTotal IOCs</div>
        """ + vt_html + """
      </div>

      <div style="background:#f8f8ff;border:1px solid #e8e8f0;border-radius:8px;padding:14px">
        <div style="font-size:10px;font-weight:700;color:#534AB7;text-transform:uppercase;
                    letter-spacing:0.06em;margin-bottom:12px">AI Analyst Brief</div>

        <div style="margin-bottom:10px">
          <div style="font-size:11px;color:#666;margin-bottom:3px">Summary</div>
          <div style="font-size:13px;color:#1a1a1a;line-height:1.5">""" + summary + """</div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
          <div>
            <div style="font-size:11px;color:#666;margin-bottom:3px">MITRE ATT&amp;CK</div>
            <div style="font-size:12px;color:#1a1a1a;font-weight:500">""" + mitre + """</div>
          </div>
          <div>
            <div style="font-size:11px;color:#666;margin-bottom:3px">IOC Assessment</div>
            <div style="font-size:12px;color:#1a1a1a">""" + ioc_ass + """</div>
          </div>
        </div>

        <div style="background:#fff9e6;border:1px solid #f0d070;border-radius:6px;padding:10px 14px">
          <div style="font-size:10px;color:#854f0b;font-weight:700;
                      text-transform:uppercase;margin-bottom:4px">Recommended Action</div>
          <div style="font-size:13px;color:#1a1a1a;font-weight:500">""" + action + """</div>
        </div>
      </div>
    </div>"""

    return card


def generate_report(analyzed_results, enriched_iocs, scores):
    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sorted_results = sorted(
        enumerate(analyzed_results),
        key=lambda x: scores.get(x[0], 0),
        reverse=True)

    total    = len(analyzed_results)
    critical = sum(1 for _, (_, ai) in sorted_results if ai.get("threat_level","").upper() == "CRITICAL")
    high     = sum(1 for _, (_, ai) in sorted_results if ai.get("threat_level","").upper() == "HIGH")
    mal_iocs = sum(1 for v in enriched_iocs.values() if v.get("malicious", 0) > 0)
    provider = os.getenv("AI_PROVIDER", "openai").upper()
    ts_now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary_cards = ""
    card_data = [
        (str(total),    "#1a1a1a", "Total Alerts"),
        (str(critical), "#a32d2d", "Critical (AI)"),
        (str(high),     "#854f0b", "High (AI)"),
        (str(mal_iocs), "#a32d2d" if mal_iocs > 0 else "#3b6d11", "Malicious IOCs"),
    ]
    for val, color, label in card_data:
        summary_cards += """
        <div style="background:#ffffff;border:1px solid #e8e8e8;border-radius:8px;
                    padding:16px;text-align:center">
          <div style="font-size:28px;font-weight:600;color:""" + color + """">""" + val + """</div>
          <div style="font-size:11px;color:#888;text-transform:uppercase;margin-top:4px">""" + label + """</div>
        </div>"""

    alert_cards = ""
    for rank, (idx, (alert, ai)) in enumerate(sorted_results, 1):
        alert_cards += build_alert_card(
            rank, alert, ai, scores.get(idx, 0), enriched_iocs)

    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Triage Report</title>
</head>
<body style="font-family:-apple-system,Segoe UI,sans-serif;
             background:#f5f5f5;margin:0;padding:2rem">

  <div style="max-width:1000px;margin:0 auto">

    <div style="margin-bottom:1.5rem">
      <h1 style="font-size:22px;font-weight:600;color:#1a1a1a;margin:0 0 4px">
        SOC Alert Triage Report
      </h1>
      <div style="font-size:12px;color:#888">
        Generated: """ + ts_now + """ &nbsp;|&nbsp;
        AI: """ + provider + """ &nbsp;|&nbsp;
        """ + str(total) + """ alerts analyzed
      </div>
    </div>

    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:1.5rem">
      """ + summary_cards + """
    </div>

    <h2 style="font-size:16px;font-weight:600;color:#1a1a1a;margin:0 0 12px">
      Alerts ranked by priority
    </h2>

    """ + alert_cards + """

  </div>
</body>
</html>"""

    REPORT_DIR = Path("reports")
    REPORT_DIR.mkdir(exist_ok=True)
    out = REPORT_DIR / ("triage_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".html")
    out.write_text(html, encoding="utf-8")
    return out