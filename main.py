"""
main.py — run this to execute the full triage pipeline
"""
import subprocess, sys
from triage_tool import get_alerts, extract_iocs, enrich_iocs, priority_score
from ai_layer    import analyze_all
from report_gen  import generate_report

def main():
    print("\n" + "="*55)
    print("  AI-POWERED SOC ALERT TRIAGE")
    print("="*55 + "\n")

    # Step 1: Pull alerts from Splunk
    alerts = get_alerts()
    if not alerts:
        print("\n[!] No alerts found. Options:")
        print("    1. Upload test_alerts.json to Splunk (see README)")
        print("    2. Check SPLUNK_INDEX in .env matches your data index")
        print("    3. Verify Splunk is running: http://localhost:8000")
        sys.exit(1)

    # Step 2: Extract IOCs
    iocs = extract_iocs(alerts)

    # Step 3: VirusTotal enrichment
    enriched = enrich_iocs(iocs) if iocs else {}

    # Step 4: Calculate priority scores
    scores = {i: priority_score(a, enriched) for i, a in enumerate(alerts)}

    # Step 5: AI analysis
    analyzed = analyze_all(alerts, enriched)

    # Step 6: Generate HTML report
    print("\n[*] Generating HTML report...")
    out = generate_report(analyzed, enriched, scores)
    print(f"[+] Report saved: {out}")

    # Open in default browser (Windows)
    subprocess.Popen(["start", str(out)], shell=True)
    print("[+] Opened in browser.")
    print("\nDone.\n")

if __name__ == "__main__":
    main()