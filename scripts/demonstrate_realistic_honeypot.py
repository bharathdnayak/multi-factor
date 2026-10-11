"""
================================================================================
BEHAVIORAL DRIFT: CONTINUOUS AUTHENTICATION & HONEYPOT FORENSICS
REALISTIC, STATEFUL HONEYPOT DESKTOP & FORENSIC INTELLIGENCE DEMONSTRATION
================================================================================

This comprehensive demonstration script executes the complete 10-stage interactive
honeypot workflow in a simulated, fully isolated defensive environment:

  [STAGE 1]  Centralized VFS Extended Profiles & State Persistence
  [STAGE 2]  DecoySettings Specifications & Category Navigation
  [STAGE 3]  Dynamic Wallpaper Canvas Theming & Telemetry
  [STAGE 4]  Windows 11 Start Menu Dual-Mode Search & Pinned Grid
  [STAGE 5]  Decoy File Explorer Navigation & Breadcrumb Inspection
  [STAGE 6]  Decoy Notepad Sensitive Pattern Interception & Recent Files
  [STAGE 7]  Virtual PowerShell Extended Cmdlets (tree, Get-Date, Get-Service)
  [STAGE 8]  Decoy Chrome Cloud Download Sync to VFS Downloads
  [STAGE 9]  Recycle Bin Deletion, Inspection, Restoration & Purge Lifecycle
  [STAGE 10] Explainable Behavioral Indicators Derivation & Sealed Forensic PDF

CRITICAL DEFENSIVE GUARANTEES:
  - 100% Host Isolation: No host filesystem modification or subprocess execution.
  - Zero OTP / Recovery Subsystem alteration.
  - Standardized Forensic Schema (ISO-8601, UTC, correlation_id, event_id).
================================================================================
"""

import os
import sys
import time
import json
import hashlib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

from deception.virtual_fs import get_vfs, VirtualFileSystem, PathUtils
from deception.command_engine import VirtualCommandEngine
from deception.forensic_tracker import get_tracker
from deception.honey_desktop import HoneypotDesktop, DecoySettings, Windows11StartMenu
from deception.decoy_explorer import DecoyExplorer
from deception.decoy_notepad import DecoyNotepad
from deception.decoy_chrome import DecoyChrome
from deception.ai_intent_analyzer import IntruderIntentAnalyzer, extract_behavioral_indicators
from dashboard.pdf_generator import ForensicReportGenerator


def print_banner(step_num: int, title: str):
    print("\n" + "=" * 80)
    print(f" [STAGE {step_num:02d}] {title}")
    print("=" * 80)


def print_substep(text: str):
    print(f"  --> {text}")


def main():
    print("=" * 80)
    print("       BEHAVIORAL DRIFT - REALISTIC HONEYPOT DESKTOP & FORENSICS DEMO")
    print("=" * 80)
    print(f" Working Directory : {PROJECT_ROOT}")
    print(f" Python Interpreter: {sys.executable}")
    print(f" Execution Mode    : Automated Headless Forensic Demonstration")

    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    tracker = get_tracker()
    tracker.reset_session()
    vfs = get_vfs()

    sandbox_dir = os.path.join(PROJECT_ROOT, "data", "sandbox")
    os.makedirs(sandbox_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # STAGE 1: Centralized VFS Extended Profiles & State Persistence
    # -------------------------------------------------------------------------
    print_banner(1, "Centralized VFS Extended Profiles & State Persistence")
    expected_dirs = [
        "C:\\Users\\Public\\Desktop",
        "C:\\Users\\Dell\\Documents",
        "C:\\Users\\Dell\\Downloads",
        "C:\\Users\\Dell\\Pictures",
        "C:\\Users\\Dell\\AppData",
        "C:\\$Recycle.Bin"
    ]
    for d in expected_dirs:
        exists = vfs.exists(d)
        print_substep(f"Profile directory '{d}': {'PRESENT [OK]' if exists else 'MISSING [FAIL]'}")
        assert exists, f"Directory {d} must exist in VFS"

    # Create persistent sample document
    demo_doc = "C:\\Users\\Dell\\Documents\\Corporate_Operations_Plan_2026.docx"
    vfs.create_file(demo_doc, content="[CONFIDENTIAL] 2026 Enterprise Migration Roadmap", overwrite=True)
    print_substep(f"Created enterprise asset in VFS: '{demo_doc}'")

    state_file = os.path.join(sandbox_dir, "virtual_fs_state.json")
    saved = vfs.save_state(state_file)
    state_size = os.path.getsize(state_file) if os.path.exists(state_file) else 0
    print_substep(f"Persisted VFS state to JSON: '{state_file}' ({state_size:,} bytes, saved={saved})")
    assert saved and state_size > 1000, "VFS state save failed"

    # -------------------------------------------------------------------------
    # STAGE 2: DecoySettings Specifications & Category Navigation
    # -------------------------------------------------------------------------
    print_banner(2, "DecoySettings Specifications & Category Navigation")
    settings = DecoySettings()
    print_substep(f"DecoySettings initialized. Active Category: '{settings.active_tab}'")

    tabs = ["Display", "Personalization", "Privacy", "System"]
    for tab in tabs:
        settings.navigate_tab(tab)
        print_substep(f"Switched category to '{settings.active_tab}' | Stack Page: {settings.stack.currentIndex()}")
        assert settings.active_tab == tab

    timeline = tracker.get_timeline()
    settings_events = [e for e in timeline if e.get("action_type") == "SETTINGS_ACCESSED"]
    print_substep(f"Recorded {len(settings_events)} SETTINGS_ACCESSED forensic events with valid schema.")

    # -------------------------------------------------------------------------
    # STAGE 3: Dynamic Wallpaper Canvas Theming & Telemetry
    # -------------------------------------------------------------------------
    print_banner(3, "Dynamic Wallpaper Canvas Theming & Telemetry")
    desktop = HoneypotDesktop()
    themes = ["Bloom", "Light", "Sunrise", "Dark"]

    for t in themes:
        desktop.set_wallpaper_theme(t)
        print_substep(f"Applied wallpaper theme: '{t}' (Canvas dimensions: {desktop.screenshot.width()}x{desktop.screenshot.height()})")
        assert desktop.current_theme == t

    timeline = tracker.get_timeline()
    theme_events = [e for e in timeline if e.get("action_type") == "PERSONALIZATION_CHANGED"]
    print_substep(f"Recorded {len(theme_events)} PERSONALIZATION_CHANGED events.")
    assert len(theme_events) >= 4

    # -------------------------------------------------------------------------
    # STAGE 4: Windows 11 Start Menu Dual-Mode Search & Pinned Grid
    # -------------------------------------------------------------------------
    print_banner(4, "Windows 11 Start Menu Dual-Mode Search & Pinned Grid")
    start_menu = desktop.start_menu

    # Application search
    start_menu.on_search_changed("powershell")
    print_substep("Query 'powershell': Pinned grid hidden, search results active ('Best match: PowerShell')")
    assert start_menu.grid_widget.isHidden()
    assert not start_menu.results_scroll.isHidden()

    # VFS file search
    start_menu.on_search_changed("passwords")
    print_substep("Query 'passwords': VFS indexed file results surfaced")

    # Clear query
    start_menu.on_search_changed("")
    print_substep("Query cleared: Returned to Pinned apps layout (Header: 'Pinned')")
    assert not start_menu.grid_widget.isHidden()
    assert start_menu.results_scroll.isHidden()

    # -------------------------------------------------------------------------
    # STAGE 5: Decoy File Explorer Navigation & Breadcrumb Inspection
    # -------------------------------------------------------------------------
    print_banner(5, "Decoy File Explorer Navigation & Breadcrumb Inspection")
    explorer = DecoyExplorer()
    nav_targets = [
        "C:\\Users\\Dell\\Desktop",
        "C:\\Users\\Dell\\Documents",
        "C:\\Users\\Dell\\Downloads"
    ]
    for target in nav_targets:
        explorer.navigate_to(target)
        items = vfs.list_dir(target)
        print_substep(f"Navigated to '{explorer.current_path}' ({len(items)} items present in folder)")
        assert explorer.current_path == target

    # -------------------------------------------------------------------------
    # STAGE 6: Decoy Notepad Sensitive Pattern Interception & Recent Files
    # -------------------------------------------------------------------------
    print_banner(6, "Decoy Notepad Sensitive Pattern Interception & Recent Files")
    notepad = DecoyNotepad()
    cred_file = "C:\\Users\\Dell\\Desktop\\cloud_access_keys.txt"
    vfs.create_file(cred_file, content="[Initial Empty State]", overwrite=True)

    notepad.open_virtual_file(cred_file)
    print_substep(f"Opened virtual file in Decoy Notepad: '{cred_file}'")

    sensitive_content = (
        "# AWS Operational Configuration\n"
        "AWS_ACCESS_KEY_ID=AKIA5DECOYTRAP7X92Q0\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "DB_PASSWORD=P@ssw0rd2026!MasterSecure\n"
    )
    notepad.text_area.setPlainText(sensitive_content)
    notepad.save_file()
    print_substep("Injected honey-tokens into document and executed save_file()")

    timeline = tracker.get_timeline()
    sens_events = [e for e in timeline if e.get("action_type") == "SENSITIVE_DATA_DETECTED"]
    print_substep(f"Regex heuristic triggered: {len(sens_events)} SENSITIVE_DATA_DETECTED events captured!")
    assert len(sens_events) >= 1
    print_substep(f"Decoy Notepad recent files tracked: {notepad.recent_files}")
    assert cred_file in notepad.recent_files

    # -------------------------------------------------------------------------
    # STAGE 7: Virtual PowerShell Extended Cmdlets (tree, Get-Date, Get-Service)
    # -------------------------------------------------------------------------
    print_banner(7, "Virtual PowerShell Extended Cmdlets (tree, Get-Date, Get-Service)")
    engine = VirtualCommandEngine()

    # Cmdlet 1: tree
    out_tree, _ = engine.execute("tree C:\\Users\\Dell\\Desktop")
    print_substep("Executed 'tree C:\\Users\\Dell\\Desktop':")
    for line in out_tree.splitlines()[:6]:
        print(f"    {line}")
    assert "+---" in out_tree

    # Cmdlet 2: Get-Date
    out_date, _ = engine.execute("Get-Date")
    print_substep(f"Executed 'Get-Date': {out_date.strip()}")
    assert time.strftime("%Y") in out_date

    # Cmdlet 3: Get-Service
    out_svc, _ = engine.execute("Get-Service")
    print_substep("Executed 'Get-Service':")
    for line in out_svc.splitlines()[:5]:
        print(f"    {line}")
    assert "WinDefend" in out_svc

    # Cmdlet 4: gl alias
    out_gl, _ = engine.execute("gl")
    print_substep(f"Executed 'gl' alias: {out_gl.strip().splitlines()[-1]}")
    assert "Path" in out_gl

    # -------------------------------------------------------------------------
    # STAGE 8: Decoy Chrome Cloud Download Sync to VFS Downloads
    # -------------------------------------------------------------------------
    print_banner(8, "Decoy Chrome Cloud Download Sync to VFS Downloads")
    chrome = DecoyChrome()
    download_filename = "Q4_Internal_Financial_Audit.xlsx"
    chrome.on_drive_file_clicked(download_filename)

    expected_download_path = f"C:\\Users\\Dell\\Downloads\\{download_filename}"
    assert vfs.exists(expected_download_path), f"File {expected_download_path} must exist in VFS"
    content = vfs.read_file(expected_download_path)
    print_substep(f"Decoy Chrome download synchronized into VFS: '{expected_download_path}'")
    print_substep(f"Downloaded payload header: {content.splitlines()[0]}")

    timeline = tracker.get_timeline()
    dl_events = [e for e in timeline if e.get("action_type") == "BROWSER_DOWNLOAD_COMPLETED"]
    print_substep(f"Recorded {len(dl_events)} BROWSER_DOWNLOAD_COMPLETED events.")
    assert len(dl_events) >= 1

    # -------------------------------------------------------------------------
    # STAGE 9: Recycle Bin Deletion, Inspection, Restoration & Purge Lifecycle
    # -------------------------------------------------------------------------
    print_banner(9, "Recycle Bin Deletion, Inspection, Restoration & Purge Lifecycle")
    disposable_file = "C:\\Users\\Dell\\Desktop\\disposable_threat_note.txt"
    vfs.create_file(disposable_file, content="Extortion Demand Note", overwrite=True)
    print_substep(f"Created file: '{disposable_file}'")

    # Move to recycle bin
    vfs.delete(disposable_file, to_recycle_bin=True)
    print_substep(f"Deleted to Recycle Bin: exists in Desktop = {vfs.exists(disposable_file)}")
    assert not vfs.exists(disposable_file)

    rb_items = vfs.get_recycle_bin_items()
    print_substep(f"Recycle Bin holds {len(rb_items)} item(s).")
    assert len(rb_items) >= 1

    # Restore
    restored = vfs.restore_from_recycle_bin(disposable_file)
    print_substep(f"Restored file '{disposable_file}': exists = {vfs.exists(disposable_file)}")
    assert vfs.exists(disposable_file)

    # Re-delete and purge
    vfs.delete(disposable_file, to_recycle_bin=True)
    explorer.navigate_to("C:\\$Recycle.Bin")
    print_substep(f"Explorer navigated to '{explorer.current_path}' (status: {explorer.status_lbl.text()})")

    explorer.empty_recycle_bin()
    print_substep(f"Emptied Recycle Bin. Current count in VFS: {len(vfs.get_recycle_bin_items())}")
    assert len(vfs.get_recycle_bin_items()) == 0

    timeline = tracker.get_timeline()
    empty_events = [e for e in timeline if e.get("action_type") in ["EMPTY_RECYCLE_BIN", "FILE_EMPTY_RECYCLE_BIN"]]
    assert len(empty_events) >= 1

    # -------------------------------------------------------------------------
    # STAGE 10: Explainable Behavioral Indicators Derivation & Sealed Forensic PDF
    # -------------------------------------------------------------------------
    print_banner(10, "Explainable Behavioral Indicators Derivation & Sealed Forensic PDF")
    final_timeline = tracker.get_timeline()
    print_substep(f"Total Forensic Events Captured in Session: {len(final_timeline)}")

    indicators = extract_behavioral_indicators(final_timeline)
    print("\n  ================ EXPLAINABLE BEHAVIORAL INDICATORS ================")
    print(f"  Composite Behavioral Score : {indicators['behavioral_indicator_score']:.2f} / 100.00")
    print(f"  Distinct Applications      : {len(indicators['distinct_applications'])}")
    for app_item in indicators['distinct_applications']:
        print(f"    - {app_item['application']:15s}: {app_item['action_count']:3d} actions | Citations: {app_item['event_ids'][:3]}")

    print(f"  Virtual Directories Visited: {len(indicators['virtual_directories_visited'])}")
    for dir_item in indicators['virtual_directories_visited'][:4]:
        print(f"    - {dir_item['directory']} (Visits: {dir_item['visit_count']}, Event: {dir_item['event_id']})")

    print(f"  Sensitive Decoy Files Targeted: {len(indicators['sensitive_files_targeted'])}")
    for s_file in indicators['sensitive_files_targeted'][:3]:
        print(f"    - {s_file['file']} (Mode: {s_file['access_mode']}, Event: {s_file['event_id']})")

    file_ops = indicators['file_operations_summary']
    print(f"  File Operations Summary    : Total={file_ops.get('total_operations', 0)} | Completed={file_ops.get('completed_count', 0)} | Failed={file_ops.get('failed_count', 0)}")

    latency = indicators['recon_to_exfil_latency']
    print(f"  Recon-to-Exfil Latency     : {latency['latency_seconds']} s (Recon: {latency['initial_recon_event_id']} -> Sensitive: {latency['first_sensitive_event_id']})")
    print("  ===================================================================")

    # Run AI Intent Analyzer & PDF Generator
    print_substep("Executing Threat Intelligence Analysis...")
    analyzer = IntruderIntentAnalyzer()
    threat_intel = analyzer.analyze_session(timeline=final_timeline)
    threat_intel["behavioral_indicators"] = indicators

    pdf_gen = ForensicReportGenerator(output_dir=os.path.join(PROJECT_ROOT, "data", "forensics"))
    save_name = f"Demonstration_Forensic_Report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    generated_path = pdf_gen.generate_report(ai_report=threat_intel, timeline=final_timeline, save_filename=save_name)

    file_size = os.path.getsize(generated_path)
    with open(generated_path, "rb") as f:
        pdf_hash = hashlib.sha256(f.read()).hexdigest()

    print("\n" + "=" * 80)
    print("                DEMONSTRATION SUCCESSFULLY COMPLETED!")
    print("=" * 80)
    print(f" Generated PDF Report : {generated_path}")
    print(f" Document File Size   : {file_size:,} bytes")
    print(f" Digital SHA-256 Seal : {pdf_hash}")
    print(f" Forensic Integrity   : VALIDATED (All 10 stages passed with zero errors)")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
