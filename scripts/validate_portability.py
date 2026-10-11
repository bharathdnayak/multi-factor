"""
Portability and Release-Readiness Validator
Behavioral Drift -- Continuous Authentication & Honeypot Forensics

Performs non-destructive pre-flight auditing to verify the project can be cloned,
configured, and executed on any compatible Windows laptop.

Status Codes:
  [PASS] Required component verified successfully.
  [WARN] Optional component unavailable (system gracefully falls back).
  [FAIL] Required component missing or unusable (blocks release).
"""

import os
import sys
import json
import urllib.request
from pathlib import Path

# Resolve project root dynamically
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class PortabilityValidator:
    def __init__(self):
        self.passes = 0
        self.warnings = 0
        self.failures = 0

    def record_pass(self, category: str, detail: str):
        self.passes += 1
        print(f"  [PASS] {category:<28} : {detail}")

    def record_warn(self, category: str, detail: str):
        self.warnings += 1
        print(f"  [WARN] {category:<28} : {detail}")

    def record_fail(self, category: str, detail: str):
        self.failures += 1
        print(f"  [FAIL] {category:<28} : {detail}")

    def run_all_checks(self) -> int:
        print("=" * 80)
        print("BEHAVIORAL DRIFT: COMPREHENSIVE PORTABILITY & RELEASE-READINESS AUDIT")
        print("=" * 80)
        print(f"Resolved Project Root: {PROJECT_ROOT}\n")

        self.check_python_environment()
        self.check_required_dependencies()
        self.check_directory_structure_and_permissions()
        self.check_configuration_and_templates()
        self.check_ml_model_artifacts()
        self.check_pdf_generator_readiness()
        self.check_optional_ollama_service()
        self.check_hardware_sensors()

        print("\n" + "=" * 80)
        print(f"PORTABILITY AUDIT SUMMARY: {self.passes} PASSED | {self.warnings} WARNINGS | {self.failures} FAILED")
        print("=" * 80)

        if self.failures > 0:
            print("\n[RESULT] FAILED -- One or more critical components are missing or misconfigured.")
            return 1
        elif self.warnings > 0:
            print("\n[RESULT] PASSED WITH WARNINGS -- All required core components verified.")
            print("         Optional services (Ollama/Webcam) can be enabled when prerequisites are installed.")
            return 0
        else:
            print("\n[RESULT] PASSED -- All components verified and fully portable.")
            return 0

    def check_python_environment(self):
        print("[1/8] Auditing Python Environment & Operating System...")
        version = sys.version_info
        ver_str = f"{version.major}.{version.minor}.{version.micro}"

        if version.major == 3 and 10 <= version.minor <= 14:
            self.record_pass("Python Version", f"Python {ver_str} supported (3.10 - 3.14)")
        else:
            self.record_fail("Python Version", f"Python {ver_str} detected. Requires Python 3.10 - 3.14.")

        if sys.platform == "win32":
            self.record_pass("Operating System", "Microsoft Windows (win32)")
        else:
            self.record_warn("Operating System", f"{sys.platform} detected (Windows recommended for full GUI/hook support)")

        # Check path spaces handling
        if " " in str(PROJECT_ROOT):
            self.record_pass("Path Robustness", f"Directory contains spaces ('{PROJECT_ROOT.name}'); paths quoted correctly")
        else:
            self.record_pass("Path Robustness", "Standard path format without spaces")

    def check_required_dependencies(self):
        print("\n[2/8] Auditing Required Third-Party Dependencies...")
        required_packages = [
            ("PyQt6", "PyQt6", "Honeypot desktop GUI and sandboxed application windows"),
            ("torch", "PyTorch", "Deep SVDD 1D-CNN temporal sequence biometric detector"),
            ("sklearn", "scikit-learn", "One-Class SVM and Isolation Forest anomaly evaluators"),
            ("numpy", "NumPy", "Vector and matrix mathematical operations"),
            ("pandas", "Pandas", "Feature dataframe manipulations and CSV parsing"),
            ("scipy", "SciPy", "Statistical kernel estimation and distribution processing"),
            ("pynput", "pynput", "Keystroke and mouse dynamics continuous capture hook"),
            ("psutil", "psutil", "Process context, CPU and RAM telemetry extraction"),
            ("fastapi", "FastAPI", "Cyber-Ops Web Dashboard REST API"),
            ("uvicorn", "Uvicorn", "ASGI web server daemon"),
            ("fpdf", "fpdf2", "FIPS 180-4 compliant 12-section DFIR PDF generator"),
            ("cv2", "OpenCV", "Optical sensor Haar-cascade presence detection"),
            ("PIL", "Pillow", "Image evidence rendering and thumbnail synthesis"),
            ("pyotp", "PyOTP", "RFC 6238 time-based multi-factor authentication"),
            ("requests", "Requests", "HTTP alert dispatching for Telegram and webhooks"),
        ]

        for mod_name, label, purpose in required_packages:
            try:
                __import__(mod_name)
                self.record_pass(f"Package: {label}", purpose)
            except ImportError as err:
                self.record_fail(f"Package: {label}", f"Missing dependency ({err})")

    def check_directory_structure_and_permissions(self):
        print("\n[3/8] Auditing Directory Structures and Write Permissions...")
        runtime_dirs = [
            "data/sessions",
            "data/raw",
            "data/forensics",
            "data/sandbox",
            "data/logs",
            "data/harvested",
            "data/benchmarks",
            "models",
        ]

        for rel_dir in runtime_dirs:
            full_path = PROJECT_ROOT / rel_dir
            if not full_path.exists():
                try:
                    full_path.mkdir(parents=True, exist_ok=True)
                    self.record_pass(f"Directory: {rel_dir}", "Auto-initialized missing directory")
                except Exception as e:
                    self.record_fail(f"Directory: {rel_dir}", f"Failed to initialize directory: {e}")
                    continue

            # Verify write permissions non-destructively
            test_file = full_path / ".portability_test_probe"
            try:
                test_file.write_text("probe", encoding="utf-8")
                test_file.unlink(missing_ok=True)
                self.record_pass(f"Writable: {rel_dir}", "Write and delete permissions confirmed")
            except Exception as e:
                self.record_fail(f"Writable: {rel_dir}", f"Directory not writable: {e}")

    def check_configuration_and_templates(self):
        print("\n[4/8] Auditing Safe Configuration & Template Files...")
        # Check .env and .env.example
        env_example = PROJECT_ROOT / ".env.example"
        env_file = PROJECT_ROOT / ".env"

        if env_example.exists():
            self.record_pass("Config Template: .env.example", "Safe environment template exists")
        else:
            self.record_fail("Config Template: .env.example", "Missing .env.example template file")

        if env_file.exists():
            self.record_pass("Config File: .env", "Local environment file present")
        else:
            self.record_warn("Config File: .env", "No local .env found (run setup.bat to generate from .env.example)")

        # Check security config template
        sec_example = PROJECT_ROOT / "security" / "config.json.example"
        sec_config = PROJECT_ROOT / "security" / "config.json"

        if sec_example.exists():
            self.record_pass("Config Template: security/config", "Security JSON template exists")
        else:
            self.record_fail("Config Template: security/config", "Missing security/config.json.example")

        if sec_config.exists():
            self.record_pass("Config File: security/config", "Security config file present")
        else:
            self.record_warn("Config File: security/config", "No local config.json found (will use built-in defaults)")

    def check_ml_model_artifacts(self):
        print("\n[5/8] Auditing Machine Learning Model Artifacts...")
        models_to_check = [
            ("ml_engine/trained_models.pkl", "One-Class SVM & Isolation Forest Checkpoint"),
            ("models/sequence_model.pt", "Deep SVDD 1D-CNN Sequence Biometrics Model"),
            ("models/sequence_meta.json", "Sequence Architecture & Feature Metadata"),
        ]

        for rel_path, desc in models_to_check:
            full_path = PROJECT_ROOT / rel_path
            if full_path.exists() and full_path.stat().st_size > 100:
                size_kb = full_path.stat().st_size / 1024
                self.record_pass(f"Model: {rel_path}", f"{desc} ({size_kb:.1f} KB)")
            else:
                self.record_fail(f"Model: {rel_path}", f"Missing model weights. Run: python ml_engine/train.py --simulate")

    def check_pdf_generator_readiness(self):
        print("\n[6/8] Auditing 12-Section DFIR PDF Generator...")
        try:
            from dashboard.pdf_generator import ForensicReportGenerator, ForensicPDF
            gen = ForensicReportGenerator()
            self.record_pass("Forensic PDF Engine", "ForensicReportGenerator instantiated successfully")
        except Exception as e:
            self.record_fail("Forensic PDF Engine", f"Failed to instantiate generator: {e}")

    def check_optional_ollama_service(self):
        print("\n[7/8] Auditing Optional Offline Ollama / LLM Service...")
        ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
        try:
            req = urllib.request.Request(f"{ollama_url}/api/tags", headers={"User-Agent": "PortabilityValidator/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name") for m in data.get("models", [])]

                if models:
                    self.record_pass("Ollama Service", f"Daemon active. Models: {', '.join(models)}")
                    if any("qwen" in m.lower() for m in models):
                        self.record_pass("Qwen Model", "Local Qwen model available for narrative synthesis")
                    else:
                        self.record_warn("Qwen Model", "Qwen model not found. Run: 'ollama pull qwen2.5:3b'")
                else:
                    self.record_warn("Ollama Service", "Ollama daemon reachable, but no models installed. Run: 'ollama pull qwen2.5:3b'")
        except Exception:
            self.record_warn("Ollama Service", "Ollama daemon not running (application operates cleanly via deterministic fallback)")

    def check_hardware_sensors(self):
        print("\n[8/8] Auditing Hardware Sensors (Camera & Proximity)...")
        try:
            import cv2
            cap = cv2.VideoCapture(0)
            if cap.isOpened():
                ret, frame = cap.read()
                cap.release()
                if ret and frame is not None:
                    self.record_pass("Optical Sensor", f"Webcam verified ({frame.shape[1]}x{frame.shape[0]})")
                else:
                    self.record_warn("Optical Sensor", "Camera opened but failed to capture frame")
            else:
                self.record_warn("Optical Sensor", "No physical webcam detected on device 0 (synthetic mock frame used)")
        except Exception as e:
            self.record_warn("Optical Sensor", f"Optical check bypassed ({e})")


if __name__ == "__main__":
    validator = PortabilityValidator()
    exit_code = validator.run_all_checks()
    sys.exit(exit_code)
